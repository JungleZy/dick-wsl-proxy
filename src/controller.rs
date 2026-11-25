//! A single owner and recovery journal for scoped M1 and policy-managed M2 sessions.
//! The journal is immutable while active: persist intent BEFORE any guest mutation.
use crate::managed::{Readiness, Runtime};
use crate::{host, ingress::Ingress, kernel, lease, plan::Plan, transition};
use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

pub(crate) mod journal;
pub(crate) mod lifecycle;

#[derive(Default)]
pub struct Controller {
    pub(crate) live: Option<(Plan, Ingress)>,
    pub(crate) readiness: Option<Result<Readiness, String>>,
    pub(crate) runtime: Option<Arc<Runtime>>,
    recent_exit: Option<serde_json::Value>,
    watch: Watch,
    /// Marked entries the last stop or switch left because they could not
    /// be proven this takeover's (decision 20); reported once, then cleared.
    unproven_left: u32,
}

/// Periodic, read-only evidence that the live target still carries this
/// generation's rules. Only definite loss changes the phase; a check that
/// could not run is reported but is not evidence either way.
#[derive(Default)]
struct Watch {
    cookie: u32,
    lost: Option<String>,
    checked_unix_seconds: Option<u64>,
    target_running: Option<bool>,
    consecutive_failures: u32,
    last_error: Option<String>,
}

/// The outcome of one guest observation, judged only by its evidence.
#[derive(Debug, PartialEq, Eq)]
enum Observed {
    Protected,
    Lost(String),
    Unverified(String),
}

/// How an identity or environment drift reported by the guest counts.
#[derive(Debug, PartialEq, Eq)]
enum Drift {
    /// The target or the WSL VM restarted: old rules no longer apply.
    Restarted,
    /// A passing race or a missing or failing tool: says nothing about the rules.
    Unverifiable,
    /// Anything else (rename, new address, a workload outside the cgroup, ...).
    Changed,
}

fn drift_kind(reason: &str) -> Drift {
    const UNVERIFIABLE: [&str; 4] = [
        "unverifiable_workload",
        "tool_unavailable_or_timeout",
        "tool_failed",
        "missing_prerequisite",
    ];
    if UNVERIFIABLE.iter().any(|prefix| reason.starts_with(prefix)) {
        Drift::Unverifiable
    } else if matches!(
        reason,
        "boot_changed" | "cgroup_namespace_changed" | "cgroup_root_changed"
    ) {
        Drift::Restarted
    } else {
        Drift::Changed
    }
}

const RESTARTED: &str = "protection_lost: restarted: the target or the WSL VM restarted; this takeover's rules no longer apply";

fn changed(reason: &str) -> String {
    format!(
        "protection_lost: environment_changed: {reason}: this takeover can no longer prove it covers the target"
    )
}

fn classify(result: Result<(kernel::Ownership, Option<String>), String>) -> Observed {
    match result {
        // Per-connection lookups read only the one entry they authorize, so
        // this check is where a marked entry that is not a provable mapping of
        // this takeover, or two entries sharing a tuple, is caught.
        Ok((own, _)) if own.identity_matches && own.rules_complete && own.unproven_mappings > 0 => {
            Observed::Lost(format!(
                "protection_lost: mapping_integrity: {} connection-tracking entries carry this takeover's mark without a provable mapping",
                own.unproven_mappings
            ))
        }
        Ok((own, _)) if own.identity_matches && own.rules_complete => Observed::Protected,
        Ok((own, _)) if own.identity_matches => Observed::Lost(
            "protection_lost: rules_incomplete: this takeover's rules are missing or incomplete in the target".into(),
        ),
        // Identity unconfirmed and nothing of this generation is left: the rules
        // are gone, whatever else changed.
        Ok((_, drift)) => Observed::Lost(match drift.as_deref().map(|reason| (drift_kind(reason), reason)) {
            Some((Drift::Restarted, _)) => RESTARTED.into(),
            Some((Drift::Changed, reason)) => changed(reason),
            _ => "protection_lost: rules_missing: this takeover's rules are gone from the target".into(),
        }),
        // Rules survive, but the guest could not confirm the identity they were
        // installed for. Only a restart or a real change counts as a loss.
        Err(error) => match error
            .split_once("stale_identity_has_owned_artifacts: ")
            .map(|(_, reason)| reason.trim())
        {
            Some(reason) => match drift_kind(reason) {
                Drift::Restarted => Observed::Lost(RESTARTED.into()),
                Drift::Changed => Observed::Lost(changed(reason)),
                Drift::Unverifiable => Observed::Unverified(error),
            },
            None => Observed::Unverified(error),
        },
    }
}

fn unix_seconds() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// One protection check, started under the controller lock by
/// [`Controller::watch_round`] so that its slow part can run without it.
pub(crate) struct WatchRound {
    plan: Plan,
    generation: u64,
}

/// What [`WatchRound::observe`] found, for [`Controller::finish_watch`].
pub(crate) struct WatchFinding(Finding);

enum Finding {
    RegistryUnreadable(String),
    Unregistered,
    RunningListFailed(String),
    NotRunning,
    Inspected(Observed),
}

impl WatchRound {
    pub(crate) fn target(&self) -> &str {
        &self.plan.target.name
    }

    /// The slow, read-only part of a check: the registry, `wsl --list
    /// --running` and a guest inspect, together up to about 40 seconds. It
    /// holds no controller lock, so a stop never waits behind it. Never mutates
    /// the guest, and skips a target that WSL does not list as running (no
    /// traffic can leave it), so the check does not wake a stopped distribution.
    pub(crate) fn observe(&self) -> WatchFinding {
        // Registration first: a renamed or unregistered target is no longer
        // listed under the name this takeover recorded.
        let current = match host::distributions() {
            Ok(all) => all
                .into_iter()
                .find(|d| d.id.eq_ignore_ascii_case(&self.plan.target.id)),
            Err(error) => return WatchFinding(Finding::RegistryUnreadable(error)),
        };
        let Some(current) = current else {
            return WatchFinding(Finding::Unregistered);
        };
        WatchFinding(match host::running_distributions() {
            Ok(names)
                if names
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(&current.name)) =>
            {
                Finding::Inspected(classify(kernel::inspect_detail(&self.plan)))
            }
            Ok(_) => Finding::NotRunning,
            Err(error) => Finding::RunningListFailed(error),
        })
    }
}

impl Controller {
    /// Starts one protection check of the forwarding target, or returns `None`
    /// when there is nothing to check: no verified takeover, protection already
    /// lost, or an operation in flight.
    pub(crate) fn watch_round(&mut self) -> Option<WatchRound> {
        let plan = match &self.live {
            Some((plan, _)) if self.readiness.as_ref().is_some_and(Result::is_ok) => plan.clone(),
            _ => return None,
        };
        if self.watch.cookie != plan.cookie {
            self.watch = Watch {
                cookie: plan.cookie,
                ..Watch::default()
            };
        }
        if self.watch.lost.is_some() {
            return None;
        }
        let record = transition::load()
            .ok()
            .filter(|record| record.pending.is_none())?;
        Some(WatchRound {
            plan,
            generation: record.generation,
        })
    }

    /// Records what a round found. Returns the reason the first time
    /// protection is found lost; the loss stays until stop.
    ///
    /// A command may have run while the round observed without the lock, and
    /// a stop or switch removes the rules mid-inspect. So the finding counts
    /// only if the same takeover is still live and ready and no operation began
    /// since the round started: a stop that failed halfway keeps the cookie,
    /// but not the operation generation.
    pub(crate) fn finish_watch(
        &mut self,
        round: WatchRound,
        finding: WatchFinding,
    ) -> Option<String> {
        let unchanged = matches!(&self.live, Some((plan, _)) if *plan == round.plan)
            && self.readiness.as_ref().is_some_and(Result::is_ok)
            && self.watch.cookie == round.plan.cookie
            && self.watch.lost.is_none()
            && transition::load().is_ok_and(|record| {
                record.pending.is_none() && record.generation == round.generation
            });
        if !unchanged {
            return None;
        }
        let finding = finding.0;
        if !matches!(finding, Finding::RegistryUnreadable(_)) {
            self.watch.checked_unix_seconds = unix_seconds();
        }
        match finding {
            Finding::RegistryUnreadable(error) => {
                self.unverified(format!("registry_read_failed:{error}"))
            }
            Finding::Unregistered => self.lose(
                "protection_lost: target_unregistered: the target distribution is no longer registered"
                    .into(),
            ),
            Finding::RunningListFailed(error) => {
                self.unverified(format!("running_list_failed:{error}"))
            }
            Finding::NotRunning => {
                self.watch.target_running = Some(false);
                self.watch.consecutive_failures = 0;
                self.watch.last_error = None;
                None
            }
            Finding::Inspected(observed) => {
                self.watch.target_running = Some(true);
                match observed {
                    Observed::Protected => {
                        self.watch.consecutive_failures = 0;
                        self.watch.last_error = None;
                        None
                    }
                    Observed::Lost(reason) => self.lose(reason),
                    Observed::Unverified(error) => self.unverified(error),
                }
            }
        }
    }

    fn lose(&mut self, reason: String) -> Option<String> {
        self.watch.lost = Some(reason.clone());
        Some(reason)
    }

    fn unverified(&mut self, error: String) -> Option<String> {
        self.watch.consecutive_failures = self.watch.consecutive_failures.saturating_add(1);
        self.watch.last_error = Some(error);
        None
    }

    fn watch_lost(&self, plan: &Plan) -> Option<String> {
        (self.watch.cookie == plan.cookie)
            .then(|| self.watch.lost.clone())
            .flatten()
    }

    fn watch_view(&self, plan: &Plan) -> serde_json::Value {
        if self.watch.cookie != plan.cookie {
            return serde_json::json!({"checked_unix_seconds": null});
        }
        serde_json::json!({
            "checked_unix_seconds": self.watch.checked_unix_seconds,
            "target_running": self.watch.target_running,
            "consecutive_failures": self.watch.consecutive_failures,
            "last_error": self.watch.last_error,
            "lost": self.watch.lost,
        })
    }

    /// Explicit operator request only: observe the target's actual TLS-verified public exit.
    pub(crate) fn probe_exit(&mut self, expected: u64) -> Result<(), String> {
        let (plan, runtime) = self.switch_source(expected)?;
        if runtime.policy.allows_domain("my.ippure.com") {
            return Err("exit_probe_domain_is_direct".into());
        }
        let script = concat!(
            "exec /usr/bin/python3 -I - <<'WPL_EXIT'\n",
            include_str!("guest/exit_probe.py"),
            "\nWPL_EXIT\n"
        );
        let raw =
            host::guest_script(&plan.target, script).map_err(|_| "target_exit_probe_failed")?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ResultIp {
            ip: Ipv4Addr,
            peer: Ipv4Addr,
            country: String,
        }
        let observed: ResultIp =
            serde_json::from_str(&raw).map_err(|_| "invalid_exit_probe_response")?;
        if runtime.policy.allows_ip(observed.peer)
            || runtime.dns.direct_alias(observed.peer)?.is_some()
            || runtime
                .policy
                .is_reserved_endpoint(SocketAddrV4::new(observed.peer, 443))
        {
            return Err("exit_probe_destination_not_chained".into());
        }
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "invalid_clock")?
            .as_secs();
        self.recent_exit = Some(
            serde_json::json!({"ip":observed.ip,"country":observed.country,"checked_unix_seconds":t,"matches_residential":runtime.policy.matches_residence(observed.ip)}),
        );
        Ok(())
    }

    pub(crate) fn settled_status(&self) -> Result<serde_json::Value, String> {
        use serde_json::json;
        let disk = journal::load()?;
        match (&self.live, disk) {
            (None, None) => Ok(json!({"phase":"idle","active_target":null,"config_generation":0})),
            (Some((p, ingress)), Some(d)) if *p == d => {
                let issue = self
                    .readiness
                    .as_ref()
                    .and_then(|r| r.as_ref().err().cloned())
                    .or_else(|| ingress.health().err())
                    .or_else(|| match lease::alive(p) {
                        Ok(true) => None,
                        Ok(false) => Some("port_custodian_missing".into()),
                        Err(e) => Some(e),
                    })
                    .or_else(|| self.watch_lost(p));
                Ok(
                    json!({"phase":if issue.is_some(){"recovery_required"}else if p.system_dns.is_some(){"forwarding_managed"}else{"forwarding_scoped"},"active_target":p.target.name,"config_generation":p.cookie,"ingress":p.ingress,"origins":p.origins,"issue":issue,"forwarding":ingress.diagnostics(),"dns_managed":p.system_dns.is_some() && issue.is_none(),"startup_verified":self.readiness.as_ref().and_then(|r|r.as_ref().ok()),"active_policy":self.runtime.as_ref().map(|r|r.policy.public_summary()),"dns_stats":self.runtime.as_ref().map(|r|r.dns.report()),"recent_exit":self.recent_exit,"protection_check":self.watch_view(p),"target_registered":issue.is_some().then(|| lifecycle::registration_present(p).ok()).flatten()}),
                )
            }
            (None, Some(d)) => Ok(
                json!({"phase":"recovery_required","active_target":d.target.name,"config_generation":d.cookie,"ingress":d.ingress,"port_reserved":lease::alive(&d)?,"target_registered":lifecycle::registration_present(&d).ok(),"dns_managed":false}),
            ),
            _ => Err("journal_ownership_changed".into()),
        }
    }
    pub(crate) fn activate(
        &mut self,
        p: Plan,
        runtime: Option<Arc<Runtime>>,
        window: kernel::GrantWindow,
    ) -> Result<(), String> {
        if p.system_dns.is_some() != runtime.is_some() {
            return Err("policy_mode_mismatch".into());
        }
        // IPv4 domain exceptions use per-name synthetic addresses. IPv6 has no
        // equivalent alias space, so refuse this combination instead of
        // silently routing an allowlisted AAAA answer through the chain.
        if p.ipv6.is_some()
            && runtime
                .as_ref()
                .is_some_and(|runtime| runtime.policy.has_domain_allowlist())
        {
            return Err("ipv6_domain_allowlist_unsupported".into());
        }
        if self.live.is_some() || journal::load()?.is_some() {
            return Err("recover_or_stop_existing_target_first".into());
        }
        journal::persist(&p)?;
        let mut sockets = match Ingress::bind(&p, runtime.clone()) {
            Ok(s) => s,
            Err(e) => {
                lease::release(&p)?;
                journal::forget(&p)?;
                return Err(e);
            }
        };
        if let Err(e) = kernel::arm(&p, window).and_then(|_| kernel::install(&p)) {
            if runtime.is_some() {
                // A partial filter/NAT transaction is not proof of either a healthy or an
                // idle target. Keep ownership and stop all forwarding until explicit recovery.
                let shutdown = sockets.stop().err();
                self.live = Some((p, sockets));
                let reason = format!("managed_install_unverified:{e}; ingress_stop:{shutdown:?}");
                self.readiness = Some(Err(reason.clone()));
                return Err(reason);
            }
            // A guest invocation can time out AFTER installing some rules. Keep journal and
            // independent socket reservation if cleanup is incomplete; never infer rollback.
            let rollback = kernel::remove(&p)
                .and_then(|_| sockets.stop())
                .and_then(|_| lease::release(&p))
                .and_then(|_| journal::forget(&p));
            return Err(match rollback {
                Ok(()) => format!("start_rolled_back:{e}"),
                Err(r) => format!("recovery_required:{e}; rollback:{r}"),
            });
        }
        if let Some(runtime) = &runtime {
            let chain_tcp_before = sockets.chain_tcp_attempts();
            match runtime.verify(&p) {
                Ok(ok) if sockets.chain_tcp_attempts() > chain_tcp_before => {
                    self.readiness = Some(Ok(ok))
                }
                Ok(_) => {
                    let forwarding = sockets.diagnostics();
                    let shutdown = sockets.stop().err();
                    self.live = Some((p, sockets));
                    let reason = format!(
                        "managed_readiness_failed:https_probe_not_observed_on_chain; ingress_stop:{shutdown:?}; forwarding:{forwarding}"
                    );
                    self.readiness = Some(Err(reason.clone()));
                    return Err(reason);
                }
                Err(e) => {
                    let forwarding = sockets.diagnostics();
                    let shutdown = sockets.stop().err();
                    self.live = Some((p, sockets));
                    let reason = format!(
                        "managed_readiness_failed:{e}; ingress_stop:{shutdown:?}; forwarding:{forwarding}"
                    );
                    self.readiness = Some(Err(reason.clone()));
                    return Err(reason);
                }
            }
        }
        self.runtime = runtime;
        self.live = Some((p, sockets));
        Ok(())
    }
    pub(crate) fn retire(&mut self, expected: &Plan) -> Result<(), String> {
        let Some(p) = journal::load()? else {
            if self.live.is_some() {
                return Err("missing_active_journal".into());
            }
            return lifecycle::verify_gone(expected);
        };
        if &p != expected {
            return Err("operation_owner_mismatch".into());
        }
        if self.live.as_ref().is_some_and(|(l, _)| *l != p) {
            return Err("journal_ownership_changed".into());
        }
        if !host::distributions()?
            .iter()
            .any(|d| d.id.eq_ignore_ascii_case(&p.target.id))
        {
            return Err("journal_distribution_no_longer_matches_registration".into());
        }
        // Revoke even an armed install that has not committed a rule yet. A stale
        // identity is never permission to mutate; retire it only on a separate
        // read-only proof that the old generation is already completely absent.
        let unproven = match kernel::remove(&p) {
            Ok(unproven) => unproven,
            Err(error) => match kernel::inspect(&p) {
                Ok(owned) if !owned.identity_matches && owned.clean() => owned.unproven_mappings,
                _ => return Err(error),
            },
        };
        if let Some((_, i)) = &mut self.live {
            // Like `abandon`: an earlier forwarding failure, which `stop` reports
            // once after joining every worker, is no reason to keep the ports or
            // the journal. Status already showed it while the takeover ran.
            let _ = i.stop();
        }
        lease::release(&p)?;
        lifecycle::verify_gone(&p)?;
        journal::forget(&p)?;
        self.live = None;
        self.readiness = None;
        self.runtime = None;
        self.recent_exit = None;
        self.watch = Watch::default();
        self.unproven_left = unproven;
        Ok(())
    }

    /// How many unprovable marked entries the last stop or switch left in
    /// the old target, once; zero afterwards.
    pub(crate) fn take_unproven_left(&mut self) -> u32 {
        std::mem::take(&mut self.unproven_left)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ownership(identity_matches: bool, rules_complete: bool) -> kernel::Ownership {
        kernel::Ownership {
            identity_matches,
            rules_present: rules_complete,
            mappings_present: false,
            rules_complete,
            unproven_mappings: 0,
        }
    }

    #[test]
    fn only_definite_evidence_marks_protection_lost() {
        let observed = |identity, complete, drift: Option<&str>| {
            classify(Ok((
                ownership(identity, complete),
                drift.map(str::to_owned),
            )))
        };
        let lost = |observed: Observed, kind: &str| match observed {
            Observed::Lost(reason) => assert!(reason.starts_with(kind), "{reason}"),
            other => panic!("expected loss {kind}, got {other:?}"),
        };
        assert_eq!(observed(true, true, None), Observed::Protected);
        // Same identity, but the rules were flushed or partly removed.
        lost(
            observed(true, false, None),
            "protection_lost: rules_incomplete",
        );
        // Identity unconfirmed and nothing of ours is left: lost, named by cause.
        lost(
            observed(false, false, Some("boot_changed")),
            "protection_lost: restarted",
        );
        lost(
            observed(false, false, Some("workload_outside_distro_cgroup")),
            "protection_lost: environment_changed: workload_outside_distro_cgroup",
        );
        lost(
            observed(false, false, Some("unverifiable_workload")),
            "protection_lost: rules_missing",
        );
        let surviving = |reason: &str| {
            classify(Err(format!(
                "inspect:wsl_exit_failed: exit code: 1: kernel_operation_failed: stale_identity_has_owned_artifacts: {reason}"
            )))
        };
        // Rules survive an identity the guest could not confirm.
        lost(
            surviving("cgroup_namespace_changed"),
            "protection_lost: restarted",
        );
        lost(
            surviving("guest_ipv6_address_changed"),
            "protection_lost: environment_changed: guest_ipv6_address_changed",
        );
        // A marked entry that is not a provable mapping is caught here, not
        // per connection: the lookups read only the entry they authorize. The
        // guest counts such entries instead of failing, so a stop can still
        // remove the rules (decision 20).
        let mut unprovable = ownership(true, true);
        unprovable.unproven_mappings = 2;
        lost(
            classify(Ok((unprovable, None))),
            "protection_lost: mapping_integrity: 2 connection-tracking entries",
        );
        // A passing race or a missing tool is not evidence of loss.
        for reason in [
            "unverifiable_workload",
            "tool_unavailable_or_timeout: ip",
            "missing_prerequisite: iptables-legacy-save",
        ] {
            assert!(
                matches!(surviving(reason), Observed::Unverified(_)),
                "{reason}"
            );
        }
        // A check that could not run at all is not evidence either.
        for error in [
            "inspect:wsl_deadline_exceeded",
            "registry_enumeration_failed: access denied",
        ] {
            assert_eq!(
                classify(Err(error.into())),
                Observed::Unverified(error.into())
            );
        }
    }

    #[test]
    fn an_idle_controller_never_checks_the_guest() {
        let mut controller = Controller::default();
        assert!(controller.watch_round().is_none());
        assert_eq!(controller.watch.checked_unix_seconds, None);
    }
}
