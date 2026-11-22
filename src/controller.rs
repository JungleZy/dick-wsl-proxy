//! A single owner and recovery journal for scoped M1 and policy-managed M2 sessions.
//! The journal is immutable while active: persist intent BEFORE any guest mutation.
use crate::managed::{Readiness, Runtime};
use crate::{host, ingress::Ingress, kernel, lease, plan::Plan};
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
}
impl Controller {
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
                    });
                Ok(
                    json!({"phase":if issue.is_some(){"recovery_required"}else if p.system_dns.is_some(){"forwarding_managed"}else{"forwarding_scoped"},"active_target":p.target.name,"config_generation":p.cookie,"ingress":p.ingress,"origins":p.origins,"issue":issue,"forwarding":ingress.diagnostics(),"dns_managed":p.system_dns.is_some() && issue.is_none(),"startup_verified":self.readiness.as_ref().and_then(|r|r.as_ref().ok()),"active_policy":self.runtime.as_ref().map(|r|r.policy.public_summary()),"recent_exit":self.recent_exit}),
                )
            }
            (None, Some(d)) => Ok(
                json!({"phase":"recovery_required","active_target":d.target.name,"config_generation":d.cookie,"ingress":d.ingress,"port_reserved":lease::alive(&d)?,"dns_managed":false}),
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
        if let Err(error) = kernel::remove(&p) {
            match kernel::inspect(&p) {
                Ok(owned) if !owned.identity_matches && owned.clean() => (),
                _ => return Err(error),
            }
        }
        if let Some((_, i)) = &mut self.live {
            i.stop()?;
        }
        lease::release(&p)?;
        lifecycle::verify_gone(&p)?;
        journal::forget(&p)?;
        self.live = None;
        self.readiness = None;
        self.runtime = None;
        self.recent_exit = None;
        Ok(())
    }
}
