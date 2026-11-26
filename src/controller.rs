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
    /// The target's Docker bridge networks this takeover covers (decision 24).
    networks: Vec<String>,
    /// Why they could not be read or synced in the last round, if so.
    network_error: Option<String>,
    /// After a loss that leaves the target direct, the drop-only rules
    /// (decision 33): where they stand as of the last round.
    block: Option<BlockState>,
}

/// The drop-only rules of a lost takeover (decision 33), as last seen.
#[derive(Clone, Debug, PartialEq, Eq)]
enum BlockState {
    /// In place in the target as it ran at that round, dropping also what
    /// these Docker bridges of the target forward.
    Installed(Vec<String>),
    /// Could not be put in place; the target may be direct.
    Failed(String),
    /// Not running: nothing can leave it. Blocked again when it runs.
    TargetStopped,
}

impl BlockState {
    fn view(&self) -> serde_json::Value {
        match self {
            Self::Installed(bridges) => {
                serde_json::json!({"state": "installed", "error": null, "bridges": bridges})
            }
            Self::Failed(error) => serde_json::json!({"state": "failed", "error": error}),
            Self::TargetStopped => serde_json::json!({"state": "target_stopped", "error": null}),
        }
    }
}

/// Decision 33 once the controller that ran a takeover is gone: one round for
/// the managed takeover the journal still records, run by a controller that
/// started again (and so has no live takeover) or, with no controller at all,
/// by the port custodian. The slow part is read-only; the block itself runs
/// only after [`Self::current`] rechecks the record under the lock that a stop
/// needs too, so it never follows the stop that would remove it.
pub(crate) struct RecoveryRound {
    plan: Plan,
    generation: u64,
}

impl RecoveryRound {
    /// The recorded managed takeover, when no operation is in flight.
    pub(crate) fn recorded() -> Option<Self> {
        let record = transition::load()
            .ok()
            .filter(|record| record.pending.is_none())?;
        let plan = journal::load().ok().flatten()?;
        plan.system_dns.is_some().then_some(Self {
            plan,
            generation: record.generation,
        })
    }

    pub(crate) fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Slow and read-only: whether the target is registered, running, and
    /// its rules gone or no longer applying. Never wakes a stopped target.
    pub(crate) fn due(&self) -> bool {
        let Ok(all) = host::distributions() else {
            return false;
        };
        let Some(current) = all
            .into_iter()
            .find(|d| d.id.eq_ignore_ascii_case(&self.plan.target.id))
        else {
            return false;
        };
        match host::running_distributions() {
            Ok(names)
                if names
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(&current.name)) => {}
            _ => return false,
        }
        recovery_due(&classify(kernel::inspect_detail(&self.plan)))
    }

    /// Still the same recorded takeover with nothing in flight.
    pub(crate) fn current(&self) -> bool {
        journal::load().ok().flatten().as_ref() == Some(&self.plan)
            && transition::load().is_ok_and(|record| {
                record.pending.is_none() && record.generation == self.generation
            })
    }
}

/// Whether what a recovery round observed calls for a block.
fn recovery_due(observed: &Observed) -> bool {
    matches!(observed, Observed::Lost(reason) if blockable(reason))
}

/// Losses after which the target's own new connections leave directly: its
/// rules are gone or no longer apply (decision 33). Not a changed
/// environment or unprovable mappings, where the rules still stand.
fn blockable(reason: &str) -> bool {
    [
        "restarted",
        "rules_missing",
        "rules_incomplete",
        "rules_rebound",
    ]
    .iter()
    .any(|kind| reason.starts_with(&format!("protection_lost: {kind}:")))
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

/// What a block says about the target's containers (decision 33).
pub(crate) fn containers_blocked(bridges: &[String]) -> String {
    if bridges.is_empty() {
        "没有记下目标的 Docker 网络，若目标里有容器，它们转发出去的流量不在其内".to_owned()
    } else {
        format!(
            "目标的 Docker 网络（{}）转发出去的流量也一并丢弃；接管期间没见过的网络不在其内",
            bridges.join("、")
        )
    }
}

/// The log line after a probe that was not counted led to a successful
/// re-anchoring (decision 37).
const REANCHORED: &str = "目标发行版里本次接管的规则一度不再匹配目标（别的发行版整表导回了含这些规则的 nft 表），目标的新连接可能短暂直连、那个发行版的连接可能被送进了住宅出口；已在目标里重新锚定，探测确认恢复。";

/// A probe still not counted after re-anchoring, or a re-anchoring that failed.
fn rebound(detail: &str) -> String {
    format!(
        "protection_lost: rules_rebound: this takeover's rules no longer match the target and re-anchoring did not fix it ({detail})"
    )
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
        // Not blocked: the decision 33 block covers the target's own
        // processes, which the local guard still covers; the containers are
        // what the gate no longer may (decision 37).
        Ok((own, _)) if own.identity_matches && own.rules_complete && own.forward_displaced => {
            Observed::Lost(
                "protection_lost: forward_gate_displaced: another rule now precedes this takeover's forward gate; the target's containers may bypass it"
                    .into(),
            )
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
    /// The loss is already recorded and leaves the target direct: this round
    /// only (re)blocks it (decision 33).
    block: bool,
}

/// What [`WatchRound::observe`] found, for [`Controller::finish_watch`].
pub(crate) struct WatchFinding(Finding);

enum Finding {
    RegistryUnreadable(String),
    Unregistered,
    RunningListFailed(String),
    NotRunning,
    /// What the inspect concluded, the network sync it led to, and a log
    /// line when the rules had to be re-anchored (decision 37).
    Inspected(Observed, Option<NetworkUpdate>, Option<String>),
    /// A blocking round found the target registered and running.
    BlockDue,
}

/// The target's Docker networks after a round, and what changed (decision 24).
struct NetworkUpdate {
    current: Vec<String>,
    added: Vec<String>,
    removed: Vec<String>,
    error: Option<String>,
}

/// What [`Controller::finish_watch`] reports back: a first protection loss,
/// and a runtime log line about the target's container networks.
pub(crate) struct WatchOutcome {
    pub(crate) lost: Option<String>,
    pub(crate) note: Option<(&'static str, String)>,
    /// Block this plan's target now, still under the controller lock that
    /// rechecked the takeover, then report through [`Controller::record_block`].
    pub(crate) block: Option<Plan>,
}

impl WatchRound {
    pub(crate) fn target(&self) -> &str {
        &self.plan.target.name
    }

    /// One guest inspect; when the rules are complete but the probe from the
    /// target was not counted, one re-anchoring (decision 37); when the
    /// target's Docker networks no longer match the rules, one sync to add or
    /// remove per-network rules (decision 24). These are the only changes a
    /// round ever makes.
    fn inspect(&self) -> Finding {
        match kernel::inspect_networks(&self.plan) {
            Ok((ownership, drift, networks)) => {
                let mut observed = classify(Ok((ownership, drift)));
                let mut anchored = None;
                if observed == Observed::Protected && !ownership.rules_bound {
                    match kernel::anchor(&self.plan) {
                        Ok(true) => anchored = Some(REANCHORED.to_owned()),
                        Ok(false) => {
                            observed = Observed::Lost(rebound("still_unbound_after_anchor"))
                        }
                        Err(error) => observed = Observed::Lost(rebound(&error)),
                    }
                }
                let update = match (&observed, networks) {
                    (Observed::Protected, Some(networks)) => Some(self.update_networks(networks)),
                    _ => None,
                };
                Finding::Inspected(observed, update, anchored)
            }
            Err(error) => Finding::Inspected(classify(Err(error)), None, None),
        }
    }

    fn update_networks(&self, networks: kernel::Networks) -> NetworkUpdate {
        let unchanged = |error: Option<String>| NetworkUpdate {
            current: networks.installed.clone(),
            added: Vec::new(),
            removed: Vec::new(),
            error,
        };
        if let Some(error) = networks.error.clone() {
            return unchanged(Some(error));
        }
        if networks.in_sync == Some(true) {
            return unchanged(None);
        }
        match kernel::sync_networks(&self.plan) {
            Ok(synced) => NetworkUpdate {
                current: synced.current,
                added: synced.added,
                removed: synced.removed,
                error: None,
            },
            Err(error) => unchanged(Some(error)),
        }
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
                if self.block {
                    Finding::BlockDue
                } else {
                    self.inspect()
                }
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
        // After a loss whose rules still stand (a changed environment,
        // unprovable mappings), rounds keep observing read-only, so a restart
        // after it is still found and blocked (decision 33).
        let block = self.watch.lost.as_deref().is_some_and(blockable);
        let record = transition::load()
            .ok()
            .filter(|record| record.pending.is_none())?;
        Some(WatchRound {
            plan,
            generation: record.generation,
            block,
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
    ) -> WatchOutcome {
        let mut note = None;
        let mut block = None;
        let lost = self.record_watch(round, finding, &mut note, &mut block);
        WatchOutcome { lost, note, block }
    }

    /// A recovery round for the takeover this controller only knows from the
    /// journal (it started after the one that ran it ended).
    pub(crate) fn recovery_round(&self) -> Option<RecoveryRound> {
        if self.live.is_some() {
            return None;
        }
        RecoveryRound::recorded()
    }

    /// Blocks the recorded target after a due recovery round, if nothing
    /// changed meanwhile, and says what is worth a log line.
    pub(crate) fn finish_recovery(
        &mut self,
        round: RecoveryRound,
    ) -> Option<(&'static str, String)> {
        if self.live.is_some() || !round.current() {
            return None;
        }
        if self.watch.cookie != round.plan.cookie {
            self.watch = Watch {
                cookie: round.plan.cookie,
                ..Watch::default()
            };
        }
        self.record_block(kernel::block(&round.plan, &[]))
    }

    /// Where the block of the recorded takeover stands, for its status.
    pub(crate) fn recovery_block_view(&self, plan: &Plan) -> serde_json::Value {
        match &self.watch.block {
            Some(block) if self.watch.cookie == plan.cookie => {
                serde_json::json!({"fallback_block": block.view()})
            }
            _ => serde_json::json!({"fallback_block": null}),
        }
    }

    /// Records what a block did and says what is worth a log line: each
    /// change of where the block stands, not every round.
    pub(crate) fn record_block(
        &mut self,
        result: Result<kernel::Blocked, String>,
    ) -> Option<(&'static str, String)> {
        let state = match result {
            Ok(blocked) => BlockState::Installed(blocked.bridges),
            Err(error) => BlockState::Failed(error),
        };
        self.note_block(state)
    }

    fn note_block(&mut self, state: BlockState) -> Option<(&'static str, String)> {
        if self.watch.block.as_ref() == Some(&state) {
            return None;
        }
        let note = match &state {
            BlockState::Installed(bridges) => Some((
                "warning",
                format!(
                    "已在目标里断网：目标本机进程新发起的连接一律丢弃（回环除外），{}。请停止接管并恢复直连，再重新启动接管。",
                    containers_blocked(bridges)
                ),
            )),
            BlockState::Failed(error) => Some((
                "error",
                format!(
                    "在目标里断网失败（{error}），目标的新连接可能直连。下一轮核对会再试；请尽快停止接管。"
                ),
            )),
            BlockState::TargetStopped => None,
        };
        self.watch.block = Some(state);
        note
    }

    /// The target's Docker bridges this takeover covered, for a block of
    /// `plan` (decision 33).
    pub(crate) fn block_bridges(&self, plan: &Plan) -> Vec<String> {
        if self.watch.cookie == plan.cookie {
            self.watch.networks.clone()
        } else {
            Vec::new()
        }
    }

    fn record_watch(
        &mut self,
        round: WatchRound,
        finding: WatchFinding,
        note: &mut Option<(&'static str, String)>,
        block: &mut Option<Plan>,
    ) -> Option<String> {
        let unchanged = matches!(&self.live, Some((plan, _)) if *plan == round.plan)
            && self.readiness.as_ref().is_some_and(Result::is_ok)
            && self.watch.cookie == round.plan.cookie
            && (if round.block {
                self.watch.lost.as_deref().is_some_and(blockable)
            } else {
                !self.watch.lost.as_deref().is_some_and(blockable)
            })
            && transition::load().is_ok_and(|record| {
                record.pending.is_none() && record.generation == round.generation
            });
        if !unchanged {
            return None;
        }
        let finding = finding.0;
        if round.block {
            match finding {
                Finding::BlockDue => {
                    self.watch.target_running = Some(true);
                    *block = Some(round.plan);
                }
                Finding::NotRunning => {
                    self.watch.target_running = Some(false);
                    *note = self.note_block(BlockState::TargetStopped);
                }
                // Unregistered or unreadable: nothing to block, nothing new.
                _ => {}
            }
            return None;
        }
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
            // Only blocking rounds, handled above, report this.
            Finding::BlockDue => None,
            Finding::Inspected(observed, update, anchored) => {
                self.watch.target_running = Some(true);
                if let Some(update) = update {
                    *note = self.record_networks(update);
                }
                if let Some(anchored) = anchored {
                    *note = Some(match note.take() {
                        Some((_, networks)) => ("warning", format!("{anchored}{networks}")),
                        None => ("warning", anchored),
                    });
                }
                match observed {
                    Observed::Protected => {
                        self.watch.consecutive_failures = 0;
                        self.watch.last_error = None;
                        None
                    }
                    // Already lost, its rules still standing: only a loss
                    // that leaves the target direct changes anything now.
                    Observed::Lost(reason) if self.watch.lost.is_some() && !blockable(&reason) => {
                        None
                    }
                    Observed::Lost(reason) => {
                        let reason = self.lose(reason);
                        // Block in the same locked section the finding was
                        // accepted in; later rounds keep it in place.
                        if reason.as_deref().is_some_and(blockable) {
                            *block = Some(round.plan.clone());
                        }
                        reason
                    }
                    Observed::Unverified(error) => self.unverified(error),
                }
            }
        }
    }

    /// Keeps the round's view of the target's Docker networks and says what
    /// is worth a log line: each change, and a read failure when it first
    /// appears or changes, not again every round.
    fn record_networks(&mut self, update: NetworkUpdate) -> Option<(&'static str, String)> {
        self.watch.networks = update.current;
        let note = if let Some(error) = &update.error {
            (self.watch.network_error.as_ref() != Some(error)).then(|| {
                (
                    "warning",
                    format!(
                        "读不出目标的 Docker 网络（{error}）：已有的容器规则保持不变，新建的容器网络暂时不经代理。"
                    ),
                )
            })
        } else if !update.added.is_empty() || !update.removed.is_empty() {
            let mut parts = Vec::new();
            if !update.added.is_empty() {
                parts.push(format!("已纳入 {}", update.added.join("、")));
            }
            if !update.removed.is_empty() {
                parts.push(format!("已移除 {}", update.removed.join("、")));
            }
            Some((
                "info",
                format!("目标的 Docker 网络有变化：{}。", parts.join("；")),
            ))
        } else {
            None
        };
        self.watch.network_error = update.error;
        note
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
            "container_networks": self.watch.networks,
            "container_network_error": self.watch.network_error,
            "fallback_block": self.watch.block.as_ref().map(BlockState::view),
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
        // The target's own Docker networks are covered from the start; a
        // running dockerd whose networks cannot be read fails the start like
        // an unverified install (decision 24).
        let installed = kernel::arm(&p, window)
            .and_then(|_| kernel::install(&p))
            .and_then(|_| match runtime {
                Some(_) => kernel::sync_networks(&p)
                    .map(|synced| synced.current)
                    .map_err(|e| format!("container_networks_unavailable:{e}")),
                None => Ok(Vec::new()),
            });
        let networks = match installed {
            Ok(networks) => networks,
            Err(e) => {
                if runtime.is_some() {
                    // A partial filter/NAT transaction is not proof of either a healthy or an
                    // idle target. Keep ownership and stop all forwarding until explicit recovery.
                    let shutdown = sockets.stop().err();
                    self.live = Some((p, sockets));
                    let reason =
                        format!("managed_install_unverified:{e}; ingress_stop:{shutdown:?}");
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
        };
        self.watch = Watch {
            cookie: p.cookie,
            networks,
            ..Watch::default()
        };
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

    #[test]
    fn network_changes_are_logged_and_a_read_failure_only_once() {
        let update = |added: &[&str], removed: &[&str], error: Option<&str>| NetworkUpdate {
            current: vec!["br-0123456789ab".into()],
            added: added.iter().map(|name| (*name).to_owned()).collect(),
            removed: removed.iter().map(|name| (*name).to_owned()).collect(),
            error: error.map(str::to_owned),
        };
        let mut controller = Controller::default();
        assert_eq!(controller.record_networks(update(&[], &[], None)), None);
        let (level, message) = controller
            .record_networks(update(&["br-0123456789ab"], &["docker0"], None))
            .unwrap();
        assert_eq!(level, "info");
        assert_eq!(
            message,
            "目标的 Docker 网络有变化：已纳入 br-0123456789ab；已移除 docker0。"
        );
        let unreadable = Some("docker_networks_unavailable");
        assert_eq!(
            controller
                .record_networks(update(&[], &[], unreadable))
                .unwrap()
                .0,
            "warning"
        );
        // The same failure next round is not logged again.
        assert_eq!(
            controller.record_networks(update(&[], &[], unreadable)),
            None
        );
        assert_eq!(controller.record_networks(update(&[], &[], None)), None);
        assert_eq!(controller.watch.networks, ["br-0123456789ab"]);
        assert_eq!(controller.watch.network_error, None);
    }

    fn ownership(identity_matches: bool, rules_complete: bool) -> kernel::Ownership {
        kernel::Ownership {
            identity_matches,
            rules_present: rules_complete,
            mappings_present: false,
            rules_complete,
            unproven_mappings: 0,
            forward_displaced: false,
            rules_bound: true,
        }
    }

    #[test]
    fn rules_that_stay_unbound_after_re_anchoring_are_a_loss_that_blocks() {
        let reason = rebound("still_unbound_after_anchor");
        assert!(
            reason.starts_with("protection_lost: rules_rebound:"),
            "{reason}"
        );
        assert!(blockable(&reason));
        // Unbound alone is not judged by classify: the round re-anchors first.
        let unbound = kernel::Ownership {
            rules_bound: false,
            ..ownership(true, true)
        };
        assert_eq!(classify(Ok((unbound, None))), Observed::Protected);
    }

    #[test]
    fn a_displaced_forward_gate_is_a_loss_that_is_not_blocked() {
        let displaced = kernel::Ownership {
            forward_displaced: true,
            ..ownership(true, true)
        };
        let Observed::Lost(reason) = classify(Ok((displaced, None))) else {
            panic!("a displaced gate must be a loss");
        };
        assert!(
            reason.starts_with("protection_lost: forward_gate_displaced:"),
            "{reason}"
        );
        // The block covers the target's own processes, which the guard still
        // does; it would cut working traffic and leave the containers as they are.
        assert!(!blockable(&reason));
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
    fn only_losses_that_leave_the_target_direct_are_blocked() {
        assert!(!blockable(
            "protection_lost: forward_gate_displaced: another rule now precedes this takeover's forward gate"
        ));
        assert!(blockable(RESTARTED));
        assert!(blockable(
            "protection_lost: rules_missing: this takeover's rules are gone from the target"
        ));
        assert!(blockable(
            "protection_lost: rules_incomplete: this takeover's rules are missing or incomplete in the target"
        ));
        // The rules still stand, or there is no target left to block.
        assert!(!blockable(&changed("guest_address_changed")));
        assert!(!blockable(
            "protection_lost: mapping_integrity: 2 connection-tracking entries carry this takeover's mark without a provable mapping"
        ));
        assert!(!blockable(
            "protection_lost: target_unregistered: the target distribution is no longer registered"
        ));
        assert!(!blockable("protection_lost: restartedish: x"));
    }

    #[test]
    fn a_recovery_round_blocks_only_when_the_rules_no_longer_apply() {
        assert!(recovery_due(&Observed::Lost(RESTARTED.into())));
        assert!(recovery_due(&classify(Err(
            "inspect:kernel_operation_failed: stale_identity_has_owned_artifacts: boot_changed"
                .into()
        ))));
        // Rules intact after a controller crash: the held ports keep it closed.
        assert!(!recovery_due(&Observed::Protected));
        assert!(!recovery_due(&Observed::Unverified(
            "inspect:wsl_deadline_exceeded".into()
        )));
        assert!(!recovery_due(&Observed::Lost(changed(
            "guest_address_changed"
        ))));
    }

    #[test]
    fn a_block_is_logged_when_it_changes_not_every_round() {
        let mut controller = Controller::default();
        let installed = || {
            Ok(kernel::Blocked {
                rules: 14,
                bridges: vec!["docker0".into()],
            })
        };
        let (level, message) = controller.record_block(installed()).unwrap();
        assert_eq!(level, "warning");
        assert!(
            message.contains("目标的 Docker 网络（docker0）转发出去的流量也一并丢弃"),
            "{message}"
        );
        assert!(containers_blocked(&[]).contains("不在其内"));
        assert_eq!(controller.record_block(installed()), None);
        let (level, message) = controller
            .record_block(Err("block:wsl_exit_failed".into()))
            .unwrap();
        assert_eq!(level, "error");
        assert!(message.contains("可能直连"), "{message}");
        assert_eq!(
            controller.record_block(Err("block:wsl_exit_failed".into())),
            None
        );
        // A stopped target needs no line; blocking it again does.
        assert_eq!(controller.note_block(BlockState::TargetStopped), None);
        assert!(controller.record_block(installed()).is_some());
        assert_eq!(
            controller.watch.block.as_ref().map(BlockState::view),
            Some(serde_json::json!({"state": "installed", "error": null, "bridges": ["docker0"]}))
        );
    }

    #[test]
    fn an_idle_controller_never_checks_the_guest() {
        let mut controller = Controller::default();
        assert!(controller.watch_round().is_none());
        assert_eq!(controller.watch.checked_unix_seconds, None);
    }
}
