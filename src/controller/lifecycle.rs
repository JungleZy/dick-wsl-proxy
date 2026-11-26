//! Serialize changes under the Windows controller lock. The operation log records
//! ordering; only authenticated kernel evidence and the owner journal authorize cleanup.
use super::{Controller, journal};
use crate::{
    host, kernel, lease,
    managed::Runtime,
    plan::Plan,
    transition::{self, Intent, Kind, Record, Stage},
};
use serde_json::{Value, json};
use std::sync::Arc;

fn registered(p: &Plan) -> Result<(), String> {
    // A WSL restart or storage move can refresh the display name/base path
    // while retaining the registry GUID. Guest-side stale-context checks still
    // decide whether any tagged rules are removable.
    if host::distributions()?
        .iter()
        .any(|d| d.id.eq_ignore_ascii_case(&p.target.id))
    {
        Ok(())
    } else {
        Err("journal_distribution_no_longer_matches_registration".into())
    }
}

pub(super) fn registration_present(p: &Plan) -> Result<bool, String> {
    Ok(host::distributions()?
        .iter()
        .any(|d| d.id.eq_ignore_ascii_case(&p.target.id)))
}

fn inspect(p: &Plan) -> Result<kernel::Ownership, String> {
    registered(p)?;
    kernel::inspect(p)
}

/// `old_restored` is written only after `retire` has verified the old plan is
/// gone. Rechecking an unregistered old distribution would turn that durable
/// proof into an unrecoverable stop failure.
fn verify_restored(p: &Plan) -> Result<(), String> {
    verify_restored_if(p, registration_present(p)?, verify_gone)
}

fn verify_restored_if(
    p: &Plan,
    registered: bool,
    verify: impl FnOnce(&Plan) -> Result<(), String>,
) -> Result<(), String> {
    if registered { verify(p) } else { Ok(()) }
}
pub(crate) fn verify_gone(p: &Plan) -> Result<(), String> {
    if !inspect(p)?.clean() || lease::alive(p)? {
        return Err("old_kernel_state_or_endpoint_still_owned".into());
    }
    Ok(())
}
fn stage_owner(intent: &Intent) -> Option<&Plan> {
    match intent.stage {
        Stage::ReleasingOld => intent.old.as_ref(),
        Stage::OldRestored => None,
        Stage::StartingNew => intent.new.as_ref(),
    }
}
pub fn checked(expected: Option<u64>) -> Result<Record, String> {
    let current = transition::load()?;
    if let Some(old) = expected
        && old != current.generation
    {
        return Err(format!(
            "stale_generation: expected {old}, current {}",
            current.generation
        ));
    }
    Ok(current)
}

impl Controller {
    pub fn status(&self) -> Result<Value, String> {
        let op = transition::load()?;
        let owner = journal::load()?;
        if self
            .live
            .as_ref()
            .is_some_and(|(l, _)| owner.as_ref() != Some(l))
        {
            return Err("journal_ownership_changed".into());
        }
        if let (Some(intent), Some(disk)) = (&op.pending, &owner)
            && stage_owner(intent) != Some(disk)
        {
            return Err("operation_owner_mismatch".into());
        }
        if op.pending.is_none() && (owner.is_none() || self.live.is_some()) {
            let mut s = self.settled_status()?;
            s["operation_generation"] = op.generation.into();
            return Ok(s);
        }
        // Read-only on process restart. Do not report `idle` for an interrupted gap,
        // take over a surviving worker, or silently finish an abandoned switch.
        let intent = op.pending.as_ref();
        let subject = owner
            .as_ref()
            .or_else(|| intent.and_then(stage_owner))
            .or_else(|| intent.and_then(|i| i.old.as_ref()));
        let mut protected_target = None;
        let target_registered = subject.and_then(|p| registration_present(p).ok());
        let evidence = subject.map(
            |p| match inspect(p).and_then(|k| Ok((k, lease::alive(p)?))) {
                Ok((k, custodian)) => {
                    if k.identity_matches && k.rules_present {
                        protected_target = Some(&p.target.name);
                    }
                    json!({"target":p.target.name,"kernel":k,"custodian":custodian})
                }
                Err(e) => json!({"target":p.target.name,"unverified":e}),
            },
        );
        Ok(
            json!({"phase":"recovery_required","operation_generation":op.generation,"active_target":protected_target,"recorded_target":owner.as_ref().map(|p|&p.target.name),"config_generation":owner.as_ref().map(|p|p.cookie),"dns_managed":false,"pending":intent.map(|i|json!({"kind":i.kind,"stage":i.stage,"old":i.old.as_ref().map(|p|&p.target.name),"new":i.new.as_ref().map(|p|&p.target.name)})),"observation":evidence,"target_registered":target_registered,"issue":self.readiness.as_ref().and_then(|r|r.as_ref().err()),"protection_check":owner.as_ref().map(|p|self.recovery_block_view(p))}),
        )
    }
    pub fn switch_source(&self, expected: u64) -> Result<(&Plan, &Runtime), String> {
        let current = checked(Some(expected))?;
        if current.pending.is_some() {
            return Err("operation_pending: explicit recovery required".into());
        }
        let (p, ingress) = self
            .live
            .as_ref()
            .ok_or("switch_requires_live_managed_owner")?;
        let runtime = self
            .runtime
            .as_deref()
            .ok_or("switch_requires_live_managed_owner")?;
        if journal::load()?.as_ref() != Some(p)
            || !self.readiness.as_ref().is_some_and(Result::is_ok)
        {
            return Err("active_owner_unverified".into());
        }
        ingress.health()?;
        if !lease::alive(p)? || !inspect(p)?.rules_complete {
            return Err("active_kernel_or_listener_unverified".into());
        }
        Ok((p, runtime))
    }
    pub fn start(
        &mut self,
        p: Plan,
        runtime: Option<Arc<Runtime>>,
        expected: Option<u64>,
    ) -> Result<(), String> {
        let current = checked(expected)?;
        if current.pending.is_some() || self.live.is_some() || journal::load()?.is_some() {
            return Err("recover_or_stop_existing_target_first".into());
        }
        let window = kernel::precheck(&p)?;
        let record = transition::begin(&current, Kind::Start, None, Some(&p))?;
        self.activate_and_commit(p, runtime, &record, window)
    }
    pub fn switch(&mut self, expected: u64, p: Plan, runtime: Arc<Runtime>) -> Result<(), String> {
        let (old, _) = self.switch_source(expected)?;
        if old.target.id.eq_ignore_ascii_case(&p.target.id) {
            return Err("same_target".into());
        }
        if p.system_dns.is_none() || p.cookie == old.cookie {
            return Err("invalid_switch_candidate".into());
        }
        let old = old.clone();
        kernel::precheck(&p)?; // still no change to A, including its operation generation
        let current = checked(Some(expected))?;
        let record = transition::begin(&current, Kind::Switch, Some(&old), Some(&p))?;
        self.retire(&old)?; // verifies absence, stops old workers and drops per-target runtime
        let restored = transition::advance(&record, Stage::OldRestored)?;
        let window = match registered(&p).and_then(|_| kernel::precheck(&p)) {
            Ok(window) => window,
            Err(e) => {
                transition::finish(&restored)?;
                return Err(format!("old_restored_candidate_rejected:{e}"));
            }
        };
        let next = transition::advance(&restored, Stage::StartingNew)?;
        self.activate_and_commit(p, Some(runtime), &next, window)
    }
    fn activate_and_commit(
        &mut self,
        p: Plan,
        runtime: Option<Arc<Runtime>>,
        record: &Record,
        window: kernel::GrantWindow,
    ) -> Result<(), String> {
        let result = self.activate(p, runtime, window);
        // If any guest mutation is still possible, activate has kept its owner journal.
        if result.is_ok() || (journal::load()?.is_none() && self.live.is_none()) {
            transition::finish(record)?;
        }
        result
    }
    /// Explicit operator release of a takeover whose target distribution is no
    /// longer registered, so no guest exists to restore or inspect. Frees this
    /// instance's Windows ports and recovery records only. Rules it installed
    /// may remain inside a still-running WSL VM until the next `wsl --shutdown`.
    pub fn abandon(&mut self, expected: Option<u64>) -> Result<Value, String> {
        let record = checked(expected)?;
        let owner = journal::load()?;
        let Some(plan) = owner
            .clone()
            .or_else(|| record.pending.as_ref().and_then(stage_owner).cloned())
        else {
            return Err("abandon_nothing_recorded: use stop".into());
        };
        // Only a successful registry read without this GUID proves it gone;
        // an unreadable registry is no evidence and refuses.
        if registration_present(&plan)? {
            return Err("abandon_requires_unregistered_target: use stop".into());
        }
        if let Some((live, ingress)) = &mut self.live {
            if *live != plan {
                return Err("journal_ownership_changed".into());
            }
            // An earlier forwarding failure is no reason to keep the ports.
            let _ = ingress.stop();
        }
        lease::release(&plan)?;
        if owner.is_some() {
            journal::forget(&plan)?;
        }
        if record.pending.is_some() {
            transition::abandon(&record)?;
        }
        self.live = None;
        self.readiness = None;
        self.runtime = None;
        self.recent_exit = None;
        self.watch = super::Watch::default();
        Ok(json!({"abandoned":plan.target.name,"next":"run wsl --shutdown before the next start"}))
    }

    pub fn stop(&mut self) -> Result<(), String> {
        let mut record = checked(None)?;
        if record.pending.is_none() {
            let Some(p) = journal::load()? else {
                return if self.live.is_none() {
                    Ok(())
                } else {
                    Err("missing_active_journal".into())
                };
            };
            record = transition::begin(&record, Kind::Stop, Some(&p), None)?;
        }
        let pending = record.pending.as_ref().ok_or("missing_operation")?;
        match pending.stage {
            Stage::ReleasingOld => {
                self.retire(pending.old.as_ref().ok_or("missing_old_owner")?)?;
                record = transition::advance(&record, Stage::OldRestored)?;
            }
            Stage::OldRestored => {
                if self.live.is_some() || journal::load()?.is_some() {
                    return Err("unexpected_owner_in_restored_gap".into());
                }
                verify_restored(pending.old.as_ref().ok_or("missing_old_owner")?)?;
            }
            Stage::StartingNew => {
                if let Some(old) = &pending.old {
                    verify_restored(old)?;
                }
                self.retire(pending.new.as_ref().ok_or("missing_new_owner")?)?;
            }
        }
        transition::finish(&record)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn plan() -> Plan {
        Plan {
            target: host::Distro {
                id: "{01234567-89ab-cdef-0123-456789abcdef}".into(),
                name: "old".into(),
                base_path: "C:\\old".into(),
                version: 2,
            },
            cgroup_ns: "cgroup:[1]".into(),
            cgroup_root: "1:1".into(),
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            guest: Ipv4Addr::new(172, 28, 1, 2),
            ingress: SocketAddrV4::new(Ipv4Addr::new(172, 28, 1, 1), 43531),
            origins: Vec::new(),
            cookie: 1,
            system_dns: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ipv6: None,
        }
    }

    #[test]
    fn restored_old_plan_does_not_require_a_deleted_registration() {
        let mut called = false;
        let result = verify_restored_if(&plan(), false, |_| {
            called = true;
            Err("should not inspect an unregistered old target".into())
        });
        assert!(result.is_ok());
        assert!(!called);
    }
}
