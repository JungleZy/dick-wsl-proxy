//! Serialize changes under the Windows controller lock. The operation log records
//! ordering; only authenticated kernel evidence and the owner journal authorize cleanup.
use crate::{
    host, kernel, lease,
    m1::{self, Controller, Plan},
    m2::Runtime,
    transition::{self, Intent, Kind, Record, Stage},
};
use serde_json::{Value, json};
use std::sync::Arc;

fn registered(p: &Plan) -> Result<(), String> {
    if host::distributions()?.iter().any(|d| d == &p.target) {
        Ok(())
    } else {
        Err("journal_distribution_no_longer_matches_registration".into())
    }
}
fn inspect(p: &Plan) -> Result<kernel::Ownership, String> {
    registered(p)?;
    kernel::inspect(p)
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
        let owner = m1::load()?;
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
            json!({"phase":"recovery_required","operation_generation":op.generation,"active_target":protected_target,"recorded_target":owner.as_ref().map(|p|&p.target.name),"config_generation":owner.as_ref().map(|p|p.cookie),"dns_managed":false,"pending":intent.map(|i|json!({"kind":i.kind,"stage":i.stage,"old":i.old.as_ref().map(|p|&p.target.name),"new":i.new.as_ref().map(|p|&p.target.name)})),"observation":evidence,"issue":self.readiness.as_ref().and_then(|r|r.as_ref().err())}),
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
        if m1::load()?.as_ref() != Some(p) || !self.readiness.as_ref().is_some_and(Result::is_ok) {
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
        if current.pending.is_some() || self.live.is_some() || m1::load()?.is_some() {
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
        if result.is_ok() || (m1::load()?.is_none() && self.live.is_none()) {
            transition::finish(record)?;
        }
        result
    }
    pub fn stop(&mut self) -> Result<(), String> {
        let mut record = checked(None)?;
        if record.pending.is_none() {
            let Some(p) = m1::load()? else {
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
                if self.live.is_some() || m1::load()?.is_some() {
                    return Err("unexpected_owner_in_restored_gap".into());
                }
                verify_gone(pending.old.as_ref().ok_or("missing_old_owner")?)?;
            }
            Stage::StartingNew => {
                if let Some(old) = &pending.old {
                    verify_gone(old)?;
                }
                self.retire(pending.new.as_ref().ok_or("missing_new_owner")?)?;
            }
        }
        transition::finish(&record)?;
        Ok(())
    }
}
