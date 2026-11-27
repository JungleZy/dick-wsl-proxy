//! One backend, several takeovers (decision 40): a `Session` per environment,
//! found by its record scope. Requests are serialized by the controller lock
//! and the single pipe, so one environment's start or stop never runs at the
//! same time as another's.

use super::{RecoveryRound, Session, WatchFinding, WatchOutcome, WatchRound};
use crate::managed::Runtime;
use crate::{kernel, plan::Plan, transition};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::sync::Arc;

#[derive(Default)]
pub struct Controller {
    sessions: BTreeMap<String, Session>,
}

impl Session {
    pub(crate) fn new(scope: &str) -> Self {
        Self {
            scope: scope.to_owned(),
            ..Self::default()
        }
    }
}

impl Controller {
    /// The session of `scope`, created empty on first use.
    pub(crate) fn session(&mut self, scope: &str) -> &mut Session {
        self.sessions
            .entry(scope.to_owned())
            .or_insert_with(|| Session::new(scope))
    }

    /// Every scope with a session in memory or records on disk.
    fn scopes(&self) -> Result<Vec<String>, String> {
        let mut scopes = transition::scopes()?;
        for scope in self.sessions.keys() {
            if !scopes.contains(scope) {
                scopes.push(scope.clone());
            }
        }
        scopes.sort();
        Ok(scopes)
    }

    /// `{"sessions": [...]}`: each environment's status as one takeover used
    /// to report it, plus its `scope`. Environments that never had a
    /// takeover are absent: their generation is 0 and they are idle.
    pub fn status(&self) -> Result<Value, String> {
        let mut sessions = Vec::new();
        for scope in self.scopes()? {
            sessions.push(self.session_status(&scope)?);
        }
        Ok(json!({ "sessions": sessions }))
    }

    /// One environment's status, with its `scope`.
    pub fn session_status(&self, scope: &str) -> Result<Value, String> {
        let blank;
        let session = match self.sessions.get(scope) {
            Some(session) => session,
            None => {
                blank = Session::new(scope);
                &blank
            }
        };
        let mut status = session.status()?;
        status["scope"] = json!(scope);
        Ok(status)
    }

    /// Whether any environment is not idle: a takeover live, recorded, or in
    /// the middle of an operation.
    pub fn any_owned(&self) -> Result<bool, String> {
        if self.sessions.values().any(|session| session.live.is_some()) {
            return Ok(true);
        }
        for scope in transition::scopes()? {
            if super::journal::load(&scope)?.is_some()
                || transition::load(&scope)?.pending.is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether the environment `distro_id` is not idle.
    pub fn owned(&self, distro_id: &str) -> Result<bool, String> {
        let scope = transition::scope(distro_id)?;
        Ok(self
            .sessions
            .get(&scope)
            .is_some_and(|session| session.live.is_some())
            || super::journal::load(&scope)?.is_some()
            || transition::load(&scope)?.pending.is_some())
    }

    pub fn start(
        &mut self,
        p: Plan,
        runtime: Option<Arc<Runtime>>,
        expected: Option<u64>,
    ) -> Result<(), String> {
        let scope = transition::scope(&p.target.id)?;
        self.session(&scope).start(p, runtime, expected)
    }

    /// The ingress each live takeover holds: a preflight of another
    /// environment must not test-bind over them.
    pub fn live_ingresses(&self) -> Vec<(String, SocketAddrV4)> {
        self.sessions
            .values()
            .filter_map(|session| {
                session
                    .live
                    .as_ref()
                    .map(|(plan, _)| (plan.target.id.clone(), plan.ingress))
            })
            .collect()
    }

    /// The scopes of the takeovers this process runs.
    pub fn live_scopes(&self) -> Vec<String> {
        self.sessions
            .iter()
            .filter(|(_, session)| session.live.is_some())
            .map(|(scope, _)| scope.clone())
            .collect()
    }

    /// The scopes of every environment that is not idle, for a stop of all.
    pub fn owned_scopes(&self) -> Result<Vec<String>, String> {
        let mut owned = Vec::new();
        for scope in self.scopes()? {
            if self
                .sessions
                .get(&scope)
                .is_some_and(|session| session.live.is_some())
                || super::journal::load(&scope)?.is_some()
                || transition::load(&scope)?.pending.is_some()
            {
                owned.push(scope);
            }
        }
        Ok(owned)
    }

    /// The one environment that is not idle, for commands that name none.
    pub fn sole_owned(&self) -> Result<String, String> {
        let mut owned = self.owned_scopes()?;
        match owned.len() {
            1 => Ok(owned.remove(0)),
            0 => Err("no_takeover".into()),
            _ => Err("target_required: several environments are taken over".into()),
        }
    }

    /// Starts one protection check per verified takeover.
    pub(crate) fn watch_rounds(&mut self) -> Vec<WatchRound> {
        self.sessions
            .values_mut()
            .filter_map(Session::watch_round)
            .collect()
    }

    pub(crate) fn finish_watch(
        &mut self,
        round: WatchRound,
        finding: WatchFinding,
    ) -> WatchOutcome {
        let scope = round.scope().to_owned();
        self.session(&scope).finish_watch(round, finding)
    }

    /// One recovery round per environment this controller only knows from
    /// its journal.
    pub(crate) fn recovery_rounds(&self) -> Vec<RecoveryRound> {
        RecoveryRound::all_recorded()
            .into_iter()
            .filter(|round| {
                !self
                    .sessions
                    .get(round.scope())
                    .is_some_and(|session| session.live.is_some())
            })
            .collect()
    }

    pub(crate) fn finish_recovery(
        &mut self,
        round: RecoveryRound,
    ) -> Option<(&'static str, String)> {
        let scope = round.scope().to_owned();
        self.session(&scope).finish_recovery(round)
    }

    pub(crate) fn record_block(
        &mut self,
        scope: &str,
        result: Result<kernel::Blocked, String>,
    ) -> Option<(&'static str, String)> {
        self.session(scope).record_block(result)
    }

    pub(crate) fn block_bridges(&self, scope: &str, plan: &Plan) -> Vec<String> {
        self.sessions
            .get(scope)
            .map(|session| session.block_bridges(plan))
            .unwrap_or_default()
    }

    /// The live takeovers other than `scope`'s, for clean-up from their
    /// distribution (decision 41).
    pub(crate) fn other_live(&self, scope: &str) -> Vec<Plan> {
        self.sessions
            .iter()
            .filter(|(key, _)| key.as_str() != scope)
            .filter_map(|(_, session)| session.live.as_ref().map(|(plan, _)| plan.clone()))
            .collect()
    }

    /// Releases the takeover of `scope`, whose distribution was unregistered,
    /// then deletes its private tables from another environment that is
    /// still taken over (decision 41). With none, the tables stay until the
    /// next `wsl --shutdown`, which then cuts no other takeover.
    pub fn abandon(&mut self, scope: &str, expected: Option<u64>) -> Result<Value, String> {
        let cookie = self.session(scope).recorded_cookie()?;
        let mut result = self.session(scope).abandon(expected)?;
        let others = self.other_live(scope);
        let Some(cookie) = cookie else {
            return Ok(result);
        };
        if others.is_empty() {
            return Ok(result);
        }
        let mut errors = Vec::new();
        for other in &others {
            match kernel::drop_instance(other, cookie) {
                Ok(_) => {
                    result["next"] = json!("tables_removed");
                    return Ok(result);
                }
                Err(error) => errors.push(error),
            }
        }
        result["next"] = json!("tables_left");
        result["cleanup_error"] = json!(errors.join("; "));
        Ok(result)
    }

    /// The name of another live takeover that covers Docker networks, if any
    /// (decision 40: at most one environment taken over runs Docker).
    pub fn other_with_containers(&self, distro_id: &str) -> Option<String> {
        let scope = transition::scope(distro_id).ok()?;
        self.sessions
            .iter()
            .filter(|(key, _)| key.as_str() != scope)
            .find_map(|(_, session)| session.container_target())
    }

    /// The scope a request names by `distro_id`, or the only taken-over one.
    pub fn resolve(&self, distro_id: Option<&str>) -> Result<String, String> {
        match distro_id {
            Some(id) => transition::scope(id),
            None => self.sole_owned(),
        }
    }
}
