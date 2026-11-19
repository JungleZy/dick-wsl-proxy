//! A single owner and recovery journal for scoped M1 and policy-managed M2 sessions.
//! The journal is immutable while active: persist intent BEFORE any guest mutation.
use crate::m2::{Readiness, Runtime};
use crate::{host, ingress::Ingress, kernel, lease, probe::Snapshot};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub target: host::Distro,
    pub cgroup_ns: String,
    pub cgroup_root: String,
    pub boot_id: String,
    pub guest: Ipv4Addr,
    pub ingress: SocketAddrV4,
    pub origins: Vec<SocketAddrV4>,
    pub cookie: u32,
    // Omitted for old M1 journals: their kernel rule tag is a digest of the plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_dns: Option<Ipv4Addr>,
}

fn scope(
    guest: Ipv4Addr,
    ingress: SocketAddrV4,
    origins: &[SocketAddrV4],
    system_dns: Option<Ipv4Addr>,
) -> Result<(), String> {
    let local = |ip: Ipv4Addr| {
        !ip.is_unspecified()
            && !ip.is_loopback()
            && !ip.is_multicast()
            && !ip.is_broadcast()
            && !ip.is_link_local()
    };
    if !local(guest)
        || !local(*ingress.ip())
        || ingress.ip() == &guest
        || ingress.port() < 1024
        || (system_dns.is_none() && origins.is_empty())
        || system_dns
            .is_some_and(|ip| !origins.is_empty() || !crate::m2::valid_resolver(ip) || ip == guest)
        || origins.len() > 8
    {
        return Err("invalid_lab_scope".into());
    }
    for (i, ep) in origins.iter().enumerate() {
        if (ep.ip() != ingress.ip() && *ep.ip() != guest)
            || ep.port() < 1024
            || ep.port() == ingress.port()
            || origins[..i].contains(ep)
        {
            return Err(format!("invalid_or_duplicate_lab_origin:{ep}"));
        }
    }
    Ok(())
}

impl Plan {
    pub(crate) fn validate(&self) -> Result<(), String> {
        scope(self.guest, self.ingress, &self.origins, self.system_dns)?;
        kernel::validate(self)
    }

    pub fn new(
        target: &host::Distro,
        s: &Snapshot,
        port: NonZeroU16,
        origins: Vec<SocketAddrV4>,
        system_dns: Option<Ipv4Addr>,
    ) -> Result<Self, String> {
        if !s.identity_valid
            || !s.blockers.is_empty()
            || s.cgroup_path != "/"
            || s.cgroup_mount_root != "/"
        {
            return Err("target_scope_unverified".into());
        }
        let value = |key: &str| {
            s.evidence
                .get(key)
                .filter(|e| e.status == "ok")
                .map(|e| e.value.as_str())
                .ok_or_else(|| format!("missing_evidence:{key}"))
        };
        let gw = s.gateway.ok_or("gateway_missing")?;
        let route = value("network.gateway_route")?;
        let words: Vec<_> = route.split_whitespace().collect();
        let mut sources = words.windows(2).filter(|w| w[0] == "src");
        let guest = sources.next().ok_or("guest_source_missing")?[1]
            .parse::<Ipv4Addr>()
            .map_err(|_| "guest_source_invalid")?;
        if sources.next().is_some() {
            return Err("ambiguous_guest_source".into());
        }
        let ingress = SocketAddrV4::new(gw, port.get());
        scope(guest, ingress, &origins, system_dns)?;
        // RandomState uses OS-seeded keys. The mark is an ownership discriminator, not a secret;
        // the kernel precheck must also exclude collisions before any rule is committed.
        use std::hash::{BuildHasher, RandomState};
        let cookie = RandomState::new().hash_one(&target.id) as u32;
        if cookie == 0 {
            return Err("zero_instance_mark_retry_start".into());
        }
        Ok(Self {
            target: target.clone(),
            cgroup_ns: s.cgroup_ns.clone(),
            cgroup_root: s.cgroup_root.clone(),
            boot_id: value("identity.boot_id")?.into(),
            guest,
            ingress,
            origins,
            cookie,
            system_dns,
        })
    }
}

fn journal() -> Result<PathBuf, String> {
    Ok(host::state_dir()?.join("m1-active.json"))
}
fn read_regular(path: &Path) -> Result<Option<File>, String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("journal_open:{e}")),
    };
    let meta = f.metadata().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err("journal_reparse_point".into());
        }
    }
    if !meta.is_file() || meta.len() > 16384 {
        return Err("journal_not_regular_or_too_large".into());
    }
    Ok(Some(f))
}
pub fn load() -> Result<Option<Plan>, String> {
    let Some(f) = read_regular(&journal()?)? else {
        return Ok(None);
    };
    let plan: Plan =
        serde_json::from_reader(f.take(16385)).map_err(|e| format!("invalid_journal:{e}"))?;
    plan.validate()?;
    Ok(Some(plan))
}
fn persist(plan: &Plan) -> Result<(), String> {
    if load()?.is_some() {
        return Err("recover_or_stop_existing_target_first".into());
    }
    let path = journal()?;
    let tmp = path.with_file_name(format!("m1-{:08x}.tmp", plan.cookie));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| format!("journal_create:{e}"))?;
    let result = (|| {
        serde_json::to_writer(&mut f, plan)?;
        f.flush()?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(tmp);
        return Err(format!("journal_commit:{e}"));
    }
    Ok(())
}
fn forget(plan: &Plan) -> Result<(), String> {
    if load()?.as_ref() != Some(plan) {
        return Err("journal_ownership_changed".into());
    }
    fs::remove_file(journal()?).map_err(|e| format!("journal_remove:{e}"))
}

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
            include_str!("exit_probe.py"),
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
        let disk = load()?;
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
        if self.live.is_some() || load()?.is_some() {
            return Err("recover_or_stop_existing_target_first".into());
        }
        persist(&p)?;
        let mut sockets = match Ingress::bind(&p, runtime.clone()) {
            Ok(s) => s,
            Err(e) => {
                lease::release(&p)?;
                forget(&p)?;
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
                .and_then(|_| forget(&p));
            return Err(match rollback {
                Ok(()) => format!("start_rolled_back:{e}"),
                Err(r) => format!("recovery_required:{e}; rollback:{r}"),
            });
        }
        if let Some(runtime) = &runtime {
            match runtime.verify(&p) {
                Ok(ok) => self.readiness = Some(Ok(ok)),
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
        let Some(p) = load()? else {
            if self.live.is_some() {
                return Err("missing_active_journal".into());
            }
            return crate::lifecycle::verify_gone(expected);
        };
        if &p != expected {
            return Err("operation_owner_mismatch".into());
        }
        if self.live.as_ref().is_some_and(|(l, _)| *l != p) {
            return Err("journal_ownership_changed".into());
        }
        if !host::distributions()?.iter().any(|d| d == &p.target) {
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
        crate::lifecycle::verify_gone(&p)?;
        forget(&p)?;
        self.live = None;
        self.readiness = None;
        self.runtime = None;
        self.recent_exit = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_loop_and_outside_destinations() {
        let guest = Ipv4Addr::new(172, 28, 4, 5);
        let listener = "172.28.0.1:41000".parse().unwrap();
        for ep in [
            "172.28.0.1:41000",
            "172.28.4.5:53",
            "8.8.8.8:41001",
            "127.0.0.1:41001",
        ] {
            assert!(scope(guest, listener, &[ep.parse().unwrap()], None).is_err());
        }
        assert!(
            scope(
                guest,
                listener,
                &["172.28.4.5:41001".parse().unwrap()],
                None
            )
            .is_ok()
        );
        let dns = Some(Ipv4Addr::new(10, 255, 255, 254));
        assert!(scope(guest, listener, &[], dns).is_ok());
        assert!(scope(guest, listener, &["172.28.4.5:41001".parse().unwrap()], dns).is_err());
    }
}
