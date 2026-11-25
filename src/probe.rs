use serde::Serialize;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

const SCRIPT: &str = include_str!("guest/probe.sh");

#[derive(Debug, Serialize)]
pub struct Observation {
    pub status: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub registered_name: String,
    pub guest_name: String,
    pub cgroup_ns: String,
    /// Device:inode of the observed workload common-ancestor cgroup, not sysfs.
    pub cgroup_root: String,
    pub cgroup_path: String,
    pub cgroup_mount_root: String,
    /// Local identity evidence used to validate the selected target.
    pub identity_valid: bool,
    pub pid1: String,
    pub uid: Option<u32>,
    pub cap_net_admin: bool,
    pub networking_mode: String,
    pub gateway: Option<Ipv4Addr>,
    pub blockers: Vec<String>,
    /// SHA-256 over each successful baseline value, without its trailing newlines.
    pub baseline_fingerprints: BTreeMap<String, String>,
    /// Failed/missing tools are explicit observations, never successful empty data.
    pub evidence: BTreeMap<String, Observation>,
}

pub fn inspect(distro: &crate::host::Distro) -> Result<Snapshot, String> {
    let output = crate::host::guest_script(distro, SCRIPT)?;
    snapshot(&distro.name, parse(&output)?)
}

fn parse(output: &str) -> Result<BTreeMap<String, Observation>, String> {
    let mut evidence = BTreeMap::new();
    for line in output.lines() {
        let mut fields = line.split('\t');
        let key = fields.next().unwrap_or_default();
        let status = fields.next().ok_or("probe.protocol.malformed_record")?;
        let hex = fields.next().ok_or("probe.protocol.malformed_record")?;
        if fields.next().is_some()
            || key.is_empty()
            || !key
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_')
            || !matches!(status, "ok" | "failed" | "not_applicable" | "unavailable")
            || hex.len() % 2 != 0
        {
            return Err("probe.protocol.malformed_record".into());
        }
        let bytes: Result<Vec<_>, _> = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let high = (pair[0] as char)
                    .to_digit(16)
                    .ok_or("probe.protocol.invalid_hex")?;
                let low = (pair[1] as char)
                    .to_digit(16)
                    .ok_or("probe.protocol.invalid_hex")?;
                Ok::<u8, &str>(((high << 4) | low) as u8)
            })
            .collect();
        let value = String::from_utf8(bytes?).map_err(|_| "probe.protocol.invalid_utf8")?;
        if evidence
            .insert(
                key.to_owned(),
                Observation {
                    status: status.to_owned(),
                    value,
                },
            )
            .is_some()
        {
            return Err("probe.protocol.duplicate_record".into());
        }
    }
    if successful(&evidence, "protocol") != Some("wsl-proxy-m0-v1") {
        return Err("probe.protocol.missing_version".into());
    }
    Ok(evidence)
}

fn successful<'a>(evidence: &'a BTreeMap<String, Observation>, key: &str) -> Option<&'a str> {
    evidence
        .get(key)
        .filter(|item| item.status == "ok")
        .map(|item| item.value.as_str())
}

fn normalized_path(path: &str) -> bool {
    path.starts_with('/')
        && (path == "/" || !path.ends_with('/'))
        && !path.contains('\n')
        && !path.contains('\0')
        && path
            .split('/')
            .skip(1)
            .all(|part| !matches!(part, "." | "..") && (path == "/" || !part.is_empty()))
}

fn within(path: &str, root: &str) -> bool {
    normalized_path(path)
        && normalized_path(root)
        && (root == "/"
            || path == root
            || path
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/')))
}

fn namespace(value: &str, kind: &str) -> bool {
    value
        .strip_prefix(kind)
        .and_then(|rest| rest.strip_prefix(":["))
        .and_then(|rest| rest.strip_suffix(']'))
        .is_some_and(|id| !id.is_empty() && id.bytes().all(|c| c.is_ascii_digit()))
}

fn root_identity(value: &str) -> bool {
    value.split_once(':').is_some_and(|(device, inode)| {
        device.parse::<u64>().is_ok_and(|n| n > 0) && inode.parse::<u64>().is_ok_and(|n| n > 0)
    })
}

fn default_gateway(routes: &str) -> Option<Ipv4Addr> {
    let mut gateway = None;
    let mut count = 0;
    for line in routes.lines().filter(|line| !line.trim().is_empty()) {
        let mut words = line.split_whitespace();
        if words.next()? != "default" {
            return None;
        }
        let mut found = None;
        while let Some(word) = words.next() {
            if word == "via" {
                if found.is_some() {
                    return None;
                }
                found = Some(words.next()?.parse().ok()?);
            }
            if word == "nexthop" {
                return None;
            }
        }
        gateway = found;
        count += 1;
    }
    if count == 1 { gateway } else { None }
}

/// The WSL kernel on which cross-distribution isolation was verified on a
/// real machine (decision 01): with one distribution taken over, another
/// distribution's own traffic stayed direct. A target on an older kernel is
/// refused; newer kernels are assumed to behave the same.
pub(crate) const VERIFIED_KERNEL: [u32; 4] = [6, 18, 58, 1];
pub(crate) const KERNEL_RELEASE_UNVERIFIED: &str = "kernel.release_unverified";

/// Whether `release` (`/proc/sys/kernel/osrelease`) is at least
/// [`VERIFIED_KERNEL`], comparing its leading dotted numbers. Unreadable or
/// unparsable counts as not verified.
fn kernel_release_verified(release: &str) -> bool {
    let prefix = release
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .next()
        .unwrap_or_default();
    let Some(mut parts) = prefix
        .split('.')
        .map(|part| part.parse::<u32>().ok())
        .collect::<Option<Vec<u32>>>()
    else {
        return false;
    };
    if parts.len() < 3 {
        return false;
    }
    parts.resize(parts.len().max(VERIFIED_KERNEL.len()), 0);
    parts.as_slice() >= VERIFIED_KERNEL.as_slice()
}

fn snapshot(
    registered_name: &str,
    evidence: BTreeMap<String, Observation>,
) -> Result<Snapshot, String> {
    let get = |key: &str| successful(&evidence, key).unwrap_or_default();
    let mut blockers = Vec::new();
    let mut identity_check = |valid: bool, reason: &str| {
        if !valid {
            blockers.push(reason.to_owned());
        }
    };
    let guest_name = get("identity.guest_name");
    identity_check(
        !guest_name.is_empty() && guest_name == registered_name,
        "identity.registered_guest_name_mismatch",
    );
    let cgroup_ns = get("identity.cgroup_ns");
    identity_check(
        namespace(cgroup_ns, "cgroup") && cgroup_ns == get("identity.pid1_cgroup_ns"),
        "identity.cgroup_namespace_unverified",
    );
    let pid_ns = get("identity.pid_ns");
    identity_check(
        namespace(pid_ns, "pid") && pid_ns == get("identity.pid1_pid_ns"),
        "identity.pid_namespace_unverified",
    );
    let mounts: Vec<_> = get("identity.mountinfo")
        .lines()
        .filter_map(|line| {
            let (before, after) = line.split_once(" - ")?;
            if after.split_whitespace().next()? != "cgroup2" {
                return None;
            }
            let mut fields = before.split_whitespace();
            let root = fields.nth(3)?;
            let mountpoint = fields.next()?;
            Some((root, mountpoint))
        })
        .collect();
    let cgroup_mount_root = if mounts.len() == 1 { mounts[0].0 } else { "" };
    identity_check(
        mounts.len() == 1
            && normalized_path(cgroup_mount_root)
            && !cgroup_mount_root.contains('\\')
            && !mounts[0].1.contains('\\'),
        "identity.cgroup2_mount_unverified",
    );
    let cgroup_path = get("identity.cgroup_path");
    let cgroup_root = get("identity.cgroup_root");
    identity_check(
        normalized_path(cgroup_path) && root_identity(cgroup_root),
        "identity.cgroup_subtree_unverified",
    );
    identity_check(
        within(get("identity.pid1_cgroup"), cgroup_path)
            && within(get("identity.self_cgroup"), cgroup_path),
        "identity.pid1_probe_outside_subtree",
    );
    let workloads = get("identity.workloads");
    let mut has_pid1 = false;
    let mut has_workload = false;
    let workload_valid = !workloads.is_empty()
        && workloads.lines().all(|line| {
            let Some((pid, path)) = line.split_once('\t') else {
                return false;
            };
            let Ok(pid) = pid.parse::<u32>() else {
                return false;
            };
            has_pid1 |= pid == 1;
            has_workload |= pid > 1;
            pid > 0 && within(path, cgroup_path)
        });
    identity_check(
        workload_valid && has_pid1 && has_workload,
        "identity.workload_tree_unverified",
    );
    let pid1 = get("identity.pid1_comm");
    identity_check(pid1 == "systemd", "identity.systemd_pid1_required");
    let networking_mode = get("identity.networking_mode");
    identity_check(
        networking_mode == "nat",
        "identity.networking_mode_not_verified_nat",
    );
    let identity_valid = blockers.is_empty();

    let uid = get("identity.uid").parse::<u32>().ok();
    if uid != Some(0) {
        blockers.push("permission.root_required".into());
    }
    let cap_net_admin = get("identity.status")
        .lines()
        .find_map(|line| {
            line.strip_prefix("CapEff:")
                .and_then(|caps| u64::from_str_radix(caps.trim(), 16).ok())
        })
        .is_some_and(|caps| caps & (1 << 12) != 0);
    if !cap_net_admin {
        blockers.push("permission.cap_net_admin_missing".into());
    }
    for (key, reason) in [
        (
            "tooling.iptables_legacy",
            "tooling.iptables_legacy_missing_or_unsuitable",
        ),
        (
            "tooling.ip6tables_legacy",
            "tooling.ip6tables_legacy_missing_or_unsuitable",
        ),
    ] {
        if !get(key).contains("(legacy)") {
            blockers.push(reason.into());
        }
    }
    if get("kernel.conntrack_readable").is_empty() {
        blockers.push("capability.kernel.conntrack_readable.unverified".into());
    }
    for (key, builtin) in [
        (
            "kernel.module.xt_cgroup",
            "CONFIG_NETFILTER_XT_MATCH_CGROUP=y",
        ),
        ("kernel.module.nf_conntrack", "CONFIG_NF_CONNTRACK=y"),
        ("kernel.module.nf_nat", "CONFIG_NF_NAT=y"),
        ("kernel.module.iptable_nat", "CONFIG_IP_NF_NAT=y"),
        ("kernel.module.ip6table_nat", "CONFIG_IP6_NF_NAT=y"),
    ] {
        if get(key) != "present" && !get("kernel.config").lines().any(|line| line == builtin) {
            blockers.push(format!("capability.{key}.unverified"));
        }
    }
    for (key, expected) in [
        ("kernel.matches_v4", "cgroup"),
        ("kernel.matches_v6", "cgroup"),
        ("kernel.targets_v4", "DNAT"),
        ("kernel.targets_v6", "DNAT"),
        ("kernel.tables_v4", "nat"),
        ("kernel.tables_v6", "nat"),
    ] {
        if !get(key).lines().any(|line| line.trim() == expected) {
            blockers.push(format!("capability.{key}.{expected}.unverified"));
        }
    }
    if !kernel_release_verified(get("kernel.release")) {
        blockers.push(KERNEL_RELEASE_UNVERIFIED.into());
    }
    let mut baseline_fingerprints = BTreeMap::new();
    for key in [
        "resolv_conf",
        "resolv_target",
        "nsswitch",
        "hosts",
        "links",
        "addresses_v4",
        "addresses_v6",
        "routes_v4",
        "routes_v6",
        "rules_v4",
        "rules_v6",
        "iptables_legacy",
        "ip6tables_legacy",
        "iptables_nft",
        "ip6tables_nft",
        "nft",
        "resolved_dns",
        "resolved_domains",
        "resolved_default_route",
    ] {
        let record_key = format!("baseline.{key}");
        let optional = matches!(
            key,
            "iptables_nft" | "ip6tables_nft" | "nft" | "resolved_dns"
        ) && evidence
            .get(&record_key)
            .is_some_and(|record| record.status == "not_applicable");
        let resolved_absent = matches!(key, "resolved_domains" | "resolved_default_route")
            && evidence
                .get("baseline.resolved_dns")
                .is_some_and(|record| record.status == "not_applicable");
        if optional || resolved_absent {
            continue;
        }
        let fingerprint = get(&format!("fingerprint.{key}"));
        if successful(&evidence, &record_key).is_none()
            || fingerprint.len() != 64
            || !fingerprint.bytes().all(|c| c.is_ascii_hexdigit())
        {
            blockers.push(format!("baseline.{key}.unavailable"));
        } else {
            baseline_fingerprints.insert(key.to_owned(), fingerprint.to_owned());
        }
    }
    let gateway = default_gateway(get("network.default_routes"));
    if gateway.is_none() {
        blockers.push("network.default_ipv4_gateway_ambiguous_or_absent".into());
    }
    Ok(Snapshot {
        registered_name: registered_name.to_owned(),
        guest_name: guest_name.to_owned(),
        cgroup_ns: cgroup_ns.to_owned(),
        cgroup_root: cgroup_root.to_owned(),
        cgroup_path: cgroup_path.to_owned(),
        cgroup_mount_root: cgroup_mount_root.to_owned(),
        identity_valid,
        pid1: pid1.to_owned(),
        uid,
        cap_net_admin,
        networking_mode: networking_mode.to_owned(),
        gateway,
        blockers,
        baseline_fingerprints,
        evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_preserve_empty_success_and_failure() {
        let records = parse("protocol\tok\t77736c2d70726f78792d6d302d7631\nbaseline.empty\tok\t\nbaseline.failed\tfailed\t\n").unwrap();
        assert_eq!(successful(&records, "baseline.empty"), Some(""));
        assert_eq!(successful(&records, "baseline.failed"), None);
    }

    #[test]
    fn records_reject_corruption() {
        for output in [
            "protocol\tok\t0",
            "protocol\tok\tgg",
            "protocol\tok\tff",
            "protocol\tok\t00\textra",
            "protocol\tok\t\nprotocol\tok\t",
            "",
        ] {
            assert!(parse(output).is_err());
        }
    }

    #[test]
    fn paths_require_component_boundary() {
        assert!(within("/distro/service.scope", "/distro"));
        assert!(!within("/distro-other/service.scope", "/distro"));
        assert!(!within("/distro/../peer", "/distro"));
        assert!(!within("", "/"));
    }

    #[test]
    fn default_routes_refuse_ambiguity_and_direct_defaults() {
        assert_eq!(
            default_gateway("default via 172.28.80.1 dev eth0 proto kernel"),
            Some(Ipv4Addr::new(172, 28, 80, 1))
        );
        assert_eq!(default_gateway("default dev eth0"), None);
        assert_eq!(
            default_gateway("default via 10.0.0.1 dev eth0\ndefault via 10.0.0.2 dev eth1"),
            None
        );
        assert_eq!(
            default_gateway("default via 10.0.0.1 nexthop via 10.0.0.2"),
            None
        );
    }

    #[test]
    fn kernels_older_than_the_verified_one_are_refused() {
        for release in [
            "6.18.58.1-microsoft-standard-WSL2",
            "6.18.58.2-microsoft-standard-WSL2",
            "6.18.59-microsoft-standard-WSL2",
            "6.19.1",
            "7.0.0-microsoft-standard-WSL2",
            "6.18.58.1.1",
        ] {
            assert!(kernel_release_verified(release), "{release}");
        }
        for release in [
            "6.18.58.0-microsoft-standard-WSL2",
            "6.18.58-microsoft-standard-WSL2",
            "6.6.87.2-microsoft-standard-WSL2",
            "5.15.167.4-microsoft-standard-WSL2",
            "6.18",
            "",
            "microsoft",
            "6..58.1",
            "6.18.58.1.",
            "99999999999.1.1",
        ] {
            assert!(!kernel_release_verified(release), "{release}");
        }
        let mut evidence = BTreeMap::new();
        let blocked = snapshot("WSLProxyLab-Target", BTreeMap::new()).unwrap();
        assert!(
            blocked
                .blockers
                .iter()
                .any(|b| b == KERNEL_RELEASE_UNVERIFIED)
        );
        evidence.insert(
            "kernel.release".into(),
            Observation {
                status: "ok".into(),
                value: "6.18.58.1-microsoft-standard-WSL2".into(),
            },
        );
        let verified = snapshot("WSLProxyLab-Target", evidence).unwrap();
        assert!(
            !verified
                .blockers
                .iter()
                .any(|b| b == KERNEL_RELEASE_UNVERIFIED)
        );
        // Not a capability: preparing the kernel cannot clear it.
        assert!(!KERNEL_RELEASE_UNVERIFIED.starts_with("capability."));
    }

    #[test]
    fn missing_evidence_never_passes_identity() {
        let snapshot = snapshot("WSLProxyLab-Target", BTreeMap::new()).unwrap();
        assert!(!snapshot.identity_valid);
        assert!(!snapshot.blockers.is_empty());
        assert!(snapshot.baseline_fingerprints.is_empty());
    }
}
