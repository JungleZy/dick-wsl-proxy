use crate::plan::Plan;
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

const SCRIPT: &str = include_str!("guest/kernel.py");

/// One-shot window issued by the very guest that enforces its expiry. Never journal or renew it.
pub struct GrantWindow {
    cookie: u32,
    deadline: u64,
}

/// Checks the target, required kernel features and absence of an existing owner.
/// This must succeed before persisting a new installation journal.
pub fn precheck(p: &Plan) -> Result<GrantWindow, String> {
    let deadline = invoke(p, "precheck", None)?
        .grant_deadline
        .ok_or("kernel_missing_guest_grant_window")?;
    Ok(GrantWindow {
        cookie: p.cookie,
        deadline,
    })
}

pub fn install(p: &Plan) -> Result<(), String> {
    invoke(p, "install", None).map(|_| ())
}

/// Arms one short-lived install after the Windows recovery journal is persisted.
/// Call once per immutable Plan, never retry even after an uncertain response;
/// recover with remove and choose a new generation before another activation.
pub fn arm(p: &Plan, window: GrantWindow) -> Result<(), String> {
    if window.cookie != p.cookie {
        return Err("grant_window_target_changed".into());
    }
    invoke(p, "arm", Some(window.deadline)).map(|_| ())
}

/// Removes interception before deleting precisely identified owned mappings.
/// The Windows ingress must remain alive until this succeeds; TCP must reconnect.
/// Returns how many entries carrying this instance's mark could not be proven
/// ours and were left in place (decision 20).
pub fn remove(p: &Plan) -> Result<u32, String> {
    invoke(p, "remove", None).map(|response| response.unproven_mappings.unwrap_or(0))
}

/// A read-only observation of this generation, not permission to delete it.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ownership {
    pub identity_matches: bool,
    pub rules_present: bool,
    pub mappings_present: bool,
    pub rules_complete: bool,
    /// Entries carrying this instance's mark that cannot be proven its
    /// mappings. Never deleted; the periodic check counts any as a loss.
    #[serde(default)]
    pub unproven_mappings: u32,
}

impl Ownership {
    /// True only after inspection independently verifies this generation absent.
    /// A changed identity may be clean, but can never authorize deletion.
    /// Unprovable marked entries are not this generation's to clean.
    pub fn clean(&self) -> bool {
        !self.rules_present && !self.rules_complete && !self.mappings_present
    }
}

/// Rechecks the live guest, exact tagged rules and connmark tuples without writes.
/// The caller must first verify the current Windows registration. A stale guest
/// identity can attest absence only; surviving or ambiguous artifacts fail closed.
pub fn inspect(p: &Plan) -> Result<Ownership, String> {
    inspect_detail(p).map(|(ownership, _)| ownership)
}

/// As `inspect`, plus the guest's reason when it could not confirm this
/// generation's identity (restart, rename, new address, foreign workload, ...).
pub fn inspect_detail(p: &Plan) -> Result<(Ownership, Option<String>), String> {
    inspect_networks(p).map(|(ownership, drift, _)| (ownership, drift))
}

/// As `inspect_detail`, plus how the target's Docker networks compare with
/// this takeover's per-network rules; reported only for a complete managed
/// takeover of the same identity (decision 24). Changes nothing.
pub fn inspect_networks(p: &Plan) -> Result<(Ownership, Option<String>, Option<Networks>), String> {
    let response = invoke(p, "inspect", None)?;
    let ownership = response.ownership.ok_or("kernel_missing_ownership")?;
    Ok((ownership, response.identity_error, response.networks))
}

/// Brings the per-network rules in line with the target's Docker bridge
/// networks (decision 24). Only extends a complete managed takeover of the
/// same identity; after a stop it fails without changing anything.
pub fn sync_networks(p: &Plan) -> Result<Synced, String> {
    invoke(p, "sync_networks", None)?
        .synced
        .ok_or_else(|| "kernel_missing_network_sync".into())
}

/// Drops everything the target's own processes start, except to loopback, in
/// the target as it runs now, whatever drifted (decision 33). Only for a lost
/// managed takeover, and only under the controller lock with the takeover
/// rechecked, so it can never run after the stop that would remove it. A stop
/// removes these rules with the rest. The target's containers are not covered.
///
/// `bridges` are the target's Docker bridges seen during the takeover; the
/// guest adds those its per-network rules, an earlier block and the target's
/// dockerd show, and drops what they forward too.
pub fn block(p: &Plan, bridges: &[String]) -> Result<Blocked, String> {
    invoke_with(p, "block", None, Some(bridges))?
        .blocked
        .ok_or_else(|| "kernel_missing_block_result".into())
}

/// The target's Docker bridge networks next to the bridges this takeover has
/// per-network rules for. `wanted` and `in_sync` are `None` when the networks
/// could not be read, with the reason in `error`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Networks {
    pub installed: Vec<String>,
    pub wanted: Option<Vec<String>>,
    pub in_sync: Option<bool>,
    pub error: Option<String>,
}

/// What a network sync left: the target's networks now, and the bridges
/// whose rules it added (or replaced) and removed.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Synced {
    pub current: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Serialize)]
struct Request<'a> {
    operation: &'a str,
    plan: &'a Plan,
    protocol: Option<&'a str>,
    peer: Option<SocketAddrV4>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deadline: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bridges: Option<&'a [String]>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    ok: bool,
    operation: String,
    origin: Option<SocketAddr>,
    ownership: Option<Ownership>,
    grant_deadline: Option<u64>,
    #[serde(default)]
    identity_error: Option<String>,
    #[serde(default)]
    unproven_mappings: Option<u32>,
    #[serde(default)]
    networks: Option<Networks>,
    #[serde(default)]
    synced: Option<Synced>,
    #[serde(default)]
    blocked: Option<Blocked>,
}

/// What a block left: how many drop-only rules are in place, and the
/// target's Docker bridges whose forwarding they drop too (decision 33).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Blocked {
    pub rules: u32,
    #[serde(default)]
    pub bridges: Vec<String>,
}

fn invoke(p: &Plan, operation: &str, deadline: Option<u64>) -> Result<Response, String> {
    invoke_with(p, operation, deadline, None)
}

fn invoke_with(
    p: &Plan,
    operation: &str,
    deadline: Option<u64>,
    bridges: Option<&[String]>,
) -> Result<Response, String> {
    validate(p)?;
    let request = Request {
        operation,
        plan: p,
        protocol: None,
        peer: None,
        deadline,
        bridges,
    };
    let bytes = serde_json::to_vec(&request)
        .map_err(|error| format!("kernel_request_encoding_failed: {error}"))?;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    // Only hex crosses a shell interpolation boundary, including registered names.
    let script = format!(
        "exec /usr/bin/python3 -I - <<'WSLPROXY_M1_PY'\nREQUEST_HEX = '{hex}'\n{SCRIPT}\nWSLPROXY_M1_PY\n"
    );
    let output =
        crate::host::guest_script(&p.target, &script).map_err(|e| format!("{operation}:{e}"))?;
    parse_response(&output, operation)
}

fn parse_response(output: &str, operation: &str) -> Result<Response, String> {
    let response: Response = serde_json::from_str(output)
        .map_err(|error| format!("kernel_invalid_response: {error}"))?;
    if !response.ok || response.operation != operation {
        return Err("kernel_response_operation_mismatch".into());
    }
    if (operation == "precheck") != response.grant_deadline.is_some()
        || response.grant_deadline == Some(0)
    {
        return Err("kernel_invalid_guest_grant_window".into());
    }
    if operation != "lookup" && response.origin.is_some() {
        return Err("kernel_unexpected_origin".into());
    }
    if (operation == "inspect") != response.ownership.is_some() {
        return Err("kernel_unexpected_or_missing_ownership".into());
    }
    if response.identity_error.is_some() && !matches!(operation, "inspect" | "remove") {
        return Err("kernel_unexpected_identity_error".into());
    }
    if response.unproven_mappings.is_some() != (operation == "remove") {
        return Err("kernel_unexpected_or_missing_unproven_count".into());
    }
    if response.networks.is_some() && operation != "inspect" {
        return Err("kernel_unexpected_network_report".into());
    }
    if response.synced.is_some() != (operation == "sync_networks") {
        return Err("kernel_unexpected_or_missing_network_sync".into());
    }
    if response.blocked.is_some() != (operation == "block") {
        return Err("kernel_unexpected_or_missing_block_result".into());
    }
    if let Some(ownership) = &response.ownership
        && ((ownership.rules_complete && !ownership.rules_present)
            || (!ownership.identity_matches
                && (ownership.rules_present || ownership.mappings_present)))
    {
        return Err("kernel_inconsistent_ownership".into());
    }
    Ok(response)
}

pub(crate) fn validate(p: &Plan) -> Result<(), String> {
    let target = &p.target;
    if !uuid(&target.id, true)
        || target.version != 2
        || target.name.is_empty()
        || target.name.len() > 256
        || target.name.chars().any(char::is_control)
        || target.base_path.is_empty()
        || target.base_path.len() > 32768
        || target.base_path.chars().any(char::is_control)
    {
        return Err("kernel_invalid_registered_target".into());
    }
    if !uuid(&p.boot_id, false)
        || !p
            .cgroup_ns
            .strip_prefix("cgroup:[")
            .and_then(|value| value.strip_suffix(']'))
            .is_some_and(decimal)
        || !p
            .cgroup_root
            .split_once(':')
            .is_some_and(|(device, inode)| decimal(device) && decimal(inode))
        || p.cookie == 0
    {
        return Err("kernel_invalid_instance_identity".into());
    }
    if !unicast(p.guest)
        || !unicast(*p.ingress.ip())
        || p.guest == *p.ingress.ip()
        || p.ingress.port() < 1024
        || p.origins.is_empty() != p.system_dns.is_some()
        || p.origins.len() > 8
        || p.system_dns.is_some_and(|dns| !unicast(dns))
    {
        return Err("kernel_invalid_local_endpoints".into());
    }
    for (index, origin) in p.origins.iter().enumerate() {
        if (*origin.ip() != p.guest && origin.ip() != p.ingress.ip())
            || origin.port() < 1024
            || origin.port() == p.ingress.port()
            || p.origins[..index].contains(origin)
        {
            return Err("kernel_invalid_original_endpoint".into());
        }
    }
    if let Some(ipv6) = &p.ipv6
        && (p.system_dns.is_none()
            || !global_unicast(ipv6.guest)
            || !valid_ipv6_ingress(ipv6.ingress)
            || ipv6.guest == *ipv6.ingress.ip())
    {
        return Err("kernel_invalid_ipv6_endpoints".into());
    }
    Ok(())
}

fn unicast(ip: Ipv4Addr) -> bool {
    let [first, second, _, _] = ip.octets();
    first != 0 && first != 127 && first < 224 && !(first == 169 && second == 254)
}

fn global_unicast(ip: Ipv6Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && ip.to_ipv4_mapped().is_none()
        && !ip.is_unicast_link_local()
}

fn valid_ipv6_ingress(address: std::net::SocketAddrV6) -> bool {
    address.port() >= 1024
        && (!address.ip().is_unicast_link_local() || address.scope_id() != 0)
        && (address.ip().is_unicast_link_local() || address.scope_id() == 0)
        && !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && !address.ip().is_loopback()
        && address.ip().to_ipv4_mapped().is_none()
}

fn decimal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && !value.starts_with('0')
        && value.parse::<u64>().is_ok()
}

fn uuid(value: &str, braces: bool) -> bool {
    let value = if braces {
        let Some(value) = value
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
        else {
            return false;
        };
        value
    } else {
        value
    };
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        Plan {
            target: crate::host::Distro {
                id: "{01234567-89ab-cdef-0123-456789abcdef}".into(),
                name: "a registered name with ' ; $(characters)".into(),
                base_path: "D:\\WSL\\ProxyLab\\Target".into(),
                version: 2,
            },
            cgroup_ns: "cgroup:[4026534269]".into(),
            cgroup_root: "25:386884".into(),
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            guest: Ipv4Addr::new(172, 28, 83, 138),
            ingress: "172.28.80.1:43771".parse().unwrap(),
            origins: vec![
                "172.28.80.1:43772".parse().unwrap(),
                "172.28.83.138:43772".parse().unwrap(),
            ],
            cookie: 0x12345678,
            system_dns: None,
            ipv6: None,
        }
    }

    #[test]
    fn validates_registered_strings_as_data_not_shell() {
        assert!(validate(&plan()).is_ok());
        let mut p = plan();
        p.target.name.push('\n');
        assert!(validate(&p).is_err());
        p = plan();
        p.target.id.push_str(";id");
        assert!(validate(&p).is_err());
    }

    #[test]
    fn rejects_uncertain_namespace_identity() {
        for value in [
            "",
            "4026534269",
            "cgroup:[0]",
            "cgroup:[01]",
            "cgroup:[1];id",
        ] {
            let mut p = plan();
            p.cgroup_ns = value.into();
            assert!(validate(&p).is_err(), "{value}");
        }
        for value in ["25:0", "25:1:2", "-1:2", "25:18446744073709551616"] {
            let mut p = plan();
            p.cgroup_root = value.into();
            assert!(validate(&p).is_err(), "{value}");
        }
        let mut p = plan();
        p.cookie = 0;
        assert!(validate(&p).is_err());
    }

    #[test]
    fn limits_interception_to_explicit_local_business_tuples() {
        for endpoint in [
            "127.0.0.1:43772",
            "172.28.80.2:43772",
            "172.28.80.1:53",
            "172.28.80.1:43771",
            "0.0.0.0:43772",
        ] {
            let mut p = plan();
            p.origins = vec![endpoint.parse().unwrap()];
            assert!(validate(&p).is_err(), "{endpoint}");
        }
        let mut p = plan();
        p.origins.push(p.origins[0]);
        assert!(validate(&p).is_err());
        p.origins.clear();
        assert!(validate(&p).is_err());
    }

    #[test]
    fn comprehensive_mode_requires_single_nonloopback_resolver_and_no_origins() {
        let mut p = plan();
        p.system_dns = Some("10.255.255.254".parse().unwrap());
        assert!(validate(&p).is_err());
        p.origins.clear();
        assert!(validate(&p).is_ok());
        for value in ["127.0.0.53", "0.0.0.0", "169.254.1.1", "224.0.0.1"] {
            p.system_dns = Some(value.parse().unwrap());
            assert!(validate(&p).is_err(), "{value}");
        }
    }

    #[test]
    fn accepts_a_scoped_ipv6_plan_for_managed_mode() {
        let mut p = plan();
        p.system_dns = Some("10.255.255.254".parse().unwrap());
        p.origins.clear();
        p.ipv6 = Some(crate::plan::Ipv6Plan {
            guest: "2001:db8:1::2".parse().unwrap(),
            ingress: std::net::SocketAddrV6::new("fe80::1".parse().unwrap(), 43771, 0, 2),
        });
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn refuses_forged_or_ambiguous_response_envelopes() {
        for response in [
            r#"{"ok":true,"operation":"install"}"#,
            r#"{"ok":false,"operation":"lookup"}"#,
            r#"{"ok":true,"operation":"lookup","extra":1}"#,
            "{}\n{}",
        ] {
            assert!(parse_response(response, "lookup").is_err());
        }
        assert!(
            parse_response(
                r#"{"ok":true,"operation":"remove","origin":"172.28.80.1:43772"}"#,
                "remove"
            )
            .is_err()
        );
    }

    #[test]
    fn ownership_requires_verified_absence_not_a_stored_identity_guess() {
        for identity_matches in [false, true] {
            for rules_present in [false, true] {
                for mappings_present in [false, true] {
                    let ownership = Ownership {
                        identity_matches,
                        rules_present,
                        mappings_present,
                        rules_complete: false,
                        unproven_mappings: 1,
                    };
                    assert_eq!(ownership.clean(), !rules_present && !mappings_present);
                    assert!(serde_json::to_string(&ownership).is_ok());
                }
            }
        }
    }

    #[test]
    fn identity_drift_is_reported_only_by_inspect_and_remove() {
        let inspect = r#"{"ok":true,"operation":"inspect","ownership":{"identity_matches":false,"rules_present":false,"rules_complete":false,"mappings_present":false},"identity_error":"boot_changed"}"#;
        assert_eq!(
            parse_response(inspect, "inspect")
                .unwrap()
                .identity_error
                .as_deref(),
            Some("boot_changed")
        );
        let remove = r#"{"ok":true,"operation":"remove","identity_error":"workload_outside_distro_cgroup","unproven_mappings":0}"#;
        assert!(parse_response(remove, "remove").is_ok());
        // Remove always reports how many unprovable marked entries it left,
        // and nothing else does.
        let counted = r#"{"ok":true,"operation":"remove","unproven_mappings":3}"#;
        assert_eq!(
            parse_response(counted, "remove").unwrap().unproven_mappings,
            Some(3)
        );
        assert!(parse_response(r#"{"ok":true,"operation":"remove"}"#, "remove").is_err());
        // The network report belongs to inspect, the sync result to its own
        // operation (decision 24).
        let report = r#"{"ok":true,"operation":"inspect","ownership":{"identity_matches":true,"rules_present":true,"rules_complete":true,"mappings_present":false},"networks":{"installed":["docker0"],"wanted":["docker0","br-0123456789ab"],"in_sync":false,"error":null}}"#;
        let networks = parse_response(report, "inspect").unwrap().networks.unwrap();
        assert_eq!(networks.in_sync, Some(false));
        assert_eq!(networks.wanted.unwrap().len(), 2);
        // The block result belongs to the block operation only (decision 33).
        assert_eq!(
            parse_response(
                r#"{"ok":true,"operation":"block","blocked":{"rules":4}}"#,
                "block"
            )
            .unwrap()
            .blocked,
            Some(Blocked {
                rules: 4,
                bridges: Vec::new()
            })
        );
        assert!(parse_response(r#"{"ok":true,"operation":"block"}"#, "block").is_err());
        // Decision 41 dropped the probe and re-anchoring: those fields are
        // no longer part of the protocol.
        let unbound = r#"{"ok":true,"operation":"inspect","ownership":{"identity_matches":true,"rules_present":true,"rules_complete":true,"mappings_present":false,"rules_bound":false}}"#;
        assert!(parse_response(unbound, "inspect").is_err());
        assert!(
            parse_response(
                r#"{"ok":true,"operation":"remove","unproven_mappings":0,"blocked":{"rules":0}}"#,
                "remove"
            )
            .is_err()
        );
        let synced = r#"{"ok":true,"operation":"sync_networks","synced":{"current":["docker0"],"added":["docker0"],"removed":[]}}"#;
        assert_eq!(
            parse_response(synced, "sync_networks")
                .unwrap()
                .synced
                .unwrap()
                .added,
            ["docker0"]
        );
        assert!(
            parse_response(
                r#"{"ok":true,"operation":"sync_networks"}"#,
                "sync_networks"
            )
            .is_err()
        );
        assert!(
            parse_response(
                r#"{"ok":true,"operation":"remove","unproven_mappings":0,"networks":{"installed":[],"wanted":null,"in_sync":null,"error":null}}"#,
                "remove"
            )
            .is_err()
        );
        assert!(
            parse_response(
                r#"{"ok":true,"operation":"install","unproven_mappings":0}"#,
                "install"
            )
            .is_err()
        );
        for operation in ["install", "arm"] {
            let response = format!(
                r#"{{"ok":true,"operation":"{operation}","identity_error":"boot_changed"}}"#
            );
            assert!(parse_response(&response, operation).is_err(), "{operation}");
        }
        assert!(
            parse_response(
                r#"{"ok":true,"operation":"precheck","grant_deadline":5,"identity_error":"boot_changed"}"#,
                "precheck"
            )
            .is_err()
        );
    }

    #[test]
    fn inspection_requires_typed_exclusive_ownership_response() {
        let clean = r#"{"ok":true,"operation":"inspect","ownership":{"identity_matches":true,"rules_present":false,"rules_complete":false,"mappings_present":false}}"#;
        assert!(
            parse_response(clean, "inspect")
                .unwrap()
                .ownership
                .unwrap()
                .clean()
        );
        let retired = r#"{"ok":true,"operation":"inspect","ownership":{"identity_matches":false,"rules_present":false,"rules_complete":false,"mappings_present":false}}"#;
        assert!(
            parse_response(retired, "inspect")
                .unwrap()
                .ownership
                .unwrap()
                .clean()
        );
        for response in [
            r#"{"ok":true,"operation":"inspect"}"#,
            r#"{"ok":true,"operation":"inspect","ownership":{"identity_matches":true,"rules_present":false}}"#,
            r#"{"ok":true,"operation":"inspect","ownership":{"identity_matches":true,"rules_present":false,"rules_complete":false,"mappings_present":false,"extra":true}}"#,
            r#"{"ok":true,"operation":"inspect","ownership":{"identity_matches":true,"rules_present":0,"rules_complete":false,"mappings_present":false}}"#,
            r#"{"ok":true,"operation":"remove","ownership":{"identity_matches":true,"rules_present":false,"rules_complete":false,"mappings_present":false}}"#,
            r#"{"ok":true,"operation":"inspect","ownership":{"identity_matches":true,"rules_present":false,"rules_complete":true,"mappings_present":false}}"#,
            r#"{"ok":true,"operation":"inspect","ownership":{"identity_matches":false,"rules_present":true,"rules_complete":false,"mappings_present":false}}"#,
        ] {
            let operation = if response.contains("remove") {
                "remove"
            } else {
                "inspect"
            };
            assert!(parse_response(response, operation).is_err());
        }
    }
}
