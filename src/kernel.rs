use crate::m1::Plan;
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::net::{Ipv4Addr, SocketAddrV4};

const SCRIPT: &str = include_str!("kernel.py");

/// Checks the target, required kernel features and absence of an existing owner.
/// This must succeed before persisting a new installation journal.
pub fn precheck(p: &Plan) -> Result<(), String> {
    invoke(p, "precheck").map(|_| ())
}

pub fn install(p: &Plan) -> Result<(), String> {
    invoke(p, "install").map(|_| ())
}

/// Arms one short-lived install after the Windows recovery journal is persisted.
/// Call once per immutable Plan, never retry even after an uncertain response;
/// recover with remove and choose a new generation before another activation.
pub fn arm(p: &Plan) -> Result<(), String> {
    invoke(p, "arm").map(|_| ())
}

/// Removes interception before deleting precisely identified owned mappings.
/// The Windows ingress must remain alive until this succeeds; TCP must reconnect.
pub fn remove(p: &Plan) -> Result<(), String> {
    invoke(p, "remove").map(|_| ())
}

/// A read-only observation of this generation, not permission to delete it.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ownership {
    pub identity_matches: bool,
    pub rules_present: bool,
    pub mappings_present: bool,
    pub rules_complete: bool,
}

impl Ownership {
    /// True only after inspection independently verifies this generation absent.
    /// A changed identity may be clean, but can never authorize deletion.
    pub fn clean(&self) -> bool {
        !self.rules_present && !self.rules_complete && !self.mappings_present
    }
}

/// Rechecks the live guest, exact tagged rules and connmark tuples without writes.
/// The caller must first verify the current Windows registration. A stale guest
/// identity can attest absence only; surviving or ambiguous artifacts fail closed.
pub fn inspect(p: &Plan) -> Result<Ownership, String> {
    invoke(p, "inspect")?
        .ownership
        .ok_or_else(|| "kernel_missing_ownership".into())
}

#[derive(Serialize)]
struct Request<'a> {
    operation: &'a str,
    plan: &'a Plan,
    protocol: Option<&'a str>,
    peer: Option<SocketAddrV4>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deadline: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    ok: bool,
    operation: String,
    origin: Option<SocketAddrV4>,
    ownership: Option<Ownership>,
}

fn invoke(p: &Plan, operation: &str) -> Result<Response, String> {
    validate(p)?;
    let request = Request {
        operation,
        plan: p,
        protocol: None,
        peer: None,
        deadline: if operation == "arm" {
            Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| "kernel_invalid_host_clock")?
                    .as_secs()
                    + 30,
            )
        } else {
            None
        },
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
    if operation != "lookup" && response.origin.is_some() {
        return Err("kernel_unexpected_origin".into());
    }
    if (operation == "inspect") != response.ownership.is_some() {
        return Err("kernel_unexpected_or_missing_ownership".into());
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
    Ok(())
}

fn unicast(ip: Ipv4Addr) -> bool {
    let [first, second, _, _] = ip.octets();
    first != 0 && first != 127 && first < 224 && !(first == 169 && second == 254)
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
                    };
                    assert_eq!(ownership.clean(), !rules_present && !mappings_present);
                    assert!(serde_json::to_string(&ownership).is_ok());
                }
            }
        }
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
