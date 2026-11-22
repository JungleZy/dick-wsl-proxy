//! Runtime-only M2 configuration. The recovery journal never contains credentials or policy.
use crate::{host, managed_dns::ManagedDns, plan::Plan, policy::Policy, probe::Snapshot};
use serde::Serialize;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Runtime {
    pub policy: Arc<Policy>,
    pub dns: ManagedDns,
}

pub fn valid_resolver(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a != 0 && a != 127 && a < 224 && !(a == 169 && b == 254)
}

fn average_dns_latency_ms(total: Duration) -> u32 {
    u32::try_from((total.as_millis() / 2).max(1)).unwrap_or(u32::MAX)
}

fn parse_resolver(contents: &str) -> Result<Ipv4Addr, String> {
    let mut result = None;
    for line in contents.lines() {
        let mut fields = line
            .split(['#', ';'])
            .next()
            .unwrap_or_default()
            .split_ascii_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let candidate = fields
            .next()
            .and_then(|v| v.parse::<Ipv4Addr>().ok())
            .filter(|v| valid_resolver(*v))
            .ok_or("unsupported_system_dns_address")?;
        if fields.next().is_some() || result.is_some_and(|old| old != candidate) {
            return Err("multiple_or_ambiguous_system_resolvers".into());
        }
        result = Some(candidate);
    }
    result.ok_or_else(|| "system_resolver_missing".into())
}

pub fn resolver(s: &Snapshot) -> Result<Ipv4Addr, String> {
    let item = s
        .evidence
        .get("baseline.resolv_conf")
        .filter(|e| e.status == "ok")
        .ok_or("system_resolver_unavailable")?;
    parse_resolver(&item.value)
}

#[derive(Serialize)]
pub struct Readiness {
    pub system_dns: Ipv4Addr,
    pub fresh_udp_dns: bool,
    pub fresh_tcp_dns: bool,
    pub dns_latency_ms: u32,
    pub https_host: String,
    pub https_status: u16,
    pub checked_unix_seconds: u64,
}

impl Runtime {
    pub fn from_file(path: &Path) -> Result<Arc<Self>, String> {
        if path.extension().and_then(|v| v.to_str()) == Some("sqlite") {
            let (config, residential) = crate::desktop_store::load_runtime(path)?;
            let validated = crate::policy::Validated::new(config)?;
            let policy = Arc::new(Policy::assemble_for_store(validated, residential)?);
            return Self::with_policy(policy);
        }
        let policy = Arc::new(Policy::from_file(path)?);
        Self::with_policy(policy)
    }

    /// Keep the selected policy, not the previous distro's DNS aliases or readiness latch.
    pub fn for_next_target(&self) -> Result<Arc<Self>, String> {
        Self::with_policy(Arc::clone(&self.policy))
    }

    fn with_policy(policy: Arc<Policy>) -> Result<Arc<Self>, String> {
        let dns = ManagedDns::new(Arc::clone(&policy))?;
        Ok(Arc::new(Self { policy, dns }))
    }

    /// Exercise the actual target's sockets (not a Windows probe that skips the NAT rules).
    pub fn verify(&self, p: &Plan) -> Result<Readiness, String> {
        let server = p.system_dns.ok_or("missing_system_resolver")?;
        let mut dns_elapsed = Duration::ZERO;
        for (label, tcp) in [("udp", false), ("tcp", true)] {
            let name = format!("wpl-{:08x}-{label}.example.com", p.cookie);
            self.dns.arm_probe(&name)?;
            // Only typed IPs, generated ASCII labels, and integer literals enter this script.
            let script = format!(
                "exec /usr/bin/python3 -I - <<'WPL_DNS'\nname='{name}'\nserver='{server}'\ntcp={}\n{}\nWPL_DNS\n",
                u8::from(tcp),
                include_str!("guest/dns_probe.py")
            );
            let started = Instant::now();
            let result = host::guest_script(&p.target, &script)
                .map_err(|_| format!("{label}_dns_probe_failed"))?;
            dns_elapsed = dns_elapsed.saturating_add(started.elapsed());
            if result.trim() != "ok" || !self.dns.probe_seen() {
                return Err(format!("{label}_dns_not_verified_through_upstream"));
            }
        }
        // A healthy DNS path only proves the managed DNS terminator. Verify that
        // the selected residential chain can create both SOCKS5 UDP associations
        // before claiming that ordinary non-whitelisted UDP is covered. The
        // documentation endpoint is carried only in the association setup, so
        // this probe emits no application datagram.
        self.policy
            .chain_udp(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 443))
            .map(|_| ())
            .map_err(|error| format!("nonwhite_udp_chain_unavailable:{error}"))?;
        let host = self.policy.health_domain();
        if self.policy.allows_domain(host) {
            return Err("health_domain_is_direct_not_chain".into());
        }
        // No shell interpolation of a user-configured hostname, no curl proxy environment.
        let encoded = host
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let script = format!(
            "exec /usr/bin/python3 -I - <<'WPL_TLS'\nname=bytes.fromhex('{encoded}').decode('ascii')\n{}\nWPL_TLS\n",
            include_str!("guest/https_probe.py")
        );
        let response = host::guest_script(&p.target, &script)
            .map_err(|_| "target_https_probe_failed".to_string())?;
        let (ip, code) = response
            .trim()
            .split_once(' ')
            .ok_or("bad_https_probe_output")?;
        let addr = ip.parse::<Ipv4Addr>().map_err(|_| "bad_probe_address")?;
        let status = code.parse::<u16>().map_err(|_| "bad_probe_status")?;
        if !(200..400).contains(&status)
            || self.policy.allows_ip(addr)
            || self.dns.direct_alias(addr)?.is_some()
            || self
                .policy
                .is_reserved_endpoint(SocketAddrV4::new(addr, 443))
        {
            return Err("https_probe_not_successful_nonwhite_path".into());
        }
        Ok(Readiness {
            system_dns: server,
            fresh_udp_dns: true,
            fresh_tcp_dns: true,
            dns_latency_ms: average_dns_latency_ms(dns_elapsed),
            https_host: host.to_string(),
            https_status: status,
            checked_unix_seconds: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "invalid_clock")?
                .as_secs(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_unprotected_resolver_paths() {
        assert_eq!(
            parse_resolver("# Generated by WSL\nnameserver 10.255.255.254 # local\n").unwrap(),
            Ipv4Addr::new(10, 255, 255, 254)
        );
        for unsound in [
            "nameserver ::1",
            "nameserver 127.0.0.53",
            "nameserver 224.0.0.1",
            "nameserver 10.0.0.1\nnameserver 10.0.0.2",
            "nameserver",
            "search resolver.test",
        ] {
            assert!(parse_resolver(unsound).is_err());
        }
    }

    #[test]
    fn averages_dns_probe_latency_with_a_nonzero_floor() {
        assert_eq!(average_dns_latency_ms(Duration::ZERO), 1);
        assert_eq!(average_dns_latency_ms(Duration::from_millis(5)), 2);
        assert_eq!(average_dns_latency_ms(Duration::from_millis(8)), 4);
    }
}
