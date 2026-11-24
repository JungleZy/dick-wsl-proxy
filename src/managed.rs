//! Runtime-only M2 configuration. The recovery journal never contains credentials or policy.
use crate::{
    host,
    managed_dns::ManagedDns,
    plan::Plan,
    policy::{ChainTarget, Policy, UdpChain},
    probe::Snapshot,
};
use serde::Serialize;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// The leading code lets the desktop translate this when it surfaces as last_error.
const UDP_CHAIN_UNSUPPORTED: &str = "udp_chain_unavailable: chained UDP failed its readiness probe; non-whitelisted UDP is refused until the next start or switch";
const HTTPS_PROBE_ATTEMPTS: usize = 2;
const HTTPS_PROBE_RETRY_DELAY: Duration = Duration::from_millis(250);

pub struct Runtime {
    pub policy: Arc<Policy>,
    pub dns: ManagedDns,
    // Set when the readiness UDP probe fails for any reason (UDP ASSOCIATE
    // refused, hop unreachable, timeout). There is no in-session retry: a fresh
    // Runtime (new start or switch) starts unset and is probed again.
    udp_chain_unsupported: AtomicBool,
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

/// The `search` and `domain` suffixes in a resolv.conf, lower case without a
/// trailing dot. Names under them are local names and keep real resolution.
fn parse_search_suffixes(contents: &str) -> Vec<String> {
    let mut suffixes = Vec::new();
    for line in contents.lines() {
        let mut fields = line
            .split(['#', ';'])
            .next()
            .unwrap_or_default()
            .split_ascii_whitespace();
        if !matches!(fields.next(), Some("search" | "domain")) {
            continue;
        }
        for suffix in fields {
            let suffix = suffix.trim_end_matches('.').to_ascii_lowercase();
            if !suffix.is_empty() && !suffixes.contains(&suffix) {
                suffixes.push(suffix);
            }
        }
    }
    suffixes
}

/// The target's resolver search suffixes; none when the baseline is missing.
pub fn search_suffixes(s: &Snapshot) -> Vec<String> {
    s.evidence
        .get("baseline.resolv_conf")
        .filter(|e| e.status == "ok")
        .map(|item| parse_search_suffixes(&item.value))
        .unwrap_or_default()
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
    pub udp_supported: bool,
    pub dns_latency_ms: u32,
    pub https_host: String,
    pub https_status: u16,
    /// Whether names outside the whitelist get fake addresses, and if not, why.
    pub fake_ip: bool,
    pub fake_ip_reason: Option<String>,
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

    /// A runtime over a fixture policy whose hops are never reached.
    #[cfg(test)]
    pub(crate) fn for_test(fake_ip: bool) -> Arc<Self> {
        let config: crate::policy::Config = serde_json::from_value(serde_json::json!({
            "first_hop": "127.0.0.1:19",
            "credential": "fixture",
            "dns_upstream": "8.8.8.8:443",
            "dns_tls_name": "dns.google",
            "direct_ips": [],
            "direct_domains": [],
            "direct_suffixes": [],
            "allow_loopback_residential": true,
            "fake_ip": fake_ip
        }))
        .unwrap();
        let policy = Policy::assemble_for_store(
            crate::policy::Validated::new(config).unwrap(),
            crate::credential::fixture(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)),
        )
        .unwrap();
        Self::with_policy(Arc::new(policy)).unwrap()
    }

    fn with_policy(policy: Arc<Policy>) -> Result<Arc<Self>, String> {
        let dns = ManagedDns::new(Arc::clone(&policy))?;
        Ok(Arc::new(Self {
            policy,
            dns,
            udp_chain_unsupported: AtomicBool::new(false),
        }))
    }

    /// Turns fake-ip on when the policy asks for it, the address pool has
    /// room and the residential proxy accepts CONNECT by name, checked with
    /// the health domain. Otherwise leaves it off and says why.
    fn enable_fake_ip(&self, health_domain: &str) -> Option<String> {
        let reason = if !self.policy.fake_ip() {
            Some("fake_ip_off_in_policy".to_owned())
        } else if let Some(reason) = self.dns.fake_pool_unavailable() {
            Some(reason)
        } else if let Err(error) = self
            .policy
            .probe_connect(&ChainTarget::Name(health_domain.to_owned(), 443))
        {
            Some(format!("residential_name_connect_failed: {error}"))
        } else {
            self.dns.set_fake_ip(true).err()
        };
        if reason.is_some() {
            // Turning it off cannot fail.
            let _ = self.dns.set_fake_ip(false);
        }
        reason
    }

    fn record_udp_capability(&self, supported: bool) {
        self.udp_chain_unsupported
            .store(!supported, Ordering::Release);
    }

    /// The refusal for every new chained UDP flow once the readiness probe has
    /// failed, so callers need not start a setup worker just to be refused.
    pub(crate) fn udp_chain_refusal(&self) -> Option<&'static str> {
        self.udp_chain_unsupported
            .load(Ordering::Acquire)
            .then_some(UDP_CHAIN_UNSUPPORTED)
    }

    /// Chained UDP for a new flow. Once the readiness probe has failed, refuse
    /// immediately: retrying the two-hop setup for
    /// every datagram would block the ingress UDP loop (and system DNS intake)
    /// for up to the setup timeout per flow, only to be refused again.
    pub(crate) fn chain_udp(&self, dest: impl Into<SocketAddr>) -> Result<UdpChain, String> {
        if self.udp_chain_unsupported.load(Ordering::Acquire) {
            return Err(UDP_CHAIN_UNSUPPORTED.into());
        }
        let dest = dest.into();
        if let SocketAddr::V4(address) = dest
            && self.dns.is_fake(*address.ip())
        {
            let (name, lease) = self
                .dns
                .fake_lease(*address.ip())
                .ok_or("fake address reclaimed before the UDP chain started")?;
            return Ok(self
                .policy
                .chain_udp_name(&name, address.port())?
                .holding(Box::new(lease)));
        }
        self.policy.chain_udp(dest)
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
            // Probe output carries no credentials, only the cause worth seeing.
            let result = host::guest_script(&p.target, &script).map_err(|error| {
                format!("{label}_dns_probe_failed: {}", host::failure_tail(&error))
            })?;
            dns_elapsed = dns_elapsed.saturating_add(started.elapsed());
            if result.trim() != "ok" || !self.dns.probe_seen() {
                return Err(format!("{label}_dns_not_verified_through_upstream"));
            }
        }
        // DNS and HTTPS are the readiness gates for ordinary web traffic. A
        // residential SOCKS5 endpoint may support CONNECT while rejecting
        // UDP-ASSOCIATE. Keep that capability in the readiness snapshot so
        // TCP applications can still use the managed path and UDP callers can
        // receive an explicit flow error instead of taking a direct fallback.
        // The probe bypasses the gate so a fresh check is never short-circuited.
        let udp_supported = self
            .policy
            .chain_udp(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 443))
            .is_ok();
        self.record_udp_capability(udp_supported);
        let host = self.policy.health_domain();
        if self.policy.allows_domain(host) {
            return Err("health_domain_is_direct_not_chain".into());
        }
        // Before the HTTPS probe, so that probe goes the way ordinary traffic
        // will: by fake address and name when fake-ip is on.
        let fake_ip_reason = self.enable_fake_ip(host);
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
        // A transient WSL or proxy reset should not leave a newly installed
        // target in recovery solely because the readiness request lost its
        // first connection attempt. Retry only the guest execution failure.
        let mut response = None;
        for attempt in 0..HTTPS_PROBE_ATTEMPTS {
            match host::guest_script(&p.target, &script) {
                Ok(value) => {
                    response = Some(value);
                    break;
                }
                Err(_) if attempt + 1 < HTTPS_PROBE_ATTEMPTS => {
                    std::thread::sleep(HTTPS_PROBE_RETRY_DELAY);
                }
                Err(error) => {
                    return Err(format!(
                        "target_https_probe_failed: {}",
                        host::failure_tail(&error)
                    ));
                }
            }
        }
        let response = response.expect("HTTPS probe attempts must be nonzero");
        let (ip, code) = response
            .trim()
            .split_once(' ')
            .ok_or("bad_https_probe_output")?;
        let addr = ip.parse::<Ipv4Addr>().map_err(|_| "bad_probe_address")?;
        let status = code.parse::<u16>().map_err(|_| "bad_probe_status")?;
        // A fake address is chained by name; one no name stands behind
        // could not have been connected through.
        if self.dns.is_fake(addr) && self.dns.fake_name(addr).is_none() {
            return Err("https_probe_unknown_fake_address".into());
        }
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
            udp_supported,
            dns_latency_ms: average_dns_latency_ms(dns_elapsed),
            https_host: host.to_string(),
            https_status: status,
            fake_ip: fake_ip_reason.is_none(),
            fake_ip_reason,
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
    fn reads_search_and_domain_suffixes() {
        assert_eq!(
            parse_search_suffixes(
                "nameserver 10.255.255.254\nsearch Corp.Example. lab.example # note\ndomain corp.example\n# search ignored.example\n"
            ),
            ["corp.example", "lab.example"]
        );
        assert!(parse_search_suffixes("nameserver 10.0.0.1\n").is_empty());
    }

    #[test]
    fn unsupported_residential_udp_refuses_new_flows_without_dialing() {
        use std::net::TcpListener;
        let first_hop = TcpListener::bind("127.0.0.1:0").unwrap();
        first_hop.set_nonblocking(true).unwrap();
        let first_endpoint = match first_hop.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!(),
        };
        let config: crate::policy::Config = serde_json::from_value(serde_json::json!({
            "first_hop": first_endpoint.to_string(),
            "credential": "fixture",
            "dns_upstream": "8.8.8.8:443",
            "dns_tls_name": "dns.google",
            "direct_ips": [],
            "direct_domains": [],
            "direct_suffixes": [],
            "allow_loopback_residential": true
        }))
        .unwrap();
        let policy = Policy::assemble_for_store(
            crate::policy::Validated::new(config).unwrap(),
            crate::credential::fixture(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)),
        )
        .unwrap();
        let runtime = Runtime::with_policy(Arc::new(policy)).unwrap();
        assert!(!runtime.udp_chain_unsupported.load(Ordering::Acquire));

        runtime.record_udp_capability(false);
        let v4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 443);
        let v6: SocketAddr = "[2001:db8::9]:443".parse().unwrap();
        for target in [SocketAddr::V4(v4), v6] {
            let started = Instant::now();
            let error = runtime.chain_udp(target).err();
            assert_eq!(error.as_deref(), Some(UDP_CHAIN_UNSUPPORTED));
            assert!(started.elapsed() < Duration::from_millis(100));
        }
        // Neither the first hop nor the residential hop was contacted.
        assert_eq!(
            first_hop.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );

        runtime.record_udp_capability(true);
        assert!(!runtime.udp_chain_unsupported.load(Ordering::Acquire));
    }

    #[test]
    fn averages_dns_probe_latency_with_a_nonzero_floor() {
        assert_eq!(average_dns_latency_ms(Duration::ZERO), 1);
        assert_eq!(average_dns_latency_ms(Duration::from_millis(5)), 2);
        assert_eq!(average_dns_latency_ms(Duration::from_millis(8)), 4);
    }
}
