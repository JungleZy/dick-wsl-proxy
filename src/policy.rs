use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::credential::{self, Residential};

const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CONFIG: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    first_hop: String,
    credential: String,
    dns_upstream: String,
    dns_tls_name: String,
    direct_ips: Vec<String>,
    direct_domains: Vec<String>,
    direct_suffixes: Vec<String>,
    #[serde(default = "default_health_domain")]
    health_domain: String,
    #[serde(default)]
    allow_loopback_residential: bool,
}

fn default_health_domain() -> String {
    "ippure.com".into()
}

struct Network {
    address: u32,
    mask: u32,
}

// Immutable, secret-bearing runtime state. Never serialize or derive Debug for this type.
pub struct Policy {
    first_hop: SocketAddrV4,
    residential: Residential,
    dns_upstream: SocketAddrV4,
    dns_tls_name: String,
    direct_ips: Vec<Network>,
    direct_domains: Vec<String>,
    direct_suffixes: Vec<String>,
    health_domain: String,
}

impl Policy {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|_| "cannot open policy file")?;
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read policy file")?;
        if bytes.len() as u64 > MAX_CONFIG {
            return Err("policy file exceeds size limit".into());
        }
        let config: Config = serde_json::from_slice(&bytes)
            .map_err(|_| "invalid policy JSON or unsupported policy field")?;
        let validated = Validated::new(config)?;
        let residential = credential::load(&validated.credential)?;
        Self::assemble(validated, residential)
    }

    fn assemble(config: Validated, residential: Residential) -> Result<Self, String> {
        if residential.endpoint().ip().is_loopback() && !config.allow_loopback_residential {
            return Err("loopback residential endpoint requires explicit laboratory opt-in".into());
        }
        if config.first_hop == residential.endpoint()
            || config.dns_upstream == config.first_hop
            || config.dns_upstream == residential.endpoint()
        {
            return Err("policy contains an endpoint loop".into());
        }
        Ok(Self {
            first_hop: config.first_hop,
            residential,
            dns_upstream: config.dns_upstream,
            dns_tls_name: config.dns_tls_name,
            direct_ips: config.direct_ips,
            direct_domains: config.direct_domains,
            direct_suffixes: config.direct_suffixes,
            health_domain: config.health_domain,
        })
    }

    /// Establishes first-hop SOCKS5 -> authenticated residential SOCKS5 -> literal IPv4.
    /// The single deadline covers both handshakes, including partial reads and writes.
    pub fn chain(&self, dest: SocketAddrV4) -> Result<TcpStream, String> {
        if dest == self.first_hop
            || dest == self.residential.endpoint()
            || (dest != self.dns_upstream && !valid_endpoint(dest, cfg!(test)))
        {
            return Err("chain destination is reserved or unsupported".into());
        }
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let mut stream =
            TcpStream::connect_timeout(&SocketAddr::V4(self.first_hop), remaining(deadline)?)
                .map_err(|_| "cannot connect to first-hop SOCKS5 endpoint")?;
        stream
            .set_nodelay(true)
            .map_err(|_| "cannot configure chain socket")?;
        send(&mut stream, &[5, 1, 0], deadline)?;
        expect(
            &mut stream,
            &[5, 0],
            deadline,
            "first-hop SOCKS5 method rejected",
        )?;
        connect(&mut stream, self.residential.endpoint(), deadline)?;

        // No residential authentication bytes are emitted until outer CONNECT succeeds.
        send(&mut stream, &[5, 1, 2], deadline)?;
        expect(
            &mut stream,
            &[5, 2],
            deadline,
            "residential SOCKS5 authentication method rejected",
        )?;
        {
            let mut packet = AuthPacket([0; 513]);
            let len = self.residential.auth_packet(&mut packet.0);
            send(&mut stream, &packet.0[..len], deadline)?;
        }
        expect(
            &mut stream,
            &[1, 0],
            deadline,
            "residential SOCKS5 authentication rejected",
        )?;
        connect(&mut stream, dest, deadline)?;
        stream
            .set_read_timeout(None)
            .map_err(|_| "cannot configure chain socket")?;
        stream
            .set_write_timeout(None)
            .map_err(|_| "cannot configure chain socket")?;
        Ok(stream)
    }

    pub fn allows_ip(&self, ip: Ipv4Addr) -> bool {
        let address = u32::from(ip);
        self.direct_ips
            .iter()
            .any(|network| address & network.mask == network.address)
    }

    pub fn allows_domain(&self, name: &str) -> bool {
        let Some(name) = dns_name(name) else {
            return false;
        };
        self.direct_domains
            .iter()
            .any(|domain| name.eq_ignore_ascii_case(domain))
            || self.direct_suffixes.iter().any(|suffix| {
                name.eq_ignore_ascii_case(suffix)
                    || (name.len() > suffix.len()
                        && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
                        && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix))
            })
    }

    /// Ingress must reject these before either a direct or a chained client connection.
    /// Only the DNS owner is permitted to pass dns_upstream directly to chain().
    pub fn is_reserved_endpoint(&self, dest: SocketAddrV4) -> bool {
        dest == self.first_hop
            || dest == self.residential.endpoint()
            || dest == self.dns_upstream
            || !valid_endpoint(dest, cfg!(test))
    }

    /// HTTPS RFC8484 POST /dns-query; the explicit port does not select DoT.
    pub fn dns_upstream(&self) -> SocketAddrV4 {
        self.dns_upstream
    }

    pub fn dns_tls_name(&self) -> &str {
        &self.dns_tls_name
    }

    pub fn health_domain(&self) -> &str {
        &self.health_domain
    }
}

struct Validated {
    first_hop: SocketAddrV4,
    credential: String,
    dns_upstream: SocketAddrV4,
    dns_tls_name: String,
    direct_ips: Vec<Network>,
    direct_domains: Vec<String>,
    direct_suffixes: Vec<String>,
    health_domain: String,
    allow_loopback_residential: bool,
}

impl Validated {
    fn new(config: Config) -> Result<Self, String> {
        let first_hop: SocketAddrV4 = config
            .first_hop
            .parse()
            .map_err(|_| "first_hop must be a literal loopback IPv4:port")?;
        if !first_hop.ip().is_loopback() || first_hop.port() == 0 {
            return Err("first_hop must be a literal loopback IPv4:port".into());
        }
        let dns_upstream: SocketAddrV4 = config
            .dns_upstream
            .parse()
            .map_err(|_| "dns_upstream must be a literal unicast IPv4:port")?;
        if !valid_endpoint(dns_upstream, true) {
            return Err("dns_upstream must be a literal unicast IPv4:port".into());
        }
        let direct_ips = config
            .direct_ips
            .iter()
            .map(|entry| network(entry))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            first_hop,
            credential: config.credential,
            dns_upstream,
            dns_tls_name: normalize_domain(config.dns_tls_name)?,
            direct_ips,
            direct_domains: config
                .direct_domains
                .into_iter()
                .map(normalize_domain)
                .collect::<Result<_, _>>()?,
            direct_suffixes: config
                .direct_suffixes
                .into_iter()
                .map(normalize_domain)
                .collect::<Result<_, _>>()?,
            health_domain: normalize_domain(config.health_domain)?,
            allow_loopback_residential: config.allow_loopback_residential,
        })
    }
}

fn valid_endpoint(endpoint: SocketAddrV4, allow_loopback: bool) -> bool {
    let ip = endpoint.ip();
    endpoint.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_link_local()
        && (allow_loopback || !ip.is_loopback())
        && ip.octets()[0] != 0
        && ip.octets()[0] < 240
}

fn network(entry: &str) -> Result<Network, String> {
    let (ip, prefix) = match entry.split_once('/') {
        Some((ip, prefix)) => (
            ip,
            prefix
                .parse::<u8>()
                .map_err(|_| "invalid direct IPv4 CIDR prefix")?,
        ),
        None => (entry, 32),
    };
    let address = u32::from(
        ip.parse::<Ipv4Addr>()
            .map_err(|_| "direct_ips accepts only literal IPv4 or CIDR")?,
    );
    if prefix > 32 {
        return Err("invalid direct IPv4 CIDR prefix".into());
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if address & mask != address {
        return Err("direct IPv4 CIDR must use its network address".into());
    }
    Ok(Network { address, mask })
}

fn dns_name(name: &str) -> Option<&str> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 || !name.is_ascii() || name.parse::<Ipv4Addr>().is_ok() {
        return None;
    }
    name.split('.')
        .all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .then_some(name)
}

fn normalize_domain(mut name: String) -> Result<String, String> {
    let length = dns_name(&name)
        .ok_or("policy domain must be an ASCII DNS hostname")?
        .len();
    name.truncate(length);
    name.make_ascii_lowercase();
    Ok(name)
}

struct AuthPacket([u8; 513]);

impl Drop for AuthPacket {
    fn drop(&mut self) {
        credential::wipe(&mut self.0);
    }
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| "SOCKS5 chain setup deadline exceeded".into())
}

fn send(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> Result<(), String> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| "cannot configure chain deadline")?;
        match stream.write(bytes) {
            Ok(0) => return Err("SOCKS5 chain write closed".into()),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("SOCKS5 chain write failed or timed out".into()),
        }
    }
    Ok(())
}

fn receive(stream: &mut TcpStream, mut bytes: &mut [u8], deadline: Instant) -> Result<(), String> {
    while !bytes.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| "cannot configure chain deadline")?;
        match stream.read(bytes) {
            Ok(0) => return Err("SOCKS5 chain reply closed".into()),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("SOCKS5 chain read failed or timed out".into()),
        }
    }
    Ok(())
}

fn expect(
    stream: &mut TcpStream,
    expected: &[u8; 2],
    deadline: Instant,
    error: &str,
) -> Result<(), String> {
    let mut reply = [0; 2];
    receive(stream, &mut reply, deadline)?;
    if &reply != expected {
        return Err(error.into());
    }
    Ok(())
}

fn connect(stream: &mut TcpStream, dest: SocketAddrV4, deadline: Instant) -> Result<(), String> {
    let mut request = [5, 1, 0, 1, 0, 0, 0, 0, 0, 0];
    request[4..8].copy_from_slice(&dest.ip().octets());
    request[8..10].copy_from_slice(&dest.port().to_be_bytes());
    send(stream, &request, deadline)?;
    let mut header = [0; 4];
    receive(stream, &mut header, deadline)?;
    if header[0] != 5 || header[1] != 0 || header[2] != 0 {
        return Err("SOCKS5 CONNECT rejected or malformed".into());
    }
    let length = match header[3] {
        1 => 6,
        4 => 18,
        3 => {
            let mut length = [0];
            receive(stream, &mut length, deadline)?;
            if length[0] == 0 {
                return Err("SOCKS5 CONNECT returned an invalid bound address".into());
            }
            length[0] as usize + 2
        }
        _ => return Err("SOCKS5 CONNECT returned an unsupported address type".into()),
    };
    let mut bound = [0; 257];
    receive(stream, &mut bound[..length], deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Shutdown, TcpListener};
    use std::thread;

    fn endpoint(listener: &TcpListener) -> SocketAddrV4 {
        match listener.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => unreachable!(),
        }
    }

    fn config(first_hop: SocketAddrV4) -> Config {
        Config {
            first_hop: first_hop.to_string(),
            credential: "fixture".into(),
            dns_upstream: "8.8.8.8:443".into(),
            dns_tls_name: "dns.google".into(),
            direct_ips: vec!["192.0.2.4".into(), "198.51.100.0/24".into()],
            direct_domains: vec!["Exact.Example".into()],
            direct_suffixes: vec!["suffix.example".into()],
            allow_loopback_residential: true,
            health_domain: default_health_domain(),
        }
    }

    fn policy(first_hop: SocketAddrV4, residential: SocketAddrV4) -> Policy {
        Policy::assemble(
            Validated::new(config(first_hop)).unwrap(),
            credential::fixture(residential),
        )
        .unwrap()
    }

    fn accept(listener: TcpListener) -> TcpStream {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
    }

    fn read<const N: usize>(stream: &mut TcpStream) -> [u8; N] {
        let mut bytes = [0; N];
        stream.read_exact(&mut bytes).unwrap();
        bytes
    }

    fn request(stream: &mut TcpStream, destination: SocketAddrV4) {
        let bytes = read::<10>(stream);
        assert_eq!(&bytes[..4], &[5, 1, 0, 1]);
        assert_eq!(&bytes[4..8], &destination.ip().octets());
        assert_eq!(&bytes[8..], &destination.port().to_be_bytes());
    }

    fn success(stream: &mut TcpStream) {
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
    }

    fn relay(mut left: TcpStream, mut right: TcpStream) {
        let mut reader = left.try_clone().unwrap();
        let mut writer = right.try_clone().unwrap();
        let forward = thread::spawn(move || {
            let _ = std::io::copy(&mut reader, &mut writer);
            let _ = writer.shutdown(Shutdown::Write);
        });
        let _ = std::io::copy(&mut right, &mut left);
        let _ = left.shutdown(Shutdown::Write);
        forward.join().unwrap();
    }

    #[test]
    fn nested_connect_authenticates_only_after_outer_tunnel_and_reaches_literal_origin() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let residential = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let first_endpoint = endpoint(&first);
        let residential_endpoint = endpoint(&residential);
        let origin_endpoint = endpoint(&origin);
        let policy = policy(first_endpoint, residential_endpoint);
        let outer = thread::spawn(move || {
            let mut stream = accept(first);
            assert_eq!(read::<3>(&mut stream), [5, 1, 0]);
            stream.write_all(&[5, 0]).unwrap();
            request(&mut stream, residential_endpoint);
            let target = TcpStream::connect(residential_endpoint).unwrap();
            success(&mut stream);
            relay(stream, target);
        });
        let inner = thread::spawn(move || {
            let mut stream = accept(residential);
            assert_eq!(read::<3>(&mut stream), [5, 1, 2]);
            stream.write_all(&[5, 2]).unwrap();
            assert_eq!(read::<2>(&mut stream), [1, 12]);
            assert_eq!(&read::<12>(&mut stream), b"fixture-user");
            assert_eq!(read::<1>(&mut stream), [16]);
            assert_eq!(&read::<16>(&mut stream), b"fixture-password");
            stream.write_all(&[1, 0]).unwrap();
            request(&mut stream, origin_endpoint);
            let target = TcpStream::connect(origin_endpoint).unwrap();
            success(&mut stream);
            relay(stream, target);
        });
        let echo = thread::spawn(move || {
            let mut stream = accept(origin);
            assert_eq!(read::<4>(&mut stream), *b"ping");
            stream.write_all(b"pong").unwrap();
        });
        let mut stream = policy.chain(origin_endpoint).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream.write_all(b"ping").unwrap();
        assert_eq!(read::<4>(&mut stream), *b"pong");
        drop(stream);
        echo.join().unwrap();
        inner.join().unwrap();
        outer.join().unwrap();
    }

    #[test]
    fn rejected_outer_connect_sends_no_residential_authentication_or_fallback() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let residential = TcpListener::bind("127.0.0.1:0").unwrap();
        let first_endpoint = endpoint(&first);
        let residential_endpoint = endpoint(&residential);
        let policy = policy(first_endpoint, residential_endpoint);
        let server = thread::spawn(move || {
            let mut stream = accept(first);
            assert_eq!(read::<3>(&mut stream), [5, 1, 0]);
            stream.write_all(&[5, 0]).unwrap();
            request(&mut stream, residential_endpoint);
            stream.write_all(&[5, 5, 0, 1]).unwrap();
            let mut extra = [0];
            assert_eq!(stream.read(&mut extra).unwrap(), 0);
        });
        assert!(policy.chain("192.0.2.1:443".parse().unwrap()).is_err());
        server.join().unwrap();
        residential.set_nonblocking(true).unwrap();
        assert_eq!(
            residential.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn residential_must_select_authentication_and_never_downgrades() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let policy = policy(endpoint(&first), "127.0.0.1:1080".parse().unwrap());
        let server = thread::spawn(move || {
            let mut stream = accept(first);
            assert_eq!(read::<3>(&mut stream), [5, 1, 0]);
            stream.write_all(&[5, 0]).unwrap();
            request(&mut stream, "127.0.0.1:1080".parse().unwrap());
            success(&mut stream);
            assert_eq!(read::<3>(&mut stream), [5, 1, 2]);
            stream.write_all(&[5, 0]).unwrap();
            let mut extra = [0];
            assert_eq!(stream.read(&mut extra).unwrap(), 0);
        });
        assert!(policy.chain("192.0.2.1:443".parse().unwrap()).is_err());
        server.join().unwrap();
    }

    #[test]
    fn domain_whitelist_uses_exact_names_and_dot_boundary_suffixes() {
        let policy = policy(
            "127.0.0.1:7892".parse().unwrap(),
            "127.0.0.1:1080".parse().unwrap(),
        );
        for name in [
            "exact.example",
            "EXACT.EXAMPLE.",
            "suffix.example",
            "a.suffix.example",
        ] {
            assert!(policy.allows_domain(name));
        }
        for name in [
            "a.exact.example",
            "badsuffix.example",
            "suffix.example.evil",
            "a..suffix.example",
            "é.suffix.example",
        ] {
            assert!(!policy.allows_domain(name));
        }
        assert!(policy.allows_ip("192.0.2.4".parse().unwrap()));
        assert!(!policy.allows_ip("192.0.2.5".parse().unwrap()));
        assert!(policy.allows_ip("198.51.100.255".parse().unwrap()));
        assert!(!policy.allows_ip("198.51.101.1".parse().unwrap()));
        assert!(policy.is_reserved_endpoint(policy.dns_upstream()));
        assert!(policy.chain(policy.first_hop).is_err());
        assert!(policy.chain(policy.residential.endpoint()).is_err());
    }

    #[test]
    fn rejects_ambiguous_networks_and_unsupported_endpoint_layouts() {
        for entry in [
            "::1",
            "example.com",
            "192.0.2.1/24",
            "192.0.2.0/33",
            "192.0.2.0/-1",
        ] {
            assert!(network(entry).is_err());
        }
        assert!(network("0.0.0.0/0").is_ok());
        for endpoint in ["192.0.2.1:1080", "[::1]:1080", "127.0.0.1:0"] {
            let mut config = config("127.0.0.1:7892".parse().unwrap());
            config.first_hop = endpoint.into();
            assert!(Validated::new(config).is_err());
        }
        let mut config = config("127.0.0.1:7892".parse().unwrap());
        config.dns_upstream = "127.0.0.1:43803".into();
        assert!(Validated::new(config).is_ok());
        assert!(remaining(Instant::now() - Duration::from_millis(1)).is_err());
    }

    #[test]
    fn local_residential_requires_explicit_opt_in_and_never_permits_endpoint_loops() {
        let first = "127.0.0.1:7892".parse().unwrap();
        let local = "127.0.0.1:1080".parse().unwrap();
        let mut denied = config(first);
        denied.allow_loopback_residential = false;
        assert!(
            Policy::assemble(Validated::new(denied).unwrap(), credential::fixture(local)).is_err()
        );
        assert!(
            Policy::assemble(
                Validated::new(config(first)).unwrap(),
                credential::fixture(first)
            )
            .is_err()
        );
    }

    #[test]
    fn stalled_handshake_obeys_its_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(endpoint(&listener)).unwrap();
        let _server = accept(listener);
        let mut reply = [0; 2];
        assert!(
            receive(
                &mut client,
                &mut reply,
                Instant::now() + Duration::from_millis(20)
            )
            .is_err()
        );
    }

    #[test]
    fn json_fields_are_strict_and_health_domain_has_a_default() {
        let json = r#"{"first_hop":"127.0.0.1:7892","credential":"fixture","dns_upstream":"8.8.8.8:443","dns_tls_name":"dns.google","direct_ips":[],"direct_domains":[],"direct_suffixes":[]}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(Validated::new(config).unwrap().health_domain, "ippure.com");
        assert!(
            serde_json::from_str::<Config>(&json.replace("\"credential\":", "\"unknown\":"))
                .is_err()
        );
        assert!(
            serde_json::from_str::<Config>(&json.replace(
                "\"credential\":\"fixture\"",
                "\"credential\":\"fixture\",\"credential\":\"duplicate\""
            ))
            .is_err()
        );
    }
}
