use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, UdpSocket,
};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::credential::{self, Residential};

pub(crate) mod domestic;
pub(crate) mod profile;
mod residential_probe;
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CONFIG: u64 = 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
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
    // Forwarding limits. Defaults are not written, so a profile that keeps
    // them stays readable by builds that predate these fields.
    #[serde(
        default = "default_max_tcp",
        skip_serializing_if = "is_default_max_tcp"
    )]
    max_tcp_connections: u32,
    #[serde(
        default = "default_tcp_idle",
        skip_serializing_if = "is_default_tcp_idle"
    )]
    tcp_idle_timeout_seconds: u64,
    #[serde(
        default = "default_half_close",
        skip_serializing_if = "is_default_half_close"
    )]
    tcp_half_close_timeout_seconds: u64,
}

fn default_health_domain() -> String {
    "ippure.com".into()
}

const DEFAULT_MAX_TCP: u32 = 256;
const DEFAULT_TCP_IDLE_SECONDS: u64 = 30 * 60;
const DEFAULT_HALF_CLOSE_SECONDS: u64 = 60;
const MAX_TCP_RANGE: std::ops::RangeInclusive<u32> = 16..=1024;
const TCP_IDLE_RANGE: std::ops::RangeInclusive<u64> = 30..=86_400;
const HALF_CLOSE_RANGE: std::ops::RangeInclusive<u64> = 5..=3_600;

fn default_max_tcp() -> u32 {
    DEFAULT_MAX_TCP
}
fn is_default_max_tcp(value: &u32) -> bool {
    *value == DEFAULT_MAX_TCP
}
fn default_tcp_idle() -> u64 {
    DEFAULT_TCP_IDLE_SECONDS
}
fn is_default_tcp_idle(value: &u64) -> bool {
    *value == DEFAULT_TCP_IDLE_SECONDS
}
fn default_half_close() -> u64 {
    DEFAULT_HALF_CLOSE_SECONDS
}
fn is_default_half_close(value: &u64) -> bool {
    *value == DEFAULT_HALF_CLOSE_SECONDS
}

/// TCP forwarding limits, fixed for the life of one takeover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Concurrent guest TCP connections, DNS over TCP included.
    pub(crate) max_tcp: usize,
    /// A connection without traffic in either direction for this long is closed.
    pub(crate) tcp_idle: Duration,
    /// After one side ends, the other may stay quiet this long.
    pub(crate) half_close: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_tcp: DEFAULT_MAX_TCP as usize,
            tcp_idle: Duration::from_secs(DEFAULT_TCP_IDLE_SECONDS),
            half_close: Duration::from_secs(DEFAULT_HALF_CLOSE_SECONDS),
        }
    }
}

impl Config {
    pub(crate) fn validate_draft(&self) -> Result<(), String> {
        credential::valid_name(&self.credential)?;
        Validated::new(self.clone()).map(|_| ())
    }

    /// The credential label is metadata now that the settings live in SQLite.
    pub(crate) fn set_credential(&mut self, name: String) {
        self.credential = name;
    }
}

struct Network {
    address: IpAddr,
    mask: u128,
}

// Immutable, secret-bearing runtime state. Never serialize or derive Debug for this type.
pub struct Policy {
    credential_ref: String,
    first_hop: SocketAddrV4,
    residential: Residential,
    dns_upstream: SocketAddrV4,
    dns_tls_name: String,
    direct_ips: Vec<Network>,
    direct_domains: Vec<String>,
    direct_suffixes: Vec<String>,
    health_domain: String,
    limits: Limits,
}

/// A nested SOCKS5 UDP relay. The first-hop relay carries an inner SOCKS5
/// datagram addressed to the residential relay, so the residential proxy's
/// UDP association remains behind the configured first hop.
pub(crate) struct UdpChain {
    socket: UdpSocket,
    residential_relay: SocketAddrV4,
    target: SocketAddr,
    // Keep both TCP UDP-ASSOCIATE control channels alive for the lifetime of
    // the UDP mapping. They are intentionally opaque after the handshake.
    _first_control: TcpStream,
    _residential_control: TcpStream,
}

impl UdpChain {
    fn packet(destination: impl Into<SocketAddr>, payload: &[u8]) -> Vec<u8> {
        let destination = destination.into();
        let capacity = match destination {
            SocketAddr::V4(_) => 10,
            SocketAddr::V6(_) => 22,
        };
        let mut packet = Vec::with_capacity(capacity + payload.len());
        packet.extend_from_slice(&[0, 0, 0]);
        match destination {
            SocketAddr::V4(destination) => {
                packet.push(1);
                packet.extend_from_slice(&destination.ip().octets());
                packet.extend_from_slice(&destination.port().to_be_bytes());
            }
            SocketAddr::V6(destination) => {
                packet.push(4);
                packet.extend_from_slice(&destination.ip().octets());
                packet.extend_from_slice(&destination.port().to_be_bytes());
            }
        }
        packet.extend_from_slice(payload);
        packet
    }

    fn parse_packet(
        bytes: &[u8],
        expected_source: impl Into<SocketAddr>,
        expected_destination: impl Into<SocketAddr>,
    ) -> io::Result<&[u8]> {
        let expected_source = expected_source.into();
        let expected_destination = expected_destination.into();
        if bytes.len() < 4 || bytes[..3] != [0, 0, 0] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid nested SOCKS5 UDP response",
            ));
        }
        let (source, source_end) = decode_udp_address(bytes, 3)?;
        if !same_endpoint(source, expected_source) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected nested SOCKS5 UDP source",
            ));
        }
        // The outer relay's payload is itself an inner SOCKS5 UDP response.
        let inner = &bytes[source_end..];
        if inner.len() < 4 || inner[..3] != [0, 0, 0] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid residential SOCKS5 UDP response",
            ));
        }
        let (destination, destination_end) = decode_udp_address(inner, 3)?;
        if !same_endpoint(destination, expected_destination) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected residential SOCKS5 UDP destination",
            ));
        }
        Ok(&inner[destination_end..])
    }

    pub(crate) fn send(&self, payload: &[u8]) -> io::Result<usize> {
        if payload.len() > 65_487 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nested SOCKS5 UDP payload is too large",
            ));
        }
        let inner = Self::packet(self.target, payload);
        let outer = Self::packet(SocketAddr::V4(self.residential_relay), &inner);
        let sent = self.socket.send(&outer)?;
        if sent == outer.len() {
            Ok(payload.len())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "nested SOCKS5 UDP datagram was truncated",
            ))
        }
    }

    pub(crate) fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut packet = vec![0; 65_535];
        let size = self.socket.recv(&mut packet)?;
        let payload = Self::parse_packet(
            &packet[..size],
            SocketAddr::V4(self.residential_relay),
            self.target,
        )?;
        if payload.len() > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "nested SOCKS5 UDP payload exceeds ingress buffer",
            ));
        }
        buffer[..payload.len()].copy_from_slice(payload);
        Ok(payload.len())
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }

    #[cfg(test)]
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    #[cfg(test)]
    pub(crate) fn peek(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.socket.peek(buffer)
    }

    #[cfg(windows)]
    pub(crate) fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        use std::os::windows::io::AsRawSocket;
        self.socket.as_raw_socket()
    }

    #[cfg(not(windows))]
    pub(crate) fn as_raw_socket(&self) -> std::os::unix::io::RawFd {
        use std::os::fd::AsRawFd;
        self.socket.as_raw_fd()
    }
}

fn decode_udp_address(bytes: &[u8], offset: usize) -> io::Result<(SocketAddr, usize)> {
    let atyp = *bytes.get(offset).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nested SOCKS5 address type",
        )
    })?;
    match atyp {
        1 => {
            let end = offset.checked_add(1 + 4 + 2).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "nested SOCKS5 address overflow")
            })?;
            if bytes.len() < end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated nested SOCKS5 IPv4 address",
                ));
            }
            let ip = Ipv4Addr::new(
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
            );
            let port = u16::from_be_bytes([bytes[offset + 5], bytes[offset + 6]]);
            if port == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "nested SOCKS5 address has zero port",
                ));
            }
            Ok((SocketAddr::V4(SocketAddrV4::new(ip, port)), end))
        }
        4 => {
            let end = offset.checked_add(1 + 16 + 2).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "nested SOCKS5 address overflow")
            })?;
            if bytes.len() < end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated nested SOCKS5 IPv6 address",
                ));
            }
            let mut octets = [0; 16];
            octets.copy_from_slice(&bytes[offset + 1..offset + 17]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([bytes[offset + 17], bytes[offset + 18]]);
            if port == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "nested SOCKS5 address has zero port",
                ));
            }
            Ok((SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)), end))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported nested SOCKS5 address type",
        )),
    }
}

fn same_endpoint(left: SocketAddr, right: SocketAddr) -> bool {
    match (left, right) {
        (SocketAddr::V4(left), SocketAddr::V4(right)) => left == right,
        (SocketAddr::V6(left), SocketAddr::V6(right)) => {
            left.ip() == right.ip() && left.port() == right.port()
        }
        _ => false,
    }
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
        let config = profile::decode_policy(&bytes)?;
        let validated = Validated::new(config)?;
        // Residential settings live in the local SQLite store, not the policy file.
        let residential = crate::desktop_store::load_credential()?;
        Self::assemble(validated, residential)
    }

    fn assemble(config: Validated, residential: Residential) -> Result<Self, String> {
        Self::assemble_for_store(config, residential)
    }

    pub(crate) fn assemble_for_store(
        config: Validated,
        residential: Residential,
    ) -> Result<Self, String> {
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
            credential_ref: config.credential,
            first_hop: config.first_hop,
            residential,
            dns_upstream: config.dns_upstream,
            dns_tls_name: config.dns_tls_name,
            direct_ips: config.direct_ips,
            direct_domains: config.direct_domains,
            direct_suffixes: config.direct_suffixes,
            health_domain: config.health_domain,
            limits: config.limits,
        })
    }

    pub(crate) fn limits(&self) -> Limits {
        self.limits
    }

    pub(crate) fn public_summary(&self) -> serde_json::Value {
        serde_json::json!({"first_hop":self.first_hop,"credential":self.credential_ref,"dns_upstream":self.dns_upstream,"dns_tls_name":self.dns_tls_name,"health_domain":self.health_domain})
    }

    pub(crate) fn matches_residence(&self, ip: Ipv4Addr) -> bool {
        self.residential.endpoint().ip() == &ip
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
        connect_addr(&mut stream, SocketAddr::V4(dest), deadline)?;
        stream
            .set_read_timeout(None)
            .map_err(|_| "cannot configure chain socket")?;
        stream
            .set_write_timeout(None)
            .map_err(|_| "cannot configure chain socket")?;
        Ok(stream)
    }

    /// Establishes the same authenticated chain for an IPv6 literal. The
    /// transparent ingress still needs an IPv6 plan before this path can be
    /// selected, but the proxy protocol itself now preserves IPv6 destinations.
    #[allow(dead_code)] // Activated when the IPv6 transparent ingress plan lands.
    pub fn chain_ipv6(&self, dest: SocketAddrV6) -> Result<TcpStream, String> {
        if !valid_ipv6_endpoint(dest) {
            return Err("IPv6 chain destination is reserved or unsupported".into());
        }
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let mut stream =
            TcpStream::connect_timeout(&SocketAddr::V4(self.first_hop), remaining(deadline)?)
                .map_err(|_| "cannot connect to first-hop SOCKS5 endpoint for IPv6".to_string())?;
        stream
            .set_nodelay(true)
            .map_err(|_| "cannot configure IPv6 chain socket".to_string())?;
        negotiate_no_auth(&mut stream, deadline)?;
        connect(&mut stream, self.residential.endpoint(), deadline)?;
        send(&mut stream, &[5, 1, 2], deadline)?;
        expect(
            &mut stream,
            &[5, 2],
            deadline,
            "residential IPv6 authentication method rejected",
        )?;
        let mut packet = AuthPacket([0; 513]);
        let len = self.residential.auth_packet(&mut packet.0);
        send(&mut stream, &packet.0[..len], deadline)?;
        expect(
            &mut stream,
            &[1, 0],
            deadline,
            "residential IPv6 authentication rejected",
        )?;
        connect_addr(&mut stream, SocketAddr::V6(dest), deadline)?;
        stream
            .set_read_timeout(None)
            .map_err(|_| "cannot configure IPv6 chain socket")?;
        stream
            .set_write_timeout(None)
            .map_err(|_| "cannot configure IPv6 chain socket")?;
        Ok(stream)
    }

    /// Establishes a nested SOCKS5 UDP association for a non-whitelisted UDP
    /// destination. The first relay transports the residential relay's own
    /// SOCKS5 UDP envelope, so neither hop is bypassed.
    pub(crate) fn chain_udp(&self, dest: impl Into<SocketAddr>) -> Result<UdpChain, String> {
        let dest = dest.into();
        let valid = match dest {
            SocketAddr::V4(dest) => {
                dest != self.first_hop
                    && dest != self.residential.endpoint()
                    && dest != self.dns_upstream
                    && valid_endpoint(dest, cfg!(test))
            }
            SocketAddr::V6(dest) => valid_ipv6_endpoint(dest),
        };
        if !valid {
            return Err("UDP chain destination is reserved or unsupported".into());
        }
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let mut first_control =
            TcpStream::connect_timeout(&SocketAddr::V4(self.first_hop), remaining(deadline)?)
                .map_err(|_| "cannot connect to first-hop SOCKS5 endpoint for UDP".to_string())?;
        first_control
            .set_nodelay(true)
            .map_err(|_| "cannot configure first-hop UDP control socket".to_string())?;
        negotiate_no_auth(&mut first_control, deadline)?;
        let first_relay = udp_associate(&mut first_control, self.first_hop, deadline, "first-hop")?;

        let mut residential_control =
            TcpStream::connect_timeout(&SocketAddr::V4(self.first_hop), remaining(deadline)?)
                .map_err(|_| "cannot connect to first-hop for residential UDP".to_string())?;
        residential_control
            .set_nodelay(true)
            .map_err(|_| "cannot configure residential UDP control socket".to_string())?;
        negotiate_no_auth(&mut residential_control, deadline)?;
        connect(
            &mut residential_control,
            self.residential.endpoint(),
            deadline,
        )?;
        send(&mut residential_control, &[5, 1, 2], deadline)?;
        expect(
            &mut residential_control,
            &[5, 2],
            deadline,
            "residential UDP authentication method rejected",
        )?;
        let mut packet = AuthPacket([0; 513]);
        let len = self.residential.auth_packet(&mut packet.0);
        send(&mut residential_control, &packet.0[..len], deadline)?;
        expect(
            &mut residential_control,
            &[1, 0],
            deadline,
            "residential UDP authentication rejected",
        )?;
        let residential_relay = udp_associate(
            &mut residential_control,
            self.residential.endpoint(),
            deadline,
            "residential",
        )?;

        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .map_err(|error| format!("bind nested UDP socket: {error}"))?;
        socket
            .connect(SocketAddr::V4(first_relay))
            .map_err(|error| format!("connect nested UDP relay: {error}"))?;
        socket
            .set_nonblocking(true)
            .map_err(|_| "cannot configure nested UDP socket".to_string())?;
        Ok(UdpChain {
            socket,
            residential_relay,
            target: dest,
            _first_control: first_control,
            _residential_control: residential_control,
        })
    }

    pub fn allows_ip(&self, ip: Ipv4Addr) -> bool {
        let address = u32::from(ip);
        self.direct_ips.iter().any(|network| {
            matches!(network.address, IpAddr::V4(network_ip)
                    if u32::from(network_ip) as u128 & network.mask == address as u128 & network.mask)
        })
    }

    #[allow(dead_code)] // Activated when IPv6 route selection reaches ingress.
    pub fn allows_ipv6(&self, ip: Ipv6Addr) -> bool {
        let address = u128::from(ip);
        self.direct_ips.iter().any(|network| {
            matches!(network.address, IpAddr::V6(network_ip)
                if u128::from(network_ip) & network.mask == address & network.mask)
        })
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

    pub(crate) fn has_domain_allowlist(&self) -> bool {
        !self.direct_domains.is_empty() || !self.direct_suffixes.is_empty()
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

pub(crate) struct Validated {
    first_hop: SocketAddrV4,
    credential: String,
    dns_upstream: SocketAddrV4,
    dns_tls_name: String,
    direct_ips: Vec<Network>,
    direct_domains: Vec<String>,
    direct_suffixes: Vec<String>,
    health_domain: String,
    allow_loopback_residential: bool,
    limits: Limits,
}

impl Validated {
    pub(crate) fn new(config: Config) -> Result<Self, String> {
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
        if !MAX_TCP_RANGE.contains(&config.max_tcp_connections) {
            return Err("max_tcp_connections must be between 16 and 1024".into());
        }
        if !TCP_IDLE_RANGE.contains(&config.tcp_idle_timeout_seconds) {
            return Err("tcp_idle_timeout_seconds must be between 30 and 86400".into());
        }
        if !HALF_CLOSE_RANGE.contains(&config.tcp_half_close_timeout_seconds) {
            return Err("tcp_half_close_timeout_seconds must be between 5 and 3600".into());
        }
        let limits = Limits {
            max_tcp: config.max_tcp_connections as usize,
            tcp_idle: Duration::from_secs(config.tcp_idle_timeout_seconds),
            half_close: Duration::from_secs(config.tcp_half_close_timeout_seconds),
        };
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
            limits,
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

fn valid_ipv6_endpoint(endpoint: SocketAddrV6) -> bool {
    let ip = endpoint.ip();
    endpoint.port() != 0
        && !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && ip.to_ipv4_mapped().is_none()
        && !ip.is_unicast_link_local()
}

fn network(entry: &str) -> Result<Network, String> {
    let (ip, prefix) = match entry.split_once('/') {
        Some((ip, prefix)) => (
            ip,
            prefix
                .parse::<u8>()
                .map_err(|_| "invalid direct IP CIDR prefix")?,
        ),
        None => (entry, if entry.contains(':') { 128 } else { 32 }),
    };
    let address = ip
        .parse::<IpAddr>()
        .map_err(|_| "direct_ips accepts only literal IP addresses or CIDR")?;
    let width = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > width {
        return Err("invalid direct IP CIDR prefix".into());
    }
    let mask = match address {
        IpAddr::V4(_) => {
            if prefix == 0 {
                0
            } else {
                u128::from(u32::MAX << u32::from(32 - prefix))
            }
        }
        IpAddr::V6(_) => {
            if prefix == 0 {
                0
            } else {
                u128::MAX << u32::from(128 - prefix)
            }
        }
    };
    let value = match address {
        IpAddr::V4(ip) => u32::from(ip) as u128,
        IpAddr::V6(ip) => u128::from(ip),
    };
    if value & mask != value {
        return Err("direct IP CIDR must use its network address".into());
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

fn negotiate_no_auth(stream: &mut TcpStream, deadline: Instant) -> Result<(), String> {
    send(stream, &[5, 1, 0], deadline)?;
    expect(
        stream,
        &[5, 0],
        deadline,
        "SOCKS5 UDP no-auth method rejected",
    )
}

fn udp_associate(
    stream: &mut TcpStream,
    fallback_ip: SocketAddrV4,
    deadline: Instant,
    label: &str,
) -> Result<SocketAddrV4, String> {
    send(stream, &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0], deadline)?;
    let mut header = [0; 4];
    receive(stream, &mut header, deadline)?;
    if header[0] != 5 || header[2] != 0 {
        return Err(format!(
            "{label} SOCKS5 UDP ASSOCIATE returned a malformed response"
        ));
    }
    if header[1] != 0 {
        return Err(format!(
            "{label} SOCKS5 UDP ASSOCIATE rejected with reply code 0x{:02x}",
            header[1]
        ));
    }
    let (address, port) = match header[3] {
        1 => {
            let mut bound = [0; 6];
            receive(stream, &mut bound, deadline)?;
            (
                Ipv4Addr::new(bound[0], bound[1], bound[2], bound[3]),
                u16::from_be_bytes([bound[4], bound[5]]),
            )
        }
        4 => return Err("SOCKS5 UDP relay returned IPv6 address".into()),
        3 => {
            let mut length = [0];
            receive(stream, &mut length, deadline)?;
            if length[0] == 0 {
                return Err("SOCKS5 UDP relay returned empty hostname".into());
            }
            let mut host = vec![0; usize::from(length[0]) + 2];
            receive(stream, &mut host, deadline)?;
            let address = std::str::from_utf8(&host[..host.len() - 2])
                .ok()
                .and_then(|value| value.parse::<Ipv4Addr>().ok())
                .ok_or("SOCKS5 UDP relay returned non-literal hostname")?;
            (
                address,
                u16::from_be_bytes([host[host.len() - 2], host[host.len() - 1]]),
            )
        }
        _ => return Err("SOCKS5 UDP relay returned unsupported address type".into()),
    };
    if port == 0 {
        return Err("SOCKS5 UDP relay returned zero port".into());
    }
    Ok(SocketAddrV4::new(
        if address.is_unspecified() {
            *fallback_ip.ip()
        } else {
            address
        },
        port,
    ))
}

fn connect(stream: &mut TcpStream, dest: SocketAddrV4, deadline: Instant) -> Result<(), String> {
    connect_addr(stream, SocketAddr::V4(dest), deadline)
}

fn connect_addr(stream: &mut TcpStream, dest: SocketAddr, deadline: Instant) -> Result<(), String> {
    let mut request = Vec::with_capacity(22);
    request.extend_from_slice(&[5, 1, 0]);
    match dest {
        SocketAddr::V4(dest) => {
            request.push(1);
            request.extend_from_slice(&dest.ip().octets());
            request.extend_from_slice(&dest.port().to_be_bytes());
        }
        SocketAddr::V6(dest) => {
            request.push(4);
            request.extend_from_slice(&dest.ip().octets());
            request.extend_from_slice(&dest.port().to_be_bytes());
        }
    }
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
    use std::net::{Shutdown, TcpListener, UdpSocket};
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
            max_tcp_connections: default_max_tcp(),
            tcp_idle_timeout_seconds: default_tcp_idle(),
            tcp_half_close_timeout_seconds: default_half_close(),
        }
    }

    #[test]
    fn forwarding_limits_default_stay_unwritten_and_reject_out_of_range_values() {
        let first_hop = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7892);
        let defaults = config(first_hop);
        let written = serde_json::to_value(&defaults).unwrap();
        for key in [
            "max_tcp_connections",
            "tcp_idle_timeout_seconds",
            "tcp_half_close_timeout_seconds",
        ] {
            assert!(written.get(key).is_none(), "{key}");
        }
        assert_eq!(
            Validated::new(defaults.clone()).unwrap().limits,
            Limits::default()
        );
        let mut custom = defaults.clone();
        custom.max_tcp_connections = 512;
        custom.tcp_idle_timeout_seconds = 3600;
        custom.tcp_half_close_timeout_seconds = 30;
        let written = serde_json::to_value(&custom).unwrap();
        assert_eq!(written["max_tcp_connections"], 512);
        let limits = Validated::new(custom).unwrap().limits;
        assert_eq!(limits.max_tcp, 512);
        assert_eq!(limits.tcp_idle, Duration::from_secs(3600));
        assert_eq!(limits.half_close, Duration::from_secs(30));
        for (max_tcp, idle, half_close) in [
            (15, 1800, 60),
            (1025, 1800, 60),
            (256, 29, 60),
            (256, 1800, 4),
        ] {
            let mut invalid = defaults.clone();
            invalid.max_tcp_connections = max_tcp;
            invalid.tcp_idle_timeout_seconds = idle;
            invalid.tcp_half_close_timeout_seconds = half_close;
            assert!(Validated::new(invalid).is_err());
        }
    }

    fn policy(first_hop: SocketAddrV4, residential: SocketAddrV4) -> Policy {
        Policy::assemble(
            Validated::new(config(first_hop)).unwrap(),
            credential::fixture(residential),
        )
        .unwrap()
    }

    #[test]
    fn direct_ip_policy_accepts_ipv6_cidrs_without_changing_ipv4_matching() {
        let first = "127.0.0.1:18080".parse().unwrap();
        let residential = "198.51.100.9:1080".parse().unwrap();
        let mut config = config(first);
        config.direct_ips.push("2001:db8:1234::/48".into());
        let policy = Policy::assemble(
            Validated::new(config).unwrap(),
            credential::fixture(residential),
        )
        .unwrap();
        assert!(policy.allows_ipv6("2001:db8:1234::99".parse().unwrap()));
        assert!(!policy.allows_ipv6("2001:db8:5678::99".parse().unwrap()));
        assert!(policy.allows_ip("192.0.2.4".parse().unwrap()));
    }

    #[test]
    fn nested_udp_envelope_round_trips_and_rejects_wrong_source() {
        let target: SocketAddrV4 = "203.0.113.9:443".parse().unwrap();
        let relay: SocketAddrV4 = "198.51.100.7:53000".parse().unwrap();
        let payload = b"udp-payload";
        let inner = UdpChain::packet(target, payload);
        let outer = UdpChain::packet(relay, &inner);
        assert_eq!(
            UdpChain::parse_packet(&outer, relay, target).unwrap(),
            payload
        );
        let wrong: SocketAddrV4 = "198.51.100.8:53000".parse().unwrap();
        assert!(UdpChain::parse_packet(&outer, wrong, target).is_err());
    }

    #[test]
    fn nested_udp_envelope_preserves_an_ipv6_inner_destination() {
        let relay: SocketAddrV4 = "198.51.100.7:53000".parse().unwrap();
        let target: SocketAddrV6 = "[2001:db8:1234::9]:443".parse().unwrap();
        let payload = b"ipv6-udp-payload";
        let inner = UdpChain::packet(SocketAddr::V6(target), payload);
        let outer = UdpChain::packet(SocketAddr::V4(relay), &inner);
        assert_eq!(
            UdpChain::parse_packet(&outer, SocketAddr::V4(relay), SocketAddr::V6(target)).unwrap(),
            payload
        );
    }

    #[test]
    fn nested_udp_association_relays_a_payload_through_both_control_channels() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let first_endpoint = endpoint(&first);
        let residential_endpoint = endpoint(&TcpListener::bind("127.0.0.1:0").unwrap());
        let first_relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        let first_relay_endpoint = match first_relay.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let residential_relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        let residential_relay_endpoint = match residential_relay.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let target: SocketAddrV4 = "203.0.113.9:443".parse().unwrap();
        let policy = policy(first_endpoint, residential_endpoint);

        let control = thread::spawn(move || {
            let mut first_control = accept(&first);
            assert_eq!(read::<3>(&mut first_control), [5, 1, 0]);
            first_control.write_all(&[5, 0]).unwrap();
            assert_eq!(read::<10>(&mut first_control)[..4], [5, 3, 0, 1]);
            first_control
                .write_all(&[
                    5,
                    0,
                    0,
                    1,
                    first_relay_endpoint.ip().octets()[0],
                    first_relay_endpoint.ip().octets()[1],
                    first_relay_endpoint.ip().octets()[2],
                    first_relay_endpoint.ip().octets()[3],
                    first_relay_endpoint.port().to_be_bytes()[0],
                    first_relay_endpoint.port().to_be_bytes()[1],
                ])
                .unwrap();

            let mut residential_control = accept(&first);
            assert_eq!(read::<3>(&mut residential_control), [5, 1, 0]);
            residential_control.write_all(&[5, 0]).unwrap();
            assert_eq!(read::<10>(&mut residential_control)[..4], [5, 1, 0, 1]);
            success(&mut residential_control);
            assert_eq!(read::<3>(&mut residential_control), [5, 1, 2]);
            residential_control.write_all(&[5, 2]).unwrap();
            assert_eq!(read::<2>(&mut residential_control), [1, 12]);
            assert_eq!(&read::<12>(&mut residential_control), b"fixture-user");
            assert_eq!(read::<1>(&mut residential_control), [16]);
            assert_eq!(&read::<16>(&mut residential_control), b"fixture-password");
            residential_control.write_all(&[1, 0]).unwrap();
            assert_eq!(read::<10>(&mut residential_control)[..4], [5, 3, 0, 1]);
            residential_control
                .write_all(&[
                    5,
                    0,
                    0,
                    1,
                    residential_relay_endpoint.ip().octets()[0],
                    residential_relay_endpoint.ip().octets()[1],
                    residential_relay_endpoint.ip().octets()[2],
                    residential_relay_endpoint.ip().octets()[3],
                    residential_relay_endpoint.port().to_be_bytes()[0],
                    residential_relay_endpoint.port().to_be_bytes()[1],
                ])
                .unwrap();
        });

        let relay = thread::spawn(move || {
            let mut request = [0; 65_535];
            let (size, client) = first_relay.recv_from(&mut request).unwrap();
            let payload = &request[10..size];
            let response = UdpChain::packet(
                residential_relay_endpoint,
                &UdpChain::packet(target, &payload[10..]),
            );
            first_relay.send_to(&response, client).unwrap();
        });

        let chain = policy.chain_udp(target).unwrap();
        chain.set_nonblocking(false).unwrap();
        assert_eq!(chain.send(b"udp-payload").unwrap(), 11);
        let mut response = [0; 64];
        assert_eq!(chain.recv(&mut response).unwrap(), 11);
        assert_eq!(&response[..11], b"udp-payload");
        drop(chain);
        relay.join().unwrap();
        control.join().unwrap();
    }

    fn accept(listener: &TcpListener) -> TcpStream {
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
            let mut stream = accept(&first);
            assert_eq!(read::<3>(&mut stream), [5, 1, 0]);
            stream.write_all(&[5, 0]).unwrap();
            request(&mut stream, residential_endpoint);
            let target = TcpStream::connect(residential_endpoint).unwrap();
            success(&mut stream);
            relay(stream, target);
        });
        let inner = thread::spawn(move || {
            let mut stream = accept(&residential);
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
            let mut stream = accept(&origin);
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
            let mut stream = accept(&first);
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
            let mut stream = accept(&first);
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
        assert!(policy.has_domain_allowlist());
        assert!(policy.is_reserved_endpoint(policy.dns_upstream()));
        assert!(policy.chain(policy.first_hop).is_err());
        assert!(policy.chain(policy.residential.endpoint()).is_err());
    }

    #[test]
    fn built_in_domestic_suffixes_are_few_canonical_and_spare_the_probe_names() {
        let suffixes = domestic::DIRECT_SUFFIXES;
        assert!(!suffixes.is_empty() && suffixes.len() <= 100);
        for suffix in suffixes {
            // Stored as written, so the rules page shows what the policy matches.
            assert_eq!(normalize_domain((*suffix).into()).unwrap(), *suffix);
            for other in suffixes {
                if suffix != other {
                    assert!(
                        !suffix.ends_with(&format!(".{other}")),
                        "{suffix} is already covered by {other}"
                    );
                }
            }
        }
        let unique: std::collections::HashSet<_> = suffixes.iter().collect();
        assert_eq!(unique.len(), suffixes.len());

        let mut config = config("127.0.0.1:7892".parse().unwrap());
        config.direct_ips.clear();
        config.direct_domains.clear();
        config.direct_suffixes = suffixes.iter().map(|suffix| (*suffix).into()).collect();
        let policy = Policy::assemble(
            Validated::new(config).unwrap(),
            credential::fixture("198.51.100.9:1080".parse().unwrap()),
        )
        .unwrap();
        for name in [
            "www.baidu.com",
            "mirrors.tuna.tsinghua.edu.cn",
            "registry.npmmirror.com",
        ] {
            assert!(policy.allows_domain(name), "{name}");
        }
        // Readiness, exit probe and DoH names must stay on the chain, or a fresh
        // install could not start.
        for name in [
            default_health_domain().as_str(),
            "my.ippure.com",
            "dns.google",
            "wpl-0000abcd-udp.example.com",
            "wpl-0000abcd-tcp.example.com",
            "notbaidu.com",
        ] {
            assert!(!policy.allows_domain(name), "{name}");
        }
    }

    #[test]
    fn rejects_ambiguous_networks_and_unsupported_endpoint_layouts() {
        for entry in [
            "example.com",
            "192.0.2.1/24",
            "192.0.2.0/33",
            "192.0.2.0/-1",
        ] {
            assert!(network(entry).is_err());
        }
        assert!(network("2001:db8::/32").is_ok());
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
        let _server = accept(&listener);
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
