use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::credential::{self, Residential};

pub(crate) mod profile;
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
}

fn default_health_domain() -> String {
    "ippure.com".into()
}

impl Config {
    pub(crate) fn validate_draft(&self) -> Result<(), String> {
        credential::target_name(&self.credential)?;
        Validated::new(self.clone()).map(|_| ())
    }
}

struct Network {
    address: u32,
    mask: u32,
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
}

/// A nested SOCKS5 UDP relay. The first-hop relay carries an inner SOCKS5
/// datagram addressed to the residential relay, so the residential proxy's
/// UDP association remains behind the configured first hop.
pub(crate) struct UdpChain {
    socket: UdpSocket,
    residential_relay: SocketAddrV4,
    target: SocketAddrV4,
    // Keep both TCP UDP-ASSOCIATE control channels alive for the lifetime of
    // the UDP mapping. They are intentionally opaque after the handshake.
    _first_control: TcpStream,
    _residential_control: TcpStream,
}

impl UdpChain {
    fn packet(destination: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(10 + payload.len());
        packet.extend_from_slice(&[0, 0, 0, 1]);
        packet.extend_from_slice(&destination.ip().octets());
        packet.extend_from_slice(&destination.port().to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn parse_packet(
        bytes: &[u8],
        expected_source: SocketAddrV4,
        expected_destination: SocketAddrV4,
    ) -> io::Result<&[u8]> {
        if bytes.len() < 10 || bytes[..3] != [0, 0, 0] || bytes[3] != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid nested SOCKS5 UDP response",
            ));
        }
        let source = SocketAddrV4::new(
            Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
            u16::from_be_bytes([bytes[8], bytes[9]]),
        );
        if source != expected_source {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected nested SOCKS5 UDP source",
            ));
        }
        // The outer relay's payload is itself an inner SOCKS5 UDP response.
        let inner = &bytes[10..];
        if inner.len() < 10 || inner[..3] != [0, 0, 0] || inner[3] != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid residential SOCKS5 UDP response",
            ));
        }
        let destination = SocketAddrV4::new(
            Ipv4Addr::new(inner[4], inner[5], inner[6], inner[7]),
            u16::from_be_bytes([inner[8], inner[9]]),
        );
        if destination != expected_destination {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected residential SOCKS5 UDP destination",
            ));
        }
        Ok(&inner[10..])
    }

    pub(crate) fn send(&self, payload: &[u8]) -> io::Result<usize> {
        if payload.len() > 65_487 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nested SOCKS5 UDP payload is too large",
            ));
        }
        let inner = Self::packet(self.target, payload);
        let outer = Self::packet(self.residential_relay, &inner);
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
        let payload = Self::parse_packet(&packet[..size], self.residential_relay, self.target)?;
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
        let residential = credential::load(&validated.credential)?;
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
        })
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
        connect(&mut stream, dest, deadline)?;
        stream
            .set_read_timeout(None)
            .map_err(|_| "cannot configure chain socket")?;
        stream
            .set_write_timeout(None)
            .map_err(|_| "cannot configure chain socket")?;
        Ok(stream)
    }

    /// Establishes a nested SOCKS5 UDP association for a non-whitelisted UDP
    /// destination. The first relay transports the residential relay's own
    /// SOCKS5 UDP envelope, so neither hop is bypassed.
    pub(crate) fn chain_udp(&self, dest: SocketAddrV4) -> Result<UdpChain, String> {
        if dest == self.first_hop
            || dest == self.residential.endpoint()
            || dest == self.dns_upstream
            || !valid_endpoint(dest, cfg!(test))
        {
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
        let first_relay = udp_associate(&mut first_control, self.first_hop, deadline)?;

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
) -> Result<SocketAddrV4, String> {
    send(stream, &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0], deadline)?;
    let mut header = [0; 4];
    receive(stream, &mut header, deadline)?;
    if header[0] != 5 || header[1] != 0 || header[2] != 0 {
        return Err("SOCKS5 UDP ASSOCIATE rejected or malformed".into());
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
    fn nested_udp_envelope_round_trips_and_rejects_wrong_source() {
        let target = "203.0.113.9:443".parse().unwrap();
        let relay = "198.51.100.7:53000".parse().unwrap();
        let payload = b"udp-payload";
        let inner = UdpChain::packet(target, payload);
        let outer = UdpChain::packet(relay, &inner);
        assert_eq!(
            UdpChain::parse_packet(&outer, relay, target).unwrap(),
            payload
        );
        let wrong = "198.51.100.8:53000".parse().unwrap();
        assert!(UdpChain::parse_packet(&outer, wrong, target).is_err());
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
        let target = "203.0.113.9:443".parse().unwrap();
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
