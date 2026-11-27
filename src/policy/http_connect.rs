//! The residential hop as an HTTP proxy: one `CONNECT` request carrying
//! `Proxy-Authorization: Basic`, answered by a status line and headers. HTTP
//! proxies only tunnel TCP, so UDP through them is refused before dialing.

use std::net::{SocketAddr, TcpStream};
use std::time::Instant;

use super::dialer::ChainTarget;
use super::{WipedBytes, receive, send};
use crate::credential::Residential;

/// Longest reply header read before the tunnel is given up. Proxies answer
/// CONNECT with a few hundred bytes; a page this long is not a CONNECT reply.
const MAX_REPLY: usize = 8 * 1024;

/// How a CONNECT reply refused or failed.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    /// 407: the proxy did not accept the credentials, or the source IP.
    Authentication,
    /// Any other status: the proxy would not or could not reach the target.
    Status(u16),
    /// Not an HTTP reply, or a header that never ended.
    Malformed,
    /// The tunnel broke or timed out partway through the reply.
    Broken(String),
}

impl Refusal {
    pub(super) fn message(&self) -> String {
        match self {
            Self::Authentication => "residential HTTP proxy authentication rejected".into(),
            Self::Status(code) => format!("residential HTTP CONNECT refused with status {code}"),
            Self::Malformed => "residential HTTP CONNECT reply is malformed".into(),
            Self::Broken(message) => message.clone(),
        }
    }
}

/// `CONNECT target HTTP/1.1` with `Host` and the credentials. Names reach
/// here only through `valid_chain_name`, so they carry no spaces or line
/// breaks into the request.
pub(super) fn request(target: &ChainTarget, residential: &Residential) -> WipedBytes {
    let authority = match target {
        ChainTarget::Address(SocketAddr::V4(address)) => address.to_string(),
        // `SocketAddrV6` formats as `[address]:port`, as the authority needs.
        ChainTarget::Address(SocketAddr::V6(address)) => {
            format!("[{}]:{}", address.ip(), address.port())
        }
        ChainTarget::Name(name, port) => format!("{name}:{port}"),
    };
    // Sized exactly: growing the buffer would free a copy of the credentials
    // without wiping it.
    let length = b"CONNECT ".len()
        + 2 * authority.len()
        + b" HTTP/1.1\r\nHost: ".len()
        + b"\r\nProxy-Authorization: ".len()
        + residential.basic_authorization_len()
        + b"\r\n\r\n".len();
    let mut bytes = WipedBytes(Vec::with_capacity(length));
    bytes.0.extend_from_slice(b"CONNECT ");
    bytes.0.extend_from_slice(authority.as_bytes());
    bytes.0.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    bytes.0.extend_from_slice(authority.as_bytes());
    bytes.0.extend_from_slice(b"\r\nProxy-Authorization: ");
    residential.append_basic_authorization(&mut bytes.0);
    bytes.0.extend_from_slice(b"\r\n\r\n");
    debug_assert_eq!(bytes.0.len(), length);
    bytes
}

/// Sends the CONNECT and reads its reply. The single deadline covers both.
pub(super) fn connect(
    stream: &mut TcpStream,
    target: &ChainTarget,
    residential: &Residential,
    deadline: Instant,
) -> Result<(), Refusal> {
    send(stream, &request(target, residential).0, deadline).map_err(Refusal::Broken)?;
    let mut first = [0; 1];
    receive(stream, &mut first, deadline).map_err(Refusal::Broken)?;
    reply_rest(stream, first[0], deadline)
}

/// The rest of a CONNECT reply whose first byte was already read. Reads one
/// byte at a time and stops right after the blank line: whatever the target
/// sends next belongs to the tunnel, and the caller hands the bare stream on.
pub(super) fn reply_rest(
    stream: &mut TcpStream,
    first: u8,
    deadline: Instant,
) -> Result<(), Refusal> {
    let mut header = Vec::with_capacity(256);
    header.push(first);
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= MAX_REPLY {
            return Err(Refusal::Malformed);
        }
        let mut byte = [0; 1];
        receive(stream, &mut byte, deadline).map_err(Refusal::Broken)?;
        header.push(byte[0]);
    }
    match status(&header) {
        Some(code) if (200..300).contains(&code) => Ok(()),
        Some(407) => Err(Refusal::Authentication),
        Some(code) => Err(Refusal::Status(code)),
        None => Err(Refusal::Malformed),
    }
}

/// The status code of `HTTP/1.x NNN ...`.
fn status(header: &[u8]) -> Option<u16> {
    let line = header.split(|byte| *byte == b'\r').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.splitn(3, ' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 {
        return None;
    }
    code.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{SocketAddrV4, TcpListener};
    use std::thread;
    use std::time::Duration;

    fn fixture() -> Residential {
        crate::credential::http_fixture("198.51.100.9:8080".parse().unwrap())
    }

    #[test]
    fn requests_name_the_authority_and_carry_basic_credentials() {
        let auth = "Proxy-Authorization: Basic Zml4dHVyZS11c2VyOmZpeHR1cmUtcGFzc3dvcmQ=\r\n\r\n";
        for (target, authority) in [
            (
                ChainTarget::Address("8.8.8.8:443".parse().unwrap()),
                "8.8.8.8:443",
            ),
            (
                ChainTarget::Address("[2001:db8::1]:443".parse().unwrap()),
                "[2001:db8::1]:443",
            ),
            (
                ChainTarget::Name("dns.google".into(), 853),
                "dns.google:853",
            ),
        ] {
            let request = request(&target, &fixture());
            let text = std::str::from_utf8(&request.0).unwrap();
            assert_eq!(
                text,
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{auth}")
            );
        }
    }

    #[test]
    fn the_request_buffer_never_grows_even_with_the_longest_credentials() {
        for (user, password) in [(1, 1), (255, 255), (254, 1), (100, 101)] {
            let settings = crate::desktop_store::ResidentialSettings {
                protocol: crate::credential::Protocol::Http,
                ip: "198.51.100.9".into(),
                port: 8080,
                username: "u".repeat(user),
                password: "p".repeat(password),
            };
            let residential = crate::credential::from_settings(&settings).unwrap();
            let target = ChainTarget::Name(format!("{}.example", "a".repeat(60)), 443);
            let request = request(&target, &residential);
            assert_eq!(request.0.len(), request.0.capacity());
        }
    }

    #[test]
    fn status_lines_are_read_strictly() {
        assert_eq!(
            status(b"HTTP/1.1 200 Connection established\r\n\r\n"),
            Some(200)
        );
        assert_eq!(status(b"HTTP/1.0 200\r\n\r\n"), Some(200));
        assert_eq!(
            status(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"),
            Some(407)
        );
        assert_eq!(status(b"\x05\x02"), None);
        assert_eq!(status(b"HTTP/2 200\r\n\r\n"), None);
        assert_eq!(status(b"HTTP/1.1 2000 OK\r\n\r\n"), None);
    }

    /// A proxy that answers with `reply` and, in the same write, the first
    /// bytes from the target. Returns what the client reads after the reply.
    fn exchange(reply: &'static [u8]) -> (Result<(), Refusal>, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut byte = [0; 1];
            while !seen.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                seen.push(byte[0]);
            }
            let mut batch = reply.to_vec();
            batch.extend_from_slice(b"SSH-2.0-banner");
            stream.write_all(&batch).unwrap();
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let target =
            ChainTarget::Address(SocketAddr::V4(SocketAddrV4::new([192, 0, 2, 1].into(), 22)));
        let result = connect(&mut stream, &target, &fixture(), deadline);
        server.join().unwrap();
        let mut rest = Vec::new();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let _ = stream.read_to_end(&mut rest);
        (result, rest)
    }

    #[test]
    fn bytes_after_the_reply_stay_in_the_tunnel() {
        let (result, rest) =
            exchange(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: x\r\n\r\n");
        assert_eq!(result, Ok(()));
        assert_eq!(rest, b"SSH-2.0-banner");
    }

    #[test]
    fn a_407_is_an_authentication_refusal_and_other_codes_are_kept() {
        let (result, _) =
            exchange(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(result, Err(Refusal::Authentication));
        let (result, _) = exchange(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        assert_eq!(result, Err(Refusal::Status(403)));
    }
}
