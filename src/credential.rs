use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::sync::atomic::{Ordering, compiler_fence};

const MAGIC: &[u8; 5] = b"WSPC1";
const MAX_ENV: usize = 16 * 1024;

// Volatile stores prevent dead-store removal; all owned secret buffers use this on drop.
pub(crate) fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

struct Secret(Vec<u8>);

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// How the residential proxy is spoken to. SOCKS5 carries TCP and UDP; an
/// HTTP proxy only tunnels TCP with CONNECT, so UDP through it is refused.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Protocol {
    #[default]
    Socks5,
    Http,
}

impl Protocol {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Http => "http",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "socks5" => Some(Self::Socks5),
            "http" => Some(Self::Http),
            _ => None,
        }
    }
}

// Deliberately neither Debug nor Serialize: the endpoint is also credential material.
pub(crate) struct Residential {
    endpoint: SocketAddrV4,
    protocol: Protocol,
    blob: Secret,
}

/// A copy for the connection pool's background dialer. The copied bytes are
/// wiped on drop like the original.
impl Clone for Residential {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint,
            protocol: self.protocol,
            blob: Secret(self.blob.0.clone()),
        }
    }
}

/// Builds the credential from the settings fields exactly as typed: the
/// username and password bytes go into the SOCKS5 packet or the HTTP Basic
/// header unchanged, quotes and surrounding spaces included. Only the address
/// is trimmed.
pub(crate) fn from_settings(
    settings: &crate::desktop_store::ResidentialSettings,
) -> Result<Residential, String> {
    let ip: Ipv4Addr = settings
        .ip
        .trim()
        .parse()
        .map_err(|_| "credential ip must be literal IPv4")?;
    build(
        settings.protocol,
        ip,
        settings.port,
        settings.username.as_bytes(),
        settings.password.as_bytes(),
    )
}

fn build(
    protocol: Protocol,
    ip: Ipv4Addr,
    port: u16,
    user: &[u8],
    password: &[u8],
) -> Result<Residential, String> {
    let length = |value: &[u8]| u8::try_from(value.len()).ok().filter(|n| *n > 0);
    let (Some(user_len), Some(pass_len)) = (length(user), length(password)) else {
        return Err("residential username and password must each contain 1–255 bytes".into());
    };
    // HTTP Basic joins the two with a colon, so the username cannot hold one.
    if protocol == Protocol::Http && user.contains(&b':') {
        return Err("HTTP proxy username must not contain a colon".into());
    }
    let mut blob = Secret(Vec::with_capacity(13 + user.len() + password.len()));
    blob.0.extend_from_slice(MAGIC);
    blob.0.extend_from_slice(&ip.octets());
    blob.0.extend_from_slice(&port.to_be_bytes());
    blob.0.extend_from_slice(&[user_len, pass_len]);
    blob.0.extend_from_slice(user);
    blob.0.extend_from_slice(password);
    Residential::decode(protocol, blob)
}

pub(crate) fn settings(residential: &Residential) -> crate::desktop_store::ResidentialSettings {
    let bytes = &residential.blob.0;
    let user_len = bytes[11] as usize;
    let pass_len = bytes[12] as usize;
    crate::desktop_store::ResidentialSettings {
        protocol: residential.protocol,
        ip: residential.endpoint.ip().to_string(),
        port: residential.endpoint.port(),
        username: String::from_utf8_lossy(&bytes[13..13 + user_len]).into_owned(),
        password: String::from_utf8_lossy(&bytes[13 + user_len..13 + user_len + pass_len])
            .into_owned(),
    }
}

impl Residential {
    fn decode(protocol: Protocol, blob: Secret) -> Result<Self, String> {
        let b = &blob.0;
        if b.len() < 13 || &b[..5] != MAGIC {
            return Err("credential has an unsupported format".into());
        }
        let endpoint = SocketAddrV4::new(
            Ipv4Addr::new(b[5], b[6], b[7], b[8]),
            u16::from_be_bytes([b[9], b[10]]),
        );
        if b[11] == 0 || b[12] == 0 || b.len() != 13 + b[11] as usize + b[12] as usize {
            return Err("credential has an invalid authentication payload".into());
        }
        if !valid_endpoint(endpoint) {
            return Err("credential endpoint must be a unicast literal IPv4 endpoint".into());
        }
        Ok(Self {
            endpoint,
            protocol,
            blob,
        })
    }

    pub(crate) fn endpoint(&self) -> SocketAddrV4 {
        self.endpoint
    }

    pub(crate) fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Appends `Basic <base64(user:password)>` for an HTTP proxy's
    /// `Proxy-Authorization` header. The caller wipes `out`.
    pub(crate) fn append_basic_authorization(&self, out: &mut Vec<u8>) {
        let b = &self.blob.0;
        let user_len = b[11] as usize;
        let mut plain = Secret(Vec::with_capacity(b.len() - 12));
        plain.0.extend_from_slice(&b[13..13 + user_len]);
        plain.0.push(b':');
        plain.0.extend_from_slice(&b[13 + user_len..]);
        out.extend_from_slice(b"Basic ");
        base64(&plain.0, out);
    }

    /// Length of what `append_basic_authorization` appends.
    pub(crate) fn basic_authorization_len(&self) -> usize {
        let plain = self.blob.0.len() - 12;
        b"Basic ".len() + plain.div_ceil(3) * 4
    }

    /// The SOCKS5 username/password packet (RFC 1929). SOCKS5 only.
    pub(crate) fn auth_packet(&self, packet: &mut [u8; 513]) -> usize {
        let b = &self.blob.0;
        let user_len = b[11] as usize;
        let pass_len = b[12] as usize;
        packet[0] = 1;
        packet[1] = b[11];
        packet[2..2 + user_len].copy_from_slice(&b[13..13 + user_len]);
        packet[2 + user_len] = b[12];
        packet[3 + user_len..3 + user_len + pass_len].copy_from_slice(&b[13 + user_len..]);
        3 + user_len + pass_len
    }
}

/// Standard base64 with padding (RFC 4648), appended to `out`.
fn base64(input: &[u8], out: &mut Vec<u8>) {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for chunk in input.chunks(3) {
        let triple = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(TABLE[(triple >> 18) as usize & 63]);
        out.push(TABLE[(triple >> 12) as usize & 63]);
        out.push(if chunk.len() > 1 {
            TABLE[(triple >> 6) as usize & 63]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            TABLE[triple as usize & 63]
        } else {
            b'='
        });
    }
}

fn valid_endpoint(endpoint: SocketAddrV4) -> bool {
    let ip = endpoint.ip();
    endpoint.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_link_local()
        && ip.octets()[0] != 0
        && ip.octets()[0] < 240
}

/// The profile keeps a credential label for compatibility; the settings live in
/// the local SQLite store, so only the label's shape is checked.
pub(crate) fn valid_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("credential name must contain 1–128 ASCII letters, digits, dots, underscores or hyphens".into());
    }
    Ok(())
}

/// Reads the literal `.env` file once into settings for the SQLite store; the
/// path is not retained and no Windows credential entry is created.
pub(crate) fn settings_from_file(
    path: &Path,
) -> Result<crate::desktop_store::ResidentialSettings, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|_| "cannot open credential import file")?;
    let mut bytes = Vec::with_capacity(MAX_ENV + 1);
    file.take((MAX_ENV + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read credential import file")?;
    if bytes.len() > MAX_ENV {
        return Err("credential import file exceeds size limit".into());
    }
    let residential = parse_env(&bytes)?;
    wipe(&mut bytes);
    Ok(settings(&residential))
}

fn parse_env(bytes: &[u8]) -> Result<Residential, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "credential file must be UTF-8")?;
    let mut values: [Option<&str>; 4] = [None; 4];
    let mut protocol: Option<Protocol> = None;
    for line in text.trim_start_matches('\u{feff}').lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or("invalid credential file assignment")?;
        if key.trim() == "protocol" {
            if protocol.is_some() {
                return Err("credential file contains a duplicate key".into());
            }
            protocol = Some(
                Protocol::parse(value.trim())
                    .ok_or("credential protocol must be socks5 or http")?,
            );
            continue;
        }
        let index = match key.trim() {
            "ip" => 0,
            "port" => 1,
            "username" => 2,
            "password" => 3,
            _ => return Err("credential file contains an unsupported key".into()),
        };
        if values[index].is_some() {
            return Err("credential file contains a duplicate key".into());
        }
        let value = value.trim();
        let value = if value.starts_with('\'') || value.starts_with('"') {
            if value.len() < 2 || value.as_bytes().last() != value.as_bytes().first() {
                return Err("credential file has an unterminated quoted value".into());
            }
            &value[1..value.len() - 1]
        } else {
            value
        };
        if value.is_empty() || value.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            return Err("credential file contains an empty or invalid value".into());
        }
        values[index] = Some(value);
    }
    let [ip, port, user, password] = values
        .map(|value| value.ok_or("credential file must define ip, port, username and password"));
    let ip: Ipv4Addr = ip?
        .parse()
        .map_err(|_| "credential ip must be literal IPv4")?;
    let port: u16 = port?.parse().map_err(|_| "credential port is invalid")?;
    build(
        protocol.unwrap_or_default(),
        ip,
        port,
        user?.as_bytes(),
        password?.as_bytes(),
    )
}

/// The fixture credential spoken to as an HTTP proxy.
#[cfg(test)]
pub(crate) fn http_fixture(endpoint: SocketAddrV4) -> Residential {
    Residential {
        protocol: Protocol::Http,
        ..fixture(endpoint)
    }
}

#[cfg(test)]
pub(crate) fn fixture(endpoint: SocketAddrV4) -> Residential {
    parse_env(
        format!(
            "ip={}\nport={}\nusername=fixture-user\npassword=fixture-password\n",
            endpoint.ip(),
            endpoint.port()
        )
        .as_bytes(),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_literal_credentials_without_expansion() {
        let credential = parse_env(b"# fixture\r\nip=127.0.0.1\r\nport=1080\r\nusername='user'\r\npassword=\"p$#=word\"\r\n").unwrap();
        let mut packet = [0; 513];
        let len = credential.auth_packet(&mut packet);
        assert_eq!(&packet[..len], b"\x01\x04user\x08p$#=word");
        wipe(&mut packet);
    }

    #[test]
    fn settings_reach_the_auth_packet_byte_for_byte() {
        for (username, password) in [("user", "\"q\""), ("'u'", "'lead"), (" spaced ", "p=a#ss ")] {
            let settings = crate::desktop_store::ResidentialSettings {
                protocol: Protocol::Socks5,
                ip: " 192.0.2.10 ".into(),
                port: 1080,
                username: username.into(),
                password: password.into(),
            };
            let credential = from_settings(&settings).unwrap();
            let mut packet = [0; 513];
            let len = credential.auth_packet(&mut packet);
            let mut expected = vec![1, username.len() as u8];
            expected.extend_from_slice(username.as_bytes());
            expected.push(password.len() as u8);
            expected.extend_from_slice(password.as_bytes());
            assert_eq!(&packet[..len], expected.as_slice());
            let back = super::settings(&credential);
            assert_eq!(
                (back.username.as_str(), back.password.as_str()),
                (username, password)
            );
            wipe(&mut packet);
        }
    }

    #[test]
    fn settings_reject_empty_or_oversized_fields() {
        let base = crate::desktop_store::ResidentialSettings {
            protocol: Protocol::Socks5,
            ip: "192.0.2.10".into(),
            port: 1080,
            username: "user".into(),
            password: "secret".into(),
        };
        for broken in [
            crate::desktop_store::ResidentialSettings {
                password: String::new(),
                ..base.clone()
            },
            crate::desktop_store::ResidentialSettings {
                username: "u".repeat(256),
                ..base.clone()
            },
            crate::desktop_store::ResidentialSettings {
                ip: "proxy.example".into(),
                ..base.clone()
            },
            crate::desktop_store::ResidentialSettings {
                port: 0,
                ..base.clone()
            },
        ] {
            assert!(from_settings(&broken).is_err());
        }
        assert!(from_settings(&base).is_ok());
    }

    #[test]
    fn rejects_ambiguous_or_invalid_credentials_without_echoing_input() {
        for source in [
            "ip=127.0.0.1\nport=0\nusername=fixture\npassword=fixture",
            "ip=::1\nport=1080\nusername=fixture\npassword=fixture",
            "ip=127.0.0.1\nport=1080\nusername=fixture\npassword=fixture\npassword=other",
            "ip=127.0.0.1\nport=1080\nusername=fixture\npassword='unterminated",
            "ip=127.0.0.1\nport=1080\nusername=fixture\npassword=fixture\nextra=other",
        ] {
            assert!(parse_env(source.as_bytes()).is_err());
        }
        assert!(valid_name("../fixture").is_err());
    }

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            let mut out = Vec::new();
            base64(input.as_bytes(), &mut out);
            assert_eq!(out, expected.as_bytes());
        }
    }

    #[test]
    fn http_credentials_become_one_basic_header_value() {
        let settings = crate::desktop_store::ResidentialSettings {
            protocol: Protocol::Http,
            ip: "192.0.2.10".into(),
            port: 8080,
            username: "Aladdin".into(),
            password: "open sesame".into(),
        };
        let credential = from_settings(&settings).unwrap();
        assert_eq!(credential.protocol(), Protocol::Http);
        let mut header = Vec::new();
        credential.append_basic_authorization(&mut header);
        assert_eq!(header, b"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        assert!(super::settings(&credential) == settings);
        // A colon in the username would split differently on the proxy.
        let colon = crate::desktop_store::ResidentialSettings {
            username: "a:b".into(),
            ..settings.clone()
        };
        assert!(from_settings(&colon).is_err());
        // SOCKS5 sends the username as its own field, so a colon is fine there.
        assert!(
            from_settings(&crate::desktop_store::ResidentialSettings {
                protocol: Protocol::Socks5,
                ..colon
            })
            .is_ok()
        );
    }

    #[test]
    fn an_import_file_may_name_the_protocol() {
        let http = parse_env(b"protocol=http\nip=192.0.2.10\nport=8080\nusername=u\npassword=p\n")
            .unwrap();
        assert_eq!(http.protocol(), Protocol::Http);
        let socks = parse_env(b"ip=192.0.2.10\nport=1080\nusername=u\npassword=p\n").unwrap();
        assert_eq!(socks.protocol(), Protocol::Socks5);
        assert!(
            parse_env(b"protocol=ftp\nip=192.0.2.10\nport=21\nusername=u\npassword=p\n").is_err()
        );
    }
}
