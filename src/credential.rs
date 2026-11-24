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

// Deliberately neither Debug nor Serialize: the endpoint is also credential material.
pub(crate) struct Residential {
    endpoint: SocketAddrV4,
    blob: Secret,
}

/// A copy for the connection pool's background dialer. The copied bytes are
/// wiped on drop like the original.
impl Clone for Residential {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint,
            blob: Secret(self.blob.0.clone()),
        }
    }
}

/// Builds the credential from the four settings fields exactly as typed: the
/// username and password bytes go into the SOCKS5 packet unchanged, quotes and
/// surrounding spaces included. Only the address is trimmed.
pub(crate) fn from_settings(
    settings: &crate::desktop_store::ResidentialSettings,
) -> Result<Residential, String> {
    let ip: Ipv4Addr = settings
        .ip
        .trim()
        .parse()
        .map_err(|_| "credential ip must be literal IPv4")?;
    build(
        ip,
        settings.port,
        settings.username.as_bytes(),
        settings.password.as_bytes(),
    )
}

fn build(ip: Ipv4Addr, port: u16, user: &[u8], password: &[u8]) -> Result<Residential, String> {
    let length = |value: &[u8]| u8::try_from(value.len()).ok().filter(|n| *n > 0);
    let (Some(user_len), Some(pass_len)) = (length(user), length(password)) else {
        return Err("SOCKS5 username and password must each contain 1–255 bytes".into());
    };
    let mut blob = Secret(Vec::with_capacity(13 + user.len() + password.len()));
    blob.0.extend_from_slice(MAGIC);
    blob.0.extend_from_slice(&ip.octets());
    blob.0.extend_from_slice(&port.to_be_bytes());
    blob.0.extend_from_slice(&[user_len, pass_len]);
    blob.0.extend_from_slice(user);
    blob.0.extend_from_slice(password);
    Residential::decode(blob)
}

pub(crate) fn settings(residential: &Residential) -> crate::desktop_store::ResidentialSettings {
    let bytes = &residential.blob.0;
    let user_len = bytes[11] as usize;
    let pass_len = bytes[12] as usize;
    crate::desktop_store::ResidentialSettings {
        ip: residential.endpoint.ip().to_string(),
        port: residential.endpoint.port(),
        username: String::from_utf8_lossy(&bytes[13..13 + user_len]).into_owned(),
        password: String::from_utf8_lossy(&bytes[13 + user_len..13 + user_len + pass_len])
            .into_owned(),
    }
}

impl Residential {
    fn decode(blob: Secret) -> Result<Self, String> {
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
        Ok(Self { endpoint, blob })
    }

    pub(crate) fn endpoint(&self) -> SocketAddrV4 {
        self.endpoint
    }

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
    for line in text.trim_start_matches('\u{feff}').lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or("invalid credential file assignment")?;
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
    build(ip, port, user?.as_bytes(), password?.as_bytes())
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
}
