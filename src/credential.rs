use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::sync::atomic::{Ordering, compiler_fence};

const MAGIC: &[u8; 5] = b"WSPC1";
#[cfg(windows)]
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

pub(crate) fn from_settings(
    settings: &crate::desktop_store::ResidentialSettings,
) -> Result<Residential, String> {
    let text = format!(
        "ip={}\nport={}\nusername={}\npassword={}\n",
        settings.ip, settings.port, settings.username, settings.password
    );
    parse_env(text.as_bytes())
}

#[cfg_attr(test, allow(dead_code))]
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

pub(crate) fn target_name(name: &str) -> Result<Vec<u16>, String> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("credential name must contain 1–128 ASCII letters, digits, dots, underscores or hyphens".into());
    }
    Ok(format!("wsl-proxyctl/{name}")
        .encode_utf16()
        .chain(Some(0))
        .collect())
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
    let user = user?.as_bytes();
    let password = password?.as_bytes();
    if user.len() > 255 || password.len() > 255 {
        return Err("SOCKS5 username and password must each contain 1–255 bytes".into());
    }
    let mut blob = Secret(Vec::with_capacity(13 + user.len() + password.len()));
    blob.0.extend_from_slice(MAGIC);
    blob.0.extend_from_slice(&ip.octets());
    blob.0.extend_from_slice(&port.to_be_bytes());
    blob.0
        .extend_from_slice(&[user.len() as u8, password.len() as u8]);
    blob.0.extend_from_slice(user);
    blob.0.extend_from_slice(password);
    Residential::decode(blob)
}

/// Imports once into the current Windows user's Credential Manager; the file path is not retained.
/// Values are literal UTF-8, optionally enclosed in matching quotes (no expansion or escapes).
pub fn import(name: &str, env_file: &Path) -> Result<(), String> {
    let target = target_name(name)?;
    #[cfg(windows)]
    {
        use std::io::Read;
        let file =
            std::fs::File::open(env_file).map_err(|_| "cannot open credential import file")?;
        let mut source = Secret(Vec::with_capacity(MAX_ENV + 1));
        file.take((MAX_ENV + 1) as u64)
            .read_to_end(&mut source.0)
            .map_err(|_| "cannot read credential import file")?;
        if source.0.len() > MAX_ENV {
            return Err("credential import file exceeds size limit".into());
        }
        let residential = parse_env(&source.0)?;
        windows::store(target, residential)
    }
    #[cfg(not(windows))]
    {
        let _ = (target, env_file);
        Err("Windows Credential Manager is available only on Windows".into())
    }
}

pub fn remove(name: &str) -> Result<(), String> {
    let target = target_name(name)?;
    #[cfg(windows)]
    {
        windows::remove(target)
    }
    #[cfg(not(windows))]
    {
        let _ = target;
        Err("Windows Credential Manager is available only on Windows".into())
    }
}

pub(crate) fn load(name: &str) -> Result<Residential, String> {
    let target = target_name(name)?;
    #[cfg(windows)]
    {
        windows::load(target)
    }
    #[cfg(not(windows))]
    {
        let _ = target;
        Err("Windows Credential Manager is available only on Windows".into())
    }
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn store_settings(
    name: &str,
    settings: &crate::desktop_store::ResidentialSettings,
) -> Result<(), String> {
    let target = target_name(name)?;
    let text = format!(
        "ip={}\nport={}\nusername={}\npassword={}\n",
        settings.ip, settings.port, settings.username, settings.password
    );
    let residential = parse_env(text.as_bytes())?;
    #[cfg(windows)]
    {
        windows::replace(target, residential)
    }
    #[cfg(not(windows))]
    {
        let _ = (target, residential);
        Err("Windows Credential Manager is available only on Windows".into())
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree,
        CredReadW, CredWriteW,
    };

    pub(super) fn store(mut target: Vec<u16>, mut residential: Residential) -> Result<(), String> {
        let credential = credential(&mut target, &mut residential);
        use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
        let mut existing = std::ptr::null_mut();
        if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut existing) } != 0 {
            if !existing.is_null() {
                drop(ReadCredential(existing));
            }
            return Err(
                "credential name already exists; remove it explicitly before import".into(),
            );
        }
        if unsafe { GetLastError() } != ERROR_NOT_FOUND {
            return Err("Windows Credential Manager could not check credential name".into());
        }
        write(credential)
    }

    #[cfg_attr(test, allow(dead_code))]
    pub(super) fn replace(
        mut target: Vec<u16>,
        mut residential: Residential,
    ) -> Result<(), String> {
        write(credential(&mut target, &mut residential))
    }

    fn credential<'a>(target: &'a mut [u16], residential: &'a mut Residential) -> CREDENTIALW {
        CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            CredentialBlobSize: residential.blob.0.len() as u32,
            CredentialBlob: residential.blob.0.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..Default::default()
        }
    }

    fn write(credential: CREDENTIALW) -> Result<(), String> {
        if unsafe { CredWriteW(&credential, 0) } == 0 {
            return Err("Windows Credential Manager could not store credential".into());
        }
        Ok(())
    }

    pub(super) fn remove(target: Vec<u16>) -> Result<(), String> {
        if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            return Err("Windows Credential Manager could not remove credential".into());
        }
        Ok(())
    }

    struct ReadCredential(*mut CREDENTIALW);

    impl Drop for ReadCredential {
        fn drop(&mut self) {
            unsafe {
                let credential = &mut *self.0;
                if !credential.CredentialBlob.is_null() {
                    wipe(std::slice::from_raw_parts_mut(
                        credential.CredentialBlob,
                        credential.CredentialBlobSize as usize,
                    ));
                }
                CredFree(self.0.cast());
            }
        }
    }

    pub(super) fn load(target: Vec<u16>) -> Result<Residential, String> {
        let mut pointer = std::ptr::null_mut();
        if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut pointer) } == 0 {
            return Err("Windows Credential Manager could not load credential".into());
        }
        if pointer.is_null() {
            return Err("Windows Credential Manager returned an invalid credential".into());
        }
        let owned = ReadCredential(pointer);
        let credential = unsafe { &*owned.0 };
        if credential.Type != CRED_TYPE_GENERIC
            || credential.CredentialBlob.is_null()
            || !(13..=523).contains(&credential.CredentialBlobSize)
        {
            return Err("Windows Credential Manager returned an invalid credential".into());
        }
        let blob = unsafe {
            std::slice::from_raw_parts(
                credential.CredentialBlob,
                credential.CredentialBlobSize as usize,
            )
        };
        Residential::decode(Secret(blob.to_vec()))
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
        assert!(target_name("../fixture").is_err());
    }
}
