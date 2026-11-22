use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Distro {
    pub id: String,
    pub name: String,
    pub base_path: String,
    pub version: u32,
}

#[derive(Debug)]
pub struct ControllerLock {
    #[cfg(windows)]
    _file: std::fs::File,
}

#[derive(Debug)]
pub enum LockError {
    #[cfg(windows)]
    Busy,
    Other(String),
}

#[cfg(windows)]
pub use windows::{
    acquire, distributions, guest_script, guest_script_with_timeout, ipv6_scope_id, state_dir,
    wsl_command, wsl_executable,
};

#[cfg(not(windows))]
pub fn state_dir() -> Result<std::path::PathBuf, String> {
    Err("unsupported_platform: Windows host required".into())
}

#[cfg(not(windows))]
pub fn distributions() -> Result<Vec<Distro>, String> {
    Err("unsupported_platform: Windows host required".into())
}

#[cfg(not(windows))]
pub fn guest_script(_distro: &Distro, _script: &str) -> Result<String, String> {
    Err("unsupported_platform: Windows host required".into())
}

#[cfg(not(windows))]
pub fn guest_script_with_timeout(
    _distro: &Distro,
    _script: &str,
    _timeout: std::time::Duration,
) -> Result<String, String> {
    Err("unsupported_platform: Windows host required".into())
}

#[cfg(not(windows))]
pub fn wsl_command(
    _args: &[String],
    _input: Option<&[u8]>,
    _timeout: std::time::Duration,
) -> Result<String, String> {
    Err("unsupported_platform: Windows host required".into())
}

#[cfg(not(windows))]
pub fn acquire() -> Result<ControllerLock, LockError> {
    Err(LockError::Other(
        "unsupported_platform: Windows host required".into(),
    ))
}

#[cfg(not(windows))]
pub fn ipv6_scope_id(_: std::net::Ipv6Addr) -> Result<Option<u32>, String> {
    Ok(None)
}

#[cfg(any(windows, test))]
fn valid_distribution_id(id: &str) -> bool {
    let Some(id) = id.strip_prefix('{').and_then(|id| id.strip_suffix('}')) else {
        return false;
    };
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(windows)]
mod windows {
    use super::{ControllerLock, Distro, LockError, valid_distribution_id};
    use std::ffi::OsString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read, Seek, Write};
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::ptr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath};
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WOW64_64KEY};

    const GUEST_DEADLINE: Duration = Duration::from_secs(30);
    const OUTPUT_LIMIT: usize = 1024 * 1024;

    pub fn distributions() -> Result<Vec<Distro>, String> {
        let root = match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Lxss",
            KEY_READ | KEY_WOW64_64KEY,
        ) {
            Ok(key) => key,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("registry_open_failed: {error}")),
        };
        let mut distros = Vec::new();
        for id in root.enum_keys() {
            let id = id.map_err(|error| format!("registry_enumeration_failed: {error}"))?;
            if !valid_distribution_id(&id) {
                return Err(format!("registry_invalid_distribution_id: {id}"));
            }
            let key = root
                .open_subkey_with_flags(&id, KEY_READ | KEY_WOW64_64KEY)
                .map_err(|error| format!("registry_distribution_open_failed: {id}: {error}"))?;
            let name = registry_string(&key, "DistributionName", &id)?;
            let base_path = registry_string(&key, "BasePath", &id)?;
            let version = key
                .get_value("Version")
                .map_err(|error| format!("registry_version_read_failed: {id}: {error}"))?;
            if name.is_empty() || base_path.is_empty() {
                return Err(format!("registry_distribution_incomplete: {id}"));
            }
            distros.push(Distro {
                id,
                name,
                base_path,
                version,
            });
        }
        distros.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(distros)
    }

    fn registry_string(key: &RegKey, value: &str, id: &str) -> Result<String, String> {
        let value: OsString = key
            .get_value(value)
            .map_err(|error| format!("registry_value_read_failed: {id}: {value}: {error}"))?;
        value
            .into_string()
            .map_err(|_| format!("registry_invalid_unicode: {id}"))
    }

    pub fn wsl_executable() -> Result<PathBuf, String> {
        Ok(system_directory()?.join("wsl.exe"))
    }

    fn system_directory() -> Result<PathBuf, String> {
        let mut buffer = vec![0u16; 260];
        loop {
            // The initialized buffer is writable for the length passed to Windows.
            let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
            if length == 0 {
                return Err(format!(
                    "system_directory_failed: {}",
                    io::Error::last_os_error()
                ));
            }
            if (length as usize) < buffer.len() {
                return Ok(PathBuf::from(OsString::from_wide(
                    &buffer[..length as usize],
                )));
            }
            if length > 32768 {
                return Err("system_directory_invalid_length".into());
            }
            buffer.resize(length as usize + 1, 0);
        }
    }

    struct GuestChild(Child);

    impl Drop for GuestChild {
        fn drop(&mut self) {
            // Windows closes the process handles on drop; do not block past the deadline.
            let _ = self.0.kill();
        }
    }

    // File-backed standard handles avoid WSL interop pipe forwarding stalls. No guest path
    // or shell argument refers to these files. Even on a crash the OS removes them on close.
    fn scratch() -> io::Result<File> {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_DELETE_ON_CLOSE,
        };
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = state_dir().map_err(io::Error::other)?;
        let path = dir.join(format!(
            "io-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .attributes(FILE_ATTRIBUTE_TEMPORARY)
            .custom_flags(FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    fn capture(mut file: File) -> Result<String, String> {
        file.rewind().map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        file.take((OUTPUT_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > OUTPUT_LIMIT {
            return Err("wsl_output_limit_exceeded".into());
        }
        String::from_utf8(bytes).map_err(|_| "wsl_output_invalid_utf8".into())
    }

    fn run_wsl_process(
        args: &[String],
        input_bytes: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<String, String> {
        if cfg!(target_pointer_width = "32") {
            return Err("unsupported_windows_architecture: 64-bit controller required".into());
        }
        let directory = system_directory()?;
        let mut input = input_bytes
            .map(|bytes| {
                let mut file = scratch().map_err(|e| e.to_string())?;
                file.write_all(bytes)
                    .and_then(|_| file.rewind())
                    .map_err(|e| e.to_string())?;
                Ok::<File, String>(file)
            })
            .transpose()?;
        let stdout = scratch().map_err(|e| e.to_string())?;
        let stderr = scratch().map_err(|e| e.to_string())?;
        let stdin = input
            .as_ref()
            .map(|file| file.try_clone().map(Stdio::from).map_err(|e| e.to_string()))
            .transpose()?
            .unwrap_or_else(Stdio::null);
        let mut child = GuestChild(
            Command::new(directory.join("wsl.exe"))
                .current_dir(&directory)
                .args(args)
                .env("WSL_UTF8", "1")
                .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
                .stdin(stdin)
                .stdout(stdout.try_clone().map_err(|e| e.to_string())?)
                .stderr(stderr.try_clone().map_err(|e| e.to_string())?)
                .spawn()
                .map_err(|error| format!("wsl_start_failed: {error}"))?,
        );
        // Keep the backing file alive until the child has consumed its stdin.
        let _input = input.take();
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child
                .0
                .try_wait()
                .map_err(|error| format!("wsl_wait_failed: {error}"))?
            {
                break status;
            }
            for f in [&stdout, &stderr] {
                if f.metadata().map_err(|e| e.to_string())?.len() > OUTPUT_LIMIT as u64 {
                    return Err("wsl_output_limit_exceeded".into());
                }
            }
            let remaining = timeout
                .checked_sub(start.elapsed())
                .ok_or("wsl_deadline_exceeded")?;
            thread::sleep(remaining.min(Duration::from_millis(20)));
        };
        let stdout = capture(stdout)?;
        let stderr = capture(stderr)?;
        if !status.success() {
            let detail = if stderr.trim().is_empty() {
                &stdout
            } else {
                &stderr
            };
            return Err(format!("wsl_exit_failed: {status}: {}", detail.trim()));
        }
        Ok(stdout)
    }

    pub fn wsl_command(
        args: &[String],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<String, String> {
        run_wsl_process(args, input, timeout)
    }

    pub fn guest_script(distro: &Distro, script: &str) -> Result<String, String> {
        guest_script_with_timeout(distro, script, GUEST_DEADLINE)
    }

    pub fn guest_script_with_timeout(
        distro: &Distro,
        script: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        if !valid_distribution_id(&distro.id) {
            return Err("invalid_distribution_id".into());
        }
        let args = vec![
            "--distribution-id".into(),
            distro.id.clone(),
            "--cd".into(),
            "/".into(),
            "--user".into(),
            "root".into(),
            "--exec".into(),
            "/bin/sh".into(),
            "-s".into(),
        ];
        run_wsl_process(&args, Some(script.as_bytes()), timeout)
    }

    fn local_app_data() -> Result<PathBuf, String> {
        let mut path = ptr::null_mut();
        // A null token selects this user's OS-known folder, never an environment path.
        let result =
            unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, ptr::null_mut(), &mut path) };
        if result < 0 || path.is_null() {
            if !path.is_null() {
                unsafe { CoTaskMemFree(path.cast()) };
            }
            return Err(format!("lock_known_folder_failed: HRESULT {result:#x}"));
        }
        // SHGetKnownFolderPath returns a NUL-terminated allocation owned by this call.
        let directory = unsafe {
            let mut length = 0;
            while *path.add(length) != 0 {
                length += 1;
            }
            PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(
                path, length,
            )))
        };
        unsafe { CoTaskMemFree(path.cast()) };
        Ok(directory)
    }

    pub fn state_dir() -> Result<PathBuf, String> {
        Ok(local_app_data()?.join("WSLProxyLab"))
    }

    pub fn ipv6_scope_id(address: std::net::Ipv6Addr) -> Result<Option<u32>, String> {
        use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterfaceEx;
        use windows_sys::Win32::Networking::WinSock::{
            AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6,
        };

        let destination = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: address.octets(),
                },
            },
            ..Default::default()
        };
        let mut index = 0;
        let result =
            unsafe { GetBestInterfaceEx((&destination as *const SOCKADDR_IN6).cast(), &mut index) };
        if result != 0 {
            return Err(format!("ipv6_scope_lookup_failed:{result}"));
        }
        Ok((index != 0).then_some(index))
    }

    pub fn acquire() -> Result<ControllerLock, LockError> {
        let directory = state_dir().map_err(LockError::Other)?;
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(LockError::Other(format!("lock_directory_failed: {error}")));
            }
        }
        let metadata = fs::symlink_metadata(&directory).map_err(|error| {
            LockError::Other(format!("lock_directory_metadata_failed: {error}"))
        })?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(LockError::Other("lock_directory_not_regular".into()));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(directory.join("controller.lock"))
            .map_err(|error| {
                if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) {
                    LockError::Busy
                } else {
                    LockError::Other(format!("lock_open_failed: {error}"))
                }
            })?;
        let metadata = file
            .metadata()
            .map_err(|error| LockError::Other(format!("lock_file_metadata_failed: {error}")))?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(LockError::Other("lock_file_not_regular".into()));
        }
        Ok(ControllerLock { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::valid_distribution_id;

    #[test]
    fn accepts_only_registry_guid_ids() {
        assert!(valid_distribution_id(
            "{01234567-89ab-CDEF-0123-456789abcdef}"
        ));
        for invalid in [
            "WSLProxyLab-Target",
            "01234567-89ab-cdef-0123-456789abcdef",
            "{01234567_89ab-cdef-0123-456789abcdef}",
            "{01234567-89ab-cdef-0123-456789abcdeg}",
            "{01234567-89ab-cdef-0123-456789abcdef} --exec anything",
        ] {
            assert!(!valid_distribution_id(invalid));
        }
    }
}
