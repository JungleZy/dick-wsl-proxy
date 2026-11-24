//! Where the controller and the desktop client keep their files. Both resolve
//! through this module so they always agree on the same location.
use std::path::PathBuf;

/// Per-user account state: the controller lock, the takeover recovery records
/// and the DNS alias ledger. These guard one controller per Windows account
/// and must outlive any single program folder, so they stay in
/// `<LocalAppData>\WSLProxyLab`, resolved through the OS known-folder API,
/// never through the `LOCALAPPDATA` environment variable.
pub fn state_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        Ok(windows::local_app_data()?.join("WSLProxyLab"))
    }
    #[cfg(not(windows))]
    {
        Err("unsupported_platform: Windows host required".into())
    }
}

/// Runtime data the program produces (the desktop store, environment progress,
/// diagnostics exports and scratch files) lives in the directory of the running
/// EXE. The two EXEs always ship side by side, so the controller and the
/// desktop resolve the same directory, spelled the same way.
pub fn data_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let executable = std::env::current_exe()
            .map_err(|error| format!("data_directory_unavailable:{error}"))?;
        executable
            .parent()
            .map(|directory| without_verbatim_prefix(directory.to_path_buf()))
            .ok_or_else(|| "data_directory_unavailable: executable has no parent".into())
    }
    #[cfg(not(windows))]
    {
        Err("unsupported_platform: Windows host required".into())
    }
}

/// Drops the `\\?\` prefix from a drive path such as `\\?\D:\apps\wsl-proxy`.
/// The desktop starts the controller through a canonicalized path, which carries
/// the prefix, and the controller's `current_exe` then returns it as well; every
/// path the program shows or hands to other tools derives from that directory.
/// UNC forms, paths that would exceed `MAX_PATH` without the prefix, and paths
/// whose components end in a dot or space (which the prefix keeps literal) are
/// returned unchanged.
#[cfg_attr(not(windows), allow(dead_code))]
fn without_verbatim_prefix(path: PathBuf) -> PathBuf {
    const MAX_PATH: usize = 260;
    let Some(rest) = path.to_str().and_then(|text| text.strip_prefix(r"\\?\")) else {
        return path;
    };
    let drive = rest.as_bytes();
    let is_drive =
        drive.len() >= 3 && drive[0].is_ascii_alphabetic() && drive[1] == b':' && drive[2] == b'\\';
    let literal_only = rest
        .split('\\')
        .skip(1)
        .any(|component| component.ends_with('.') || component.ends_with(' '));
    if is_drive && rest.encode_utf16().count() < MAX_PATH && !literal_only {
        PathBuf::from(rest)
    } else {
        path
    }
}

#[cfg(test)]
mod tests {
    use super::without_verbatim_prefix;
    use std::path::PathBuf;

    #[test]
    fn a_verbatim_drive_path_loses_only_its_prefix() {
        let cases = [
            (r"\\?\D:\workspace\wsl-proxy", r"D:\workspace\wsl-proxy"),
            (
                r"\\?\c:\Program Files\WSL Proxy",
                r"c:\Program Files\WSL Proxy",
            ),
            (r"D:\already\plain", r"D:\already\plain"),
            // UNC shares and literal-only names keep the prefix that makes them work.
            (r"\\?\UNC\server\share\app", r"\\?\UNC\server\share\app"),
            (r"\\?\D:\odd\name.", r"\\?\D:\odd\name."),
            (r"\\?\D:\odd\name \app", r"\\?\D:\odd\name \app"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                without_verbatim_prefix(PathBuf::from(input)),
                PathBuf::from(expected),
                "{input}"
            );
        }
        let long = format!(r"\\?\D:\{}", "a".repeat(300));
        assert_eq!(
            without_verbatim_prefix(PathBuf::from(&long)),
            PathBuf::from(long)
        );
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::ptr;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath};

    pub(super) fn local_app_data() -> Result<PathBuf, String> {
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
}
