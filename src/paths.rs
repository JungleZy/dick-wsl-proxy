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
/// desktop resolve the same directory.
pub fn data_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let executable = std::env::current_exe()
            .map_err(|error| format!("data_directory_unavailable:{error}"))?;
        executable
            .parent()
            .map(std::path::Path::to_path_buf)
            .ok_or_else(|| "data_directory_unavailable: executable has no parent".into())
    }
    #[cfg(not(windows))]
    {
        Err("unsupported_platform: Windows host required".into())
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
