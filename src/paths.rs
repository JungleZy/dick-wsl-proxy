//! Per-user state directory, shared so the controller and the desktop client
//! always agree on where state files such as environment progress live.
use std::path::PathBuf;

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
