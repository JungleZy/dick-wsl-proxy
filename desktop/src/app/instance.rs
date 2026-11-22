//! Windows desktop single-instance guard.

use std::ptr::null;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::CreateMutexW;

pub(crate) struct Guard(HANDLE);

impl Drop for Guard {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub(crate) fn acquire() -> Option<Guard> {
    let name: Vec<u16> = "Local\\WSLProxyLabDesktop\0".encode_utf16().collect();
    let handle = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return None;
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe { CloseHandle(handle) };
        None
    } else {
        Some(Guard(handle))
    }
}
