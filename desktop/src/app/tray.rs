//! Minimal Windows notification-area integration.
#![allow(unsafe_op_in_unsafe_fn)]

use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use windows_sys::Win32::Foundation::{HWND, LPARAM, POINT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
    Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, EnumWindows, GetCursorPos, GetMessageW, GetWindowThreadProcessId,
    HWND_MESSAGE, IDI_APPLICATION, LoadIconW, MF_STRING, PostMessageW, PostQuitMessage,
    RegisterClassW, SW_RESTORE, SetForegroundWindow, ShowWindow, TPM_LEFTALIGN, TPM_RETURNCMD,
    TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, WM_APP, WM_DESTROY, WM_LBUTTONDBLCLK,
    WM_RBUTTONUP, WM_TIMER, WNDCLASSW,
};

const TRAY_MESSAGE: u32 = WM_APP + 1;
const TRAY_TIMER: usize = 1;
const OPEN_COMMAND: usize = 1;
const EXIT_COMMAND: usize = 2;
static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn start() {
    thread::Builder::new()
        .name("wsl-proxy-tray".into())
        .spawn(|| unsafe { run() })
        .ok();
}

pub(crate) fn consume_exit_request() -> bool {
    EXIT_REQUESTED.swap(false, Ordering::AcqRel)
}

pub(crate) fn hide_main_window() {
    unsafe {
        let hwnd = find_main_window();
        if !hwnd.is_null() {
            ShowWindow(hwnd, windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE);
        }
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match message {
        TRAY_MESSAGE => {
            match lparam as u32 {
                WM_LBUTTONDBLCLK => show_main_window(),
                WM_RBUTTONUP => show_menu(hwnd),
                _ => {}
            }
            0
        }
        WM_TIMER => {
            if find_main_window().is_null() {
                DestroyWindow(hwnd);
            }
            0
        }
        WM_DESTROY => {
            let mut data = notify_data(hwnd);
            Shell_NotifyIconW(NIM_DELETE, &mut data);
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, message, wparam, lparam),
    }
}

unsafe fn run() {
    let class_name = wide("WSLProxyLabTrayWindow");
    let instance = GetModuleHandleW(null());
    let class = WNDCLASSW {
        hInstance: instance,
        lpfnWndProc: Some(window_proc),
        lpszClassName: class_name.as_ptr(),
        ..Default::default()
    };
    if RegisterClassW(&class) == 0 {
        return;
    }
    let hwnd = CreateWindowExW(
        0,
        class_name.as_ptr(),
        class_name.as_ptr(),
        0,
        0,
        0,
        0,
        0,
        HWND_MESSAGE,
        null_mut(),
        instance,
        null(),
    );
    if hwnd.is_null() {
        return;
    }
    let mut data = notify_data(hwnd);
    if Shell_NotifyIconW(NIM_ADD, &mut data) == 0 {
        DestroyWindow(hwnd);
        return;
    }
    windows_sys::Win32::UI::WindowsAndMessaging::SetTimer(hwnd, TRAY_TIMER, 1000, None);
    let mut message = windows_sys::Win32::UI::WindowsAndMessaging::MSG::default();
    while GetMessageW(&mut message, null_mut(), 0, 0) > 0 {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

unsafe fn show_main_window() {
    let hwnd = find_main_window();
    if !hwnd.is_null() {
        ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
    }
}

unsafe fn show_menu(hwnd: HWND) {
    let menu = CreatePopupMenu();
    if menu.is_null() {
        return;
    }
    let open = wide("打开 WSL Proxy");
    let exit = wide("退出");
    AppendMenuW(menu, MF_STRING, OPEN_COMMAND, open.as_ptr());
    AppendMenuW(menu, MF_STRING, EXIT_COMMAND, exit.as_ptr());
    let mut point = POINT::default();
    GetCursorPos(&mut point);
    SetForegroundWindow(hwnd);
    let command = TrackPopupMenu(
        menu,
        TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD,
        point.x,
        point.y,
        0,
        hwnd,
        null(),
    );
    DestroyMenu(menu);
    PostMessageW(hwnd, 0, 0, 0);
    match command as usize {
        OPEN_COMMAND => show_main_window(),
        EXIT_COMMAND => {
            let main = find_main_window();
            if !main.is_null() {
                EXIT_REQUESTED.store(true, Ordering::Release);
                PostMessageW(
                    main,
                    windows_sys::Win32::UI::WindowsAndMessaging::WM_CLOSE,
                    0,
                    0,
                );
            }
        }
        _ => {}
    }
}

unsafe fn find_main_window() -> HWND {
    struct Search {
        pid: u32,
        hwnd: HWND,
    }
    unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> i32 {
        let search = &mut *(lparam as *mut Search);
        let mut pid = 0;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid == search.pid {
            search.hwnd = hwnd;
            0
        } else {
            1
        }
    }
    let mut search = Search {
        pid: windows_sys::Win32::System::Threading::GetCurrentProcessId(),
        hwnd: null_mut(),
    };
    EnumWindows(
        Some(callback),
        (&mut search as *mut Search).cast::<core::ffi::c_void>() as LPARAM,
    );
    search.hwnd
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

unsafe fn notify_data(hwnd: HWND) -> NOTIFYICONDATAW {
    let mut data = NOTIFYICONDATAW::default();
    data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    data.hWnd = hwnd;
    data.uID = 1;
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    data.uCallbackMessage = TRAY_MESSAGE;
    data.hIcon = LoadIconW(null_mut(), IDI_APPLICATION);
    let tip = wide("WSL Proxy");
    let length = tip.len().min(data.szTip.len());
    data.szTip[..length].copy_from_slice(&tip[..length]);
    data
}
