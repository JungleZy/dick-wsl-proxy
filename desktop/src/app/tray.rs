//! Minimal Windows notification-area integration.
#![allow(unsafe_op_in_unsafe_fn)]

use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::thread;

use windows_sys::Win32::Foundation::{HWND, LPARAM, POINT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
    Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, EnumWindows, GetClassNameW, GetCursorPos, GetMessageW,
    GetWindowThreadProcessId, IDI_APPLICATION, IMAGE_ICON, LR_DEFAULTSIZE, LoadIconW, LoadImageW,
    MF_SEPARATOR, MF_STRING, PostMessageW, PostQuitMessage, RegisterClassW, SW_HIDE, SW_RESTORE,
    SetForegroundWindow, ShowWindow, TPM_LEFTALIGN, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu,
    TranslateMessage, WM_APP, WM_DESTROY, WM_LBUTTONDBLCLK, WM_RBUTTONUP, WM_TIMER, WNDCLASSW,
    WS_OVERLAPPED,
};

const TRAY_MESSAGE: u32 = WM_APP + 1;
/// Sent by a second launch: show this instance's main window instead.
const SHOW_MESSAGE: u32 = WM_APP + 2;
const TRAY_CLASS: &str = "WSLProxyLabTrayWindow";
const TRAY_TIMER: usize = 1;
const OPEN_COMMAND: usize = 1;
const REFRESH_COMMAND: usize = 2;
const START_COMMAND: usize = 3;
const STOP_COMMAND: usize = 4;
const PROBE_COMMAND: usize = 5;
const EXIT_COMMAND: usize = 6;
static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
pub(crate) enum TrayAction {
    Refresh,
    Start,
    Stop,
    Probe,
}

const ACTION_REFRESH: u8 = 1;
const ACTION_START: u8 = 2;
const ACTION_STOP: u8 = 3;
const ACTION_PROBE: u8 = 4;
static ACTION: AtomicU8 = AtomicU8::new(0);

pub(crate) fn start() {
    thread::Builder::new()
        .name("wsl-proxy-tray".into())
        .spawn(|| unsafe { run() })
        .ok();
}

pub(crate) fn consume_exit_request() -> bool {
    EXIT_REQUESTED.swap(false, Ordering::AcqRel)
}

pub(crate) fn consume_action() -> Option<TrayAction> {
    match ACTION.swap(0, Ordering::AcqRel) {
        ACTION_REFRESH => Some(TrayAction::Refresh),
        ACTION_START => Some(TrayAction::Start),
        ACTION_STOP => Some(TrayAction::Stop),
        ACTION_PROBE => Some(TrayAction::Probe),
        _ => None,
    }
}

fn request_action(action: TrayAction) {
    let value = match action {
        TrayAction::Refresh => ACTION_REFRESH,
        TrayAction::Start => ACTION_START,
        TrayAction::Stop => ACTION_STOP,
        TrayAction::Probe => ACTION_PROBE,
    };
    ACTION.store(value, Ordering::Release);
}

/// Asks the instance that already runs in this session to show its window.
/// Returns false when no such tray window exists.
pub(crate) fn activate_running_instance() -> bool {
    let class_name = wide(TRAY_CLASS);
    unsafe {
        let hwnd =
            windows_sys::Win32::UI::WindowsAndMessaging::FindWindowW(class_name.as_ptr(), null());
        !hwnd.is_null() && PostMessageW(hwnd, SHOW_MESSAGE, 0, 0) != 0
    }
}

pub(crate) fn hide_main_window() {
    unsafe {
        let hwnd = find_main_window(null_mut());
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
        SHOW_MESSAGE => {
            show_main_window();
            0
        }
        WM_TIMER => {
            if find_main_window(hwnd).is_null() {
                DestroyWindow(hwnd);
            }
            0
        }
        WM_DESTROY => {
            let data = notify_data(hwnd);
            Shell_NotifyIconW(NIM_DELETE, &data);
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, message, wparam, lparam),
    }
}

unsafe fn run() {
    let class_name = wide(TRAY_CLASS);
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
        WS_OVERLAPPED,
        class_name.as_ptr(),
        class_name.as_ptr(),
        0,
        0,
        0,
        0,
        0,
        null_mut(),
        null_mut(),
        instance,
        null(),
    );
    if hwnd.is_null() {
        return;
    }
    ShowWindow(hwnd, SW_HIDE);
    let data = notify_data(hwnd);
    if Shell_NotifyIconW(NIM_ADD, &data) == 0 {
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
    let hwnd = find_main_window(null_mut());
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
    let refresh = wide("刷新后台状态");
    let start = wide("启动接管");
    let stop = wide("停止并恢复直连");
    let probe = wide("检测公网出口");
    let exit = wide("退出");
    AppendMenuW(menu, MF_STRING, OPEN_COMMAND, open.as_ptr());
    AppendMenuW(menu, MF_STRING, REFRESH_COMMAND, refresh.as_ptr());
    AppendMenuW(menu, MF_STRING, START_COMMAND, start.as_ptr());
    AppendMenuW(menu, MF_STRING, STOP_COMMAND, stop.as_ptr());
    AppendMenuW(menu, MF_STRING, PROBE_COMMAND, probe.as_ptr());
    AppendMenuW(menu, MF_SEPARATOR, 0, null());
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
        REFRESH_COMMAND => {
            show_main_window();
            request_action(TrayAction::Refresh);
        }
        START_COMMAND => {
            show_main_window();
            request_action(TrayAction::Start);
        }
        STOP_COMMAND => {
            show_main_window();
            request_action(TrayAction::Stop);
        }
        PROBE_COMMAND => {
            show_main_window();
            request_action(TrayAction::Probe);
        }
        EXIT_COMMAND => {
            let main = find_main_window(hwnd);
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

unsafe fn find_main_window(excluded: HWND) -> HWND {
    struct Search {
        pid: u32,
        excluded: HWND,
        hwnd: HWND,
    }
    unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> i32 {
        let search = &mut *(lparam as *mut Search);
        let mut pid = 0;
        GetWindowThreadProcessId(hwnd, &mut pid);
        let mut class = [0u16; 64];
        let class_length = GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32);
        let is_tray_window = class_length > 0
            && String::from_utf16_lossy(&class[..class_length as usize]) == TRAY_CLASS;
        if pid == search.pid && hwnd != search.excluded && !is_tray_window {
            search.hwnd = hwnd;
            0
        } else {
            1
        }
    }
    let mut search = Search {
        pid: windows_sys::Win32::System::Threading::GetCurrentProcessId(),
        excluded,
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
    // Icon resource 1, as MAKEINTRESOURCEW passes it: the integer 1 in pointer
    // form, never dereferenced. (`ptr::dangling` would be 2 for `u16`.)
    let resource = std::ptr::without_provenance::<u16>(1);
    let application = GetModuleHandleW(null());
    let icon = LoadImageW(application, resource, IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
    let mut data = NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: 1,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP,
        uCallbackMessage: TRAY_MESSAGE,
        hIcon: if icon.is_null() {
            LoadIconW(null_mut(), IDI_APPLICATION)
        } else {
            icon
        },
        ..Default::default()
    };
    let tip = wide("WSL Proxy");
    let length = tip.len().min(data.szTip.len());
    data.szTip[..length].copy_from_slice(&tip[..length]);
    data
}
