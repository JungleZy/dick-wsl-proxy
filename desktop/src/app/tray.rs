//! Minimal Windows notification-area integration.
//!
//! The tray window lives as long as the main window, even while the icon cannot
//! be shown: a second launch finds it by class name to bring the main window
//! back, and it retries the icon on every timer tick and whenever Explorer
//! announces a new taskbar. Closing the main window hides it only while the
//! icon is shown ([`ready`]).

use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::thread;

use windows_sys::Win32::Foundation::{HWND, LPARAM, POINT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
    Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, ChangeWindowMessageFilterEx, CreatePopupMenu, CreateWindowExW, DefWindowProcW,
    DestroyMenu, DestroyWindow, DispatchMessageW, EnumWindows, FindWindowW, GetClassNameW,
    GetCursorPos, GetMessageW, GetWindowThreadProcessId, IDI_APPLICATION, IMAGE_ICON,
    LR_DEFAULTSIZE, LR_SHARED, LoadIconW, LoadImageW, MF_SEPARATOR, MF_STRING, MSG, MSGFLT_ALLOW,
    PostMessageW, PostQuitMessage, RegisterClassW, RegisterWindowMessageW, SW_HIDE, SW_RESTORE,
    SetForegroundWindow, SetTimer, ShowWindow, TPM_LEFTALIGN, TPM_RETURNCMD, TPM_RIGHTBUTTON,
    TrackPopupMenu, TranslateMessage, WM_APP, WM_CLOSE, WM_DESTROY, WM_LBUTTONDBLCLK, WM_NULL,
    WM_RBUTTONUP, WM_TIMER, WNDCLASSW, WS_OVERLAPPED,
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
/// Whether the notification icon is shown right now.
static TRAY_READY: AtomicBool = AtomicBool::new(false);
/// The `TaskbarCreated` message, 0 until [`run`] registers it.
static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
pub(crate) enum TrayAction {
    Refresh,
    Start,
    Stop,
    Probe,
    /// 退出程序：界面先让后台恢复空闲并关闭，再调用 [`quit_application`]。
    Exit,
}

const ACTION_REFRESH: u8 = 1;
const ACTION_START: u8 = 2;
const ACTION_STOP: u8 = 3;
const ACTION_PROBE: u8 = 4;
const ACTION_EXIT: u8 = 5;
static ACTION: AtomicU8 = AtomicU8::new(0);

pub(crate) fn start() {
    thread::Builder::new()
        .name("wsl-proxy-tray".into())
        .spawn(run)
        .ok();
}

/// 托盘图标正在显示。只有这时关窗才能把主窗口藏起来，否则藏起来就没有入口找回。
pub(crate) fn ready() -> bool {
    TRAY_READY.load(Ordering::Acquire)
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
        ACTION_EXIT => Some(TrayAction::Exit),
        _ => None,
    }
}

/// 后台已经关闭后才调用：让主窗口的关闭流程放行，GPUI 在最后一个窗口关闭后退出进程。
/// 找不到主窗口时返回 false，由调用方直接退出应用。
pub(crate) fn quit_application() -> bool {
    let main = find_main_window(null_mut());
    if main.is_null() {
        return false;
    }
    EXIT_REQUESTED.store(true, Ordering::Release);
    // SAFETY: PostMessageW only queues the message; a stale handle makes it fail.
    unsafe { PostMessageW(main, WM_CLOSE, 0, 0) != 0 }
}

fn request_action(action: TrayAction) {
    let value = match action {
        TrayAction::Refresh => ACTION_REFRESH,
        TrayAction::Start => ACTION_START,
        TrayAction::Stop => ACTION_STOP,
        TrayAction::Probe => ACTION_PROBE,
        TrayAction::Exit => ACTION_EXIT,
    };
    ACTION.store(value, Ordering::Release);
}

/// Asks the instance that already runs in this session to show its window.
/// Returns false when no such tray window exists.
pub(crate) fn activate_running_instance() -> bool {
    let class_name = wide(TRAY_CLASS);
    // SAFETY: `class_name` is NUL-terminated and outlives the call; a null
    // window name matches any title.
    let hwnd = unsafe { FindWindowW(class_name.as_ptr(), null()) };
    // SAFETY: PostMessageW only queues the message; a stale handle makes it fail.
    !hwnd.is_null() && unsafe { PostMessageW(hwnd, SHOW_MESSAGE, 0, 0) } != 0
}

pub(crate) fn hide_main_window() {
    let hwnd = find_main_window(null_mut());
    if !hwnd.is_null() {
        // SAFETY: the handle is only a lookup key; a destroyed window makes the
        // call fail.
        unsafe { ShowWindow(hwnd, SW_HIDE) };
    }
}

/// # Safety
///
/// Called only by the system, as the window procedure of [`TRAY_CLASS`].
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
                // SAFETY: `hwnd` is the live tray window owned by this thread.
                unsafe { DestroyWindow(hwnd) };
            } else if !ready() {
                add_icon(hwnd);
            }
            0
        }
        WM_DESTROY => {
            TRAY_READY.store(false, Ordering::Release);
            let data = notify_data(hwnd);
            // SAFETY: `data` is a fully initialised NOTIFYICONDATAW that outlives
            // the call; deleting an icon that was never added only fails.
            unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
            // SAFETY: posts WM_QUIT to this thread's own message queue.
            unsafe { PostQuitMessage(0) };
            0
        }
        // Explorer restarted, and its new taskbar has none of the old icons.
        _ if message != 0 && message == TASKBAR_CREATED.load(Ordering::Acquire) => {
            TRAY_READY.store(false, Ordering::Release);
            add_icon(hwnd);
            0
        }
        // SAFETY: forwards this procedure's own arguments unchanged.
        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

fn run() {
    let class_name = wide(TRAY_CLASS);
    // SAFETY: a null name asks for this executable's own module handle.
    let instance = unsafe { GetModuleHandleW(null()) };
    let class = WNDCLASSW {
        hInstance: instance,
        lpfnWndProc: Some(window_proc),
        lpszClassName: class_name.as_ptr(),
        ..Default::default()
    };
    // SAFETY: `class` and the name it points to outlive the call.
    if unsafe { RegisterClassW(&class) } == 0 {
        return;
    }
    // SAFETY: the class is registered above, both names are NUL-terminated and
    // outlive the call, and every other argument is a plain value or null.
    let hwnd = unsafe {
        CreateWindowExW(
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
        )
    };
    if hwnd.is_null() {
        return;
    }
    // SAFETY: `hwnd` is the live window just created on this thread.
    unsafe { ShowWindow(hwnd, SW_HIDE) };
    let taskbar_created = wide("TaskbarCreated");
    // SAFETY: the name is NUL-terminated and outlives the call.
    let taskbar_created = unsafe { RegisterWindowMessageW(taskbar_created.as_ptr()) };
    if taskbar_created != 0 {
        TASKBAR_CREATED.store(taskbar_created, Ordering::Release);
        // When run elevated, UIPI would otherwise drop Explorer's broadcast.
        // SAFETY: `hwnd` is live and the optional out-parameter may be null.
        unsafe { ChangeWindowMessageFilterEx(hwnd, taskbar_created, MSGFLT_ALLOW, null_mut()) };
    }
    // A failed icon keeps the window: a second launch still finds it, and the
    // timer and `TaskbarCreated` try the icon again.
    add_icon(hwnd);
    // SAFETY: `hwnd` is live; without a callback the ticks arrive as WM_TIMER.
    unsafe { SetTimer(hwnd, TRAY_TIMER, 1000, None) };
    let mut message = MSG::default();
    // SAFETY: `message` is a live MSG that GetMessageW fills and the other two
    // calls only read.
    while unsafe { GetMessageW(&mut message, null_mut(), 0, 0) } > 0 {
        // SAFETY: as above.
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

/// Shows the notification icon and records whether it is shown.
fn add_icon(hwnd: HWND) {
    let data = notify_data(hwnd);
    // SAFETY: `data` is a fully initialised NOTIFYICONDATAW that outlives both
    // calls. NIM_ADD can report a timeout although a busy Explorer added the
    // icon; NIM_MODIFY then succeeds only if the icon exists.
    let shown = unsafe {
        Shell_NotifyIconW(NIM_ADD, &data) != 0 || Shell_NotifyIconW(NIM_MODIFY, &data) != 0
    };
    TRAY_READY.store(shown, Ordering::Release);
}

fn show_main_window() {
    let hwnd = find_main_window(null_mut());
    if !hwnd.is_null() {
        // SAFETY: the handle is only a lookup key; a destroyed window makes the
        // calls fail.
        unsafe {
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        }
    }
}

fn show_menu(hwnd: HWND) {
    // SAFETY: takes no arguments; a null menu is handled below.
    let menu = unsafe { CreatePopupMenu() };
    if menu.is_null() {
        return;
    }
    let open = wide("打开 WSL Proxy");
    let refresh = wide("刷新后台状态");
    let start = wide("启动接管");
    let stop = wide("停止并恢复直连");
    let probe = wide("检测公网出口");
    let exit = wide("退出");
    let mut point = POINT::default();
    // SAFETY: `menu` stays live until DestroyMenu after TrackPopupMenu returns;
    // every label is NUL-terminated and outlives the calls; `point` is writable;
    // `hwnd` is the tray window owned by this thread.
    let command = unsafe {
        AppendMenuW(menu, MF_STRING, OPEN_COMMAND, open.as_ptr());
        AppendMenuW(menu, MF_STRING, REFRESH_COMMAND, refresh.as_ptr());
        AppendMenuW(menu, MF_STRING, START_COMMAND, start.as_ptr());
        AppendMenuW(menu, MF_STRING, STOP_COMMAND, stop.as_ptr());
        AppendMenuW(menu, MF_STRING, PROBE_COMMAND, probe.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
        AppendMenuW(menu, MF_STRING, EXIT_COMMAND, exit.as_ptr());
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
        // The documented follow-up so a notification-icon menu closes properly.
        PostMessageW(hwnd, WM_NULL, 0, 0);
        command
    };
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
        // 不直接关窗：后台要先停止接管、关闭，界面确认后才真正退出。
        EXIT_COMMAND => {
            show_main_window();
            request_action(TrayAction::Exit);
        }
        _ => {}
    }
}

fn find_main_window(excluded: HWND) -> HWND {
    struct Search {
        pid: u32,
        excluded: HWND,
        hwnd: HWND,
    }
    /// # Safety
    ///
    /// `lparam` must be the `*mut Search` that `EnumWindows` below passes on.
    unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> i32 {
        // SAFETY: EnumWindows hands back the pointer to `search` below, which
        // outlives the enumeration and has no other borrow during it.
        let search = unsafe { &mut *(lparam as *mut Search) };
        let mut pid = 0;
        let mut class = [0u16; 64];
        // SAFETY: `hwnd` comes from the enumeration; `pid` and `class` are
        // writable and `class.len()` bounds the name.
        let class_length = unsafe {
            GetWindowThreadProcessId(hwnd, &mut pid);
            GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32)
        };
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
        pid: std::process::id(),
        excluded,
        hwnd: null_mut(),
    };
    // SAFETY: `callback` only touches the `Search` passed here, which outlives
    // the call.
    unsafe { EnumWindows(Some(callback), (&raw mut search) as LPARAM) };
    search.hwnd
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn notify_data(hwnd: HWND) -> NOTIFYICONDATAW {
    // Icon resource 1, as MAKEINTRESOURCEW passes it: the integer 1 in pointer
    // form, never dereferenced. (`ptr::dangling` would be 2 for `u16`.)
    let resource = std::ptr::without_provenance::<u16>(1);
    // SAFETY: a null name is this executable's module, and the resource is read
    // by its integer ID. LR_SHARED leaves the handle to the system, so retries
    // do not leak an icon each time.
    let icon = unsafe {
        LoadImageW(
            GetModuleHandleW(null()),
            resource,
            IMAGE_ICON,
            0,
            0,
            LR_DEFAULTSIZE | LR_SHARED,
        )
    };
    let icon = if icon.is_null() {
        // SAFETY: IDI_APPLICATION is a predefined system icon, loaded with a null
        // module.
        unsafe { LoadIconW(null_mut(), IDI_APPLICATION) }
    } else {
        icon
    };
    let mut data = NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: 1,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP,
        uCallbackMessage: TRAY_MESSAGE,
        hIcon: icon,
        ..Default::default()
    };
    let tip = wide("WSL Proxy");
    let length = tip.len().min(data.szTip.len());
    data.szTip[..length].copy_from_slice(&tip[..length]);
    data
}
