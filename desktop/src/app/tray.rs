//! Windows notification-area integration.
//!
//! The tray window lives as long as the main window, even while the icon cannot
//! be shown: a second launch finds it by class name to bring the main window
//! back, and it retries the icon on every timer tick and whenever Explorer
//! announces a new taskbar. Closing the main window hides it only while the
//! icon is shown ([`ready`]).
//!
//! The interface thread publishes a [`Snapshot`] of the takeover state on every
//! tick ([`publish`]); the tray thread draws the icon, tip and menu from it. The
//! icon is drawn at the notification area's own size ([`icon`]) and animates
//! only while a managed takeover runs.

mod icon;
mod model;

use std::cell::RefCell;
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread;

use windows_sys::Win32::Foundation::{HWND, LPARAM, POINT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BI_BITFIELDS, BITMAPINFO, BITMAPV5HEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS,
    DeleteObject,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
    Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, ChangeWindowMessageFilterEx, CreateIconIndirect, CreatePopupMenu, CreateWindowExW,
    DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow, DispatchMessageW, EnumWindows,
    FindWindowW, GetClassNameW, GetCursorPos, GetMessageW, GetSystemMetrics,
    GetWindowThreadProcessId, HICON, ICONINFO, IDI_APPLICATION, IMAGE_ICON, KillTimer,
    LR_DEFAULTSIZE, LR_SHARED, LoadIconW, LoadImageW, MF_CHECKED, MF_GRAYED, MF_SEPARATOR,
    MF_STRING, MSG, MSGFLT_ALLOW, PostMessageW, PostQuitMessage, RegisterClassW,
    RegisterWindowMessageW, SM_CXSMICON, SW_HIDE, SW_RESTORE, SetForegroundWindow,
    SetMenuDefaultItem, SetTimer, ShowWindow, TPM_LEFTALIGN, TPM_RETURNCMD, TPM_RIGHTBUTTON,
    TrackPopupMenu, TranslateMessage, WM_APP, WM_CLOSE, WM_DESTROY, WM_LBUTTONDBLCLK, WM_LBUTTONUP,
    WM_NULL, WM_RBUTTONUP, WM_TIMER, WNDCLASSW, WS_OVERLAPPED,
};

pub(crate) use model::{Command, Look, Primary, Snapshot};

use self::icon::{Line, SWEEP_FRAMES, Shine};
use self::model::Entry;
use super::theme::{STATUS_ERROR, STATUS_OK, STATUS_WARN, TRAY_IDLE};

const TRAY_MESSAGE: u32 = WM_APP + 1;
/// Sent by a second launch: show this instance's main window instead.
const SHOW_MESSAGE: u32 = WM_APP + 2;
/// Sent by [`publish`]: the snapshot changed, redraw the icon and tip.
const SNAPSHOT_MESSAGE: u32 = WM_APP + 3;
const TRAY_CLASS: &str = "WSLProxyLabTrayWindow";
const TRAY_TIMER: usize = 1;
/// Runs only while the icon animates.
const ANIMATION_TIMER: usize = 2;
/// About nine frames a second: one sweep of [`SWEEP_FRAMES`] takes 1.8 s.
const FRAME_INTERVAL_MS: u32 = 110;
static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);
/// Whether the notification icon is shown right now.
static TRAY_READY: AtomicBool = AtomicBool::new(false);
/// The `TaskbarCreated` message, 0 until [`run`] registers it.
static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);
/// The tray window, null until [`run`] creates it and after it is destroyed.
static TRAY_WINDOW: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
/// What the interface last published.
static SNAPSHOT: Mutex<Snapshot> = Mutex::new(Snapshot::INITIAL);
/// The menu command the interface has yet to carry out.
static ACTION: Mutex<Option<Command>> = Mutex::new(None);

thread_local! {
    /// State of the tray thread. Borrows never span a call that can dispatch
    /// messages (the menu's modal loop does), so the window procedure cannot
    /// find it borrowed.
    static TRAY: RefCell<Tray> = const {
        RefCell::new(Tray {
            icons: None,
            frame: 0,
            animating: false,
        })
    };
}

struct Tray {
    icons: Option<Icons>,
    frame: usize,
    animating: bool,
}

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

/// 界面每次刷新都调用；和上次一样时什么都不做，变了才让托盘重画图标和提示。
pub(crate) fn publish(snapshot: Snapshot) {
    {
        let mut current = SNAPSHOT.lock().unwrap_or_else(PoisonError::into_inner);
        if *current == snapshot {
            return;
        }
        *current = snapshot;
    }
    let hwnd = TRAY_WINDOW.load(Ordering::Acquire);
    if !hwnd.is_null() {
        // SAFETY: PostMessageW only queues the message; a stale handle makes it fail.
        unsafe { PostMessageW(hwnd, SNAPSHOT_MESSAGE, 0, 0) };
    }
}

fn snapshot() -> Snapshot {
    SNAPSHOT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

pub(crate) fn consume_exit_request() -> bool {
    EXIT_REQUESTED.swap(false, Ordering::AcqRel)
}

/// 托盘菜单点过、界面还没处理的命令。[`Command::Open`] 由托盘自己处理，不会出现在这里。
pub(crate) fn consume_action() -> Option<Command> {
    ACTION.lock().unwrap_or_else(PoisonError::into_inner).take()
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

fn request_action(command: Command) {
    *ACTION.lock().unwrap_or_else(PoisonError::into_inner) = Some(command);
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
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => show_main_window(),
                WM_RBUTTONUP => show_menu(hwnd),
                _ => {}
            }
            0
        }
        SHOW_MESSAGE => {
            show_main_window();
            0
        }
        SNAPSHOT_MESSAGE => {
            sync_animation(hwnd);
            update_icon(hwnd, true);
            0
        }
        WM_TIMER if wparam == ANIMATION_TIMER => {
            TRAY.with(|tray| {
                if let Ok(mut tray) = tray.try_borrow_mut() {
                    tray.frame = (tray.frame + 1) % SWEEP_FRAMES;
                }
            });
            update_icon(hwnd, false);
            0
        }
        WM_TIMER => {
            if find_main_window(hwnd).is_null() {
                // SAFETY: `hwnd` is the live tray window owned by this thread.
                unsafe { DestroyWindow(hwnd) };
            } else if !ready() {
                add_icon(hwnd);
            } else if icon_size_changed() {
                // The display scale changed: draw the icon again at the new size.
                update_icon(hwnd, true);
            }
            0
        }
        WM_DESTROY => {
            TRAY_WINDOW.store(null_mut(), Ordering::Release);
            TRAY_READY.store(false, Ordering::Release);
            // SAFETY: `hwnd` is the live tray window; killing a timer that is not
            // running only fails.
            unsafe {
                KillTimer(hwnd, TRAY_TIMER);
                KillTimer(hwnd, ANIMATION_TIMER);
            }
            let data = notify_data(hwnd);
            // SAFETY: `data` is a fully initialised NOTIFYICONDATAW that outlives
            // the call; deleting an icon that was never added only fails.
            unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
            // The icon is gone from the taskbar, so its images can go too.
            TRAY.with(|tray| {
                if let Ok(mut tray) = tray.try_borrow_mut() {
                    tray.icons = None;
                }
            });
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
    TRAY_WINDOW.store(hwnd, Ordering::Release);
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
    sync_animation(hwnd);
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

/// Redraws the shown icon, and its tip when `tip` is set. A failure leaves
/// [`TRAY_READY`] alone: the icon may still be there, and when Explorer lost it,
/// `TaskbarCreated` adds it again.
fn update_icon(hwnd: HWND, tip: bool) {
    if !ready() {
        return;
    }
    let mut data = notify_data(hwnd);
    if !tip {
        data.uFlags = NIF_ICON;
    }
    // SAFETY: `data` is a fully initialised NOTIFYICONDATAW that outlives the call.
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
}

/// Starts the frame timer when the snapshot asks for animation and stops it
/// otherwise; each animation starts from its first frame.
fn sync_animation(hwnd: HWND) {
    let animate = snapshot().look.animated();
    let changed = TRAY.with(|tray| {
        let Ok(mut tray) = tray.try_borrow_mut() else {
            return false;
        };
        if tray.animating == animate {
            return false;
        }
        tray.animating = animate;
        tray.frame = 0;
        true
    });
    if !changed {
        return;
    }
    // SAFETY: `hwnd` is the live tray window owned by this thread; killing a
    // timer that is not running only fails.
    unsafe {
        if animate {
            SetTimer(hwnd, ANIMATION_TIMER, FRAME_INTERVAL_MS, None);
        } else {
            KillTimer(hwnd, ANIMATION_TIMER);
        }
    }
}

pub(crate) fn show_main_window() {
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
    let entries = model::menu(&snapshot());
    // SAFETY: takes no arguments; a null menu is handled below.
    let menu = unsafe { CreatePopupMenu() };
    if menu.is_null() {
        return;
    }
    // Every label lives until DestroyMenu below.
    let mut labels = Vec::with_capacity(entries.len());
    for entry in &entries {
        let (flags, id, label) = match entry {
            // `&` would underline the next character instead of showing itself.
            Entry::Text(text) => (MF_STRING | MF_GRAYED, 0, Some(text.replace('&', "&&"))),
            Entry::Separator => (MF_SEPARATOR, 0, None),
            Entry::Item {
                command,
                label,
                enabled,
                checked,
                ..
            } => {
                let mut flags = MF_STRING;
                if !enabled {
                    flags |= MF_GRAYED;
                }
                if *checked {
                    flags |= MF_CHECKED;
                }
                (flags, command.id(), Some((*label).to_owned()))
            }
        };
        let label = label.map(|label| wide(&label));
        let pointer = label.as_ref().map_or(null(), |label| label.as_ptr());
        // SAFETY: `menu` is live; the label is NUL-terminated and kept in
        // `labels` until the menu is destroyed.
        unsafe { AppendMenuW(menu, flags, id, pointer) };
        labels.extend(label);
        if let Entry::Item {
            command,
            default: true,
            ..
        } = entry
        {
            // SAFETY: `menu` is live and the item was just appended by command ID.
            unsafe { SetMenuDefaultItem(menu, command.id() as u32, 0) };
        }
    }
    let mut point = POINT::default();
    // SAFETY: `menu` stays live until DestroyMenu after TrackPopupMenu returns;
    // `point` is writable; `hwnd` is the tray window owned by this thread.
    let chosen = unsafe {
        GetCursorPos(&mut point);
        SetForegroundWindow(hwnd);
        let chosen = TrackPopupMenu(
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
        chosen
    };
    drop(labels);
    match Command::from_id(chosen as usize) {
        None => {}
        Some(Command::Open) => show_main_window(),
        // 勾选即生效，不用打开窗口；失败时界面会把窗口叫出来说明原因。
        Some(Command::Autostart) => request_action(Command::Autostart),
        // 其余命令要在窗口里确认或显示结果。退出也不直接关窗：
        // 后台要先停止接管、关闭，界面确认后才真正退出。
        Some(command) => {
            show_main_window();
            request_action(command);
        }
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
    let snapshot = snapshot();
    let mut data = NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: 1,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP,
        uCallbackMessage: TRAY_MESSAGE,
        hIcon: current_icon(snapshot.look),
        ..Default::default()
    };
    model::fill_wide(&mut data.szTip, &snapshot.tooltip());
    data
}

/// The notification area's icon size at this process's DPI.
fn small_icon_size() -> usize {
    // SAFETY: GetSystemMetrics only reads a system setting.
    let size = unsafe { GetSystemMetrics(SM_CXSMICON) };
    usize::try_from(size)
        .ok()
        .filter(|size| (8..=256).contains(size))
        .unwrap_or(16)
}

fn icon_size_changed() -> bool {
    let size = small_icon_size();
    TRAY.with(|tray| {
        tray.try_borrow()
            .is_ok_and(|tray| tray.icons.as_ref().is_some_and(|icons| icons.size != size))
    })
}

/// The icon to show for `look` now: the current animation frame while
/// animating. Draws the icons on first use and again after the size changed.
fn current_icon(look: Look) -> HICON {
    let size = small_icon_size();
    let icon = TRAY.with(|tray| {
        let Ok(mut tray) = tray.try_borrow_mut() else {
            return null_mut();
        };
        if tray.icons.as_ref().is_none_or(|icons| icons.size != size) {
            // The old icons go first: the notification area keeps its own copy.
            tray.icons = None;
            tray.icons = Some(Icons::draw(size));
        }
        let frame = tray.frame;
        tray.icons
            .as_ref()
            .map_or(null_mut(), |icons| icons.get(look, frame))
    });
    if icon.is_null() {
        resource_icon()
    } else {
        icon
    }
}

/// The application icon, for when a drawn icon could not be created.
fn resource_icon() -> HICON {
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
    if icon.is_null() {
        // SAFETY: IDI_APPLICATION is a predefined system icon, loaded with a null
        // module.
        unsafe { LoadIconW(null_mut(), IDI_APPLICATION) }
    } else {
        icon
    }
}

/// Shield colour and line for each look. The tray does not follow the window's
/// theme: the taskbar may be light or dark whatever the window uses.
fn style(look: Look) -> (u32, Line) {
    match look {
        // A flat line on amber: not "idle", since a takeover may still be live.
        Look::Unknown => (STATUS_WARN, Line::Flat),
        Look::Idle => (TRAY_IDLE, Line::Pulse),
        Look::Managed => (STATUS_OK, Line::Pulse),
        Look::Scoped => (STATUS_WARN, Line::Pulse),
        Look::Recovery => (STATUS_ERROR, Line::Pulse),
    }
}

/// Every icon the tray can show at one size. Null entries could not be
/// created; [`current_icon`] then falls back to the application icon.
struct Icons {
    size: usize,
    /// One still icon per [`Look::ALL`] entry.
    still: Vec<HICON>,
    /// The frames of the managed-takeover animation.
    sweep: Vec<HICON>,
}

impl Icons {
    fn draw(size: usize) -> Self {
        let still = Look::ALL
            .iter()
            .map(|look| {
                let (fill, line) = style(*look);
                create_icon(size, &icon::render(size, fill, line, Shine::Full))
            })
            .collect();
        let (fill, line) = style(Look::Managed);
        let sweep = (0..SWEEP_FRAMES)
            .map(|frame| create_icon(size, &icon::render(size, fill, line, Shine::Sweep(frame))))
            .collect();
        Self { size, still, sweep }
    }

    fn get(&self, look: Look, frame: usize) -> HICON {
        let icon = if look.animated() {
            self.sweep.get(frame % SWEEP_FRAMES)
        } else {
            Look::ALL
                .iter()
                .position(|candidate| *candidate == look)
                .and_then(|index| self.still.get(index))
        };
        icon.copied().unwrap_or(null_mut())
    }
}

impl Drop for Icons {
    fn drop(&mut self) {
        for icon in self.still.iter().chain(&self.sweep) {
            if !icon.is_null() {
                // SAFETY: each icon came from CreateIconIndirect, is owned only by
                // this cache and is destroyed once.
                unsafe { DestroyIcon(*icon) };
            }
        }
    }
}

/// Turns `size * size` straight-alpha BGRA pixels, top row first, into an icon.
/// Returns null when GDI cannot create it.
fn create_icon(size: usize, pixels: &[u8]) -> HICON {
    let Ok(side) = i32::try_from(size) else {
        return null_mut();
    };
    if pixels.len() != size * size * 4 {
        return null_mut();
    }
    let header = BITMAPV5HEADER {
        bV5Size: size_of::<BITMAPV5HEADER>() as u32,
        bV5Width: side,
        // Negative height: rows run top to bottom, as `pixels` does.
        bV5Height: -side,
        bV5Planes: 1,
        bV5BitCount: 32,
        bV5Compression: BI_BITFIELDS,
        bV5RedMask: 0x00ff_0000,
        bV5GreenMask: 0x0000_ff00,
        bV5BlueMask: 0x0000_00ff,
        bV5AlphaMask: 0xff00_0000,
        ..Default::default()
    };
    let mut bits: *mut c_void = null_mut();
    // SAFETY: `header` is a complete BITMAPV5HEADER, which GDI accepts wherever
    // a BITMAPINFO is expected; with DIB_RGB_COLORS no colour table is read and
    // a null DC is allowed. `bits` receives the section's memory.
    let color = unsafe {
        CreateDIBSection(
            null_mut(),
            (&raw const header).cast::<BITMAPINFO>(),
            DIB_RGB_COLORS,
            &mut bits,
            null_mut(),
            0,
        )
    };
    if color.is_null() || bits.is_null() {
        if !color.is_null() {
            // SAFETY: `color` was just created and nothing else uses it.
            unsafe { DeleteObject(color) };
        }
        return null_mut();
    }
    // SAFETY: the section holds exactly `size * size` 32-bit pixels with no row
    // padding, which is `pixels.len()` bytes, and does not overlap `pixels`.
    unsafe { std::ptr::copy_nonoverlapping(pixels.as_ptr(), bits.cast::<u8>(), pixels.len()) };
    // An all-zero mask: the alpha channel decides transparency. Rows of a
    // monochrome bitmap are padded to 16 bits.
    let mask_bits = vec![0u8; size.div_ceil(16) * 2 * size];
    // SAFETY: `mask_bits` holds a full 1-bit bitmap of this size and outlives
    // the call, which copies it.
    let mask = unsafe { CreateBitmap(side, side, 1, 1, mask_bits.as_ptr().cast()) };
    let icon = if mask.is_null() {
        null_mut()
    } else {
        let info = ICONINFO {
            fIcon: 1,
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: mask,
            hbmColor: color,
        };
        // SAFETY: `info` names two live bitmaps of the same size; the call
        // copies them, so they can be deleted afterwards.
        unsafe { CreateIconIndirect(&info) }
    };
    // SAFETY: both bitmaps were created above and are used by nothing else now.
    unsafe {
        DeleteObject(color);
        if !mask.is_null() {
            DeleteObject(mask);
        }
    }
    icon
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Graphics::Gdi::{
        BI_RGB, BITMAPINFOHEADER, CreateCompatibleDC, DeleteDC, GetDIBits,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::GetIconInfo;

    use super::*;

    /// Reads an icon's colour bitmap back as top-down BGRA rows.
    fn read_back(icon: HICON, size: usize) -> Vec<u8> {
        let mut info = ICONINFO::default();
        // SAFETY: `icon` is live and `info` is writable.
        assert_ne!(unsafe { GetIconInfo(icon, &mut info) }, 0);
        let mut bitmap = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: size as i32,
                biHeight: -(size as i32),
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut pixels = vec![0u8; size * size * 4];
        // SAFETY: GetIconInfo returned two bitmaps this test now owns; `pixels`
        // holds `size` rows of 32-bit pixels as `bitmap` describes.
        let rows = unsafe {
            let dc = CreateCompatibleDC(null_mut());
            let rows = GetDIBits(
                dc,
                info.hbmColor,
                0,
                size as u32,
                pixels.as_mut_ptr().cast(),
                &mut bitmap,
                DIB_RGB_COLORS,
            );
            DeleteDC(dc);
            DeleteObject(info.hbmColor);
            DeleteObject(info.hbmMask);
            rows
        };
        assert_eq!(rows, size as i32);
        pixels
    }

    #[test]
    fn every_look_and_frame_becomes_an_icon() {
        let icons = Icons::draw(16);
        assert_eq!(icons.still.len(), Look::ALL.len());
        assert_eq!(icons.sweep.len(), SWEEP_FRAMES);
        assert!(
            icons
                .still
                .iter()
                .chain(&icons.sweep)
                .all(|icon| !icon.is_null())
        );
    }

    #[test]
    fn icons_keep_row_and_channel_order() {
        let size = 32;
        let icons = Icons::draw(size);
        let pixels = read_back(icons.get(Look::Idle, 0), size);
        let bgr = |x: usize, y: usize| {
            let offset = (y * size + x) * 4;
            [pixels[offset], pixels[offset + 1], pixels[offset + 2]]
        };
        // Inside the shield, above the line: the idle grey. Swapped red and blue
        // would read 86 93 8b.
        assert_eq!(bgr(16, 5), [0x8b, 0x93, 0x86]);
        // The pulse peaks upward here; rows read bottom-up would land on grey.
        assert_eq!(bgr(15, 9), [0xff, 0xff, 0xff]);
    }
}
