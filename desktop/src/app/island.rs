//! 屏幕顶部的状态岛，外观参照 Apple 灵动岛：吸在屏幕顶边上，两肩用凹圆弧接到顶边，
//! 颜色跟随软件的浅色、深色主题。收起时左端状态图标、右端一小段状态或速率，中间留空；
//! 状态变化、有提醒或鼠标移上去时，平滑地展开成卡片，接管中还列出被接管环境的出口、
//! DNS、UDP 和连接数。按住岛横向拖动可以沿顶边换位置。
//!
//! 接管中岛的边缘有两道光沿着轮廓流动（系统设置了减少动态效果时只留静止的描边），
//! 一眼就能和未接管区分开；展开时卡片右边另起一条竖胶囊，列出被接管环境里的图形应用，
//! 点一下就以默认用户启动，主窗口不出来，结果显示在岛上。
//!
//! 岛不自己判断状态：界面每次刷新把托盘用的 [`Snapshot`] 和环境信息交给 [`sync`]，
//! 按钮也和托盘菜单一样先叫出主窗口、再把 [`Command`] 交给界面；应用胶囊上的点击记成
//! [`Request`]，由界面下次刷新时取走处理。点岛本身不做任何事。
//! 窗口是 gpui 的 `PopUp`（置顶、不占任务栏）。
//!
//! 窗口大小固定为 [`model::WINDOW`]，形变动画只在窗口里画；窗口区域（`SetWindowRgn`）
//! 裁成当前形状（展开时加上应用胶囊），所以透明的地方不挡下面窗口的点击。鼠标离开窗口时
//! gpui 不发悬停回调，所以展开和收回靠岛自己每 33ms 比较一次光标位置；流动的光也跟着
//! 这个节拍重画（约每秒 30 帧），不按显示器刷新率一直重画。

mod model;

use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use gpui_kit::component::Sizable as _;
use gpui_kit::{prelude::*, *};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows_sys::Win32::Foundation::{HWND, POINT, RECT};
use windows_sys::Win32::Graphics::Dwm::{
    DWMWA_BORDER_COLOR, DWMWA_COLOR_NONE, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_DONOTROUND,
    DwmSetWindowAttribute,
};
use windows_sys::Win32::Graphics::Gdi::{
    ClientToScreen, CombineRgn, CreatePolygonRgn, CreateRoundRectRgn, DeleteObject,
    GetMonitorInfoW, MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MonitorFromPoint, RGN_OR, SetWindowRgn,
    WINDING,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, VK_LBUTTON, VK_RBUTTON};
use windows_sys::Win32::UI::Shell::{
    QUNS_BUSY, QUNS_PRESENTATION_MODE, QUNS_RUNNING_D3D_FULL_SCREEN, SHQueryUserNotificationState,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetCursorPos, GetSystemMetrics, GetWindowRect, HWND_TOPMOST, IsWindowVisible, SM_SWAPBUTTON,
    SW_HIDE, SW_SHOWNOACTIVATE, SWP_NOACTIVATE, SWP_NOSIZE, SetWindowPos, ShowWindow,
};
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

use self::model::{Action, AppTile, Fact, Line, Morph, Presence, Shape, Tone};
pub(crate) use self::model::{Apps, Details, Environment, Rates};
use super::theme::{PREFERENCES_KEY, UI_FONT};
use super::tray::{Command, Look, Snapshot};

/// 偏好里的开关，与主题放在同一个注册表键下。
const ENABLED_VALUE: &str = "DesktopIsland";
/// 拖动后的位置：窗口中心在主显示器宽度上的比例乘以 10000。
const POSITION_VALUE: &str = "DesktopIslandPosition";
/// 离屏幕顶边的距离：0，岛吸在顶边上。
const TOP_GAP: f32 = 0.;
const TITLE: &str = "WSL Proxy 状态岛";
/// 岛自己看光标的间隔，也是流动光重画的节拍；全屏检测每隔几次才做一次（约 200ms）。
const POLL: Duration = Duration::from_millis(33);
const FULLSCREEN_EVERY: u32 = 6;

/// 岛的配色，跟随软件主题。
#[derive(Clone, Copy)]
struct Palette {
    bg: u32,
    ink: u32,
    /// 次要文字（带透明度，用 `rgba`）。
    secondary: u32,
    /// 灰色胶囊和信息格的底色，及悬停时的底色（带透明度）。
    fill: u32,
    fill_hover: u32,
    ok: u32,
    warn: u32,
    error: u32,
    off: u32,
    /// 绿色主按钮上的字色。
    on_ok: u32,
}

/// 深色主题：纯黑岛，和 Apple 灵动岛一样；状态色取软件深色主题的状态色。
const DARK: Palette = Palette {
    bg: 0x000000,
    ink: 0xffffff,
    secondary: 0xffffff8c,
    fill: 0xffffff1f,
    fill_hover: 0xffffff33,
    ok: 0x47c86d,
    warn: 0xf5b841,
    error: 0xff5a52,
    off: 0x9a9aa0,
    on_ok: 0x000000,
};

/// 浅色主题：浅灰白岛、深色字；状态色取软件浅色主题的状态色。
const LIGHT: Palette = Palette {
    bg: 0xf5f5f7,
    ink: 0x1d1d1f,
    secondary: 0x3c3c4399,
    fill: 0x7878801f,
    fill_hover: 0x78788033,
    ok: 0x1f9d50,
    warn: 0xd97706,
    error: 0xd71019,
    off: 0x86938b,
    on_ok: 0xffffff,
};

impl Palette {
    fn of(dark: bool) -> Self {
        if dark { DARK } else { LIGHT }
    }

    fn tone(self, tone: Tone) -> u32 {
        match tone {
            Tone::Ok => self.ok,
            Tone::Warn => self.warn,
            Tone::Error => self.error,
            Tone::Off => self.off,
        }
    }
}

/// 应用胶囊上的点击，交给界面处理：岛不和后台通信。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Request {
    /// 以默认用户启动这个应用（桌面文件 ID）。
    Launch(String),
    /// 应用列表读失败了，再读一次。
    RetryApps,
}

static REQUEST: Mutex<Option<Request>> = Mutex::new(None);

/// 界面每次刷新取走岛上最近一次点击；同一时间只留一个，后点的盖掉先点的。
pub(crate) fn take_request() -> Option<Request> {
    REQUEST
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
}

fn request(request: Request) {
    *REQUEST.lock().unwrap_or_else(PoisonError::into_inner) = Some(request);
}

/// 岛的窗口句柄，托盘找主窗口时要排除它；没有岛时为空。
static WINDOW: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

thread_local! {
    static HANDLE: RefCell<Option<WindowHandle<Island>>> = const { RefCell::new(None) };
}

pub(crate) fn hwnd() -> HWND {
    WINDOW.load(Ordering::Acquire)
}

/// 偏好里岛是否打开；没设置过时默认打开。
pub(crate) fn enabled_preference() -> bool {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(PREFERENCES_KEY)
        .and_then(|key| key.get_value::<u32, _>(ENABLED_VALUE))
        .map_or(true, |value| value != 0)
}

pub(crate) fn persist_enabled(enabled: bool) -> Result<(), String> {
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(PREFERENCES_KEY)
        .map_err(|error| format!("island_preference_open_failed:{error}"))?;
    key.set_value(ENABLED_VALUE, &u32::from(enabled))
        .map_err(|error| format!("island_preference_write_failed:{error}"))
}

fn load_position() -> f32 {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(PREFERENCES_KEY)
        .and_then(|key| key.get_value::<u32, _>(POSITION_VALUE))
        .map_or(0.5, |value| (value.min(10_000) as f32) / 10_000.)
}

/// 位置存不进去只影响下次启动，不打扰用户。
fn persist_position(ratio: f32) {
    if let Ok((key, _)) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(PREFERENCES_KEY) {
        let _ = key.set_value(
            POSITION_VALUE,
            &((ratio.clamp(0., 1.) * 10_000.).round() as u32),
        );
    }
}

/// 打开岛。已经开着就什么都不做；开不出来也不影响主窗口，只是没有岛。
pub(crate) fn open(cx: &mut App) {
    if HANDLE.with(|handle| handle.borrow().is_some()) {
        return;
    }
    let window_size = size(px(model::WINDOW.0), px(model::WINDOW.1));
    let origin = cx
        .primary_display()
        .map(|display| {
            let screen = display.bounds();
            point(
                screen.origin.x + (screen.size.width - window_size.width) / 2.,
                screen.origin.y + px(TOP_GAP),
            )
        })
        .unwrap_or_default();
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds {
            origin,
            size: window_size,
        })),
        titlebar: None,
        focus: false,
        show: true,
        kind: WindowKind::PopUp,
        is_movable: false,
        is_resizable: false,
        is_minimizable: false,
        window_background: WindowBackgroundAppearance::Transparent,
        ..Default::default()
    };
    let opened = cx.open_window(options, |window, cx| {
        window.set_window_title(TITLE);
        let hwnd = hwnd_of(window);
        if !hwnd.is_null() {
            strip_frame(hwnd);
            WINDOW.store(hwnd, Ordering::Release);
        }
        cx.new(|cx| {
            cx.spawn_in(window, async move |island, cx| {
                loop {
                    cx.background_executor().timer(POLL).await;
                    if island
                        .update_in(cx, |island: &mut Island, window, cx| {
                            island.poll(window, cx)
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })
            .detach();
            Island::new(hwnd)
        })
    });
    if let Ok(handle) = opened {
        HANDLE.with(|slot| *slot.borrow_mut() = Some(handle));
    }
}

/// 关掉岛。主窗口真正关闭前必须调用：还有窗口开着，gpui 就不会退出进程。
pub(crate) fn close(cx: &mut App) {
    WINDOW.store(null_mut(), Ordering::Release);
    if let Some(handle) = HANDLE.with(|slot| slot.borrow_mut().take()) {
        let _ = handle.update(cx, |_, window, _| window.remove_window());
    }
}

/// 界面每次刷新调用：交给岛最新的状态、速率、环境信息和主题。
/// 展开、收回由岛自己按光标和提醒决定。
pub(crate) fn sync(
    snapshot: &Snapshot,
    rates: Option<Rates>,
    details: Option<Details>,
    dark: bool,
    cx: &mut App,
) {
    with_island(cx, |island, _, cx| {
        if island.snapshot != *snapshot
            || island.rates != rates
            || island.details != details
            || island.dark != dark
        {
            island.snapshot = snapshot.clone();
            island.rates = rates;
            island.details = details;
            island.dark = dark;
            cx.notify();
        }
    });
}

/// 设置里改了不透明度：岛重画一次。
pub(crate) fn refresh(cx: &mut App) {
    with_island(cx, |_, _, cx| cx.notify());
}

/// 主界面弹出的提醒也在岛上展开显示。
pub(crate) fn notify(message: &str, warning: bool, cx: &mut App) {
    with_island(cx, |island, _, _| {
        island
            .presence
            .notify(message.to_owned(), warning, Instant::now());
    });
}

fn with_island(cx: &mut App, f: impl FnOnce(&mut Island, &mut Window, &mut Context<Island>)) {
    let Some(handle) = HANDLE.with(|slot| *slot.borrow()) else {
        return;
    };
    if handle.update(cx, f).is_err() {
        // 窗口已经不在了（例如被系统关掉），下次刷新不再找它。
        HANDLE.with(|slot| *slot.borrow_mut() = None);
        WINDOW.store(null_mut(), Ordering::Release);
    }
}

/// 岛上的按钮：和托盘菜单一样，先叫出主窗口，再让界面处理命令。
fn run(command: Command) {
    super::tray::show_main_window();
    if command != Command::Open {
        super::tray::request_action(command);
    }
}

/// 鼠标主键现在是否按着。用户把左右键对调过时，主键是物理右键：
/// `GetAsyncKeyState` 看的是物理按键，所以要换成右键来查。
fn primary_button_held() -> bool {
    // SAFETY: reads a system setting and the global key state; no pointers involved.
    unsafe {
        let key = if GetSystemMetrics(SM_SWAPBUTTON) != 0 {
            VK_RBUTTON
        } else {
            VK_LBUTTON
        };
        GetAsyncKeyState(i32::from(key)) < 0
    }
}

struct Island {
    hwnd: HWND,
    snapshot: Snapshot,
    rates: Option<Rates>,
    details: Option<Details>,
    dark: bool,
    presence: Presence,
    expanded: bool,
    morph: Morph,
    /// 最近一帧画出的外形，看光标在不在岛上时用。
    shape: Shape,
    /// 最近一次设置的窗口区域（物理像素：外形、应用胶囊的高度（不显示时为 0）、
    /// 客户区相对窗口矩形的偏移），没变就不重设。
    region: Option<[i32; 7]>,
    /// 最近一帧应用胶囊有没有画出来，看光标在不在岛上时用。
    strip: bool,
    /// 光标停在应用胶囊的哪一格上：卡片的说明行换成它的名字。
    hint: Option<String>,
    /// 流动光的起点。
    born: Instant,
    hidden: bool,
    polls: u32,
    /// 窗口中心在主显示器宽度上的比例，0.5 是正中。
    position: f32,
    /// 按下还没松开的主键。
    press: Option<Press>,
    dragging: bool,
    /// 在按钮上长按拖动后松手时 gpui 照样会发一次点击，这次点击要吞掉。
    swallow_click: bool,
}

#[derive(Clone, Copy)]
struct Press {
    at: Instant,
    cursor: POINT,
    /// 按下时窗口左边（物理像素）。
    window_left: i32,
    /// 按在按钮上：要长按才拖，免得点按钮时手一抖就拖走了。
    on_button: bool,
}

impl Island {
    fn new(hwnd: HWND) -> Self {
        Self {
            hwnd,
            snapshot: Snapshot::INITIAL,
            rates: None,
            details: None,
            dark: super::theme::is_dark(),
            presence: Presence::default(),
            expanded: false,
            morph: Morph::default(),
            shape: model::shape(0., model::CARD),
            region: None,
            strip: false,
            hint: None,
            born: Instant::now(),
            hidden: false,
            polls: 0,
            position: load_position(),
            press: None,
            dragging: false,
            swallow_click: false,
        }
    }

    fn palette(&self) -> Palette {
        Palette::of(self.dark)
    }

    fn card(&self) -> (f32, f32) {
        model::card_size(self.details.as_ref())
    }

    /// 汇总行的速率：多个环境时是各环境之和（主界面只交来它挑出的那一个的速率）。
    fn summary_rates(&self) -> Option<Rates> {
        model::summary_rates(self.rates, self.details.as_ref())
    }

    fn poll(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.polls.is_multiple_of(FULLSCREEN_EVERY) && self.press.is_none() {
            self.hidden = fullscreen_in_front();
            place(self.hwnd, window.scale_factor(), self.hidden, self.position);
        }
        self.polls = self.polls.wrapping_add(1);
        let now = Instant::now();
        let inside = !self.hidden && self.cursor_inside(window.scale_factor());
        let notice = self.presence.notice().map(str::to_owned);
        let expanded = self.presence.update(&self.snapshot, inside, now);
        if expanded != self.expanded {
            self.expanded = expanded;
            if cx.reduce_motion() {
                self.morph.jump(expanded);
            } else {
                self.morph.aim(expanded, now);
            }
            cx.notify();
        } else if notice.as_deref() != self.presence.notice() || self.flowing(cx) {
            cx.notify();
        }
    }

    /// 接管中、看得见、系统没要求减少动态效果时，边缘的光在流动，要按节拍重画。
    fn flowing(&self, cx: &App) -> bool {
        self.glows() && !self.hidden && !cx.reduce_motion()
    }

    /// 接管中才描边。界面读详情、等确认这些短暂的操作不影响，免得边框一闪一闪。
    fn glows(&self) -> bool {
        self.snapshot.look == Look::Managed
    }

    /// 应用胶囊这一帧的位置和大小（窗口内的逻辑像素）：卡片右边，顶边留一点空，
    /// 高度按格数收紧，最高和卡片齐平，再多就滚动。
    fn strip_bounds(&self) -> (f32, f32, f32, f32) {
        let slots = self
            .details
            .as_ref()
            .map_or(1, |details| match &details.apps {
                Apps::Listed(apps) => apps.len().max(1),
                Apps::Loading | Apps::Failed(_) => 1,
            });
        (
            self.left() + self.shape.width + model::STRIP_GAP,
            model::STRIP_TOP,
            model::STRIP_WIDTH,
            model::strip_height(slots, self.shape.height - model::STRIP_TOP),
        )
    }

    /// 主键在岛上按下。
    fn press_start(&mut self, on_button: bool) {
        let mut cursor = POINT::default();
        let mut rect = RECT::default();
        // SAFETY: both out-parameters are writable locals; a stale handle makes the call fail.
        let read = !self.hwnd.is_null()
            && unsafe {
                GetCursorPos(&mut cursor) != 0 && GetWindowRect(self.hwnd, &mut rect) != 0
            };
        self.swallow_click = false;
        self.press = read.then_some(Press {
            at: Instant::now(),
            cursor,
            window_left: rect.left,
            on_button,
        });
    }

    /// 主键松开（gpui 的鼠标抬起事件，或者每帧查到的按键状态）。
    fn press_end(&mut self) {
        if self.press.take().is_some() && self.dragging {
            self.finish_drag();
        }
    }

    /// 按钮的点击要不要照常处理：在按钮上长按拖动后的那次点击不算。
    fn take_click(&mut self) -> bool {
        !std::mem::take(&mut self.swallow_click)
    }

    /// 按着的时候每帧调用：决定是否开始拖，拖动中让窗口跟着光标。
    fn track_press(&mut self, scale: f32) {
        let Some(press) = self.press else {
            return;
        };
        if !primary_button_held() {
            self.press_end();
            return;
        }
        if !self.dragging {
            let mut cursor = POINT::default();
            // SAFETY: `cursor` is a writable local.
            unsafe { GetCursorPos(&mut cursor) };
            let moved =
                ((cursor.x - press.cursor.x) as f32).hypot((cursor.y - press.cursor.y) as f32);
            let moved = moved > model::PRESS_SLOP * scale;
            let held_long = press.at.elapsed() >= model::LONG_PRESS;
            if press.on_button {
                if held_long {
                    self.dragging = true;
                    self.swallow_click = true;
                } else if moved {
                    // 在按钮上按下就拖：当作放弃这次按下，按钮自己也不会触发点击。
                    self.press = None;
                    return;
                }
            } else if moved || held_long {
                self.dragging = true;
            }
        }
        if self.dragging {
            self.follow_cursor(press);
        }
    }

    /// 拖动中每一帧：窗口跟着光标横向移动，不离开顶边、不出屏幕。
    fn follow_cursor(&mut self, press: Press) {
        let Some(screen) = primary_screen() else {
            return;
        };
        let mut cursor = POINT::default();
        let mut rect = RECT::default();
        // SAFETY: both out-parameters are writable locals; a stale handle makes the call fail.
        if unsafe { GetCursorPos(&mut cursor) == 0 || GetWindowRect(self.hwnd, &mut rect) == 0 } {
            return;
        }
        let width = rect.right - rect.left;
        let wanted = press.window_left + cursor.x - press.cursor.x;
        let left = wanted.clamp(screen.left, screen.right - width);
        if left != rect.left {
            // SAFETY: `hwnd` is the live island window owned by this thread.
            unsafe {
                SetWindowPos(
                    self.hwnd,
                    HWND_TOPMOST,
                    left,
                    rect.top,
                    0,
                    0,
                    SWP_NOACTIVATE | SWP_NOSIZE,
                )
            };
        }
    }

    /// 松手：记下位置，下次启动摆回这里。
    fn finish_drag(&mut self) {
        self.dragging = false;
        let mut rect = RECT::default();
        // SAFETY: `rect` is a writable local; a stale handle makes the call fail.
        let read = unsafe { GetWindowRect(self.hwnd, &mut rect) } != 0;
        if let (true, Some(screen)) = (read, primary_screen()) {
            self.position = model::ratio_of(
                screen.left,
                screen.right - screen.left,
                rect.left,
                rect.right - rect.left,
            );
            persist_position(self.position);
        }
    }

    fn left(&self) -> f32 {
        (model::WINDOW.0 - self.shape.width) / 2.
    }

    fn cursor_inside(&self, scale: f32) -> bool {
        let mut cursor = POINT::default();
        // SAFETY: `cursor` is a writable local.
        let Some(origin) =
            client_origin(self.hwnd).filter(|_| unsafe { GetCursorPos(&mut cursor) } != 0)
        else {
            return false;
        };
        // 岛画在客户区里；窗口矩形还带着系统留的一圈看不见的边框，不能拿它当原点。
        let x = (cursor.x - origin.x) as f32 / scale;
        let y = (cursor.y - origin.y) as f32 / scale;
        let within = |(left, top, width, height): (f32, f32, f32, f32)| {
            x >= left && x < left + width && y >= top && y < top + height
        };
        within((self.left(), 0., self.shape.width, self.shape.height))
            || (self.strip && within(self.strip_bounds()))
    }

    /// 把能点到的范围裁成当前的刘海轮廓。轮廓向外多扩一点，岛边缘的抗锯齿像素不被裁掉。
    /// 只改命中范围、不要求重绘：重绘由 gpui 自己的下一帧负责，免得闪一下。
    fn clip(&mut self, scale: f32) {
        let strip = self.strip.then(|| self.strip_bounds());
        // 窗口区域按窗口矩形算，岛画在客户区里：Windows 给这个窗口留了一圈看不见的边框
        // （实测左边 8px），不加上这段偏移，轮廓右边那一截会被裁掉。
        let mut frame = RECT::default();
        // SAFETY: `frame` is a writable local; a stale handle makes the call fail.
        let Some(origin) = client_origin(self.hwnd)
            .filter(|_| unsafe { GetWindowRect(self.hwnd, &mut frame) } != 0)
        else {
            return;
        };
        let (dx, dy) = (origin.x - frame.left, origin.y - frame.top);
        let s = |value: f32| (value * scale).round() as i32;
        let region = [
            s(self.left()),
            s(self.shape.width),
            s(self.shape.height),
            s(self.shape.radius),
            strip.map_or(0, |(_, _, _, height)| s(height)),
            dx,
            dy,
        ];
        if self.hwnd.is_null() || self.region == Some(region) {
            return;
        }
        let points: Vec<POINT> = model::outline(self.shape, self.left(), 1.5)
            .into_iter()
            .map(|(x, y)| POINT {
                x: s(x) + dx,
                y: s(y) + dy,
            })
            .collect();
        // SAFETY: `points` outlives the call and its length is passed with it. The
        // capsule's region is merged into the outline's and then deleted; on success
        // the window owns the merged region, on failure it stays ours and is deleted here.
        unsafe {
            let rgn = CreatePolygonRgn(points.as_ptr(), points.len() as i32, WINDING);
            if rgn.is_null() {
                return;
            }
            if let Some((left, top, width, height)) = strip {
                // 和外形一样向外多扩一点，边缘的抗锯齿像素不被裁掉。
                let capsule = CreateRoundRectRgn(
                    s(left - 1.5) + dx,
                    s(top - 1.5) + dy,
                    s(left + width + 1.5) + 1 + dx,
                    s(top + height + 1.5) + 1 + dy,
                    s(width + 3.),
                    s(width + 3.),
                );
                if !capsule.is_null() {
                    CombineRgn(rgn, rgn, capsule, RGN_OR);
                    DeleteObject(capsule);
                }
            }
            if SetWindowRgn(self.hwnd, rgn, 0) == 0 {
                DeleteObject(rgn);
            }
        }
        self.region = Some(region);
    }

    /// 收起时：左端状态图标，右端状态简称或下行速率，中间留空。
    fn compact(&self, tone: Tone) -> Div {
        let palette = self.palette();
        div()
            .w(px(model::PILL.0))
            .h(px(model::PILL.1))
            .flex_shrink_0()
            .flex()
            .items_center()
            .justify_between()
            .pl(px(14.))
            .pr(px(15.))
            .child(glyph(&self.snapshot, palette.tone(tone), 16.))
            .child(
                div()
                    .text_size(px(12.5))
                    .text_color(rgb(palette.tone(tone)))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(model::trailing(&self.snapshot, self.summary_rates())),
            )
    }

    /// 展开时：左上图标徽章，旁边标题和说明，右上速率；接管中接着列出出口一行、
    /// DNS / UDP / 连接三格；底部一排等宽胶囊按钮。
    fn expanded(&self, tone: Tone, cx: &mut Context<Self>) -> Div {
        let palette = self.palette();
        let caption = self
            .hint
            .clone()
            .unwrap_or_else(|| model::caption(&self.snapshot, self.presence.notice()));
        let buttons = model::actions(&self.snapshot)
            .into_iter()
            .map(|action| button(action, palette, cx));
        let rates = self
            .summary_rates()
            .filter(|_| self.snapshot.look == Look::Managed)
            .map(|rates| {
                div()
                    .flex_shrink_0()
                    .flex()
                    .flex_col()
                    .items_end()
                    .text_size(px(12.))
                    .text_color(rgba(palette.secondary))
                    .child(format!("↓ {}", model::short_rate(rates.down)))
                    .child(format!("↑ {}", model::short_rate(rates.up)))
            });
        let card = self.card();
        let header = div()
            .flex()
            .items_center()
            .gap(px(10.))
            .child(
                div()
                    .size(px(38.))
                    .flex_shrink_0()
                    .flex()
                    .items_center()
                    .justify_center()
                    .rounded_full()
                    .bg(rgba((palette.tone(tone) << 8) | 0x2e))
                    .child(glyph(&self.snapshot, palette.tone(tone), 20.)),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .text_size(px(15.))
                            .line_height(px(20.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(self.snapshot.look.label()),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .line_height(px(16.))
                            .text_color(rgba(palette.secondary))
                            // 悬停应用胶囊时的说明只占一行，卡片不因此变高、内容不往下挤。
                            .map(|text| {
                                if self.hint.is_some() {
                                    text.truncate()
                                } else {
                                    text.line_clamp(2)
                                }
                            })
                            .child(caption),
                    ),
            )
            .children(rates);
        let environments = self
            .details
            .as_ref()
            .filter(|_| model::lists_environments(self.details.as_ref()))
            .map(|details| environment_list(details, palette));
        let details = self
            .details
            .as_ref()
            .filter(|_| environments.is_none())
            .map(|details| {
                let exit = model::exit_fact(details);
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .child(
                        div()
                            .h(px(30.))
                            .px(px(10.))
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .rounded(px(10.))
                            .bg(rgba(palette.fill))
                            .child(
                                div()
                                    .flex_shrink_0()
                                    .text_size(px(11.5))
                                    .text_color(rgba(palette.secondary))
                                    .child(exit.label),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .truncate()
                                    .text_size(px(12.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(fact_color(&exit, palette)))
                                    .child(exit.value),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .gap(px(6.))
                            .children(model::cells(details).map(|fact| cell(fact, palette))),
                    )
            });
        div()
            .w(px(card.0))
            .h(px(card.1))
            .flex_shrink_0()
            .flex()
            .flex_col()
            .gap(px(8.))
            .px(px(16.))
            .pt(px(14.))
            .pb(px(14.))
            .child(header)
            .children(environments)
            .children(details)
            .child(div().flex_1())
            .child(div().flex().gap(px(8.)).children(buttons))
    }
}

/// 收起和展开的内容各自的不透明度：收起的内容在形变一开始就淡出，展开的内容在形变
/// 后段才淡入，两者不同时出现。淡入用平滑曲线，不是线性。
fn fades(m: f32) -> (f32, f32) {
    let smooth = |x: f32| {
        let x = x.clamp(0., 1.);
        x * x * (3. - 2. * x)
    };
    (1. - smooth(m * 4.), smooth((m - 0.45) / 0.4))
}

/// 信息的数值颜色：正常、留意用状态色，中性的用正文色。
fn fact_color(fact: &Fact, palette: Palette) -> u32 {
    match fact.tone {
        Tone::Off => palette.ink,
        tone => palette.tone(tone),
    }
}

/// 同时接管多个环境时的列表：每个环境一行，名字、出口、上下行速率。
fn environment_list(details: &Details, palette: Palette) -> Div {
    let row = || {
        div()
            .h(px(model::ENVIRONMENT_ROW_HEIGHT))
            .px(px(10.))
            .flex()
            .items_center()
            .gap(px(8.))
            .rounded(px(8.))
            .bg(rgba(palette.fill))
            .text_size(px(12.))
    };
    div()
        .flex()
        .flex_col()
        .gap(px(model::ENVIRONMENT_ROW_GAP))
        .children(model::environment_lines(details).into_iter().map(|line| {
            match line {
                Line::Environment { name, exit, rates } => row()
                    .child(
                        div()
                            .w(px(76.))
                            .flex_shrink_0()
                            .truncate()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(name),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .text_color(rgb(fact_color(&exit, palette)))
                            .child(exit.value),
                    )
                    .children(rates.map(|rates| {
                        div()
                            .flex_shrink_0()
                            .text_size(px(11.))
                            .text_color(rgba(palette.secondary))
                            .child(rates)
                    })),
                Line::More(count) => row()
                    .text_color(rgba(palette.secondary))
                    .child(format!("另外 {count} 个环境，打开主窗口查看")),
            }
        }))
}

/// 一格环境信息：上面小字标签，下面数值。
fn cell(fact: Fact, palette: Palette) -> Div {
    div()
        .flex_1()
        .min_w_0()
        .h(px(46.))
        .px(px(10.))
        .flex()
        .flex_col()
        .justify_center()
        .rounded(px(10.))
        .bg(rgba(palette.fill))
        .child(
            div()
                .text_size(px(11.))
                .text_color(rgba(palette.secondary))
                .child(fact.label),
        )
        .child(
            div()
                .truncate()
                .text_size(px(13.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(fact_color(&fact, palette)))
                .child(fact.value),
        )
}

/// 一侧的肩：一段向内凹的四分之一圆弧，把主体的竖直侧边接到屏幕顶边上。
/// 画法是一个粗边框的正圆环，被方框裁出四分之一：圆环内圈就是这段凹弧。
/// 用圆角和边框画，边缘和主体一样是逐像素抗锯齿；方框向主体多伸 1px，接缝处不漏光。
/// 岛身和两肩的底色，按设置里的不透明度透出后面的内容；文字和图标仍是实色。
fn translucent(color: u32) -> Rgba {
    Rgba {
        a: super::opacity::alpha(),
        ..rgb(color)
    }
}

fn shoulder(edge: f32, right: bool, color: u32) -> Div {
    // 圆环要盖住方框里离圆心最远的角（约 1.45 倍半径处）。
    quarter_ring(
        edge,
        right,
        model::FILLET * 0.5 + 2.,
        1.,
        translucent(color),
    )
}

/// 肩的描边：贴着肩的凹弧内侧的一条细圆环，和主体两侧的竖直描边接上。
fn shoulder_outline(edge: f32, right: bool, color: Rgba) -> Div {
    // 方框多伸进主体 2px，细环靠近主体那头不被裁掉半个像素，和竖直描边接得上。
    quarter_ring(edge, right, model::OUTLINE, 2., color)
}

/// 肩的方框里，一个内圈半径等于肩宽、宽 `band` 的圆环被裁出的四分之一。
/// 方框向主体多伸 `spill`，接缝处不漏光。
fn quarter_ring(edge: f32, right: bool, band: f32, spill: f32, color: Rgba) -> Div {
    let f = model::FILLET;
    let outer = f + band;
    let (left, center) = if right {
        (edge - spill, f + spill)
    } else {
        (edge - f, 0.)
    };
    let mut ring = div()
        .absolute()
        .left(px(center - outer))
        .top(px(f - outer))
        .size(px(outer * 2.))
        .rounded_full()
        .border_color(color);
    let width: AbsoluteLength = px(band).into();
    let borders = &mut ring.style().border_widths;
    borders.top = Some(width);
    borders.right = Some(width);
    borders.bottom = Some(width);
    borders.left = Some(width);
    div()
        .absolute()
        .top_0()
        .left(px(left))
        .w(px(f + spill))
        .h(px(f))
        .overflow_hidden()
        .child(ring)
}

impl Render for Island {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let now = Instant::now();
        self.track_press(window.scale_factor());
        let m = self.morph.value(now);
        if self.press.is_some() || !self.morph.settled(now) {
            window.request_animation_frame();
        }
        self.shape = model::shape(m, self.card());
        let palette = self.palette();
        let tone = Tone::of(&self.snapshot);
        let (compact, full) = fades(m);
        self.strip = full > 0. && model::shows_strip(self.details.as_ref());
        if !self.strip {
            self.hint = None;
        }
        self.clip(window.scale_factor());
        let content = if full > 0. {
            self.expanded(tone, cx).opacity(full)
        } else {
            self.compact(tone).opacity(compact)
        };
        let strip = self
            .details
            .as_ref()
            .filter(|_| self.strip)
            .map(|details| self.apps_capsule(details, cx).opacity(full));
        // 接管中的描边：主体左、右、底三边一圈淡淡的状态色（div 边框，边缘逐像素抗锯齿，
        // 静止的线不会有台阶）；再叠上沿轮廓流动的光。减少动态效果时描边加深、不流动。
        let motion = !cx.reduce_motion();
        let outline_color = self.glows().then(|| Rgba {
            a: if motion { 0.45 } else { 0.85 },
            ..rgb(palette.ok)
        });
        let flow = (self.glows() && motion).then(|| {
            let phase = (now.duration_since(self.born).as_secs_f32()
                / model::FLOW_PERIOD.as_secs_f32())
            .fract();
            flowing_light(self.shape, self.left(), phase, palette)
        });
        let left = self.left();
        div()
            .size_full()
            .child(shoulder(left, false, palette.bg))
            .child(shoulder(left + self.shape.width, true, palette.bg))
            .child(
                div()
                    .id("island")
                    .absolute()
                    .top_0()
                    .left(px(left))
                    .w(px(self.shape.width))
                    .h(px(self.shape.height))
                    .overflow_hidden()
                    .flex()
                    .justify_center()
                    .rounded_b(px(self.shape.radius))
                    .bg(translucent(palette.bg))
                    .text_color(rgb(palette.ink))
                    .font_family(UI_FONT)
                    .text_size(px(13.))
                    // 按住横向拖动换位置；拖动中稍微变淡，看得出已经拿起来了。
                    // 点岛本身不做任何事，只有按钮有动作。
                    .when(self.dragging, |island| {
                        island.opacity(0.85).cursor(CursorStyle::ClosedHand)
                    })
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|island, _, _, cx| {
                            island.press_start(false);
                            cx.notify();
                        }),
                    )
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(|island, _, _, cx| {
                            island.press_end();
                            cx.notify();
                        }),
                    )
                    .on_mouse_up_out(
                        MouseButton::Left,
                        cx.listener(|island, _, _, cx| {
                            island.press_end();
                            cx.notify();
                        }),
                    )
                    .child(content),
            )
            .children(outline_color.map(|color| shoulder_outline(left, false, color)))
            .children(
                outline_color.map(|color| shoulder_outline(left + self.shape.width, true, color)),
            )
            .children(outline_color.map(|color| {
                // 静止描边单独一层压在主体上，从肩的圆弧收拢处（往下一个肩高）才开始：
                // 再往上外沿是肩的圆弧（由上面两段肩的描边画），主体那段竖直边在形状里面，
                // 描上色会多出一截直线。
                let width: AbsoluteLength = px(model::OUTLINE).into();
                let mut outline = div()
                    .absolute()
                    .left(px(left))
                    .top(px(model::FILLET))
                    .w(px(self.shape.width))
                    .h(px((self.shape.height - model::FILLET).max(0.)))
                    .rounded_b(px(self.shape.radius))
                    .border_color(color);
                let borders = &mut outline.style().border_widths;
                borders.left = Some(width);
                borders.right = Some(width);
                borders.bottom = Some(width);
                outline
            }))
            .children(flow)
            .children(strip)
    }
}

impl Island {
    /// 卡片右边的应用胶囊：竖着一列图标，放不下时滚轮滚动。读取中转圈，读失败放一颗重试。
    fn apps_capsule(&self, details: &Details, cx: &mut Context<Self>) -> Stateful<Div> {
        let palette = self.palette();
        let (left, top, width, height) = self.strip_bounds();
        let capsule = div()
            .id("island-apps")
            .absolute()
            .left(px(left))
            .top(px(top))
            .w(px(width))
            .h(px(height))
            .rounded(px(width / 2.))
            .overflow_hidden()
            .bg(translucent(palette.bg))
            .text_color(rgb(palette.ink))
            .font_family(UI_FONT);
        match &details.apps {
            Apps::Loading => capsule.flex().items_center().justify_center().child(
                gpui_kit::component::spinner::Spinner::new()
                    .small()
                    .color(rgba(palette.secondary).into()),
            ),
            Apps::Failed(reason) => {
                let hint = format!("点一下重试 · 读取应用失败：{reason}");
                capsule.flex().items_center().justify_center().child(slot(
                    "island-apps-retry",
                    hint,
                    icon(REFRESH, palette.warn, 18.).into_any_element(),
                    Some(Request::RetryApps),
                    palette,
                    cx,
                ))
            }
            Apps::Listed(apps) => {
                let launching = details.launching.as_deref();
                // 主窗口有操作在进行（停止、切换接管也在其中）时不启动，免得应用落在已经
                // 恢复直连的环境里。
                let busy = self.snapshot.busy.as_deref();
                let mut column = div()
                    .id("island-apps-scroll")
                    .size_full()
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap(px(model::STRIP_SPACING))
                    .py(px(model::STRIP_PADDING));
                for (index, app) in apps.iter().enumerate() {
                    let starting = launching == Some(app.id.as_str());
                    let (hint, action) = match (launching, busy) {
                        (Some(_), _) if starting => (format!("正在启动 {}…", app.name), None),
                        (Some(_), _) => (format!("{}（等上一个启动完）", app.name), None),
                        (None, Some(busy)) => (format!("{}（{busy}）", app.name), None),
                        (None, None) => (
                            format!("启动 {}", app.name),
                            Some(Request::Launch(app.id.clone())),
                        ),
                    };
                    let face = app_face(app, palette).opacity(match (launching, busy) {
                        (Some(_), _) if starting => 0.45,
                        (Some(_), _) | (None, Some(_)) => 0.6,
                        (None, None) => 1.,
                    });
                    column = column.child(slot(
                        ("island-app", index),
                        hint,
                        face.into_any_element(),
                        action,
                        palette,
                        cx,
                    ));
                }
                capsule.child(column)
            }
        }
    }
}

/// 刷新箭头，应用列表读失败时的重试按钮。
const REFRESH: &[u8] = br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M15.5 10a5.5 5.5 0 1 1-1.6-3.9" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><path d="M14.4 3.2v3.4H11" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>"#;

fn icon(data: &'static [u8], color: u32, size: f32) -> gpui_kit::component::Icon {
    gpui_kit::component::Icon::default()
        .data(data)
        .text_color(rgb(color))
        .with_size(gpui_kit::component::Size::Size(px(size)))
}

/// 应用的图标；没有图标或读不出来时，圆角方块里写应用名的第一个字。
fn app_face(app: &AppTile, palette: Palette) -> Div {
    let size = model::STRIP_ICON;
    let initial: String = app
        .name
        .chars()
        .find(|character| !character.is_whitespace())
        .map(|character| character.to_uppercase().collect())
        .unwrap_or_default();
    let placeholder = move || {
        div()
            .size(px(size))
            .flex()
            .items_center()
            .justify_center()
            .rounded(px(8.))
            .bg(rgba(palette.fill_hover))
            .text_size(px(13.))
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(rgb(palette.ink))
            .child(initial.clone())
            .into_any_element()
    };
    let face = match app.icon.clone() {
        Some(path) => img(path)
            .size(px(size))
            .object_fit(ObjectFit::Contain)
            .with_fallback(placeholder)
            .into_any_element(),
        None => placeholder(),
    };
    div().size(px(size)).child(face)
}

/// 胶囊里的一格：悬停时卡片说明行换成 `hint`，点了把 `action` 交给界面；
/// `action` 为空时只显示不响应。按下也要记成「按在按钮上」，长按照样能拖岛。
fn slot(
    id: impl Into<ElementId>,
    hint: String,
    face: AnyElement,
    action: Option<Request>,
    palette: Palette,
    cx: &mut Context<Island>,
) -> Stateful<Div> {
    let shown = hint.clone();
    let cell = div()
        .id(id)
        .flex_shrink_0()
        .size(px(model::STRIP_SLOT))
        .flex()
        .items_center()
        .justify_center()
        .rounded(px(12.))
        .child(face)
        .on_hover(cx.listener(move |island, hovered: &bool, _, cx| {
            if *hovered {
                island.hint = Some(shown.clone());
            } else if island.hint.as_deref() == Some(shown.as_str()) {
                island.hint = None;
            }
            cx.notify();
        }))
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(|island, _, _, cx| {
                cx.stop_propagation();
                island.press_start(true);
                cx.notify();
            }),
        );
    let Some(action) = action else {
        return cell;
    };
    cell.cursor_pointer()
        .hover(move |style| style.bg(rgba(palette.fill_hover)))
        .active(|style| style.opacity(0.7))
        .on_click(cx.listener(move |island, _, _, cx| {
            cx.stop_propagation();
            if island.take_click() {
                request(action.clone());
                island.hint = None;
                cx.notify();
            }
        }))
}

/// 接管中沿岛的轮廓（不含贴着屏幕顶边的那条边）流动的两道光，从尾到头逐渐变亮。
/// 画在轮廓往里 1px 处，压在主体的描边上，不会被窗口区域裁掉。
fn flowing_light(shape: Shape, left: f32, phase: f32, palette: Palette) -> Canvas<()> {
    // 深色岛上光头偏白，浅色岛上用饱和的状态色，两种底色上都看得清。
    let head = if palette.bg == DARK.bg {
        mix(palette.ok, 0xffffff, 0.55)
    } else {
        palette.ok
    };
    canvas(
        |_, _, _| (),
        move |bounds, (), window, _| {
            let points = model::light_path(shape, left);
            for (piece, brightness) in model::flow(&points, phase) {
                let color = Rgba {
                    a: brightness,
                    ..rgb(head)
                };
                stroke(window, bounds.origin, &piece, model::OUTLINE + 0.5, color);
            }
        },
    )
    .absolute()
    .top_0()
    .left_0()
    .size_full()
}

fn stroke(
    window: &mut Window,
    origin: Point<Pixels>,
    points: &[(f32, f32)],
    width: f32,
    color: Rgba,
) {
    let mut points = points
        .iter()
        .map(|&(x, y)| point(origin.x + px(x), origin.y + px(y)));
    let Some(first) = points.next() else {
        return;
    };
    let mut builder = PathBuilder::stroke(px(width));
    builder.move_to(first);
    for next in points {
        builder.line_to(next);
    }
    if let Ok(path) = builder.build() {
        window.paint_path(path, color);
    }
}

/// 两个 `0xRRGGBB` 颜色按 `t` 混合（0 是 `a`，1 是 `b`）。
fn mix(a: u32, b: u32, t: f32) -> u32 {
    let channel = |shift: u32| {
        let (x, y) = (((a >> shift) & 0xff) as f32, ((b >> shift) & 0xff) as f32);
        ((x + (y - x) * t).round() as u32) << shift
    };
    channel(16) | channel(8) | channel(0)
}

/// 盾牌状态图标：接管中打勾，需要恢复和未确认画感叹号，处理中画省略号，未接管是空盾牌。
fn glyph(snapshot: &Snapshot, color: u32, size: f32) -> gpui_kit::component::Icon {
    let data: &'static [u8] = if snapshot.busy.is_some() {
        br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M10 2l6 2v5c0 4-2.5 7-6 9-3.5-2-6-5-6-9V4l6-2z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><circle cx="7.3" cy="9.5" r="1" fill="currentColor"/><circle cx="10" cy="9.5" r="1" fill="currentColor"/><circle cx="12.7" cy="9.5" r="1" fill="currentColor"/></svg>"#
    } else {
        match snapshot.look {
            Look::Managed | Look::Scoped => {
                br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M10 2l6 2v5c0 4-2.5 7-6 9-3.5-2-6-5-6-9V4l6-2z" fill="currentColor"/><path d="m7 9.8 2.1 2.1 4-4.2" fill="none" stroke="white" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>"#
            }
            Look::Recovery | Look::Unknown => {
                br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M10 2l6 2v5c0 4-2.5 7-6 9-3.5-2-6-5-6-9V4l6-2z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M10 6.5v4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="10" cy="13.2" r="1.05" fill="currentColor"/></svg>"#
            }
            Look::Idle => {
                br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M10 2l6 2v5c0 4-2.5 7-6 9-3.5-2-6-5-6-9V4l6-2z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>"#
            }
        }
    };
    gpui_kit::component::Icon::default()
        .data(data)
        .text_color(rgb(color))
        .with_size(gpui_kit::component::Size::Size(px(size)))
}

/// 等宽胶囊按钮：主操作实心状态色（停止、放弃这类会断开连接的用红色），其余是半透明底。
fn button(action: Action, palette: Palette, cx: &mut Context<Island>) -> Stateful<Div> {
    let (background, hover, ink) = match (action.primary, action.command) {
        (true, Command::Stop | Command::Abandon) => {
            (rgb(palette.error), rgb(palette.error), 0xffffff)
        }
        (true, _) => (rgb(palette.ok), rgb(palette.ok), palette.on_ok),
        (false, _) => (rgba(palette.fill), rgba(palette.fill_hover), palette.ink),
    };
    let command = action.command;
    let capsule = div()
        .id(("island-action", command.id()))
        .flex_1()
        .min_w_0()
        .h(px(36.))
        .px(px(10.))
        .flex()
        .items_center()
        .justify_center()
        .rounded_full()
        .bg(background)
        .text_color(rgb(ink))
        .font_weight(FontWeight::SEMIBOLD)
        .child(div().truncate().child(action.label));
    if !action.enabled {
        return capsule.opacity(0.35).on_mouse_down(
            MouseButton::Left,
            cx.listener(|island, _, _, cx| {
                cx.stop_propagation();
                island.press_start(true);
                cx.notify();
            }),
        );
    }
    capsule
        .cursor_pointer()
        .hover(move |style| style.bg(hover).opacity(0.92))
        .active(|style| style.opacity(0.7))
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(|island, _, _, cx| {
                cx.stop_propagation();
                island.press_start(true);
                cx.notify();
            }),
        )
        .on_click(cx.listener(move |island, _, _, cx| {
            cx.stop_propagation();
            if island.take_click() {
                run(command);
            }
        }))
}

/// 客户区左上角在屏幕上的位置（物理像素）。
fn client_origin(hwnd: HWND) -> Option<POINT> {
    let mut origin = POINT::default();
    // SAFETY: `origin` is a writable local; a null or stale handle makes the call fail.
    (!hwnd.is_null() && unsafe { ClientToScreen(hwnd, &mut origin) } != 0).then_some(origin)
}

pub(crate) fn hwnd_of(window: &Window) -> HWND {
    match HasWindowHandle::window_handle(window).map(|handle| handle.as_raw()) {
        Ok(RawWindowHandle::Win32(handle)) => handle.hwnd.get() as HWND,
        _ => null_mut(),
    }
}

/// 去掉 Windows 11 给每个窗口加的 1px 灰边和系统圆角，圆角由岛自己画。
fn strip_frame(hwnd: HWND) {
    let none = DWMWA_COLOR_NONE;
    let corner = DWMWCP_DONOTROUND;
    // SAFETY: `hwnd` is the live island window; each value outlives its call and
    // the size matches the attribute's 4-byte type.
    unsafe {
        DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR as u32, (&raw const none).cast(), 4);
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            (&raw const corner).cast(),
            4,
        );
    }
}

/// 前台是全屏程序（游戏、演示、全屏视频）时不显示岛。
fn fullscreen_in_front() -> bool {
    let mut state = 0;
    // SAFETY: `state` is a writable local.
    let ok = unsafe { SHQueryUserNotificationState(&mut state) } >= 0;
    ok && matches!(
        state,
        QUNS_BUSY | QUNS_RUNNING_D3D_FULL_SCREEN | QUNS_PRESENTATION_MODE
    )
}

/// 主显示器的范围（物理像素）。
fn primary_screen() -> Option<RECT> {
    let mut monitor = MONITORINFO {
        cbSize: size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `monitor` is a writable MONITORINFO with `cbSize` set; the primary
    // monitor contains the origin.
    let found = unsafe {
        GetMonitorInfoW(
            MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY),
            &mut monitor,
        ) != 0
    };
    found.then_some(monitor.rcMonitor)
}

/// 把岛的窗口摆在主显示器顶边、`ratio` 对应的横向位置，按需显示或隐藏。
/// 位置没变时不调用 `SetWindowPos`。
fn place(hwnd: HWND, scale: f32, hidden: bool, ratio: f32) {
    if hwnd.is_null() {
        return;
    }
    // SAFETY: `hwnd` is the live island window owned by this thread; a stale
    // handle only makes the calls fail.
    let visible = unsafe { IsWindowVisible(hwnd) } != 0;
    if hidden {
        if visible {
            // SAFETY: as above.
            unsafe { ShowWindow(hwnd, SW_HIDE) };
        }
        return;
    }
    let Some(screen) = primary_screen() else {
        return;
    };
    let mut rect = RECT::default();
    // SAFETY: as above; `rect` is a writable local.
    let current = unsafe { GetWindowRect(hwnd, &mut rect) } != 0;
    // 用窗口矩形的实际宽度（含系统留的看不见的边框）居中，岛才落在比例对应的位置上；
    // 拖动后记位置（`ratio_of`）用的也是它。
    let width = if current {
        rect.right - rect.left
    } else {
        (model::WINDOW.0 * scale).round() as i32
    };
    let left = model::window_left(screen.left, screen.right - screen.left, width, ratio);
    let top = screen.top + (TOP_GAP * scale).round() as i32;
    if !current || rect.left != left || rect.top != top {
        // SAFETY: as above.
        unsafe {
            SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                left,
                top,
                0,
                0,
                SWP_NOACTIVATE | SWP_NOSIZE,
            )
        };
    }
    if !visible {
        // SAFETY: as above.
        unsafe { ShowWindow(hwnd, SW_SHOWNOACTIVATE) };
    }
}
