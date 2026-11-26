//! 屏幕顶部的状态岛，外观参照 Apple 灵动岛：吸在屏幕顶边上，两肩用凹圆弧接到顶边，
//! 颜色跟随软件的浅色、深色主题。收起时左端状态图标、右端一小段状态或速率，中间留空；
//! 状态变化、有提醒或鼠标移上去时，平滑地展开成卡片，接管中还列出被接管环境的出口、
//! DNS、UDP 和连接数。按住岛横向拖动可以沿顶边换位置。
//!
//! 岛不自己判断状态：界面每次刷新把托盘用的 [`Snapshot`] 和环境信息交给 [`sync`]，
//! 按钮也和托盘菜单一样先叫出主窗口、再把 [`Command`] 交给界面。点岛本身不做任何事。
//! 窗口是 gpui 的 `PopUp`（置顶、不占任务栏）。
//!
//! 窗口大小固定为 [`model::WINDOW`]，形变动画只在窗口里画；窗口区域（`SetWindowRgn`）
//! 裁成当前形状，所以透明的地方不挡下面窗口的点击。鼠标离开窗口时 gpui 不发悬停回调，
//! 所以展开和收回靠岛自己每 50ms 比较一次光标位置。

mod model;

use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};
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
    CreatePolygonRgn, DeleteObject, GetMonitorInfoW, MONITOR_DEFAULTTOPRIMARY, MONITORINFO,
    MonitorFromPoint, SetWindowRgn, WINDING,
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

use self::model::{Action, Fact, Morph, Presence, Shape, Tone};
pub(crate) use self::model::{Details, Rates};
use super::theme::{PREFERENCES_KEY, UI_FONT};
use super::tray::{Command, Look, Snapshot};

/// 偏好里的开关，与主题放在同一个注册表键下。
const ENABLED_VALUE: &str = "DesktopIsland";
/// 拖动后的位置：窗口中心在主显示器宽度上的比例乘以 10000。
const POSITION_VALUE: &str = "DesktopIslandPosition";
/// 离屏幕顶边的距离：0，岛吸在顶边上。
const TOP_GAP: f32 = 0.;
const TITLE: &str = "WSL Proxy 状态岛";
/// 岛自己看光标的间隔；全屏检测每隔几次才做一次。
const POLL: Duration = Duration::from_millis(50);
const FULLSCREEN_EVERY: u32 = 4;

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
    /// 最近一次设置的窗口区域（物理像素），没变就不重设。
    region: Option<[i32; 4]>,
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
        } else if notice.as_deref() != self.presence.notice() {
            cx.notify();
        }
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
        let mut rect = RECT::default();
        // SAFETY: both out-parameters are writable locals; a stale handle makes the call fail.
        let read = !self.hwnd.is_null()
            && unsafe {
                GetCursorPos(&mut cursor) != 0 && GetWindowRect(self.hwnd, &mut rect) != 0
            };
        if !read {
            return false;
        }
        let x = (cursor.x - rect.left) as f32 / scale - self.left();
        let y = (cursor.y - rect.top) as f32 / scale;
        x >= 0. && x < self.shape.width && y >= 0. && y < self.shape.height
    }

    /// 把能点到的范围裁成当前的刘海轮廓。轮廓向外多扩一点，岛边缘的抗锯齿像素不被裁掉。
    /// 只改命中范围、不要求重绘：重绘由 gpui 自己的下一帧负责，免得闪一下。
    fn clip(&mut self, scale: f32) {
        let s = |value: f32| (value * scale).round() as i32;
        let region = [
            s(self.left()),
            s(self.shape.width),
            s(self.shape.height),
            s(self.shape.radius),
        ];
        if self.hwnd.is_null() || self.region == Some(region) {
            return;
        }
        let points: Vec<POINT> = model::outline(self.shape, self.left(), 1.5)
            .into_iter()
            .map(|(x, y)| POINT { x: s(x), y: s(y) })
            .collect();
        // SAFETY: `points` outlives the call and its length is passed with it; on
        // success the window owns the region, on failure it stays ours and is deleted here.
        unsafe {
            let rgn = CreatePolygonRgn(points.as_ptr(), points.len() as i32, WINDING);
            if !rgn.is_null() && SetWindowRgn(self.hwnd, rgn, 0) == 0 {
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
                    .child(model::trailing(&self.snapshot, self.rates)),
            )
    }

    /// 展开时：左上图标徽章，旁边标题和说明，右上速率；接管中接着列出出口一行、
    /// DNS / UDP / 连接三格；底部一排等宽胶囊按钮。
    fn expanded(&self, tone: Tone, cx: &mut Context<Self>) -> Div {
        let palette = self.palette();
        let caption = model::caption(&self.snapshot, self.presence.notice());
        let buttons = model::actions(&self.snapshot)
            .into_iter()
            .map(|action| button(action, palette, cx));
        let rates = self
            .rates
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
                            .line_clamp(2)
                            .child(caption),
                    ),
            )
            .children(rates);
        let details = self.details.as_ref().map(|details| {
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
fn shoulder(edge: f32, right: bool, color: u32) -> Div {
    let f = model::FILLET;
    // 圆环要盖住方框里离圆心最远的角（约 1.45 倍半径处）。
    let band = f * 0.5 + 2.;
    let outer = f + band;
    let (left, center) = if right {
        (edge - 1., f + 1.)
    } else {
        (edge - f, 0.)
    };
    let mut ring = div()
        .absolute()
        .left(px(center - outer))
        .top(px(f - outer))
        .size(px(outer * 2.))
        .rounded_full()
        .border_color(rgb(color));
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
        .w(px(f + 1.))
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
        self.clip(window.scale_factor());
        let palette = self.palette();
        let tone = Tone::of(&self.snapshot);
        let (compact, full) = fades(m);
        let content = if full > 0. {
            self.expanded(tone, cx).opacity(full)
        } else {
            self.compact(tone).opacity(compact)
        };
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
                    .bg(rgb(palette.bg))
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
    }
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

fn hwnd_of(window: &Window) -> HWND {
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
    let width = (model::WINDOW.0 * scale).round() as i32;
    let left = model::window_left(screen.left, screen.right - screen.left, width, ratio);
    let top = screen.top + (TOP_GAP * scale).round() as i32;
    let mut rect = RECT::default();
    // SAFETY: as above; `rect` is a writable local.
    let current = unsafe { GetWindowRect(hwnd, &mut rect) } != 0;
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
