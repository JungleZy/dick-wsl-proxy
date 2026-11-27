//! 「已安装应用」独立窗口：列出环境里的图形应用，点一下以默认用户启动。
//!
//! 窗口不自己和后台通信：列表、读取中、失败原因和启动结果都在主界面 [`Desktop`] 里，
//! 「启动」「重新读取」也交给主界面发请求。窗口画的是自己手里的一份 [`Snapshot`]，
//! 从不在重画时读主界面：Windows 会在创建、激活窗口时同步要求它画一帧，那时主界面
//! 往往正在处理点击（状态被占用），去读就会 panic、整个程序退出。快照由主界面打开
//! 窗口时交进来，之后在主界面每次通知（那时它的状态已经放开）时重拍。
//! 所以列表跟着环境页当前查看的环境走：在主窗口点另一个环境，这里换成那个环境的应用。
//!
//! 它是普通窗口（占任务栏、可以和主窗口并排、一直开着当启动器用）。主窗口藏进托盘时
//! 它留着；程序真正退出前要调用 [`close`]，还有窗口开着 gpui 就不会退出进程。

use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};

use windows_sys::Win32::Foundation::HWND;

use gpui_kit::component::{
    Disableable as _, IconName, Sizable as _, TitleBar,
    button::{Button, ButtonVariants as _},
    skeleton::Skeleton,
    spinner::Spinner,
};
use gpui_kit::{prelude::*, *};

use super::components::{app_icon, design_icon, text_tip};
use super::state::Desktop;
use super::theme::{
    AMBER, HOVER, INK, MUTED, PAPER, RULE, RUST, SURFACE, SURFACE_SOFT, TEAL, UI_FONT,
    app_rgb as rgb,
};
use super::views::window_control_button;

const TITLE: &str = "WSL Proxy 已安装应用";
const WIDTH: f32 = 560.;
const HEIGHT: f32 = 520.;
/// 网格格子宽度和图标边长。
const TILE: f32 = 104.;
const ICON: f32 = 48.;

thread_local! {
    static HANDLE: RefCell<Option<AnyWindowHandle>> = const { RefCell::new(None) };
}

/// 应用窗口的 Win32 句柄，托盘找主窗口时据此排除它；没开着时为空。
static WINDOW: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

pub(crate) fn hwnd() -> HWND {
    WINDOW.load(Ordering::Acquire)
}

/// 应用窗口是否开着。主界面据此决定读详情时要不要顺带重读应用列表。
pub(crate) fn is_open() -> bool {
    HANDLE.with(|slot| slot.borrow().is_some())
}

/// 网格里的一个应用。
#[derive(Clone, PartialEq)]
pub(crate) struct AppTile {
    /// 桌面文件 ID，启动时交给后台。
    pub(crate) id: String,
    pub(crate) name: String,
    /// 图标文件在 Windows 上的路径（`\\wsl.localhost\发行版\…`）；找不到图标时是 `None`。
    pub(crate) icon: Option<std::path::PathBuf>,
}

/// 发行版里的绝对路径换成 Windows 经 WSL 网络共享读它的路径。
fn windows_path(distribution: &str, path: &str) -> std::path::PathBuf {
    let mut windows = format!(r"\\wsl.localhost\{distribution}");
    for part in path.split('/').filter(|part| !part.is_empty()) {
        windows.push('\\');
        windows.push_str(part);
    }
    windows.into()
}

/// 窗口要画的全部内容，从主界面拍下来。
#[derive(Clone, Default, PartialEq)]
pub(crate) struct Snapshot {
    /// 列表所属的环境；还没读到列表时是详情页正在看的环境。
    pub(crate) environment: Option<String>,
    /// 还没读到列表时是 `None`。
    pub(crate) apps: Option<Vec<AppTile>>,
    pub(crate) loading: bool,
    pub(crate) error: Option<String>,
    /// 主界面有变更操作在执行（编辑、删除环境等）。
    pub(crate) busy: bool,
    pub(crate) graphics: bool,
    pub(crate) launching: Option<String>,
    pub(crate) result: Option<Result<String, String>>,
    pub(crate) traffic: Option<&'static str>,
    /// 主题会变：主界面切换主题后快照不同，窗口跟着重画。
    pub(crate) dark: bool,
    /// 底色不透明度（百分比），设置里拖动时窗口跟着重画。
    pub(crate) opacity: u32,
}

impl Desktop {
    pub(crate) fn launcher_snapshot(&self) -> Snapshot {
        let listed = self.environment_apps.as_ref();
        let environment = listed
            .and_then(|apps| apps["name"].as_str())
            .or_else(|| {
                self.environment_detail
                    .as_ref()
                    .and_then(|detail| detail["name"].as_str())
            })
            .map(str::to_owned);
        let distribution = listed.and_then(|apps| apps["name"].as_str());
        let apps = listed.and_then(|apps| apps["apps"].as_array()).map(|apps| {
            apps.iter()
                .filter_map(|app| {
                    let id = app["id"].as_str()?;
                    let name = app["name"].as_str().unwrap_or(id);
                    let icon = distribution
                        .zip(app["icon"].as_str())
                        .map(|(distribution, path)| windows_path(distribution, path));
                    Some(AppTile {
                        id: id.to_owned(),
                        name: name.to_owned(),
                        icon,
                    })
                })
                .collect()
        });
        let traffic = environment
            .as_deref()
            .and_then(|name| self.environment_traffic_hint(name));
        Snapshot {
            environment,
            apps,
            loading: self.environment_apps_loading,
            error: self.environment_apps_error.clone(),
            busy: self.busy.is_some(),
            graphics: self.environment_apps_graphics(),
            launching: self.environment_launching.clone(),
            result: self.environment_launch_result.clone(),
            traffic,
            dark: super::theme::is_dark(),
            opacity: super::opacity::percent(),
        }
    }
}

/// 打开应用窗口；已经开着就叫到前面。开不出来不影响主窗口。
/// `snapshot` 由调用方（主界面）给：这时主界面的状态被占用，窗口不能自己去读。
pub(crate) fn open(desktop: Entity<Desktop>, snapshot: Snapshot, cx: &mut App) {
    if let Some(handle) = HANDLE.with(|slot| *slot.borrow()) {
        if handle
            .update(cx, |_, window, _| window.activate_window())
            .is_ok()
        {
            return;
        }
        HANDLE.with(|slot| *slot.borrow_mut() = None);
        WINDOW.store(null_mut(), Ordering::Release);
    }
    let bounds = Bounds::centered(None, size(px(WIDTH), px(HEIGHT)), cx);
    let mut options = TitleBar::window_options();
    options.window_bounds = Some(WindowBounds::Windowed(bounds));
    options.window_min_size = Some(size(px(360.), px(320.)));
    options.window_background = WindowBackgroundAppearance::Blurred;
    let opened = gpui_kit::open_window(options, cx, |window, cx| {
        window.set_window_title(TITLE);
        WINDOW.store(super::island::hwnd_of(window), Ordering::Release);
        window.on_window_should_close(cx, |_, _| {
            HANDLE.with(|slot| *slot.borrow_mut() = None);
            WINDOW.store(null_mut(), Ordering::Release);
            true
        });
        cx.new(|cx| Launcher::new(desktop, snapshot, cx))
    });
    if let Ok((handle, _)) = opened {
        // gpui-kit 的 Root 按主题铺一层不透明底色；它自己的样式最后生效，设成透明，
        // 底色由下面半透明的界面自己画。
        let _ = handle.update(cx, |_, window, cx| {
            gpui_kit::base::Root::update(window, cx, |root, _, cx| {
                root.style().background = Some(transparent_black().into());
                cx.notify();
            });
        });
        HANDLE.with(|slot| *slot.borrow_mut() = Some(handle));
    }
}

/// 关掉应用窗口。主窗口真正关闭前调用。
pub(crate) fn close(cx: &mut App) {
    WINDOW.store(null_mut(), Ordering::Release);
    if let Some(handle) = HANDLE.with(|slot| slot.borrow_mut().take()) {
        let _ = handle.update(cx, |_, window, _| window.remove_window());
    }
}

struct Launcher {
    desktop: WeakEntity<Desktop>,
    snapshot: Snapshot,
    _observe: Subscription,
}

impl Launcher {
    fn new(desktop: Entity<Desktop>, snapshot: Snapshot, cx: &mut Context<Self>) -> Self {
        // 观察回调在主界面更新结束、通知派发时才跑，这时读主界面是安全的。
        let observe = cx.observe(&desktop, |launcher: &mut Self, desktop, cx| {
            let snapshot = desktop.read(cx).launcher_snapshot();
            if snapshot != launcher.snapshot {
                launcher.snapshot = snapshot;
                cx.notify();
            }
        });
        Self {
            desktop: desktop.downgrade(),
            snapshot,
            _observe: observe,
        }
    }
}

fn title_bar(environment: Option<&str>, refresh: AnyElement, opacity: u32) -> Div {
    let title = match environment {
        Some(name) => format!("应用 · {name}"),
        None => "应用".into(),
    };
    div()
        .w_full()
        .h(px(42.))
        .flex()
        .flex_shrink_0()
        .items_center()
        .bg(translucent(SURFACE, opacity))
        .border_b_1()
        .border_color(rgb(RULE))
        .child(
            div()
                .id("launcher-drag-region")
                .flex()
                .items_center()
                .gap(px(10.))
                .px(px(14.))
                .h_full()
                .flex_1()
                .min_w_0()
                .window_control_area(WindowControlArea::Drag)
                .child(app_icon(20.))
                .child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::BOLD)
                        .truncate()
                        .child(title),
                ),
        )
        .child(
            div()
                .h_full()
                .flex()
                .flex_shrink_0()
                .items_center()
                .child(div().px_1().child(refresh))
                .child(window_control_button(
                    WindowControlArea::Min,
                    IconName::WindowMinimize,
                    false,
                ))
                .child(window_control_button(
                    WindowControlArea::Close,
                    IconName::WindowClose,
                    true,
                )),
        )
}

/// 主题色加上设置里的不透明度。窗口用模糊背景，后面的内容模糊后透出来；
/// 文字仍是实色。
fn translucent(color: u32, opacity: u32) -> Rgba {
    Rgba {
        a: opacity as f32 / 100.,
        ..rgb(color)
    }
}

fn note(message: impl Into<SharedString>, color: u32) -> Div {
    div().text_sm().text_color(rgb(color)).child(message.into())
}

/// 没有图标或图标读不出来时的占位：圆角方块里写应用名的第一个字。
fn placeholder(name: &str) -> AnyElement {
    let initial: String = name
        .chars()
        .find(|character| !character.is_whitespace())
        .map(|character| character.to_uppercase().collect())
        .unwrap_or_default();
    div()
        .size(px(ICON))
        .flex()
        .items_center()
        .justify_center()
        .rounded_lg()
        .bg(rgb(SURFACE_SOFT))
        .border_1()
        .border_color(rgb(RULE))
        .text_xl()
        .text_color(rgb(MUTED))
        .child(initial)
        .into_any_element()
}

/// 第一次读取时网格里放的骨架格子数，大约两行。
const SKELETON_TILES: usize = 10;

/// 读取中的网格：和应用格子同样大小的骨架（图标方块加一条名字），一起明暗呼吸。
fn skeleton_grid() -> Div {
    let mut grid = div().flex().flex_wrap().gap_1();
    for _ in 0..SKELETON_TILES {
        grid = grid.child(
            div()
                .w(px(TILE))
                .flex()
                .flex_col()
                .items_center()
                .gap_2()
                .px_1()
                .pt_3()
                .pb_2()
                .child(Skeleton::new().size(px(ICON)).rounded_lg())
                .child(
                    div()
                        .h(px(32.))
                        .w_full()
                        .flex()
                        .justify_center()
                        .child(Skeleton::new().w(px(56.)).h(px(10.)).rounded_sm()),
                ),
        );
    }
    grid
}

/// 一个格子：上面大图标，下面应用名（最多两行）。整格可点。
fn app_tile(
    index: usize,
    app: &AppTile,
    launching: Option<&str>,
    disabled: bool,
    desktop: WeakEntity<Desktop>,
) -> Stateful<Div> {
    let starting = launching == Some(app.id.as_str());
    let icon = match app.icon.clone() {
        Some(path) => {
            let name = app.name.clone();
            img(path)
                .size(px(ICON))
                .object_fit(ObjectFit::Contain)
                .with_fallback(move || placeholder(&name))
                .into_any_element()
        }
        None => placeholder(&app.name),
    };
    let label = if starting {
        "启动中…".to_owned()
    } else {
        app.name.clone()
    };
    let tip = app.name.clone();
    let tile = div()
        .id(("launcher-app", index))
        .w(px(TILE))
        .flex()
        .flex_col()
        .items_center()
        .gap_2()
        .px_1()
        .pt_3()
        .pb_2()
        .rounded_lg()
        .when(disabled && !starting, |tile| tile.opacity(0.5))
        .child(icon)
        .child(
            div()
                .w_full()
                .h(px(32.))
                .text_xs()
                .text_center()
                .line_clamp(2)
                .text_color(rgb(if starting { AMBER } else { INK }))
                .child(label),
        )
        .tooltip(move |window, cx| text_tip(tip.clone(), window, cx));
    if disabled {
        return tile;
    }
    let id = app.id.clone();
    tile.cursor_pointer()
        .hover(|style| style.bg(rgb(HOVER)))
        .on_click(move |_, _, cx| {
            let _ = desktop.update(cx, |desktop, cx| desktop.environment_launch(id.clone(), cx));
        })
}

impl Render for Launcher {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let snapshot = &self.snapshot;
        let environment = snapshot.environment.as_deref();
        let launching = snapshot.launching.as_deref();
        let disabled = !snapshot.graphics || snapshot.busy || launching.is_some();
        let weak = self.desktop.clone();

        // 读取中把刷新按钮换成转圈的加载图标，占同样的位置，标题栏不跳动。
        let refresh = if snapshot.loading {
            div()
                .size(px(28.))
                .flex()
                .items_center()
                .justify_center()
                .child(Spinner::new().small().color(rgb(MUTED).into()))
                .into_any_element()
        } else {
            let weak = weak.clone();
            Button::new("launcher-refresh")
                .icon(design_icon("refresh", 15., MUTED))
                .accessibility_label("重新读取")
                .tooltip("重新读取")
                .ghost()
                .compact()
                .disabled(snapshot.busy || environment.is_none())
                .on_click(move |_, _, cx| {
                    let _ = weak.update(cx, |desktop, cx| desktop.refresh_environment_apps(cx));
                })
                .into_any_element()
        };

        let body = if let Some(error) = snapshot.error.as_ref() {
            note(format!("读取失败：{error}"), AMBER)
        } else if let Some(apps) = snapshot.apps.as_ref() {
            if apps.is_empty() {
                note("没有图形应用", MUTED)
            } else {
                let mut grid = div().flex().flex_wrap().gap_1();
                for (index, app) in apps.iter().enumerate() {
                    grid = grid.child(app_tile(index, app, launching, disabled, weak.clone()));
                }
                grid
            }
        } else if snapshot.loading {
            skeleton_grid()
        } else if environment.is_none() {
            note("先在主窗口选一个环境", MUTED)
        } else {
            note("点右上角读取", MUTED)
        };

        // 顶部最多一行状态：启动结果优先，其次缺 WSLg，再次流量直连。
        let status = match snapshot.result.as_ref() {
            Some(Ok(message)) => Some(note(message.clone(), TEAL)),
            Some(Err(message)) => Some(note(message.clone(), RUST)),
            None if !snapshot.graphics => Some(note("WSLg 不可用", AMBER)),
            None => snapshot.traffic.map(|message| note(message, AMBER)),
        };

        div()
            .size_full()
            .flex()
            .flex_col()
            .font_family(UI_FONT)
            .text_sm()
            .text_color(rgb(INK))
            .bg(translucent(PAPER, snapshot.opacity))
            .child(title_bar(environment, refresh, snapshot.opacity))
            .children(status.map(|status| div().px_3().pt_2().child(status)))
            .child(
                div()
                    .id("launcher-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p_2()
                    .child(body),
            )
    }
}
