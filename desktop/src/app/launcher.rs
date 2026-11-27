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

use gpui_kit::component::{
    Disableable as _, IconName, TitleBar,
    button::{Button, ButtonVariants as _},
};
use gpui_kit::{prelude::*, *};

use super::components::{app_icon, design_icon};
use super::state::Desktop;
use super::theme::{
    AMBER, HOVER, INK, MONO_FONT, MUTED, PAPER, RULE, RUST, SURFACE, SURFACE_SOFT, TEAL, UI_FONT,
    app_rgb as rgb,
};
use super::views::window_control_button;

const TITLE: &str = "WSL Proxy 已安装应用";
const WIDTH: f32 = 460.;
const HEIGHT: f32 = 560.;

thread_local! {
    static HANDLE: RefCell<Option<AnyWindowHandle>> = const { RefCell::new(None) };
}

/// 应用窗口是否开着。主界面据此决定读详情时要不要顺带重读应用列表。
pub(crate) fn is_open() -> bool {
    HANDLE.with(|slot| slot.borrow().is_some())
}

/// 窗口要画的全部内容，从主界面拍下来。
#[derive(Clone, Default, PartialEq)]
pub(crate) struct Snapshot {
    /// 列表所属的环境；还没读到列表时是详情页正在看的环境。
    pub(crate) environment: Option<String>,
    /// `(桌面文件 ID, 显示名)`；`None` 是还没读到。
    pub(crate) apps: Option<Vec<(String, String)>>,
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
        let apps = listed.and_then(|apps| apps["apps"].as_array()).map(|apps| {
            apps.iter()
                .filter_map(|app| {
                    let id = app["id"].as_str()?;
                    let name = app["name"].as_str().unwrap_or(id);
                    Some((id.to_owned(), name.to_owned()))
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
    }
    let bounds = Bounds::centered(None, size(px(WIDTH), px(HEIGHT)), cx);
    let mut options = TitleBar::window_options();
    options.window_bounds = Some(WindowBounds::Windowed(bounds));
    options.window_min_size = Some(size(px(360.), px(320.)));
    let opened = gpui_kit::open_window(options, cx, |window, cx| {
        window.set_window_title(TITLE);
        window.on_window_should_close(cx, |_, _| {
            HANDLE.with(|slot| *slot.borrow_mut() = None);
            true
        });
        cx.new(|cx| Launcher::new(desktop, snapshot, cx))
    });
    if let Ok((handle, _)) = opened {
        HANDLE.with(|slot| *slot.borrow_mut() = Some(handle));
    }
}

/// 关掉应用窗口。主窗口真正关闭前调用。
pub(crate) fn close(cx: &mut App) {
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

fn title_bar(environment: Option<&str>) -> Div {
    let title = match environment {
        Some(name) => format!("已安装应用 · {name}"),
        None => "已安装应用".into(),
    };
    div()
        .w_full()
        .h(px(42.))
        .flex()
        .flex_shrink_0()
        .items_center()
        .bg(rgb(SURFACE))
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

fn note(message: impl Into<SharedString>, color: u32) -> Div {
    div().text_sm().text_color(rgb(color)).child(message.into())
}

/// 一行一个应用：名称、桌面文件 ID，右边写「启动」或「启动中…」。整行可点。
fn app_row(
    index: usize,
    (id, name): &(String, String),
    launching: Option<&str>,
    disabled: bool,
    desktop: WeakEntity<Desktop>,
) -> Stateful<Div> {
    let id = id.clone();
    let name = name.clone();
    let starting = launching == Some(id.as_str());
    let action = if starting { "启动中…" } else { "启动" };
    let row = div()
        .id(("launcher-app", index))
        .flex()
        .items_center()
        .gap_3()
        .px_3()
        .py_2()
        .rounded_md()
        .bg(rgb(SURFACE_SOFT))
        .child(design_icon(
            "play",
            14.,
            if disabled { MUTED } else { TEAL },
        ))
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w_0()
                .child(div().text_sm().truncate().child(name))
                .child(
                    div()
                        .font_family(MONO_FONT)
                        .text_xs()
                        .text_color(rgb(MUTED))
                        .truncate()
                        .child(id.clone()),
                ),
        )
        .child(
            div()
                .flex_shrink_0()
                .text_sm()
                .text_color(rgb(if starting { AMBER } else { MUTED }))
                .child(action),
        );
    if disabled {
        return row;
    }
    row.cursor_pointer()
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

        let header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap_2()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .min_w_0()
                    .child(
                        div()
                            .text_sm()
                            .truncate()
                            .child(environment.unwrap_or("未选择环境").to_owned()),
                    )
                    .children(
                        snapshot
                            .apps
                            .as_ref()
                            .map(|apps| note(format!("{} 个应用", apps.len()), MUTED)),
                    ),
            )
            .child({
                let weak = weak.clone();
                Button::new("launcher-refresh")
                    .icon(design_icon("refresh", 15., MUTED))
                    .accessibility_label("重新读取应用列表")
                    .tooltip("重新读取应用列表")
                    .ghost()
                    .compact()
                    .disabled(snapshot.loading || snapshot.busy || environment.is_none())
                    .on_click(move |_, _, cx| {
                        let _ = weak.update(cx, |desktop, cx| desktop.refresh_environment_apps(cx));
                    })
            });

        let body = if let Some(error) = snapshot.error.as_ref() {
            note(format!("读取应用列表失败：{error}"), AMBER)
        } else if let Some(apps) = snapshot.apps.as_ref() {
            if apps.is_empty() {
                note(
                    "没有找到图形应用。这里只列 .desktop 入口里登记、不在终端里运行的程序。",
                    MUTED,
                )
            } else {
                let mut list = div().flex().flex_col().gap_1();
                for (index, app) in apps.iter().enumerate() {
                    list = list.child(app_row(index, app, launching, disabled, weak.clone()));
                }
                list
            }
        } else if snapshot.loading {
            note("正在读取环境里的应用…", MUTED)
        } else if environment.is_none() {
            note(
                "在主窗口的环境页点一个环境，再点详情右上角的应用按钮。",
                MUTED,
            )
        } else {
            note("还没有读取应用列表，点右上角重新读取。", MUTED)
        };

        let result = snapshot.result.as_ref().map(|result| match result {
            Ok(message) => note(message.clone(), TEAL),
            Err(message) => note(message.clone(), RUST),
        });

        div()
            .size_full()
            .flex()
            .flex_col()
            .font_family(UI_FONT)
            .text_sm()
            .text_color(rgb(INK))
            .bg(rgb(PAPER))
            .child(title_bar(environment))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .gap_2()
                    .p_3()
                    .child(header)
                    .children(
                        (!snapshot.graphics)
                            .then(|| note("WSLg 不可用，无法启动图形应用。", AMBER)),
                    )
                    .children(snapshot.traffic.map(|message| note(message, AMBER)))
                    .children(result)
                    .child(
                        div()
                            .id("launcher-scroll")
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scroll()
                            .child(body),
                    )
                    .child(note(
                        "以环境的默认用户启动；环境没运行时会先启动它。",
                        MUTED,
                    )),
            )
    }
}
