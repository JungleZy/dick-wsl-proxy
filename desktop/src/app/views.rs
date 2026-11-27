//! GPUI Kit 应用外壳和页面导航。

use gpui_kit::base::Selectable as _;
use gpui_kit::component::{
    Disableable as _, Icon, IconName, Sizable as _, WindowExt as _,
    button::{Button, ButtonGroup, ButtonVariants as _},
    checkbox::Checkbox,
    dialog::{DialogEntrance, DialogFooter},
    group_box::GroupBoxVariant,
    input::{Input, Textarea},
    progress::Progress,
    resizable::{h_resizable, resizable_panel},
    select::Select,
    setting::{SettingGroup, SettingItem, SettingPage, Settings},
};
use gpui_kit::{prelude::*, *};
use serde_json::Value;
use std::path::Path;
use std::rc::Rc;

use super::backend::Kind;
use super::components::{
    StatusTone, Tip, app_icon, badge, design_icon, icon, status_chip, status_dot, status_icon,
    text, text_tip,
};
use super::drafts::{SaveScope, names_target};
use super::environment_facts::{self, Component, ComponentState, Systemd};
use super::model::{EnvironmentEditor, Field, LogFilter, Page, RuntimeLog, UiAction};
use super::state::Desktop;
use super::theme::{
    ACCENT, ACCENT_SOFT, AMBER, HOVER, INK, MONO_FONT, MUTED, PAPER, PRIMARY, RULE, RUST,
    SELECTED_BG, SIDEBAR_BG, SUCCESS_BG, SURFACE, SURFACE_SOFT, TEAL, WARNING_BG, app_rgb as rgb,
};

const LOG_ROW_HEIGHT: f32 = 54.;

/// Editing an environment enables systemd and then terminates the distribution.
const EDIT_RESTART_WARNING: &str =
    "保存后会开启 systemd 并重启该发行版，其中正在运行的程序会被关闭，请先保存好工作。";
/// The edit form reruns the setup script; with Chrome or the input method
/// selected it resets the system language. Changing only the timezone does not.
const EDIT_LANGUAGE_NOTE: &str = "勾了 Chrome 或中文输入法时，保存会把系统语言设为 en_US（LANG=en_US.UTF-8、LANGUAGE=en_US:en）。";

pub(crate) fn card_header(title: &'static str, caption: &'static str) -> Div {
    let mut title_view = div()
        .flex()
        .flex_col()
        .gap_1()
        .child(div().text_sm().child(title));
    if !caption.is_empty() {
        title_view = title_view.child(div().text_sm().text_color(rgb(MUTED)).child(caption));
    }
    div()
        .flex()
        .items_start()
        .justify_between()
        .gap_3()
        .child(title_view)
}

/// 对话框标题：12px、常规字重。直接传字符串时组件库会用 1rem 半粗体，和正文不一致。
pub(crate) fn dialog_title(title: &'static str) -> Div {
    div().text_sm().font_weight(FontWeight::NORMAL).child(title)
}

pub(crate) fn card(title: &'static str, caption: &'static str, body: impl IntoElement) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_3()
        .bg(rgb(SURFACE))
        .border_1()
        .border_color(rgb(RULE))
        .rounded_md()
        .child(card_header(title, caption))
        .child(body)
}

/// 「刚刚检查」「3 分钟前检测」这类相对时间。
pub(crate) fn elapsed_label(at: std::time::Instant, verb: &str) -> String {
    let seconds = at.elapsed().as_secs();
    if seconds < 5 {
        format!("刚刚{verb}")
    } else if seconds < 60 {
        format!("{seconds} 秒前{verb}")
    } else if seconds < 3600 {
        format!("{} 分钟前{verb}", seconds / 60)
    } else {
        format!("{} 小时前{verb}", seconds / 3600)
    }
}

pub(crate) fn key_value(label: &'static str, value: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .items_center()
        .min_h(px(38.))
        .border_b_1()
        .border_color(rgb(RULE))
        .child(
            div()
                .w(px(112.))
                .flex_shrink_0()
                .text_sm()
                .text_color(rgb(MUTED))
                .child(label),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .text_sm()
                .truncate()
                .child(value.into()),
        )
}

pub(crate) fn chart_card(
    title: &'static str,
    caption: &'static str,
    body: impl IntoElement,
) -> Div {
    card(title, caption, body)
}

const READY: (&str, u32, u32) = ("已就绪", TEAL, SUCCESS_BG);
const NOT_READ: (&str, u32, u32) = ("未读取", MUTED, SURFACE_SOFT);

/// 环境详情里的一项：名称和状态标签同一行，下一行写用途或缺了什么（可换行）。
fn environment_feature(
    label: &'static str,
    (status, color, background): (&'static str, u32, u32),
    detail: impl Into<SharedString>,
) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .flex_1()
        .min_w(px(150.))
        .p_2()
        .bg(rgb(SURFACE_SOFT))
        .rounded_md()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap_2()
                .child(div().text_sm().child(label))
                .child(badge(status, color, background)),
        )
        .child(div().text_sm().text_color(rgb(MUTED)).child(detail.into()))
}

/// 可选组件：齐了写用途，缺东西时写缺了什么。
fn component_feature(label: &'static str, component: Component, purpose: &'static str) -> Div {
    match component.state {
        ComponentState::Ready => environment_feature(label, READY, purpose),
        ComponentState::Incomplete => environment_feature(
            label,
            ("需要补齐", AMBER, WARNING_BG),
            component.gaps.join("；"),
        ),
        // 自己装的不推「编辑 → 保存设置」，只写出跟本工具装的相比缺什么。
        ComponentState::Foreign => environment_feature(
            label,
            ("手动安装", MUTED, SURFACE_SOFT),
            format!("非本工具安装：{}", component.gaps.join("；")),
        ),
        ComponentState::Missing => {
            environment_feature(label, ("未安装", MUTED, SURFACE_SOFT), purpose)
        }
        ComponentState::Unknown => environment_feature(label, NOT_READ, purpose),
    }
}

/// 接管要用的命令：只报在不在；能不能用（比如是不是 legacy 版本）由预检判断。
fn takeover_tool(label: &'static str, present: Option<bool>, purpose: &'static str) -> Div {
    match present {
        Some(true) => environment_feature(label, ("已安装", TEAL, SUCCESS_BG), purpose),
        Some(false) => environment_feature(label, ("未安装", AMBER, WARNING_BG), purpose),
        None => environment_feature(label, NOT_READ, purpose),
    }
}

fn environment_info(label: &'static str, value: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .flex_1()
        .min_w(px(128.))
        .p_2()
        .bg(rgb(SURFACE_SOFT))
        .rounded_md()
        .child(div().text_sm().text_color(rgb(MUTED)).child(label))
        .child(
            div()
                .font_family(MONO_FONT)
                .text_sm()
                .truncate()
                .child(value.into()),
        )
}

fn theme_toggle_button(cx: &Context<Desktop>) -> Button {
    let (icon, label) = if super::theme::is_dark() {
        ("sun", "切换到白天主题")
    } else {
        ("moon", "切换到黑夜主题")
    };
    Button::new("title-theme")
        .icon(design_icon(icon, 16., MUTED))
        .accessibility_label(label)
        .tooltip(label)
        .ghost()
        .compact()
        .on_click(cx.listener(|_, _, _, cx| {
            super::theme::toggle(cx);
            cx.notify();
        }))
}

pub(crate) fn window_control_button(
    area: WindowControlArea,
    icon: IconName,
    close: bool,
) -> impl IntoElement {
    div()
        .id(if close {
            "window-close"
        } else {
            "window-minimize"
        })
        .w(px(42.))
        .h_full()
        .flex()
        .flex_shrink_0()
        .items_center()
        .justify_center()
        .text_color(rgb(INK))
        .window_control_area(area)
        .when(close, |this| {
            this.hover(|style| style.bg(rgb(RUST)).text_color(rgb(SURFACE)))
                .active(|style| style.bg(rgb(RUST)).text_color(rgb(SURFACE)))
        })
        .when(!close, |this| {
            this.hover(|style| style.bg(rgb(SURFACE_SOFT)))
                .active(|style| style.bg(rgb(RULE)))
        })
        .child(Icon::new(icon).small())
}

impl Desktop {
    fn title_bar(&self, cx: &Context<Self>) -> Div {
        div()
            .w_full()
            .h(px(42.))
            .flex()
            .items_center()
            .bg(rgb(SURFACE))
            .border_b_1()
            .border_color(rgb(RULE))
            .child(
                div()
                    .id("title-drag-region")
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .px(px(14.))
                    .h_full()
                    .flex_1()
                    .window_control_area(WindowControlArea::Drag)
                    .child(app_icon(23.))
                    .child(
                        div()
                            .text_sm()
                            .font_weight(FontWeight::BOLD)
                            .child("WSL Proxy"),
                    )
                    .child(div().flex_1()),
            )
            .child(
                div()
                    .h_full()
                    .flex()
                    .flex_shrink_0()
                    .items_center()
                    .child(theme_toggle_button(cx))
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

    /// 切到某一页，并像从侧栏进入一样读这一页需要的数据。侧栏、首页主按钮和托盘菜单共用。
    pub(crate) fn open_page(&mut self, page: Page, cx: &mut Context<Self>) {
        self.page = page;
        match page {
            Page::Overview => self.refresh_events(cx),
            // 切到环境页不自动读详情：读详情要在发行版里跑检查，没启动的会被拉起来。
            Page::Environment | Page::Policy => {}
            Page::Connection => self.refresh_connection_history(cx),
            Page::Logs => self.refresh_logs(cx),
            Page::Settings => self.check_wsl_platform(cx),
        }
        cx.notify();
    }

    fn nav_button(
        &self,
        page: Page,
        index: usize,
        label: &'static str,
        icon_path: &'static str,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let id = match page {
            Page::Overview => "nav-overview",
            Page::Environment => "nav-environment",
            Page::Policy => "nav-policy",
            Page::Connection => "nav-connection",
            Page::Logs => "nav-logs",
            Page::Settings => "nav-settings",
        };
        let icon_color = if self.page == page { ACCENT } else { MUTED };
        let mut button = div()
            .id(id)
            .role(Role::Button)
            .aria_label(label)
            .track_focus(&self.nav_focus[index])
            .tab_stop(true)
            .focus_visible(|style| style.border_1().border_color(rgb(ACCENT)))
            .flex()
            .items_center()
            .gap_2()
            .w_full()
            .h(px(40.))
            .px(px(6.))
            .rounded_md()
            .text_sm()
            .on_click(cx.listener(move |this, _, _, cx| this.open_page(page, cx)))
            .on_key_down(cx.listener(move |this, event: &KeyDownEvent, _, cx| {
                if matches!(event.keystroke.key.as_str(), "enter" | "space") {
                    this.open_page(page, cx);
                }
            }));
        button = if self.page == page {
            button.bg(rgb(ACCENT_SOFT)).text_color(rgb(ACCENT))
        } else {
            button
                .text_color(rgb(INK))
                .hover(|style| style.bg(rgb(HOVER)))
        };
        button
            .child(design_icon(icon_path, 20., icon_color))
            .child(label)
    }

    /// 窗口固定 980×700，侧栏固定 88px，图标加文字。
    fn sidebar(&self, cx: &Context<Self>) -> Div {
        let pages = [
            (Page::Overview, 0, "首页", "dashboard"),
            (Page::Environment, 1, "环境", "environment"),
            (Page::Policy, 2, "规则", "policy"),
            (Page::Connection, 3, "连接", "connection"),
            (Page::Logs, 4, "日志", "logs"),
            (Page::Settings, 5, "设置", "settings"),
        ];
        let mut navigation = div().flex().flex_col().gap_1().px_2().pt_3();
        for (page, index, label, icon_path) in pages {
            navigation = navigation.child(self.nav_button(page, index, label, icon_path, cx));
        }
        div()
            .flex()
            .flex_col()
            .h_full()
            .w(px(88.))
            .flex_shrink_0()
            .bg(rgb(SIDEBAR_BG))
            .border_r_1()
            .border_color(rgb(RULE))
            .child(navigation)
            .child(div().flex_1())
    }

    fn status_bar(&self, cx: &Context<Self>) -> Div {
        let online_tone = if self.status_valid {
            StatusTone::Ok
        } else {
            StatusTone::Error
        };
        let online_label = if self.status_valid {
            "后台在线"
        } else {
            "后台未连接，点击重新连接"
        };
        // 未接管是常态，用未启用的浅灰；接管中才用绿色，两者不能长得一样。
        let (idle_label, idle_tone) = match self.phase() {
            "idle" => ("未接管", StatusTone::Off),
            "forwarding_managed" => ("接管中", StatusTone::Ok),
            "forwarding_scoped" => ("诊断转发中", StatusTone::Warn),
            "recovery_required" => ("需要恢复", StatusTone::Error),
            _ => ("状态未知", StatusTone::Off),
        };
        let (storage_label, storage_tone) = if self.profile_exists {
            ("已加载", StatusTone::Ok)
        } else {
            ("待初始化", StatusTone::Off)
        };
        div()
            .h(px(34.))
            .flex()
            .items_center()
            .gap_1()
            .px_5()
            .bg(rgb(SURFACE))
            .border_t_1()
            .border_color(rgb(RULE))
            .child(
                // 图标作为子元素放进按钮：用 `.icon()` 会被缩成按钮的图标尺寸，比旁边的图标小一圈。
                Button::new("status-online")
                    .child(status_chip("online", online_tone))
                    .accessibility_label(online_label)
                    .tooltip(online_label)
                    .ghost()
                    .compact()
                    .on_click(cx.listener(|this, _, _, cx| this.refresh_or_reconnect(cx))),
            )
            .child(status_icon(
                "status-idle",
                "idle",
                Tip::new("接管状态").row("状态", idle_label),
                idle_tone,
            ))
            .child(status_icon(
                "status-storage",
                "storage",
                Tip::new("SQLite 配置").row("状态", storage_label),
                storage_tone,
            ))
            .children(self.health_icons())
            .child(self.status_observations())
            .child(div().flex_1())
            .children(self.update_chip(cx))
            .child(
                div()
                    .font_family(MONO_FONT)
                    .text_sm()
                    .text_color(rgb(MUTED))
                    .child(format!("v{}", env!("CARGO_PKG_VERSION"))),
            )
    }

    /// 全局错误条：操作失败的原因在每个页面顶部都能看到，直到用户关掉或下一次操作开始。
    /// 环境页、连接页、日志页本身没有显示页面提示的位置，没有它这些失败点了像没反应。
    fn error_banner(&self, cx: &Context<Self>) -> Option<Div> {
        if !self.error || self.notice.is_empty() {
            return None;
        }
        let tooltip: SharedString = self.notice.clone().into();
        Some(
            div()
                .flex()
                .flex_shrink_0()
                .items_center()
                .gap_2()
                .mx_3()
                .mt_3()
                .pl_3()
                .pr_1()
                .py_1()
                .bg(rgb(super::theme::DANGER_BG))
                .rounded_md()
                .text_color(rgb(RUST))
                .child(design_icon("info", 16., RUST))
                .child(
                    div()
                        .id("global-error-text")
                        .flex_1()
                        .min_w_0()
                        .truncate()
                        .child(self.notice.clone())
                        .tooltip(move |window, cx| text_tip(tooltip.clone(), window, cx)),
                )
                .child(
                    Button::new("global-error-dismiss")
                        .icon(design_icon("close", 15., RUST))
                        .accessibility_label("关闭错误提示")
                        .tooltip("关闭错误提示")
                        .ghost()
                        .compact()
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.error = false;
                            cx.notify();
                        })),
                ),
        )
    }

    fn environment_progress(&self) -> Option<Div> {
        let creating = self.busy == Some(Kind::EnvironmentCreate);
        let editing = self.busy == Some(Kind::EnvironmentEdit);
        if !creating && !editing {
            return None;
        }
        if self.environment_timezone_only {
            return None;
        }
        let elapsed = self
            .environment_started
            .map(|started| started.elapsed())
            .unwrap_or_default();
        // 文件在后台线程读，这里只用这次操作最近一次读到的结果。
        let progress = self
            .environment_progress_snapshot
            .as_ref()
            .filter(|progress| progress.epoch == self.epoch);
        let target_ready = creating && progress.is_some_and(|progress| progress.target_ready);
        let elapsed_seconds = elapsed.as_secs();
        // 只有后台写出的进度文件是真实进度。还没写出来时如实说在等，不按已用时间猜阶段和百分比；
        // 安装目录是否已建好是能直接看到的事实，可以用。
        let (percent, stage, detail) = match progress.and_then(|progress| progress.marker.clone()) {
            Some((percent, stage, detail)) => (Some(percent), stage, detail),
            None if creating && target_ready => (
                None,
                "环境目录已创建".to_owned(),
                format!("正在等待后台报告进度（已用时 {elapsed_seconds} 秒）"),
            ),
            None => (
                None,
                "等待后台报告进度".to_owned(),
                format!("后台还没有报告进度（已用时 {elapsed_seconds} 秒）"),
            ),
        };
        let reached = |threshold: u8| percent.is_some_and(|percent| percent >= threshold);
        let mut steps = if creating {
            vec![
                ("校验输入", true, percent.is_some() || target_ready),
                ("下载发行版", true, target_ready),
                ("安装环境", true, target_ready),
                ("初始化用户", true, false),
            ]
        } else {
            vec![("准备组件", true, reached(10))]
        };
        steps.extend([
            (
                "安装 zsh",
                self.environment_zsh,
                reached(if creating { 90 } else { 38 }),
            ),
            (
                "安装 Chrome",
                self.environment_chrome,
                reached(if creating { 90 } else { 60 }),
            ),
            (
                "中文输入法",
                self.environment_chinese,
                reached(if creating { 90 } else { 80 }),
            ),
        ]);
        steps.push(("检查环境", true, false));
        let mut step_view = div().flex().flex_col().gap_1();
        for (name, selected, done) in steps {
            let label = if selected {
                name.to_owned()
            } else {
                format!("{name} · 未选择")
            };
            step_view = step_view.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(status_dot(if selected && done { TEAL } else { RULE }))
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(if selected && done { INK } else { MUTED }))
                            .child(label),
                    ),
            );
        }
        // 一条进度条：有真实百分比时显示百分比，没有时只显示「进行中」的动画条。
        let bar = match percent {
            Some(percent) => div()
                .h(px(8.))
                .w_full()
                .bg(rgb(SURFACE_SOFT))
                .rounded_full()
                .child(
                    div()
                        .h(px(8.))
                        .w(relative(percent as f32 / 100.))
                        .bg(rgb(ACCENT))
                        .rounded_full(),
                )
                .into_any_element(),
            None => Progress::new("environment-stage-loading")
                .loading(true)
                .accessibility_label("正在等待后台报告进度")
                .into_any_element(),
        };
        Some(
            div()
                .flex()
                .flex_col()
                .gap_2()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(div().text_sm().child(stage))
                        .children(percent.map(|percent| {
                            div()
                                .font_family(super::theme::MONO_FONT)
                                .text_sm()
                                .text_color(rgb(ACCENT))
                                .child(format!("{percent}%"))
                        })),
                )
                .child(bar)
                .child(div().text_sm().text_color(rgb(MUTED)).child(detail))
                .child(step_view),
        )
    }

    fn loading_dialog_body(&self) -> Div {
        if let Some(progress) = self.environment_progress() {
            return progress;
        }
        // 读环境详情不改页面提示，这里显示固定文字，免得把上一条结果当成进展。
        let message = if self.busy.is_none() && self.reading_kind == Some(Kind::EnvironmentView) {
            "正在读取环境详情…".to_owned()
        } else {
            self.notice.clone()
        };
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(status_dot(ACCENT))
                    .child(div().text_sm().child(message)),
            )
            .child(
                Progress::new("operation-loading")
                    .loading(true)
                    .accessibility_label("正在加载"),
            )
    }

    pub(crate) fn open_loading_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.loading_dialog_open {
            return;
        }
        self.loading_dialog_open = true;
        let view = cx.entity().clone();
        window.open_dialog(cx, move |dialog, _, cx| {
            let this = view.read(cx);
            let title = match this.busy {
                Some(Kind::EnvironmentCreate) => "创建环境",
                Some(Kind::EnvironmentEdit) if this.environment_timezone_only => "更新时区",
                Some(Kind::EnvironmentEdit) => "安装组件",
                Some(Kind::EnvironmentDelete) => "删除环境",
                Some(Kind::WslUpdate) => "升级 WSL 平台",
                Some(_) => "正在处理",
                None if this.pending_prepare.is_some() => "启动前检查",
                None if this.reading_kind == Some(Kind::EnvironmentView) => "读取环境详情",
                None if this.reading => "正在加载",
                _ => "正在处理",
            };
            dialog
                .w(px(440.))
                .title(dialog_title(title))
                .entrance(DialogEntrance::Fade)
                .overlay(true)
                .overlay_closable(false)
                .keyboard(false)
                .close_button(false)
                .child(this.loading_dialog_body())
        });
    }

    pub(crate) fn open_environment_result_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.environment_result_dialog_open {
            return;
        }
        let Some(result) = self.environment_result_pending.take() else {
            return;
        };
        self.environment_result_dialog_open = true;
        let title = if result.timezone_only {
            if result.success {
                "时区已更新"
            } else {
                "时区更新失败"
            }
        } else if result.success {
            match result.kind {
                Kind::EnvironmentCreate => "环境创建成功",
                Kind::EnvironmentEdit => "环境设置已更新",
                Kind::EnvironmentDelete => "环境删除成功",
                Kind::WslUpdate => "WSL 升级完成",
                _ => "环境操作完成",
            }
        } else {
            match result.kind {
                Kind::EnvironmentCreate => "环境创建失败",
                Kind::EnvironmentEdit => "环境设置失败",
                Kind::EnvironmentDelete => "环境删除失败",
                Kind::WslUpdate => "WSL 升级失败",
                _ => "环境操作失败",
            }
        };
        let icon_color = if result.success { TEAL } else { RUST };
        let icon_name = if result.success { "check" } else { "info" };
        let message = result.message;
        let view = cx.entity().clone();
        let close_view = view.clone();
        let finish_view = view.clone();
        window.open_alert_dialog(cx, move |dialog, _, _| {
            dialog
                .w(px(520.))
                .title(dialog_title(title))
                .icon(design_icon(icon_name, 22., icon_color))
                .description(div().text_sm().child(message.clone()))
                .confirm()
                .ok_text("知道了")
                .show_cancel(false)
                .on_ok({
                    let finish_view = finish_view.clone();
                    move |_, _, cx| {
                        finish_view.update(cx, |this, cx| {
                            this.environment_result_dialog_open = false;
                            cx.notify();
                        });
                        true
                    }
                })
                .on_close({
                    let close_view = close_view.clone();
                    move |_, _, cx| {
                        close_view.update(cx, |this, cx| {
                            this.environment_result_dialog_open = false;
                            cx.notify();
                        });
                    }
                })
        });
    }

    pub(crate) fn open_backup_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.dialog_error = None;
        let view = cx.entity().clone();
        window.open_dialog(cx, move |dialog, _, cx| {
            let this = view.read(cx);
            let picker_view = view.clone();
            let submit_view = view.clone();
            let cancel_view = view.clone();
            dialog
                .w(px(520.))
                .title(dialog_title("备份环境"))
                .overlay(true)
                .overlay_closable(false)
                .keyboard(false)
                .close_button(false)
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(div().text_sm().child("选择新的 rootfs tar 输出路径。"))
                        .child(this.field(
                            "备份文件",
                            "目标文件不能已存在。",
                            &this.fields.environment_backup,
                            false,
                        ))
                        .child(
                            Button::new("environment-backup-pick")
                                .icon(design_icon("folder", 15., MUTED))
                                .label("选择位置")
                                .outline()
                                .on_click(move |_, window, cx| {
                                    picker_view.update(cx, |this, cx| {
                                        this.environment_pick_backup(window, cx);
                                    });
                                }),
                        )
                        .when_some(this.dialog_error.clone(), |body, error| {
                            body.child(div().text_sm().text_color(rgb(RUST)).child(error))
                        }),
                )
                .footer(
                    DialogFooter::new()
                        .child(
                            Button::new("environment-backup-cancel")
                                .icon(design_icon("close", 15., MUTED))
                                .label("取消")
                                .on_click(move |_, window, cx| {
                                    window.close_dialog(cx);
                                    cancel_view.update(cx, |this, cx| {
                                        this.backup_dialog_open = false;
                                        cx.notify();
                                    });
                                }),
                        )
                        .child(
                            Button::new("environment-backup-submit")
                                .icon(design_icon("archive", 15., SURFACE))
                                .label("开始备份")
                                .primary()
                                .on_click(move |_, window, cx| {
                                    let submitted = submit_view
                                        .update(cx, |this, cx| this.environment_backup_submit(cx));
                                    if submitted {
                                        window.close_dialog(cx);
                                        submit_view.update(cx, |this, cx| {
                                            this.backup_dialog_open = false;
                                            cx.notify();
                                        });
                                    }
                                }),
                        ),
                )
        });
    }

    pub(crate) fn open_backup_result_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.backup_result_dialog_open {
            return;
        }
        self.backup_result_dialog_open = true;
        let view = cx.entity().clone();
        window.open_dialog(cx, move |dialog, _, cx| {
            let this = view.read(cx);
            let path = this
                .backup_result_path
                .clone()
                .unwrap_or_else(|| "未读取备份路径".into());
            let reveal_path = path.clone();
            let close_view = view.clone();
            let reveal_view = view.clone();
            let dismiss_view = view.clone();
            dialog
                .w(px(520.))
                .title(dialog_title("备份完成"))
                .overlay(true)
                .overlay_closable(true)
                .keyboard(true)
                // Esc、点遮罩和右上角关闭都走这里；不复位的话之后的备份不会再弹结果框。
                .on_close(move |_, _, cx| {
                    dismiss_view.update(cx, |this, cx| {
                        this.backup_result_dialog_open = false;
                        cx.notify();
                    });
                })
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(div().text_sm().child("环境备份已完成。"))
                        .child(
                            div()
                                .p_2()
                                .bg(rgb(SURFACE_SOFT))
                                .rounded_md()
                                .font_family(MONO_FONT)
                                .text_sm()
                                .truncate()
                                .child(path),
                        ),
                )
                .footer(
                    DialogFooter::new()
                        .child(
                            Button::new("environment-backup-result-close")
                                .icon(design_icon("close", 15., MUTED))
                                .label("关闭")
                                .on_click(move |_, window, cx| {
                                    window.close_dialog(cx);
                                    close_view.update(cx, |this, cx| {
                                        this.backup_result_dialog_open = false;
                                        cx.notify();
                                    });
                                }),
                        )
                        .child(
                            Button::new("environment-backup-result-reveal")
                                .icon(design_icon("folder", 15., SURFACE))
                                .label("打开备份位置")
                                .primary()
                                .on_click(move |_, window, cx| {
                                    cx.reveal_path(Path::new(&reveal_path));
                                    window.close_dialog(cx);
                                    reveal_view.update(cx, |this, cx| {
                                        this.backup_result_dialog_open = false;
                                        cx.notify();
                                    });
                                }),
                        ),
                )
        });
    }

    pub(crate) fn open_timezone_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.timezone_dialog_open {
            return;
        }
        self.timezone_dialog_open = true;
        self.dialog_error = None;
        let current_timezone = Self::field_value(&self.fields.environment_timezone, cx);
        if let Some(current_timezone) = super::timezones::timezone_value(&current_timezone) {
            self.timezone_select.update(cx, |state, cx| {
                state.set_selected_value(&current_timezone, window, cx);
            });
        }
        let view = cx.entity().clone();
        window.open_dialog(cx, move |dialog, _, cx| {
            let this = view.read(cx);
            let save_view = view.clone();
            let cancel_view = view.clone();
            dialog
                .w(px(520.))
                .title(dialog_title("设置时区"))
                .overlay(true)
                .overlay_closable(false)
                .keyboard(false)
                .close_button(false)
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(
                            div()
                                .text_sm()
                                .text_color(rgb(MUTED))
                                .child("按国家分组，可搜索城市或时区名称。"),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(rgb(AMBER))
                                .child(EDIT_RESTART_WARNING),
                        )
                        .child(
                            Select::new(&this.timezone_select)
                                .placeholder("选择时区")
                                .accessibility_label("时区")
                                .menu_width(px(440.))
                                .menu_max_h(px(360.)),
                        )
                        .when_some(this.dialog_error.clone(), |body, error| {
                            body.child(div().text_sm().text_color(rgb(RUST)).child(error))
                        }),
                )
                .footer(
                    DialogFooter::new()
                        .child(
                            Button::new("timezone-cancel")
                                .icon(design_icon("close", 15., MUTED))
                                .label("取消")
                                .on_click(move |_, window, cx| {
                                    window.close_dialog(cx);
                                    cancel_view.update(cx, |this, cx| {
                                        this.timezone_dialog_open = false;
                                        cx.notify();
                                    });
                                }),
                        )
                        .child(
                            Button::new("timezone-save")
                                .icon(design_icon("check", 15., SURFACE))
                                .label("保存时区")
                                .primary()
                                .on_click(move |_, window, cx| {
                                    let saved = save_view
                                        .update(cx, |this, cx| this.environment_timezone_save(cx));
                                    if saved {
                                        window.close_dialog(cx);
                                        save_view.update(cx, |this, cx| {
                                            this.timezone_dialog_open = false;
                                            cx.notify();
                                        });
                                    }
                                }),
                        ),
                )
        });
    }

    fn environment_editor_card(&self, creating: bool, locked: bool, cx: &Context<Self>) -> Div {
        let mut body = div().flex().flex_col().gap_3().flex_1().min_h_0();
        if creating {
            body = body.child(self.compact_field(
                "环境名称",
                "environment-name-help",
                "只能使用字母、数字、点、下划线和短横线，且必须以字母或数字开头。",
                &self.fields.environment_name,
            ));
        } else {
            body = body.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .p_2()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .child(div().text_sm().text_color(rgb(MUTED)).child("环境名称"))
                    .child(
                        div().text_sm().font_family(MONO_FONT).child(
                            self.environment_edit_target
                                .clone()
                                .unwrap_or_else(|| "未命名环境".into()),
                        ),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(MUTED))
                            .child("发行版名称不可在此修改。"),
                    ),
            );
        }
        if creating {
            body = body
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(self.field_label(
                            "发行版",
                            "environment-distribution-help",
                            "从微软 WSL 官方发行版列表中选择。",
                        ))
                        .child(
                            Select::new(&self.environment_distribution_select)
                                .placeholder("选择官方发行版")
                                .accessibility_label("发行版")
                                .menu_width(px(360.))
                                .menu_max_h(px(280.))
                                .disabled(locked),
                        ),
                )
                .child(self.field_with_action(
                    "安装目录",
                    "选择父目录，系统会自动创建环境名称子目录。",
                    &self.fields.environment_install,
                    self.button(
                        "env-pick-install",
                        "选择目录",
                        UiAction::EnvironmentPickInstall,
                        locked,
                        cx,
                    ),
                ))
                .child(div().text_sm().text_color(rgb(MUTED)).child({
                    let base = Self::field_value(&self.fields.environment_install, cx);
                    let name = Self::field_value(&self.fields.environment_name, cx);
                    if base.is_empty() || name.is_empty() {
                        "实际路径将在填写父目录和环境名称后生成。".to_owned()
                    } else {
                        format!("实际路径 {}", Self::environment_install_path(&base, &name))
                    }
                }))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_3()
                        .child(
                            self.compact_field(
                                "默认用户名",
                                "environment-username-help",
                                "创建后会作为 WSL 默认用户。",
                                &self.fields.environment_username,
                            )
                            .flex_1()
                            .min_w_0(),
                        )
                        .child(
                            self.compact_secret_field(
                                "默认用户密码",
                                "environment-password-help",
                                "用于登录该 Linux 用户。",
                                &self.fields.environment_password,
                            )
                            .flex_1()
                            .min_w_0(),
                        ),
                );
        }
        body = body.child(
            div()
                .flex()
                .flex_col()
                .gap_2()
                .child(div().text_sm().child("安装组件"))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_2()
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(150.))
                                .p_2()
                                .bg(rgb(SURFACE_SOFT))
                                .rounded_md()
                                .child(
                                    Checkbox::new("env-install-zsh")
                                        .label("安装 zsh")
                                        .checked(self.environment_zsh)
                                        .disabled(locked || (!creating && self.environment_zsh))
                                        .on_click(cx.listener(|this, checked, _, cx| {
                                            this.environment_zsh = *checked;
                                            cx.notify();
                                        })),
                                ),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(150.))
                                .p_2()
                                .bg(rgb(SURFACE_SOFT))
                                .rounded_md()
                                .child(
                                    Checkbox::new("env-install-chrome")
                                        .label("安装 Chrome")
                                        .checked(self.environment_chrome)
                                        .disabled(locked || (!creating && self.environment_chrome))
                                        .on_click(cx.listener(|this, checked, _, cx| {
                                            this.environment_chrome = *checked;
                                            cx.notify();
                                        })),
                                ),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(150.))
                                .p_2()
                                .bg(rgb(SURFACE_SOFT))
                                .rounded_md()
                                .child(
                                    Checkbox::new("env-install-chinese")
                                        .label("中文输入法")
                                        .checked(self.environment_chinese)
                                        .disabled(locked || (!creating && self.environment_chinese))
                                        .on_click(cx.listener(|this, checked, _, cx| {
                                            this.environment_chinese = *checked;
                                            cx.notify();
                                        })),
                                ),
                        ),
                ),
        );
        if !creating {
            body = body
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(AMBER))
                        .child(EDIT_RESTART_WARNING),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(AMBER))
                        .child(EDIT_LANGUAGE_NOTE),
                );
        }
        body = body.child(div().flex_1());
        let action_bar = ButtonGroup::new("environment-editor-actions")
            .child(
                self.button(
                    "env-submit",
                    if creating {
                        "创建并设置"
                    } else {
                        "保存设置"
                    },
                    UiAction::EnvironmentSubmit,
                    locked,
                    cx,
                )
                .icon(design_icon(
                    if creating { "check" } else { "save" },
                    15.,
                    SURFACE,
                ))
                .primary(),
            )
            .child(
                self.button(
                    "env-cancel",
                    "取消",
                    UiAction::EnvironmentCancel,
                    locked,
                    cx,
                )
                .icon(design_icon("close", 15., MUTED)),
            );
        body = body.child(div().flex().justify_end().child(action_bar));
        card(
            if creating {
                "新增 WSL 环境"
            } else {
                "编辑 WSL 环境"
            },
            "",
            body,
        )
        .h_full()
        .min_h_0()
    }

    fn environment_detail_card(&self, detail: &Value, locked: bool, cx: &Context<Self>) -> Div {
        let features = &detail["features"];
        let name = text(detail, "name", "未命名");
        let edit_name = name.clone();
        let backup_name = name.clone();
        let delete_name = name.clone();
        let id = text(detail, "id", "");
        let role = if self.selected.as_deref() == Some(id.as_str()) {
            badge("当前目标", ACCENT, super::theme::TARGET_BG)
        } else {
            badge("未分配", MUTED, SURFACE_SOFT)
        };
        let base_path = text(detail, "base_path", "未读取");
        let location_path = base_path.clone();
        let location_available = base_path != "未读取" && !base_path.is_empty();
        let version = detail["version"].as_u64().unwrap_or_default();
        let refresh_name = name.clone();
        let components = [
            environment_facts::zsh(features),
            environment_facts::chrome(features),
            environment_facts::chinese(features),
        ];
        let incomplete = components
            .iter()
            .any(|component| component.state == ComponentState::Incomplete);
        let [zsh, chrome, chinese] = components;
        let feature_grid = div()
            .flex()
            .flex_wrap()
            .gap_2()
            .child(component_feature("zsh", zsh, "终端工具"))
            .child(component_feature(
                "Chrome",
                chrome,
                "图形浏览器和 chrome 启动器",
            ))
            .child(component_feature(
                "中文输入法",
                chinese,
                "fcitx5 拼音和 zh_CN 语言包",
            ));
        // 编辑时已装的组件默认勾选，保存会按当前版本的安装脚本重装，缺的东西随之补上。
        let repair_hint = incomplete.then(|| {
            div().text_sm().text_color(rgb(AMBER)).child(
                "有组件需要补齐：点右上角「编辑」后直接「保存设置」，会按当前版本重装勾选的组件（保存会重启该发行版；装了 Chrome 或中文输入法时，系统语言会改成 en_US）。",
            )
        });
        let systemd = match environment_facts::systemd(features) {
            Systemd::Running => {
                environment_feature("systemd", ("运行中", TEAL, SUCCESS_BG), "PID 1 是 systemd")
            }
            Systemd::ConfiguredNotRunning => environment_feature(
                "systemd",
                ("未运行", AMBER, WARNING_BG),
                "wsl.conf 已开启，重启发行版后生效；仍不运行时检查是否装了 systemd",
            ),
            Systemd::Off => environment_feature(
                "systemd",
                ("未开启", AMBER, WARNING_BG),
                "wsl.conf 没开启；「编辑 → 保存设置」会开启",
            ),
            Systemd::Unknown => environment_feature("systemd", NOT_READ, "接管需要"),
        };
        let takeover_grid = div()
            .flex()
            .flex_wrap()
            .gap_2()
            .child(systemd)
            .child(takeover_tool(
                "iptables-legacy",
                features["iptables_legacy"].as_bool(),
                "IPv4 接管规则",
            ))
            .child(takeover_tool(
                "ip6tables-legacy",
                features["ip6tables_legacy"].as_bool(),
                "IPv6 接管规则",
            ));
        let system_info = div()
            .flex()
            .flex_wrap()
            .gap_2()
            .child(environment_info("WSL 版本", format!("WSL {version}")))
            .child(environment_info(
                "发行版",
                text(features, "distribution", "未读取"),
            ))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .flex_1()
                    .min_w(px(128.))
                    .p_2()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(div().text_sm().text_color(rgb(MUTED)).child("时区"))
                            .child(
                                Button::new("environment-timezone-edit")
                                    .icon(design_icon("edit", 15., MUTED))
                                    .accessibility_label("修改时区")
                                    .tooltip("修改时区")
                                    .ghost()
                                    .compact()
                                    .disabled(locked)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.open_timezone_dialog(window, cx);
                                    })),
                            ),
                    )
                    .child(
                        div()
                            .font_family(MONO_FONT)
                            .text_sm()
                            .truncate()
                            .child(text(features, "timezone", "未读取")),
                    ),
            )
            .child(environment_info(
                "Locale",
                text(features, "locale", "未读取"),
            ))
            .child(environment_info("内核", text(features, "kernel", "未读取")))
            .child(environment_info(
                "架构",
                text(features, "architecture", "未读取"),
            ))
            .child(environment_info(
                "默认用户",
                environment_facts::default_user(features),
            ))
            .child(environment_info(
                "图形界面",
                environment_facts::graphics(features),
            ))
            .child(environment_info(
                "磁盘 已用/上限",
                environment_facts::disk(features),
            ));
        div()
            .flex()
            .flex_col()
            .gap_3()
            .p_3()
            .bg(rgb(SURFACE))
            .border_1()
            .border_color(rgb(RULE))
            .rounded_md()
            .child(
                div()
                    .flex()
                    .items_start()
                    .justify_between()
                    .gap_3()
                    .child(card_header("环境详情", ""))
                    .child(
                        ButtonGroup::new("environment-detail-actions")
                            .child(
                                Button::new("environment-detail-refresh")
                                    .icon(design_icon("refresh", 15., MUTED))
                                    .accessibility_label("重新读取详情")
                                    .tooltip("重新读取详情")
                                    .ghost()
                                    .compact()
                                    .disabled(locked)
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.environment_view(refresh_name.clone(), window, cx)
                                    })),
                            )
                            .child(
                                Button::new("environment-detail-apps")
                                    .icon(design_icon("apps", 15., MUTED))
                                    .accessibility_label("已安装应用")
                                    .tooltip("已安装应用：在新窗口里列出并启动")
                                    .ghost()
                                    .compact()
                                    .disabled(locked)
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.open_app_launcher(cx)),
                                    ),
                            )
                            .child(
                                Button::new("environment-detail-edit")
                                    .icon(design_icon("edit", 15., MUTED))
                                    .accessibility_label("编辑环境")
                                    .tooltip("编辑环境")
                                    .ghost()
                                    .compact()
                                    .small()
                                    .disabled(locked)
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.environment_edit(edit_name.clone(), window, cx)
                                    })),
                            )
                            .child(
                                Button::new("environment-detail-backup")
                                    .icon(design_icon("archive", 15., MUTED))
                                    .accessibility_label("备份环境")
                                    .tooltip("备份环境")
                                    .ghost()
                                    .compact()
                                    .disabled(locked)
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.environment_backup(backup_name.clone(), window, cx)
                                    })),
                            )
                            .child(
                                Button::new("environment-detail-delete")
                                    .icon(design_icon("trash", 15., RUST))
                                    .accessibility_label("删除环境")
                                    .tooltip("删除环境")
                                    .ghost()
                                    .compact()
                                    .disabled(locked)
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.environment_delete(delete_name.clone(), window, cx)
                                    })),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p_3()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(icon("icons/folder.svg"))
                                    .child(div().text_sm().child(name)),
                            )
                            .child(role),
                    )
                    .child(
                        div()
                            .flex()
                            .items_start()
                            .gap_2()
                            .child(
                                div()
                                    .w(px(72.))
                                    .text_sm()
                                    .text_color(rgb(MUTED))
                                    .child("安装位置"),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .font_family(MONO_FONT)
                                    .text_sm()
                                    .truncate()
                                    .child(base_path),
                            )
                            .child(
                                Button::new("environment-open-location")
                                    .icon(icon("icons/folder.svg"))
                                    .accessibility_label("打开安装位置")
                                    .tooltip("打开安装位置")
                                    .ghost()
                                    .compact()
                                    .disabled(locked || !location_available)
                                    .on_click(cx.listener(move |_, _, _, cx| {
                                        cx.reveal_path(Path::new(&location_path));
                                    })),
                            ),
                    )
                    .child(system_info),
            )
            .child(div().text_sm().child("环境能力"))
            .child(feature_grid)
            .children(repair_hint)
            .child(div().text_sm().child("接管基础"))
            .child(takeover_grid)
            .child(
                div()
                    .text_sm()
                    .text_color(rgb(MUTED))
                    .child("这里只列组件在不在；能不能接管以预检结果为准。"),
            )
    }

    fn environment_page(&self, cx: &Context<Self>) -> Div {
        let locked = self.locked();
        let controls_locked = locked || self.environment_editor.is_some();
        let selected = self.environment_selected.as_deref();
        let mut rows = div().flex().flex_col().gap_2();
        for (index, distro) in self.distributions.iter().enumerate() {
            let id = text(distro, "id", "");
            let name = text(distro, "name", "未命名发行版");
            let version = distro["version"].as_u64().unwrap_or_default();
            let target = self
                .selected
                .as_deref()
                .is_some_and(|selected| names_target(distro, selected));
            let active = selected == Some(name.as_str()) || selected == Some(id.as_str());
            let row_name = name.clone();
            let view_name = row_name.clone();
            let target_id = id.clone();
            let row_background = if active {
                SELECTED_BG
            } else if target {
                super::theme::ACCENT_SOFT
            } else {
                SURFACE_SOFT
            };
            let row_border = if active {
                super::theme::PRIMARY
            } else if target {
                super::theme::ACCENT
            } else {
                RULE
            };
            // 当前目标和 WSL 1 只是状态，用标签；其余发行版给一个带文字的「设为目标」按钮。
            let target_control = if version != 2 {
                badge("WSL 1 不支持", RUST, super::theme::DANGER_BG).into_any_element()
            } else if target {
                badge("当前目标", ACCENT, super::theme::TARGET_BG).into_any_element()
            } else {
                // 确认后立即保存目标；环境页没有单独的保存按钮。
                Button::new(("environment-target", index))
                    .label("设为目标")
                    .outline()
                    .small()
                    .disabled(controls_locked || self.profile_path.is_none())
                    .on_click(cx.listener(move |this, _, window, cx| {
                        cx.stop_propagation();
                        this.prompt_set_target(target_id.clone(), window, cx);
                    }))
                    .into_any_element()
            };
            rows = rows.child(
                div()
                    .id(("environment-row", index))
                    .role(Role::Button)
                    .aria_label("查看环境详情")
                    // `tab_stop` 只是一个标记：元素可聚焦（有焦点句柄）才进 Tab 顺序。
                    // 没有 `focusable()` 时键盘到不了这一行，也就打不开详情。
                    .focusable()
                    .tab_stop(true)
                    .focus_visible(|style| style.border_1().border_color(rgb(ACCENT)))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.environment_view(view_name.clone(), window, cx);
                    }))
                    .on_key_down(cx.listener(move |this, event: &KeyDownEvent, window, cx| {
                        if matches!(event.keystroke.key.as_str(), "enter" | "space") {
                            this.environment_view(row_name.clone(), window, cx);
                        }
                    }))
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p_3()
                    .bg(rgb(row_background))
                    .border_1()
                    .border_color(rgb(row_border))
                    .rounded_md()
                    // 普通行悬停用中性灰；蓝底只留给当前目标和正在查看的行，免得悬停像被设成目标。
                    .when(!active && !target, |row| {
                        row.hover(|style| style.bg(rgb(HOVER)))
                    })
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().flex_shrink_0().child(icon("icons/folder.svg")))
                            .child(
                                div().flex().flex_col().gap_1().flex_1().min_w_0().child(
                                    div()
                                        .text_sm()
                                        .text_color(rgb(if active { PRIMARY } else { INK }))
                                        .truncate()
                                        .child(name),
                                ),
                            )
                            .child(div().flex_shrink_0().child(target_control)),
                    ),
            );
        }
        if self.distributions.is_empty() {
            rows = rows.child(
                div()
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap_2()
                    .p_4()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .child(design_icon("environment", 24., MUTED))
                    .child(div().text_sm().child("没有发现 WSL2 发行版"))
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(MUTED))
                            .child("刷新列表后重新读取系统注册信息。"),
                    ),
            );
        }
        let top_actions = ButtonGroup::new("environment-actions")
            .child(
                self.button(
                    "environment-create-top",
                    "新增环境",
                    UiAction::EnvironmentCreate,
                    controls_locked,
                    cx,
                )
                .icon(design_icon("plus", 15., SURFACE))
                .small()
                .primary(),
            )
            .child(
                self.button(
                    "environment-list",
                    if self.reading {
                        "读取中…"
                    } else {
                        "刷新列表"
                    },
                    UiAction::List,
                    controls_locked,
                    cx,
                )
                .icon(design_icon("refresh", 15., MUTED))
                .outline()
                .small(),
            );
        // 左右两栏中间只隔着拖动条，挨在一起，所以两栏都不要圆角。
        let left = div()
            .flex()
            .flex_col()
            .gap_3()
            .p_3()
            .bg(rgb(SURFACE))
            .border_1()
            .border_color(rgb(RULE))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(card_header("WSL 环境", ""))
                    .child(top_actions),
            )
            .child(rows);
        let right_main = if let Some(editor) = self.environment_editor {
            self.environment_editor_card(matches!(editor, EnvironmentEditor::Create), locked, cx)
        } else if let Some(detail) = self.environment_detail.as_ref() {
            self.environment_detail_card(detail, locked, cx)
        } else {
            card(
                "环境详情",
                "",
                div()
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap_2()
                    .p_4()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .text_sm()
                    .text_color(rgb(MUTED))
                    .child(design_icon("environment", 24., MUTED))
                    .child("点左侧的环境查看详情。")
                    .child("读取详情要在该发行版里运行检查，没启动的发行版会被启动。"),
            )
        };
        // 两栏是固定高度的分栏，外层页面滚动管不到栏内；详情比窗口高时右栏自己滚动。
        let right = div()
            .id("environment-detail-scroll")
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_3()
            .flex_1()
            .min_w_0()
            .child(right_main.rounded_none());
        // 窗口固定 980 宽，左右两栏总放得下，不需要窄窗口的上下堆叠。
        let columns = div().flex_1().h_full().min_h_0().child(
            h_resizable("environment-panels")
                .child(
                    resizable_panel()
                        .size(px(280.))
                        .size_range(px(280.)..px(520.))
                        .child(left.w_full().h_full()),
                )
                .child(
                    resizable_panel()
                        .size_range(px(360.)..px(1600.))
                        .child(right.w_full().h_full()),
                ),
        );
        div().flex().flex_col().h_full().min_h_0().child(columns)
    }

    fn page_content(&self, window: &Window, cx: &Context<Self>) -> Div {
        match self.page {
            Page::Overview => self.overview(cx),
            Page::Environment => self.environment_page(cx),
            Page::Policy => self.policy_page(),
            Page::Connection => self.connection_page(window, cx),
            Page::Logs => self.logs_page(window, cx),
            Page::Settings => self.settings_page(cx),
        }
    }

    fn logs_page(&self, window: &Window, cx: &Context<Self>) -> Div {
        let list_height = (window.viewport_size().height - px(280.)).max(px(260.));
        let search = match &self.fields.log_search {
            Field::Single(state) => Input::new(state).w(px(240.)).into_any_element(),
            Field::Multi(state) => Textarea::new(state).into_any_element(),
        };
        let log_row = |log: RuntimeLog| {
            let (label, color, background) = match log.level.as_str() {
                "error" => ("错误", RUST, super::theme::DANGER_BG),
                "warning" => ("警告", AMBER, WARNING_BG),
                _ => ("信息", TEAL, SUCCESS_BG),
            };
            let context = log.context();
            div()
                .id(("runtime-log-row", log.id as u64))
                .flex()
                .w_full()
                .min_w_0()
                .items_center()
                .gap_3()
                .h(px(LOG_ROW_HEIGHT))
                .px_2()
                .border_b_1()
                .border_color(rgb(RULE))
                .child(
                    div()
                        .w(px(142.))
                        .flex_shrink_0()
                        .font_family(super::theme::MONO_FONT)
                        .text_color(rgb(MUTED))
                        .child(log.occurred_at),
                )
                .child(
                    div()
                        .w(px(68.))
                        .flex_shrink_0()
                        .child(badge(label, color, background)),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .justify_center()
                        .gap_1()
                        .flex_1()
                        .min_w_0()
                        .child(div().truncate().child(log.message))
                        .child(div().text_color(rgb(MUTED)).truncate().child(context)),
                )
                .child(
                    div()
                        .w(px(112.))
                        .flex_shrink_0()
                        .text_color(rgb(MUTED))
                        .truncate()
                        .child(log.source),
                )
        };
        let rows = if self.logs.is_empty() {
            div()
                .w_full()
                .h(list_height)
                .flex()
                .items_center()
                .justify_center()
                .text_color(rgb(if self.logs_error.is_some() {
                    RUST
                } else {
                    MUTED
                }))
                .child(if self.logs_in_flight {
                    SharedString::from("正在读取运行日志…")
                } else if let Some(error) = &self.logs_error {
                    format!("读取运行日志失败：{error}").into()
                } else if self.log_filter == LogFilter::Errors {
                    "暂无错误记录。".into()
                } else if self.log_filter == LogFilter::Warnings {
                    "暂无警告记录。".into()
                } else {
                    "暂无运行日志。".into()
                })
                .into_any_element()
        } else {
            let item_sizes = Rc::new(vec![size(px(1.), px(LOG_ROW_HEIGHT)); self.logs.len()]);
            let list = gpui_kit::base::v_virtual_list(
                cx.entity(),
                "runtime-log-list",
                item_sizes,
                move |this, range, _, _| {
                    range
                        .filter_map(|index| this.logs.get(index).cloned())
                        .map(&log_row)
                        .collect::<Vec<_>>()
                },
            );
            div()
                .id("runtime-log-viewport")
                .w_full()
                .h(list_height)
                .min_h_0()
                .overflow_x_hidden()
                .child(list.track_scroll(&self.logs_scroll).size_full())
                .into_any_element()
        };
        let count = if self.logs_has_more {
            format!(
                "显示最近 {} 条，共 {} 条；最新的在顶部",
                self.logs.len(),
                self.logs_total
            )
        } else {
            format!("共 {} 条；最新的在顶部", self.logs_total)
        };
        // 刷新失败但还有上次读到的日志：说明下面是旧结果，失败原因只显示在日志页。
        let (count, count_color) = match &self.logs_error {
            Some(error) if !self.logs.is_empty() => {
                (format!("刷新日志失败，下面是上次读到的结果：{error}"), RUST)
            }
            _ => (count, MUTED),
        };
        let table_header = div()
            .flex()
            .w_full()
            .h(px(32.))
            .px_2()
            .items_center()
            .gap_3()
            .border_b_1()
            .border_color(rgb(RULE))
            .text_color(rgb(MUTED))
            .child(div().w(px(142.)).flex_shrink_0().child("时间"))
            .child(div().w(px(68.)).flex_shrink_0().child("级别"))
            .child(div().flex_1().min_w_0().child("事件"))
            .child(div().w(px(112.)).flex_shrink_0().child("来源"));
        let load_more = if self.logs_has_more {
            div().flex().justify_center().pt_2().child(
                self.button(
                    "log-load-more",
                    "加载更早",
                    UiAction::LogLoadMore,
                    self.logs_loading_more,
                    cx,
                )
                .outline()
                .small(),
            )
        } else {
            div().h(px(4.))
        };
        card(
            "运行日志",
            "后台事件、预检结果和接管生命周期，数据保存在 SQLite",
            div()
                .flex()
                .flex_col()
                .w_full()
                .min_h_0()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .mb_3()
                        .child(search)
                        .child(div().flex_1())
                        .child(
                            self.button(
                                "log-all",
                                "全部",
                                UiAction::LogFilter(LogFilter::All),
                                false,
                                cx,
                            )
                            .outline()
                            .small()
                            .selected(self.log_filter == LogFilter::All),
                        )
                        .child(
                            self.button(
                                "log-errors",
                                "错误",
                                UiAction::LogFilter(LogFilter::Errors),
                                false,
                                cx,
                            )
                            .outline()
                            .small()
                            .selected(self.log_filter == LogFilter::Errors),
                        )
                        .child(
                            self.button(
                                "log-warnings",
                                "警告",
                                UiAction::LogFilter(LogFilter::Warnings),
                                false,
                                cx,
                            )
                            .outline()
                            .small()
                            .selected(self.log_filter == LogFilter::Warnings),
                        )
                        .child(
                            self.button("log-refresh", "刷新", UiAction::LogRefresh, false, cx)
                                .outline()
                                .small(),
                        ),
                )
                .child(div().text_color(rgb(count_color)).child(count))
                .child(table_header)
                .child(rows)
                .child(load_more),
        )
        .w_full()
        .min_h_0()
    }

    /// 设置页「WSL 平台」分区的内容：只读检查结果与显式升级。发行版本身在「环境」页管理。
    fn wsl_platform_body(&self, cx: &Context<Self>) -> Div {
        let report = self.wsl_platform.as_ref();
        let (status_label, tone) = super::backend::wsl_platform_badge(
            report,
            self.wsl_platform_checking,
            self.wsl_platform_error.as_deref(),
        );
        let (status_color, status_background) = match tone {
            "ok" => (TEAL, SUCCESS_BG),
            "warning" => (AMBER, WARNING_BG),
            "blocked" | "failed" => (RUST, super::theme::DANGER_BG),
            _ => (MUTED, SURFACE_SOFT),
        };
        let wsl_value = |key: &str| {
            report
                .and_then(|report| report["wsl"][key].as_str())
                .filter(|value| !value.is_empty())
                .unwrap_or("未读取")
                .to_owned()
        };
        let default_version = report
            .and_then(|report| report["defaults"]["version"].as_u64())
            .map(|version| format!("WSL {version}"))
            .unwrap_or_else(|| "未读取".into());
        let default_distribution = report
            .and_then(|report| report["defaults"]["distribution"].as_str())
            .unwrap_or("未读取")
            .to_owned();
        let distributions = report
            .and_then(|report| report["distributions"].as_array())
            .map_or(0, Vec::len);
        let wsl1 = report
            .and_then(|report| report["wsl1"].as_array())
            .map_or(0, Vec::len);
        let elevated = report.and_then(|report| report["elevated"].as_bool());
        let checked = self.wsl_platform_at.map(|at| elapsed_label(at, "检查"));
        let checks = report
            .and_then(|report| report["checks"].as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        let code = item["code"].as_str()?;
                        let level = item["level"].as_str().unwrap_or("ok");
                        let text =
                            super::backend::wsl_check_text(code, level, item["detail"].as_str());
                        let (color, icon) = match level {
                            "ok" => (TEAL, "check"),
                            "warning" => (AMBER, "info"),
                            _ => (RUST, "info"),
                        };
                        Some(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(design_icon(icon, 15., color))
                                .child(div().text_sm().text_color(rgb(INK)).child(text)),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let unavailable = self
            .wsl_platform
            .as_ref()
            .is_some_and(|report| report["wsl"]["installed"].as_bool() == Some(false));
        let mut hint = "检查只读：只运行 wsl --version、wsl --status 并读注册表，不启动发行版、不写规则。升级运行 wsl --update，只在没有接管时可用；它会替换 WSL 包并可能重启 WSL，发行版里正在运行的程序会停止。".to_owned();
        if elevated == Some(false) {
            hint.push_str("当前以标准用户运行，升级时 Windows 可能弹出管理员权限提示。");
        }
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(badge(status_label, status_color, status_background))
                            .when_some(checked, |body, checked| {
                                body.child(div().text_sm().text_color(rgb(MUTED)).child(checked))
                            }),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                self.button(
                                    "settings-wsl-check",
                                    "检查",
                                    UiAction::WslPlatformCheck,
                                    self.locked() || self.wsl_platform_checking,
                                    cx,
                                )
                                .icon(design_icon("refresh", 15., MUTED)),
                            )
                            .child(
                                self.button(
                                    "settings-wsl-upgrade",
                                    "升级 WSL",
                                    UiAction::WslUpdate,
                                    self.locked() || !self.idle() || unavailable,
                                    cx,
                                )
                                .primary()
                                .icon(design_icon("play", 15., SURFACE)),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .flex_1()
                            .min_w(px(260.))
                            .child(key_value("WSL 版本", wsl_value("version")))
                            .child(key_value("WSL2 内核", wsl_value("kernel_version")))
                            .child(key_value("Windows 版本", wsl_value("windows_version")))
                            .child(key_value("wsl.exe", wsl_value("executable"))),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .flex_1()
                            .min_w(px(260.))
                            .child(key_value("默认版本", default_version))
                            .child(key_value("默认发行版", default_distribution))
                            .child(key_value(
                                "发行版",
                                format!("{distributions} 个（{wsl1} 个 WSL1）"),
                            ))
                            .child(key_value(
                                "权限",
                                match elevated {
                                    Some(true) => "管理员",
                                    Some(false) => "标准用户（升级时可能要确认管理员权限）",
                                    None => "未读取",
                                },
                            )),
                    ),
            )
            .children(checks)
            .when_some(self.wsl_update_result.as_ref(), |body, update| {
                body.child(key_value(
                    "上次升级",
                    super::backend::wsl_update_notice(update),
                ))
            })
            .when_some(self.wsl_platform_error.clone(), |body, error| {
                body.child(div().text_sm().text_color(rgb(RUST)).child(error))
            })
            .child(div().text_sm().text_color(rgb(MUTED)).child(hint))
    }

    /// 检测结果只对检测时的那版配置有效；之后又保存过设置就不再显示旧结论。
    fn residential_probe_stale(&self) -> bool {
        self.residential_probe.as_ref().is_some_and(|report| {
            report["revision"].as_str() != Some(self.revision.as_str().unwrap_or("0"))
        })
    }

    /// 住宅代理卡片顶部：检测状态和「检测」按钮。
    fn residential_probe_row(&self, cx: &Context<Self>) -> Div {
        let (label, tone) = super::backend::residential_probe_badge(
            self.residential_probe.as_ref(),
            self.residential_probe_checking,
            self.residential_probe_error.as_deref(),
            self.residential_probe_stale(),
        );
        let (color, background) = match tone {
            "ok" => (TEAL, SUCCESS_BG),
            "warning" => (AMBER, WARNING_BG),
            "failed" => (RUST, super::theme::DANGER_BG),
            _ => (MUTED, SURFACE_SOFT),
        };
        let checked = self
            .residential_probe_at
            .filter(|_| !self.residential_probe_stale())
            .map(|at| elapsed_label(at, "检测"));
        div()
            .flex()
            .items_center()
            .justify_between()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(badge(label, color, background))
                    .when_some(checked, |row, checked| {
                        row.child(div().text_sm().text_color(rgb(MUTED)).child(checked))
                    }),
            )
            .child(
                self.button(
                    "settings-residential-probe",
                    "检测",
                    UiAction::ResidentialProbe,
                    self.locked() || self.residential_probe_checking,
                    cx,
                )
                .icon(design_icon("refresh", 15., MUTED)),
            )
    }

    /// 住宅代理卡片底部：两条路各自的结果、失败原因和检测说明。
    fn residential_probe_result(&self) -> Vec<Div> {
        let mut rows = Vec::new();
        if let Some(error) = self.residential_probe_error.clone() {
            rows.push(div().text_sm().text_color(rgb(RUST)).child(error));
        } else if let Some(report) = self
            .residential_probe
            .as_ref()
            .filter(|_| !self.residential_probe_stale())
        {
            let verdict = report["verdict"].as_str().unwrap_or("unreachable");
            rows.push(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(INK))
                            .child(super::backend::residential_probe_summary(verdict)),
                    )
                    .child(key_value(
                        "直接连接",
                        super::backend::residential_stage_text(&report["direct"]),
                    ))
                    .child(key_value(
                        "经宿主 SOCKS5",
                        super::backend::residential_stage_text(&report["chained"]),
                    )),
            );
        }
        rows.push(div().text_sm().text_color(rgb(MUTED)).child(
            "检测只用已保存的配置，看住宅代理能否从 Windows 直接连上、能否经宿主 SOCKS5 连上；直接连接会把账号密码不经前置代理发出去，点「检测」后先确认。Windows 上开着 TUN 或全局模式的代理时，「直接连接」也可能被它接管。接管始终经宿主 SOCKS5，检测结果不改变接管方式。",
        ));
        rows
    }

    /// 有保存按钮的页面：规则页和设置页。
    fn page_save_scope(&self) -> Option<SaveScope> {
        match self.page {
            Page::Policy => Some(SaveScope::Policy),
            Page::Settings => Some(SaveScope::Settings),
            _ => None,
        }
    }

    /// 规则页、设置页底部的固定栏，不随页面滚动：右边是保存按钮，有未保存修改或上次保存
    /// 失败时按钮左边显示对应标签；保存结果用窗口右上角的通知弹出。
    fn save_footer(&self, scope: SaveScope, cx: &Context<Self>) -> Div {
        let id = match scope {
            SaveScope::Policy => "save-policy",
            _ => "settings-save",
        };
        div()
            .flex()
            .flex_shrink_0()
            .items_center()
            .justify_end()
            .gap_2()
            .px_3()
            .py_2()
            .bg(rgb(SURFACE))
            .border_t_1()
            .border_color(rgb(RULE))
            .children(self.unsaved_badge(scope))
            .child(
                self.button(
                    id,
                    scope.action(),
                    UiAction::Save(scope),
                    self.locked() || self.profile_path.is_none(),
                    cx,
                )
                .primary(),
            )
    }

    /// 设置页「关于」分区：logo、名称、版本和一句说明，下面是组成、运行平台和配置库位置。
    /// 版本是这个桌面端编译时的版本；后台状态里没有版本号，这里不显示正在运行的后台版本。
    fn about_page(&self) -> SettingPage {
        const SUMMARY: &str = "只接管一个 WSL2 发行版新建的出站连接：命中直连规则的直接出网，其余经宿主 SOCKS5 和住宅 SOCKS5 两跳出网；其他发行版和 Windows 本身的网络不变。";
        let version = env!("CARGO_PKG_VERSION");
        let profile_path: SharedString = self
            .profile_path
            .clone()
            .unwrap_or_else(|| "等待后台返回路径".into())
            .into();
        let header = SettingItem::render(move |_, _, _| {
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(app_icon(48.))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .min_w_0()
                        .child(
                            div()
                                .text_sm()
                                .text_color(rgb(INK))
                                .child(super::theme::TITLE),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(rgb(MUTED))
                                .child(format!("版本 {version}")),
                        )
                        .child(div().text_sm().text_color(rgb(MUTED)).child(SUMMARY)),
                )
        })
        .keywords(["关于", "版本", super::theme::TITLE]);
        let path_item = setting_row("配置库", move |_| {
            let tip = profile_path.clone();
            div()
                .id("about-profile-path")
                .max_w(px(360.))
                .truncate()
                .font_family(MONO_FONT)
                .text_sm()
                .text_color(rgb(MUTED))
                .child(profile_path.clone())
                .tooltip(move |window, cx| text_tip(tip.clone(), window, cx))
        });
        SettingPage::new("关于").resettable(false).group(
            SettingGroup::new()
                .item(header)
                .item(value_item(
                    "组成",
                    "桌面端 wsl-proxy-desktop.exe 和后台 wsl-proxyctl.exe，需同一版本、放在同一目录",
                ))
                .item(value_item(
                    "运行平台",
                    format!("Windows · {}", std::env::consts::ARCH),
                ))
                .item(path_item),
        )
    }

    /// 设置页「住宅代理 · 检测」分组的内容：状态和「检测」按钮，下面是两条路的结果和说明。
    fn residential_probe_panel(&self, cx: &Context<Self>) -> Div {
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.residential_probe_row(cx))
            .children(self.residential_probe_result())
    }

    /// 设置页用 gpui-kit 的 Settings：左边按分区切换，右边是当前分区的设置项。输入框沿用
    /// 页面自己的输入状态，草稿、未保存检测和底部「保存设置」都不变；保存时提交所有分区的
    /// 字段，不只是当前看到的这一个分区。
    fn settings_page(&self, cx: &Context<Self>) -> Div {
        let view = cx.entity().clone();
        let locked = self.locked();
        let input = |label: &'static str, field: &Field| {
            let field = field.clone();
            setting_row(label, move |horizontal| {
                setting_input(&field, locked, horizontal)
            })
        };
        let residential = SettingPage::new("住宅代理")
            .resettable(false)
            .group(
                SettingGroup::new()
                    .title("服务器")
                    .item(input("服务器 IPv4", &self.fields.residential_ip))
                    .item(input("服务器端口", &self.fields.residential_port))
                    .item(input("用户名", &self.fields.residential_username))
                    .item(input("密码", &self.fields.residential_password)),
            )
            .group(SettingGroup::new().title("检测").item(view_item(
                &view,
                &["检测", "直连", "前置代理", "住宅代理"],
                |this, cx| this.residential_probe_panel(cx),
            )));
        let network = SettingPage::new("网络与 DNS")
            .resettable(false)
            .group(
                SettingGroup::new()
                    .title("网络入口")
                    .item(input("宿主 SOCKS5", &self.fields.first_hop))
                    .item(input("Windows 入口端口", &self.fields.port)),
            )
            .group(
                SettingGroup::new()
                    .title("受管 DNS")
                    .item(input("DoH 上游 IPv4:端口", &self.fields.dns_upstream))
                    .item(input("TLS 主机名", &self.fields.dns_tls_name))
                    .item(input("健康检查域名", &self.fields.health_domain)),
            )
            .group(
                SettingGroup::new()
                    .title("白名单域名解析")
                    .description(
                        "命中域名白名单的查询由 Windows 直接问这个国内 DoH，让直连站点拿到国内地址；连不上时仍经代理链。上游留空即关闭，全部经代理链解析。",
                    )
                    .item(input("国内 DoH 上游 IPv4:端口", &self.fields.direct_dns_upstream))
                    .item(input("国内 DoH TLS 主机名", &self.fields.direct_dns_tls_name)),
            )
            .group(
                SettingGroup::new()
                    .title("远端解析")
                    .description(
                        "白名单以外的域名先回一个占位地址，连接时把域名交给住宅代理解析，省掉一次经代理链的 DNS 往返。住宅代理不支持按域名连接时自动不启用。下次启动或切换接管时生效。",
                    )
                    .item(setting_row("白名单以外的域名由住宅代理解析", {
                        let view = view.clone();
                        let checked = self.fake_ip_draft;
                        move |_| {
                            let view = view.clone();
                            Checkbox::new("settings-fake-ip")
                                .checked(checked)
                                .disabled(locked)
                                .on_click(move |checked: &bool, _, cx: &mut App| {
                                    view.update(cx, |this, cx| {
                                        this.set_fake_ip_draft(*checked, cx)
                                    });
                                })
                        }
                    })),
            );
        let limits = SettingPage::new("转发限制").resettable(false).group(
            SettingGroup::new()
                .item(input(
                    "并发 TCP 上限（条）",
                    &self.fields.max_tcp_connections,
                ))
                .item(input("TCP 空闲断开（秒）", &self.fields.tcp_idle_timeout))
                .item(input(
                    "半关闭等待（秒）",
                    &self.fields.tcp_half_close_timeout,
                ))
                .footer(|_, _| "下次启动或切换接管时生效。"),
        );
        // 开机自启沿用已经配好主题色的 Checkbox；gpui-kit 的 Switch 颜色没有跟应用主题设置。
        let autostart = self.autostart_enabled;
        let autostart_view = view.clone();
        let island = self.island_enabled;
        let island_view = view.clone();
        let runtime = SettingPage::new("桌面运行").resettable(false).group(
            SettingGroup::new()
                .item(setting_row("开机自动启动", move |_| {
                    let view = autostart_view.clone();
                    Checkbox::new("settings-autostart")
                        .checked(autostart)
                        .disabled(locked)
                        .on_click(move |checked: &bool, _, cx: &mut App| {
                            view.update(cx, |this, cx| this.set_autostart(*checked, cx));
                        })
                }))
                .item(setting_row("屏幕顶部状态岛", move |_| {
                    let view = island_view.clone();
                    Checkbox::new("settings-island").checked(island).on_click(
                        move |checked: &bool, _, cx: &mut App| {
                            view.update(cx, |this, cx| this.set_island(*checked, cx));
                        },
                    )
                }))
                .item(value_item("关闭窗口", "隐藏到托盘"))
                .item(value_item("托盘退出", "停止接管并关闭后台"))
                .item(value_item("配置库", "SQLite"))
                .item(value_item(
                    "配置状态",
                    if self.profile_exists {
                        "已加载"
                    } else {
                        "待初始化"
                    },
                ))
                .item(value_item(
                    "Revision",
                    self.revision.as_str().unwrap_or("0").to_owned(),
                )),
        );
        let wsl = SettingPage::new("WSL 平台")
            .resettable(false)
            .description("wsl.exe 与共享的 WSL2 内核；发行版本身在「环境」页管理。")
            .group(SettingGroup::new().item(view_item(
                &view,
                &["WSL", "wsl.exe", "内核", "升级", "版本"],
                |this, cx| this.wsl_platform_body(cx),
            )));
        let auto_update = self.updater.auto;
        let auto_update_view = view.clone();
        let about = self.about_page().group(
            SettingGroup::new()
                .title("更新")
                .description("自动检查时，打开程序 15 秒后查一次 GitHub 上的新版本，之后每天一次；配置了宿主 SOCKS5 就经它查，连不上再直连。每次检查都会让 GitHub 看到出口 IP。")
                .item(setting_row("自动检查更新", move |_| {
                    let view = auto_update_view.clone();
                    Checkbox::new("settings-auto-update")
                        .checked(auto_update)
                        .on_click(move |checked: &bool, _, cx: &mut App| {
                            view.update(cx, |this, cx| this.set_auto_update(*checked, cx));
                        })
                }))
                .item(view_item(
                    &view,
                    &["更新", "升级", "新版本", "检查更新"],
                    |this, cx| this.update_panel(cx),
                )),
        );
        let settings = Settings::new("settings")
            .sidebar_width(px(180.))
            .sidebar_size_range(px(160.)..px(240.))
            .with_group_variant(GroupBoxVariant::Outline)
            .pages([residential, network, limits, runtime, wsl, about]);
        // 和环境页的两栏一样：外层定高，可拖动的分栏和分区内的滚动才排得开。
        div().flex().flex_col().h_full().min_h_0().child(
            div()
                .flex_1()
                .h_full()
                .min_h_0()
                .bg(rgb(SURFACE))
                .border_1()
                .border_color(rgb(RULE))
                .child(settings),
        )
    }
}

/// 设置项名称一栏的最小宽度，放得下最长的输入项名称「国内 DoH 上游 IPv4:端口」，
/// 同一分区里的输入框因此左边对齐。更长的名称只撑宽自己那一行，不换行。
const SETTING_LABEL_WIDTH: f32 = 160.;

/// 设置页的一项：左边是名称，输入框或值紧跟在名称栏后面。gpui-kit 自带的设置项横排时
/// 把名称和输入框推到两端，窗口一宽中间就空出一大块，所以设置页的项都用这个自己排。
/// 分区窄到上下排时名称在上、内容占满一行，`field` 收到的参数表示当前是否横排。
/// 自定义项默认只在搜索框为空时显示，名称同时设为搜索关键字，照样能按名称过滤。
fn setting_row<E: IntoElement>(
    label: &'static str,
    field: impl Fn(bool) -> E + 'static,
) -> SettingItem {
    SettingItem::render(move |options, _, _| {
        let horizontal = options.layout() == Axis::Horizontal;
        div()
            .w_full()
            .flex()
            .gap_3()
            .map(|row| {
                if horizontal {
                    row.flex_row().items_center()
                } else {
                    row.flex_col()
                }
            })
            .child(
                div()
                    .flex_none()
                    .when(horizontal, |name| name.min_w(px(SETTING_LABEL_WIDTH)))
                    .text_sm()
                    .text_color(rgb(INK))
                    .child(label),
            )
            .child(
                div()
                    .min_w_0()
                    .map(|value| {
                        if horizontal {
                            value.flex_1()
                        } else {
                            value.w_full()
                        }
                    })
                    .child(field(horizontal)),
            )
    })
    .keywords([label])
}

/// 设置项里的输入框，沿用页面自己的输入状态。横排时定宽、竖排时占满。`locked` 直接传给
/// 输入框，不用 `SettingItem::disabled`：那会让整项变暗，每次保存整个分区都会闪一下。
fn setting_input(field: &Field, locked: bool, horizontal: bool) -> AnyElement {
    match field {
        Field::Single(state) => Input::new(state)
            .disabled(locked)
            .map(|input| {
                if horizontal {
                    input.w_64()
                } else {
                    input.w_full()
                }
            })
            .into_any_element(),
        Field::Multi(state) => Textarea::new(state)
            .h(px(96.))
            .disabled(locked)
            .map(|input| {
                if horizontal {
                    input.w_64()
                } else {
                    input.w_full()
                }
            })
            .into_any_element(),
    }
}

/// 只读的一项：名称后面是一段说明文字。
fn value_item(label: &'static str, value: impl Into<SharedString>) -> SettingItem {
    let value = value.into();
    setting_row(label, move |_| {
        div().text_sm().text_color(rgb(MUTED)).child(value.clone())
    })
}

/// 一整块自定义内容的一项，用桌面端自己的绘制方法。Settings 在桌面视图的 `render` 返回之后
/// 才布局这些项，那时视图已经释放，可以 `update` 拿到 `Context` 来挂按钮回调。自定义项默认
/// 只在搜索框为空时显示，`keywords` 让它在搜索时也能被找到。
fn view_item(
    view: &Entity<Desktop>,
    keywords: &'static [&'static str],
    render: impl Fn(&Desktop, &Context<Desktop>) -> Div + 'static,
) -> SettingItem {
    let view = view.clone();
    SettingItem::render(move |_, _, cx| view.update(cx, |this, cx| render(this, cx)))
        .keywords(keywords.iter().copied())
}

impl Render for Desktop {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .flex()
            .flex_col()
            .font_family(super::theme::UI_FONT)
            .text_sm()
            .text_color(rgb(INK))
            .bg(rgb(PAPER))
            .child(self.title_bar(cx))
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .child(self.sidebar(cx))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .children(self.error_banner(cx))
                            .child(
                                div()
                                    .id("page-scroll")
                                    .flex_1()
                                    .min_h_0()
                                    .overflow_y_scroll()
                                    .p_3()
                                    .child(self.page_content(window, cx)),
                            )
                            .when_some(self.page_save_scope(), |column, scope| {
                                column.child(self.save_footer(scope, cx))
                            }),
                    ),
            )
            .child(self.status_bar(cx))
    }
}
