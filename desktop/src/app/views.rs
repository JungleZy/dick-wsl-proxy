//! GPUI Kit 应用外壳和页面导航。

use gpui_kit::base::Selectable as _;
use gpui_kit::component::{
    Disableable as _, Icon, IconName, Sizable as _, WindowExt as _,
    button::{Button, ButtonGroup, ButtonVariants as _},
    checkbox::Checkbox,
    dialog::{DialogEntrance, DialogFooter},
    input::{Input, Textarea},
    progress::Progress,
    resizable::{h_resizable, resizable_panel},
    select::Select,
};
use gpui_kit::{prelude::*, *};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use super::backend::Kind;
use super::components::{app_icon, badge, design_icon, icon, status_dot, text};
use super::model::{EnvironmentEditor, Field, LogFilter, Page, RuntimeLog, UiAction};
use super::state::Desktop;
use super::theme::{
    AMBER, BLUE, BLUE_ACTIVE, BLUE_SOFT, INK, MONO_FONT, MUTED, PAPER, RULE, RUST, SELECTED_BG,
    SIDEBAR_BG, SUCCESS_BG, SURFACE, SURFACE_SOFT, TEAL, WARNING_BG, app_rgb as rgb,
};

const LOG_ROW_HEIGHT: f32 = 54.;

/// Editing an environment enables systemd and then terminates the distribution.
const EDIT_RESTART_WARNING: &str =
    "保存后会开启 systemd 并重启该发行版，其中正在运行的程序会被关闭，请先保存好工作。";

pub(crate) fn card_header(title: &'static str, caption: &'static str) -> Div {
    let mut title_view = div()
        .flex()
        .flex_col()
        .gap_1()
        .child(div().text_base().child(title));
    if !caption.is_empty() {
        title_view = title_view.child(div().text_base().text_color(rgb(MUTED)).child(caption));
    }
    div()
        .flex()
        .items_start()
        .justify_between()
        .gap_3()
        .child(title_view)
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

pub(crate) fn metric(label: &'static str, value: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .flex_1()
        .min_w_0()
        .p_3()
        .bg(rgb(SURFACE_SOFT))
        .rounded_md()
        .child(div().text_base().text_color(rgb(MUTED)).child(label))
        .child(
            div()
                .text_base()
                .font_family(super::theme::MONO_FONT)
                .child(value.into()),
        )
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
                .text_base()
                .text_color(rgb(MUTED))
                .child(label),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .text_base()
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

fn environment_feature(label: &'static str, installed: bool, detail: &'static str) -> Div {
    let (status, color, background) = if installed {
        ("已就绪", TEAL, SUCCESS_BG)
    } else {
        ("未安装", MUTED, SURFACE_SOFT)
    };
    div()
        .flex()
        .flex_col()
        .gap_2()
        .flex_1()
        .min_w(px(120.))
        .p_2()
        .bg(rgb(SURFACE_SOFT))
        .rounded_md()
        .child(div().text_base().child(label))
        .child(div().text_base().text_color(rgb(MUTED)).child(detail))
        .child(badge(status, color, background))
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
        .child(div().text_base().text_color(rgb(MUTED)).child(label))
        .child(
            div()
                .font_family(MONO_FONT)
                .text_base()
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

fn window_control_button(area: WindowControlArea, icon: IconName, close: bool) -> impl IntoElement {
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
                            .text_lg()
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

    fn nav_button(
        &self,
        page: Page,
        index: usize,
        label: &'static str,
        icon_path: &'static str,
        compact: bool,
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
        let key_page = page;
        let icon_color = if self.page == page { BLUE } else { MUTED };
        let mut button = div()
            .id(id)
            .role(Role::Button)
            .aria_label(label)
            .track_focus(&self.nav_focus[index])
            .tab_stop(true)
            .focus_visible(|style| style.border_1().border_color(rgb(BLUE)))
            .flex()
            .items_center()
            .gap_3()
            .w_full()
            .h(px(40.))
            .px_3()
            .rounded_md()
            .text_base()
            .on_click(cx.listener(move |this, _, window, cx| {
                this.page = page;
                match page {
                    Page::Environment => this.open_target_environment(window, cx),
                    Page::Connection => this.refresh_connection_history(cx),
                    Page::Logs => this.refresh_logs(cx),
                    _ => {}
                }
                cx.notify();
            }))
            .on_key_down(cx.listener(move |this, event: &KeyDownEvent, window, cx| {
                if matches!(event.keystroke.key.as_str(), "enter" | "space") {
                    this.page = key_page;
                    match key_page {
                        Page::Environment => this.open_target_environment(window, cx),
                        Page::Connection => this.refresh_connection_history(cx),
                        Page::Logs => this.refresh_logs(cx),
                        _ => {}
                    }
                    cx.notify();
                }
            }));
        button = if self.page == page {
            button.bg(rgb(BLUE_SOFT)).text_color(rgb(BLUE))
        } else {
            button
                .text_color(rgb(INK))
                .hover(|style| style.bg(rgb(0xe3e8ed)))
        };
        button = button.child(design_icon(icon_path, 20., icon_color));
        if compact {
            button = button.justify_center().px_0();
        } else {
            button = button.gap_2().px(px(6.)).child(label);
        }
        button
    }

    fn sidebar(&self, compact: bool, cx: &Context<Self>) -> Div {
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
            navigation =
                navigation.child(self.nav_button(page, index, label, icon_path, compact, cx));
        }
        div()
            .flex()
            .flex_col()
            .h_full()
            .w(px(if compact { 72. } else { 88. }))
            .flex_shrink_0()
            .bg(rgb(SIDEBAR_BG))
            .border_r_1()
            .border_color(rgb(RULE))
            .child(navigation)
            .child(div().flex_1())
    }

    fn status_bar(&self, cx: &Context<Self>) -> Div {
        let online_color = if self.status_valid { TEAL } else { RUST };
        let (idle_label, idle_color) = match self.phase() {
            "idle" => ("未接管", TEAL),
            "forwarding_managed" => ("接管中", TEAL),
            "forwarding_scoped" => ("诊断转发中", AMBER),
            "recovery_required" => ("需要恢复", RUST),
            _ => ("状态未知", MUTED),
        };
        let storage_color = if self.profile_exists { TEAL } else { MUTED };
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
                Button::new("status-online")
                    .icon(design_icon("online", 17., online_color))
                    .accessibility_label("后台在线")
                    .tooltip("后台在线")
                    .text_color(rgb(online_color))
                    .ghost()
                    .compact()
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.send(Kind::Status, json!({"command":"status"}), cx);
                    })),
            )
            .child(
                Button::new("status-idle")
                    .icon(design_icon("idle", 17., idle_color))
                    .accessibility_label(idle_label)
                    .tooltip(idle_label)
                    .text_color(rgb(idle_color))
                    .disabled(true)
                    .tab_stop(false)
                    .ghost()
                    .compact(),
            )
            .child(
                Button::new("status-storage")
                    .icon(design_icon("storage", 17., storage_color))
                    .accessibility_label("SQLite 配置已加载")
                    .tooltip("SQLite 配置已加载")
                    .text_color(rgb(storage_color))
                    .disabled(true)
                    .tab_stop(false)
                    .ghost()
                    .compact(),
            )
            .child(self.status_observations())
            .child(div().flex_1())
            .child(
                div()
                    .font_family(MONO_FONT)
                    .text_base()
                    .text_color(rgb(MUTED))
                    .child(format!("v{}", env!("CARGO_PKG_VERSION"))),
            )
    }

    fn environment_target_ready(&self, cx: &App) -> bool {
        if self.busy != Some(Kind::EnvironmentCreate) {
            return false;
        }
        let base = Self::field_value(&self.fields.environment_install, cx);
        let name = Self::field_value(&self.fields.environment_name, cx);
        if base.is_empty() || name.is_empty() {
            return false;
        }
        let path = Self::environment_install_path(&base, &name);
        Path::new(&path).is_dir()
    }

    fn environment_progress_marker(&self, cx: &App) -> Option<(u8, String, String)> {
        let creating = self.busy == Some(Kind::EnvironmentCreate);
        let name = if creating {
            Self::field_value(&self.fields.environment_name, cx)
        } else {
            self.environment_edit_target.clone().unwrap_or_default()
        };
        if name.is_empty() {
            return None;
        }
        // Same known-folder lookup the controller uses when it writes the file.
        let path = wsl_proxyctl::paths::state_dir()
            .ok()?
            .join(format!("environment-progress-{name}.json"));
        let value = serde_json::from_str::<Value>(&fs::read_to_string(path).ok()?).ok()?;
        Some((
            value["percent"].as_u64()?.min(100) as u8,
            value["stage"].as_str()?.to_owned(),
            value["detail"].as_str()?.to_owned(),
        ))
    }

    fn environment_progress(&self, cx: &App) -> Option<Div> {
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
        let target_ready = self.environment_target_ready(cx);
        let elapsed_seconds = elapsed.as_secs();
        let (percent, stage, detail) = if let Some(marker) = self.environment_progress_marker(cx) {
            marker
        } else {
            let (percent, stage, detail) = if creating {
                if elapsed < Duration::from_secs(2) {
                    (
                        6,
                        "校验输入",
                        "正在检查名称、发行版、父目录和用户信息".into(),
                    )
                } else if target_ready {
                    (
                        72,
                        "初始化用户和组件",
                        format!(
                            "环境目录已创建，正在完成用户、zsh、Chrome 和中文环境初始化（已用时 {elapsed_seconds} 秒）"
                        ),
                    )
                } else {
                    (
                        18,
                        "下载发行版",
                        format!("正在等待微软 WSL 安装命令完成（已用时 {elapsed_seconds} 秒）"),
                    )
                }
            } else {
                if elapsed < Duration::from_secs(2) {
                    (10, "准备组件", "正在校验发行版能力和安装选项".into())
                } else if elapsed < Duration::from_secs(16) {
                    (38, "安装 zsh", "正在安装 zsh 终端工具".into())
                } else if elapsed < Duration::from_secs(30) {
                    (
                        60,
                        "安装 Chrome",
                        "正在安装 Chrome、中文语言支持和静默启动命令".into(),
                    )
                } else if elapsed < Duration::from_secs(44) {
                    (
                        80,
                        "配置中文环境和输入法",
                        "正在写入 locale、fcitx5 和自动启动配置".into(),
                    )
                } else {
                    (
                        88,
                        "完成检查",
                        format!("正在等待组件命令返回（已用时 {elapsed_seconds} 秒）"),
                    )
                }
            };
            (percent, stage.to_owned(), detail)
        };
        let mut steps = if creating {
            vec![
                ("校验输入", true, elapsed >= Duration::from_secs(2)),
                ("下载发行版", true, target_ready),
                ("安装环境", true, target_ready),
                ("初始化用户", true, false),
            ]
        } else {
            vec![("准备组件", true, percent >= 10)]
        };
        steps.extend([
            (
                "安装 zsh",
                self.environment_zsh,
                percent >= if creating { 90 } else { 38 },
            ),
            (
                "安装 Chrome",
                self.environment_chrome,
                percent >= if creating { 90 } else { 60 },
            ),
            (
                "中文环境和输入法",
                self.environment_chinese,
                percent >= if creating { 90 } else { 80 },
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
                            .text_base()
                            .text_color(rgb(if selected && done { INK } else { MUTED }))
                            .child(label),
                    ),
            );
        }
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
                        .child(div().text_base().child(stage))
                        .child(
                            div()
                                .font_family(super::theme::MONO_FONT)
                                .text_base()
                                .text_color(rgb(BLUE))
                                .child(format!("{percent}%")),
                        ),
                )
                .child(
                    div()
                        .h(px(8.))
                        .w_full()
                        .bg(rgb(SURFACE_SOFT))
                        .rounded_full()
                        .child(
                            div()
                                .h(px(8.))
                                .w(relative(percent as f32 / 100.))
                                .bg(rgb(BLUE))
                                .rounded_full(),
                        ),
                )
                .child(div().text_base().text_color(rgb(MUTED)).child(detail))
                .child(
                    Progress::new("environment-stage-loading")
                        .loading(true)
                        .accessibility_label("正在等待当前阶段完成"),
                )
                .child(step_view),
        )
    }

    fn loading_dialog_body(&self, cx: &App) -> Div {
        if let Some(progress) = self.environment_progress(cx) {
            return progress;
        }
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(status_dot(BLUE))
                    .child(div().text_base().child(self.notice.clone())),
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
                Some(_) => "正在处理",
                None if this.pending_prepare.is_some() => "启动前检查",
                None if this.reading => "正在加载",
                _ => "正在处理",
            };
            dialog
                .w(px(440.))
                .title(title)
                .entrance(DialogEntrance::Fade)
                .overlay(true)
                .overlay_closable(false)
                .keyboard(false)
                .close_button(false)
                .child(this.loading_dialog_body(cx))
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
                _ => "环境操作完成",
            }
        } else {
            match result.kind {
                Kind::EnvironmentCreate => "环境创建失败",
                Kind::EnvironmentEdit => "环境设置失败",
                Kind::EnvironmentDelete => "环境删除失败",
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
                .title(title)
                .icon(design_icon(icon_name, 22., icon_color))
                .description(div().text_base().child(message.clone()))
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
        let view = cx.entity().clone();
        window.open_dialog(cx, move |dialog, _, cx| {
            let this = view.read(cx);
            let picker_view = view.clone();
            let submit_view = view.clone();
            let cancel_view = view.clone();
            dialog
                .w(px(520.))
                .title("备份环境")
                .overlay(true)
                .overlay_closable(false)
                .keyboard(false)
                .close_button(false)
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(div().text_base().child("选择新的 rootfs tar 输出路径。"))
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
                        ),
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
            dialog
                .w(px(520.))
                .title("备份完成")
                .overlay(true)
                .overlay_closable(true)
                .keyboard(true)
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(div().text_base().child("环境备份已完成。"))
                        .child(
                            div()
                                .p_2()
                                .bg(rgb(SURFACE_SOFT))
                                .rounded_md()
                                .font_family(MONO_FONT)
                                .text_base()
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
                .title("设置时区")
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
                                .text_base()
                                .text_color(rgb(MUTED))
                                .child("按国家分组，可搜索城市或时区名称。"),
                        )
                        .child(
                            div()
                                .text_base()
                                .text_color(rgb(AMBER))
                                .child(EDIT_RESTART_WARNING),
                        )
                        .child(
                            Select::new(&this.timezone_select)
                                .placeholder("选择时区")
                                .accessibility_label("时区")
                                .menu_width(px(440.))
                                .menu_max_h(px(360.)),
                        ),
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
                    .child(div().text_base().text_color(rgb(MUTED)).child("环境名称"))
                    .child(
                        div().text_base().font_family(MONO_FONT).child(
                            self.environment_edit_target
                                .clone()
                                .unwrap_or_else(|| "未命名环境".into()),
                        ),
                    )
                    .child(
                        div()
                            .text_base()
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
                    UiAction::EnvironmentPickInstall,
                    "env-pick-install",
                    "选择目录",
                    locked,
                    cx,
                ))
                .child(div().text_base().text_color(rgb(MUTED)).child({
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
                .child(div().text_base().child("安装组件"))
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
                                        .label("中文环境和输入法")
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
            body = body.child(
                div()
                    .text_base()
                    .text_color(rgb(AMBER))
                    .child(EDIT_RESTART_WARNING),
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
            badge("当前目标", BLUE, super::theme::TARGET_BG)
        } else {
            badge("未分配", MUTED, SURFACE_SOFT)
        };
        let base_path = text(detail, "base_path", "未读取");
        let location_path = base_path.clone();
        let location_available = base_path != "未读取" && !base_path.is_empty();
        let version = detail["version"].as_u64().unwrap_or_default();
        let feature_grid = div()
            .flex()
            .flex_wrap()
            .gap_2()
            .child(environment_feature(
                "zsh",
                features["zsh"].as_bool().unwrap_or(false),
                "终端工具",
            ))
            .child(environment_feature(
                "Chrome",
                features["chrome"].as_bool().unwrap_or(false),
                "图形浏览器",
            ))
            .child(environment_feature(
                "中文输入法",
                features["input_method"].as_bool().unwrap_or(false),
                "fcitx5",
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
                            .child(div().text_base().text_color(rgb(MUTED)).child("时区"))
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
                            .text_base()
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
                                    .child(div().text_base().child(name)),
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
                                    .text_base()
                                    .text_color(rgb(MUTED))
                                    .child("安装位置"),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .font_family(MONO_FONT)
                                    .text_base()
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
            .child(div().text_base().child("环境能力"))
            .child(feature_grid)
    }

    fn environment_page(&self, window: &Window, cx: &Context<Self>) -> Div {
        let locked = self.locked();
        let controls_locked = locked || self.environment_editor.is_some();
        let selected = self.environment_selected.as_deref();
        let mut rows = div().flex().flex_col().gap_2();
        for (index, distro) in self.distributions.iter().enumerate() {
            let id = text(distro, "id", "");
            let name = text(distro, "name", "未命名发行版");
            let version = distro["version"].as_u64().unwrap_or_default();
            let target = self.selected.as_deref() == Some(id.as_str());
            let active = selected == Some(name.as_str()) || selected == Some(id.as_str());
            let row_name = name.clone();
            let view_name = row_name.clone();
            let target_id = id.clone();
            let row_background = if active {
                SELECTED_BG
            } else if target {
                super::theme::BLUE_SOFT
            } else {
                SURFACE_SOFT
            };
            let row_border = if active {
                super::theme::BLUE_ACTIVE
            } else if target {
                super::theme::BLUE
            } else {
                RULE
            };
            let target_label = if version != 2 {
                "WSL 1 不支持"
            } else if target {
                "当前目标"
            } else {
                "设为目标"
            };
            let target_color = if version != 2 {
                RUST
            } else if target {
                SURFACE
            } else {
                MUTED
            };
            rows = rows.child(
                div()
                    .id(("environment-row", index))
                    .role(Role::Button)
                    .aria_label("查看环境详情")
                    .tab_stop(true)
                    .focus_visible(|style| style.border_1().border_color(rgb(BLUE)))
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
                    .hover(|style| style.bg(rgb(BLUE_SOFT)))
                    .child(
                        div()
                            .flex()
                            .items_start()
                            .gap_2()
                            .child(div().pt_1().flex_shrink_0().child(icon("icons/folder.svg")))
                            .child(
                                div().flex().flex_col().gap_1().flex_1().min_w_0().child(
                                    div()
                                        .text_base()
                                        .font_weight(if active {
                                            FontWeight::SEMIBOLD
                                        } else {
                                            FontWeight::NORMAL
                                        })
                                        .text_color(rgb(if active { BLUE_ACTIVE } else { INK }))
                                        .truncate()
                                        .child(name),
                                ),
                            )
                            .child(
                                Button::new(("environment-target", index))
                                    .icon(design_icon("select", 17., target_color))
                                    .accessibility_label(target_label)
                                    .tooltip(target_label)
                                    .selected(target)
                                    .disabled(controls_locked || version != 2)
                                    .ghost()
                                    .compact()
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        cx.stop_propagation();
                                        this.selected = Some(target_id.clone());
                                        this.preflight = None;
                                        this.dirty = this.draft_is_dirty(cx);
                                        this.notice = "目标已更新，请保存选择后再启动接管。".into();
                                        this.error = false;
                                        cx.notify();
                                    })),
                            ),
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
                    .child(div().text_base().child("没有发现 WSL2 发行版"))
                    .child(
                        div()
                            .text_base()
                            .text_color(rgb(MUTED))
                            .child("刷新列表后重新读取系统注册信息。"),
                    ),
            );
        }
        let mut top_actions = ButtonGroup::new("environment-actions")
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
        if self.dirty {
            top_actions = top_actions.child(
                self.button(
                    "environment-save",
                    "保存选择",
                    UiAction::Save,
                    controls_locked || self.profile_path.is_none(),
                    cx,
                )
                .icon(design_icon("save", 15., MUTED))
                .small(),
            );
        }
        let left = div()
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
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(card_header("WSL 环境", ""))
                    .child(top_actions),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(badge(
                        format!("{} 个发行版", self.distributions.len()),
                        MUTED,
                        SURFACE_SOFT,
                    ))
                    .child(if self.dirty {
                        badge("有未保存更改", AMBER, WARNING_BG)
                    } else if self.profile_path.is_some() {
                        badge("选择已保存", TEAL, SUCCESS_BG)
                    } else {
                        badge("等待配置库", MUTED, SURFACE_SOFT)
                    }),
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
                    .text_base()
                    .text_color(rgb(MUTED))
                    .child(design_icon("environment", 24., MUTED))
                    .child("请选择左侧环境。"),
            )
        };
        let right = div()
            .flex()
            .flex_col()
            .gap_3()
            .flex_1()
            .min_w_0()
            .child(right_main);
        let stacked = window.viewport_size().width < px(980.);
        let columns = if stacked {
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_h_0()
                .gap_3()
                .child(left)
                .child(right)
                .into_any_element()
        } else {
            div()
                .flex_1()
                .h_full()
                .min_h_0()
                .child(
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
                )
                .into_any_element()
        };
        div().flex().flex_col().h_full().min_h_0().child(columns)
    }

    fn page_content(&self, window: &Window, cx: &Context<Self>) -> Div {
        match self.page {
            Page::Overview => self.overview(cx),
            Page::Environment => self.environment_page(window, cx),
            Page::Policy => self.policy_page(cx),
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
                "error" => ("错误", RUST, WARNING_BG),
                "warning" => ("警告", AMBER, WARNING_BG),
                _ => ("信息", TEAL, SUCCESS_BG),
            };
            let phase = log.phase.as_deref().map(|phase| match phase {
                "idle" => "空闲",
                "forwarding_managed" => "接管中",
                "forwarding_scoped" => "诊断转发",
                "recovery_required" => "需要恢复",
                _ => phase,
            });
            let context = match (log.target.as_deref(), phase) {
                (Some(target), Some(phase)) => format!("{target} · {phase}"),
                (Some(target), None) => target.to_owned(),
                (None, Some(phase)) => phase.to_owned(),
                (None, None) => String::new(),
            };
            let context = match log.generation {
                Some(generation) if context.is_empty() => format!("代次 {generation}"),
                Some(generation) => format!("{context} · 代次 {generation}"),
                None => context,
            };
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
                        .child(
                            div()
                                .text_sm()
                                .text_color(rgb(MUTED))
                                .truncate()
                                .child(context),
                        ),
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
                .text_color(rgb(MUTED))
                .child(if self.reading {
                    "正在读取运行日志…"
                } else if self.log_filter == LogFilter::Errors {
                    "暂无错误记录。"
                } else if self.log_filter == LogFilter::Warnings {
                    "暂无警告记录。"
                } else {
                    "暂无运行日志。"
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
        let table_header = div()
            .flex()
            .w_full()
            .h(px(32.))
            .px_2()
            .items_center()
            .gap_3()
            .border_b_1()
            .border_color(rgb(RULE))
            .text_sm()
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
                .child(div().text_sm().text_color(rgb(MUTED)).child(count))
                .child(table_header)
                .child(rows)
                .child(load_more),
        )
        .w_full()
        .min_h_0()
    }

    fn compact_setting(&self, label: &'static str, field: &Field) -> Div {
        let input = match field {
            Field::Single(state) => Input::new(state).disabled(self.locked()).into_any_element(),
            Field::Multi(state) => Textarea::new(state)
                .h(px(96.))
                .disabled(self.locked())
                .into_any_element(),
        };
        div()
            .flex()
            .flex_col()
            .gap_1()
            .flex_1()
            .min_w_0()
            .child(div().text_base().text_color(rgb(MUTED)).child(label))
            .child(input)
    }

    fn settings_page(&self, cx: &Context<Self>) -> Div {
        let has_residential_default = self.residential["ip"]
            .as_str()
            .is_some_and(|value| !value.is_empty());
        let (save_label, save_color, save_background) = if self.error {
            ("保存失败", super::theme::RUST, super::theme::DANGER_BG)
        } else if self.dirty {
            ("草稿未保存", super::theme::RUST, super::theme::WARNING_BG)
        } else if self.profile_exists {
            ("已保存", TEAL, SUCCESS_BG)
        } else if has_residential_default {
            ("默认配置已读取", AMBER, WARNING_BG)
        } else {
            ("尚未初始化", MUTED, SURFACE_SOFT)
        };
        let header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap_3()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(div().text_xl().child("设置")),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(badge(save_label, save_color, save_background))
                    .child(
                        self.button(
                            "settings-save-top",
                            "保存设置",
                            UiAction::Save,
                            self.locked() || self.profile_path.is_none(),
                            cx,
                        )
                        .primary(),
                    ),
            );
        let residential = card(
            "住宅代理",
            "",
            div()
                .flex()
                .flex_col()
                .gap_3()
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_3()
                        .child(self.compact_setting("服务器 IPv4", &self.fields.residential_ip))
                        .child(self.compact_setting("服务器端口", &self.fields.residential_port)),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_3()
                        .child(self.compact_setting("用户名", &self.fields.residential_username))
                        .child(self.compact_setting("密码", &self.fields.residential_password)),
                ),
        );
        let routing = card(
            "网络入口",
            "",
            div()
                .flex()
                .flex_wrap()
                .gap_3()
                .child(self.compact_setting("宿主 SOCKS5", &self.fields.first_hop))
                .child(self.compact_setting("Windows 入口端口", &self.fields.port)),
        );
        let dns = card(
            "受管 DNS",
            "",
            div()
                .flex()
                .flex_col()
                .gap_3()
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_3()
                        .child(
                            self.compact_setting("DoH 上游 IPv4:端口", &self.fields.dns_upstream),
                        )
                        .child(self.compact_setting("TLS 主机名", &self.fields.dns_tls_name)),
                )
                .child(self.compact_setting("健康检查域名", &self.fields.health_domain)),
        );
        let runtime = card(
            "桌面运行",
            "",
            div()
                .flex()
                .flex_col()
                .gap_2()
                .child(
                    Checkbox::new("settings-autostart")
                        .label("开机自动启动")
                        .checked(self.autostart_enabled)
                        .disabled(self.locked())
                        .on_click(cx.listener(|this, checked, _, cx| {
                            this.set_autostart(*checked, cx);
                        })),
                )
                .child(key_value("关闭窗口", "隐藏到托盘"))
                .child(key_value("配置库", "SQLite"))
                .child(key_value(
                    "配置状态",
                    if self.profile_exists {
                        "已加载"
                    } else {
                        "待初始化"
                    },
                ))
                .child(key_value("Revision", self.revision.as_str().unwrap_or("0"))),
        );
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(header)
            .child(residential)
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(routing.flex_1().min_w(px(360.)))
                    .child(dns.flex_1().min_w(px(460.))),
            )
            .child(runtime)
            .child(if self.error {
                div()
                    .text_base()
                    .text_color(rgb(RUST))
                    .child(self.notice.clone())
            } else {
                div()
            })
    }
}

impl Render for Desktop {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let compact = window.viewport_size().width <= px(800.);
        div()
            .size_full()
            .flex()
            .flex_col()
            .font_family(super::theme::UI_FONT)
            .text_base()
            .text_color(rgb(INK))
            .bg(rgb(PAPER))
            .child(self.title_bar(cx))
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .child(self.sidebar(compact, cx))
                    .child(
                        div().flex().flex_col().flex_1().min_w_0().child(
                            div()
                                .id("page-scroll")
                                .flex_1()
                                .min_h_0()
                                .overflow_y_scroll()
                                .p_3()
                                .child(self.page_content(window, cx)),
                        ),
                    ),
            )
            .child(self.status_bar(cx))
    }
}
