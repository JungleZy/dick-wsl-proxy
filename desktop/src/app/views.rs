//! GPUI Kit 应用外壳和页面导航。

use gpui_kit::base::Selectable as _;
use gpui_kit::component::{
    Disableable as _, Sizable as _, TitleBar,
    button::{Button, ButtonVariants as _},
    checkbox::Checkbox,
};
use gpui_kit::{prelude::*, *};
use serde_json::json;

use super::backend::Kind;
use super::components::{app_icon, badge, design_icon, icon, text};
use super::model::{EnvironmentEditor, LogFilter, Page, UiAction};
use super::state::Desktop;
use super::theme::{
    AMBER, BLUE, BLUE_SOFT, INK, MUTED, PAPER, RULE, RUST, SIDEBAR_BG, SUCCESS_BG, SURFACE,
    SURFACE_SOFT, TEAL, WARNING_BG,
};

pub(crate) fn card_header(title: &'static str, caption: &'static str) -> Div {
    div().flex().items_start().justify_between().gap_3().child(
        div()
            .flex()
            .flex_col()
            .gap_1()
            .child(div().text_base().child(title))
            .child(div().text_base().text_color(rgb(MUTED)).child(caption)),
    )
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
                .text_base()
                .text_color(rgb(MUTED))
                .child(label),
        )
        .child(div().flex_1().text_base().child(value.into()))
}

pub(crate) fn chart_card(
    title: &'static str,
    caption: &'static str,
    body: impl IntoElement,
) -> Div {
    card(title, caption, body)
}

fn titlebar_button(
    id: &'static str,
    label: &'static str,
    icon_path: &'static str,
    page: Page,
    cx: &Context<Desktop>,
) -> Button {
    Button::new(id)
        .icon(design_icon(icon_path, 16., MUTED))
        .accessibility_label(label)
        .tooltip(label)
        .ghost()
        .compact()
        .on_click(cx.listener(move |this, _, _, cx| {
            this.page = page;
            cx.notify();
        }))
}

impl Desktop {
    fn title_bar(&self, cx: &Context<Self>) -> TitleBar {
        TitleBar::new().h(px(42.)).child(
            div()
                .w_full()
                .h(px(42.))
                .flex()
                .items_center()
                .gap(px(10.))
                .px(px(14.))
                .bg(rgb(SURFACE))
                .border_b_1()
                .border_color(rgb(RULE))
                .child(app_icon(23.))
                .child(
                    div()
                        .text_lg()
                        .font_weight(FontWeight::BOLD)
                        .child("WSL Proxy"),
                )
                .child(div().flex_1())
                .child(titlebar_button(
                    "title-settings",
                    "设置",
                    "settings",
                    Page::Settings,
                    cx,
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
            .on_click(cx.listener(move |this, _, _, cx| {
                this.page = page;
                cx.notify();
            }))
            .on_key_down(cx.listener(move |this, event: &KeyDownEvent, _, cx| {
                if matches!(event.keystroke.key.as_str(), "enter" | "space") {
                    this.page = key_page;
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
            button = button.px(px(14.)).child(label);
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
        let mut navigation = div().flex().flex_col().gap_1().px_3().pt_3();
        for (page, index, label, icon_path) in pages {
            navigation =
                navigation.child(self.nav_button(page, index, label, icon_path, compact, cx));
        }
        div()
            .flex()
            .flex_col()
            .h_full()
            .w(px(if compact { 72. } else { 216. }))
            .flex_shrink_0()
            .bg(rgb(SIDEBAR_BG))
            .border_r_1()
            .border_color(rgb(RULE))
            .child(navigation)
            .child(div().flex_1())
    }

    fn status_bar(&self, cx: &Context<Self>) -> Div {
        let online_color = if self.status_valid { TEAL } else { RUST };
        let idle_color = if self.status_valid && self.phase() == "idle" {
            TEAL
        } else {
            MUTED
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
                    .accessibility_label("未接管")
                    .tooltip("未接管")
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
    }

    fn environment_page(&self, cx: &Context<Self>) -> Div {
        let locked = self.locked();
        let mut rows = div().flex().flex_col().gap_2();
        for (index, distro) in self.distributions.iter().enumerate() {
            let id = text(distro, "id", "");
            let name = text(distro, "name", "未命名发行版");
            let version = distro["version"].as_u64().unwrap_or_default();
            let selected = self.selected.as_deref() == Some(id.as_str());
            let witness = self.witness.as_deref() == Some(id.as_str());
            let row_background = if selected {
                super::theme::TARGET_BG
            } else if witness {
                SUCCESS_BG
            } else {
                SURFACE_SOFT
            };
            let target_id = id.clone();
            let witness_id = id.clone();
            let view_name = name.clone();
            let edit_name = name.clone();
            let backup_name = name.clone();
            let role = if selected {
                badge("当前目标", BLUE, super::theme::TARGET_BG)
            } else if witness {
                badge("见证环境", TEAL, SUCCESS_BG)
            } else {
                badge("未分配", MUTED, SURFACE)
            };
            rows = rows.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p_2()
                    .bg(rgb(row_background))
                    .border_1()
                    .border_color(rgb(RULE))
                    .rounded_md()
                    .hover(|style| style.bg(rgb(super::theme::BLUE_SOFT)))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(icon("icons/folder.svg"))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .child(div().text_base().truncate().child(name))
                                    .child(
                                        div()
                                            .text_base()
                                            .text_color(rgb(MUTED))
                                            .child(format!("WSL {version}")),
                                    ),
                            )
                            .child(role),
                    )
                    .child(
                        div()
                            .flex()
                            .justify_end()
                            .flex_wrap()
                            .gap_1()
                            .child(
                                Button::new(("env-target", index))
                                    .label(if selected {
                                        "目标已选"
                                    } else {
                                        "设为目标"
                                    })
                                    .small()
                                    .disabled(locked || version != 2)
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.selected = Some(target_id.clone());
                                        if this.witness == this.selected {
                                            this.witness = None;
                                        }
                                        this.preflight = None;
                                        this.preflight_key = None;
                                        this.dirty = this.draft_is_dirty(cx);
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new(("env-witness", index))
                                    .label(if witness {
                                        "见证已选"
                                    } else {
                                        "设为见证"
                                    })
                                    .small()
                                    .disabled(locked || version != 2 || selected)
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.witness = Some(witness_id.clone());
                                        this.preflight = None;
                                        this.preflight_key = None;
                                        this.dirty = this.draft_is_dirty(cx);
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new(("env-view", index))
                                    .label("查看")
                                    .small()
                                    .disabled(locked || version != 2)
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.environment_view(view_name.clone(), cx);
                                    })),
                            )
                            .child(
                                Button::new(("env-edit", index))
                                    .label("编辑")
                                    .small()
                                    .disabled(locked || version != 2)
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.environment_edit(edit_name.clone(), window, cx);
                                    })),
                            )
                            .child(
                                Button::new(("env-backup", index))
                                    .label("备份")
                                    .small()
                                    .disabled(locked || version != 2)
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.environment_backup(backup_name.clone(), cx);
                                    })),
                            ),
                    ),
            );
        }
        if self.distributions.is_empty() {
            rows = rows.child(
                div()
                    .p_3()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .text_base()
                    .text_color(rgb(MUTED))
                    .child("没有发现 WSL2 发行版，请刷新列表。"),
            );
        }
        let selection = card(
            "WSL 环境",
            "选择目标与见证，配置入口端口。",
            div()
                .flex()
                .flex_col()
                .gap_3()
                .child(rows)
                .child(self.field(
                    "Windows 入口端口",
                    "范围 1024–65535。",
                    &self.fields.port,
                    false,
                ))
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(self.button("env-list", "刷新列表", UiAction::List, locked, cx))
                        .child(
                            self.button(
                                "env-preflight",
                                "运行预检",
                                UiAction::Preflight,
                                locked,
                                cx,
                            )
                            .primary(),
                        ),
                ),
        );
        let management = card(
            "环境管理",
            "新增、查看、编辑和备份 WSL 环境。",
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(
                    self.button(
                        "env-create",
                        "新增环境",
                        UiAction::EnvironmentCreate,
                        locked,
                        cx,
                    )
                    .primary(),
                )
                .child(
                    div()
                        .flex_1()
                        .text_base()
                        .text_color(rgb(MUTED))
                        .child("创建会导入 rootfs tar，并按勾选项安装基本工具。"),
                ),
        );
        let editor = self.environment_editor.map(|mode| {
            let creating = matches!(mode, EnvironmentEditor::Create);
            let mut body = div().flex().flex_col().gap_3().child(self.field(
                "环境名称",
                if creating {
                    "只允许字母、数字、点、下划线和短横线。"
                } else {
                    "编辑操作针对当前环境。"
                },
                &self.fields.environment_name,
                false,
            ));
            if creating {
                body = body
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .items_end()
                            .gap_2()
                            .child(self.field(
                                "rootfs tar",
                                "选择发行版 rootfs 的 .tar 或 .tar.gz。",
                                &self.fields.environment_source,
                                false,
                            ))
                            .child(self.button(
                                "env-pick-source",
                                "选择文件",
                                UiAction::EnvironmentPickSource,
                                locked,
                                cx,
                            )),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .items_end()
                            .gap_2()
                            .child(self.field(
                                "安装目录",
                                "目录必须不存在，wsl.exe 会创建它。",
                                &self.fields.environment_install,
                                false,
                            ))
                            .child(self.button(
                                "env-pick-install",
                                "选择目录",
                                UiAction::EnvironmentPickInstall,
                                locked,
                                cx,
                            )),
                    );
            }
            body = body.child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_4()
                    .child(
                        Checkbox::new("env-install-zsh")
                            .label("安装 zsh")
                            .checked(self.environment_zsh)
                            .disabled(locked)
                            .on_click(cx.listener(|this, checked, _, cx| {
                                this.environment_zsh = *checked;
                                cx.notify();
                            })),
                    )
                    .child(
                        Checkbox::new("env-install-chrome")
                            .label("安装 Chrome")
                            .checked(self.environment_chrome)
                            .disabled(locked)
                            .on_click(cx.listener(|this, checked, _, cx| {
                                this.environment_chrome = *checked;
                                cx.notify();
                            })),
                    )
                    .child(
                        Checkbox::new("env-install-chinese")
                            .label("中文环境和输入法")
                            .checked(self.environment_chinese)
                            .disabled(locked)
                            .on_click(cx.listener(|this, checked, _, cx| {
                                this.environment_chinese = *checked;
                                cx.notify();
                            })),
                    ),
            );
            body = body.child(
                div()
                    .flex()
                    .gap_2()
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
                        .primary(),
                    )
                    .child(self.button(
                        "env-cancel",
                        "取消",
                        UiAction::EnvironmentCancel,
                        locked,
                        cx,
                    )),
            );
            card(
                if creating {
                    "新增 WSL 环境"
                } else {
                    "编辑 WSL 环境"
                },
                "安装完成后可以在查看面板确认能力。",
                body,
            )
        });
        let backup = card(
            "备份环境",
            "先选择一个新的 .tar 文件路径，再点击环境列表中的备份。",
            div()
                .flex()
                .flex_wrap()
                .items_end()
                .gap_2()
                .child(self.field(
                    "备份文件",
                    "目标文件不能已存在。",
                    &self.fields.environment_backup,
                    false,
                ))
                .child(self.button(
                    "env-pick-backup",
                    "选择位置",
                    UiAction::EnvironmentPickBackup,
                    locked,
                    cx,
                )),
        );
        let details = self.environment_detail.as_ref().map(|detail| {
            let features = &detail["features"];
            card(
                "环境详情",
                "最近一次查看结果。",
                div()
                    .flex()
                    .flex_col()
                    .child(key_value("名称", text(detail, "name", "未命名")))
                    .child(key_value("安装位置", text(detail, "base_path", "未读取")))
                    .child(key_value(
                        "版本",
                        format!("WSL {}", detail["version"].as_u64().unwrap_or_default()),
                    ))
                    .child(key_value(
                        "zsh",
                        if features["zsh"].as_bool().unwrap_or(false) {
                            "已安装"
                        } else {
                            "未安装"
                        },
                    ))
                    .child(key_value(
                        "Chrome",
                        if features["chrome"].as_bool().unwrap_or(false) {
                            "已安装"
                        } else {
                            "未安装"
                        },
                    ))
                    .child(key_value(
                        "中文输入法",
                        if features["input_method"].as_bool().unwrap_or(false) {
                            "已配置 fcitx5"
                        } else {
                            "未配置"
                        },
                    ))
                    .child(key_value("Locale", text(features, "locale", "未读取"))),
            )
        });
        let baseline = card(
            "环境基线",
            "启动前检查的只读能力。",
            div()
                .flex()
                .gap_3()
                .child(metric("网络模式", "NAT"))
                .child(metric(
                    "cgroup",
                    if self.status_valid {
                        "已观测"
                    } else {
                        "待检查"
                    },
                ))
                .child(metric(
                    "NAT 表",
                    if self.status_valid {
                        "已观测"
                    } else {
                        "待检查"
                    },
                )),
        );
        let preflight = card(
            "预检",
            "目标身份、cgroup、NAT 表和入口端口。",
            self.preflight_panel(),
        );
        let ports = card(
            "端口占用",
            "当前入口端口的可用性。",
            div()
                .flex()
                .flex_col()
                .child(key_value(
                    "TCP",
                    if self.status_valid {
                        "待确认"
                    } else {
                        "未检查"
                    },
                ))
                .child(key_value(
                    "UDP",
                    if self.status_valid {
                        "待确认"
                    } else {
                        "未检查"
                    },
                )),
        );
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_start()
                    .flex_wrap()
                    .gap_3()
                    .child(selection.flex_1().min_w(px(420.)))
                    .child(preflight.flex_1().min_w(px(420.))),
            )
            .child(management)
            .children(editor)
            .child(backup)
            .children(details)
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(baseline.flex_1())
                    .child(ports.flex_1()),
            )
    }

    fn page_content(&self, cx: &Context<Self>) -> Div {
        match self.page {
            Page::Overview => self.overview(cx),
            Page::Environment => self.environment_page(cx),
            Page::Policy => self.policy_page(cx),
            Page::Connection => self.diagnostics(cx),
            Page::Logs => self.logs_page(cx),
            Page::Settings => self.settings_page(cx),
        }
    }

    fn logs_page(&self, cx: &Context<Self>) -> Div {
        let row = |time: &'static str,
                   level: &'static str,
                   message: &'static str,
                   source: &'static str| {
            div()
                .flex()
                .items_center()
                .gap_3()
                .min_h(px(42.))
                .border_b_1()
                .border_color(rgb(RULE))
                .child(
                    div()
                        .w(px(72.))
                        .font_family(super::theme::MONO_FONT)
                        .child(time),
                )
                .child(div().w(px(72.)).child(if level == "待处理" {
                    badge(level, AMBER, WARNING_BG)
                } else {
                    badge(level, TEAL, SUCCESS_BG)
                }))
                .child(div().flex_1().child(message))
                .child(div().w(px(120.)).text_color(rgb(MUTED)).child(source))
        };
        let rows = if self.log_filter == LogFilter::Errors {
            div()
                .p_4()
                .bg(rgb(SURFACE_SOFT))
                .rounded_md()
                .text_base()
                .text_color(rgb(MUTED))
                .child("暂无错误记录。")
        } else {
            div()
                .flex()
                .flex_col()
                .child(row("刚刚", "信息", "后台心跳正常，等待接管目标", "runtime"))
                .child(row("2 分钟", "信息", "SQLite 配置已加载", "desktop_store"))
                .child(row(
                    "5 分钟",
                    "待处理",
                    "目标 WSL 尚未选择，预检未执行",
                    "preflight",
                ))
        };
        card(
            "运行日志",
            "后台事件、预检结果和接管生命周期",
            div()
                .flex()
                .flex_col()
                .child(
                    div()
                        .flex()
                        .justify_end()
                        .gap_2()
                        .mb_3()
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
                        ),
                )
                .child(rows),
        )
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
            (
                "默认配置已读取",
                super::theme::AMBER,
                super::theme::WARNING_BG,
            )
        } else {
            ("尚未初始化", MUTED, SURFACE_SOFT)
        };
        let residential = card(
            "住宅 SOCKS5",
            "个人配置直接填写，保存到 SQLite",
            div()
                .flex()
                .flex_col()
                .gap_3()
                .child(
                    div()
                        .flex()
                        .gap_3()
                        .child(self.field(
                            "服务器 IPv4",
                            "住宅出口服务器地址。",
                            &self.fields.residential_ip,
                            false,
                        ))
                        .child(self.field(
                            "服务器端口",
                            "范围 1–65535。",
                            &self.fields.residential_port,
                            false,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .gap_3()
                        .child(self.field(
                            "用户名",
                            "SOCKS5 认证用户名。",
                            &self.fields.residential_username,
                            false,
                        ))
                        .child(self.field(
                            "密码",
                            "SOCKS5 认证密码。",
                            &self.fields.residential_password,
                            false,
                        )),
                ),
        );
        let host = card(
            "宿主 SOCKS5",
            "第一跳连接",
            self.field(
                "代理地址",
                "填写 IPv4:端口。",
                &self.fields.first_hop,
                false,
            ),
        );
        let dns = card(
            "DNS 保护",
            "DoH 上游与 TLS",
            div()
                .flex()
                .flex_col()
                .gap_3()
                .child(self.field(
                    "DoH 上游 IPv4:端口",
                    "固定地址，通过代理链访问 HTTPS。",
                    &self.fields.dns_upstream,
                    false,
                ))
                .child(self.field(
                    "DoH TLS 主机名",
                    "用于 SNI 和证书校验。",
                    &self.fields.dns_tls_name,
                    false,
                ))
                .child(self.field(
                    "健康检查域名",
                    "启动时验证链路。",
                    &self.fields.health_domain,
                    false,
                )),
        );
        let storage = card(
            "存储",
            "本机配置和运行数据",
            div()
                .flex()
                .flex_col()
                .child(key_value("配置库", "SQLite"))
                .child(key_value(
                    "状态",
                    if self.profile_exists {
                        "已加载"
                    } else {
                        "待初始化"
                    },
                ))
                .child(key_value("Revision", self.revision.as_str().unwrap_or("0"))),
        );
        let window = card(
            "窗口",
            "桌面行为",
            div()
                .flex()
                .flex_col()
                .child(key_value("关闭窗口", "保持后台运行"))
                .child(key_value("语言", "简体中文")),
        );
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .justify_end()
                    .child(badge(save_label, save_color, save_background)),
            )
            .child(residential)
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(host.flex_1())
                    .child(dns.flex_1()),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(storage.flex_1())
                    .child(window.flex_1()),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        self.button(
                            "settings-save",
                            "保存到 SQLite",
                            UiAction::Save,
                            self.locked() || self.profile_path.is_none(),
                            cx,
                        )
                        .primary(),
                    )
                    .child(
                        div().text_base().text_color(rgb(MUTED)).child(
                            self.profile_path
                                .clone()
                                .unwrap_or_else(|| "等待后台返回配置路径。".into()),
                        ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .text_base()
                            .text_color(rgb(if self.error {
                                super::theme::RUST
                            } else {
                                MUTED
                            }))
                            .child(self.notice.clone()),
                    ),
            )
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
                                .child(self.page_content(cx)),
                        ),
                    ),
            )
            .child(self.status_bar(cx))
    }
}
