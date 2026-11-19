//! 总览页：选择目标/对照发行版、运行能力预检并展示后台实况。
use gpui::{prelude::*, *};
use gpui_component::{button::{Button, ButtonVariants}, Disableable};

use super::backend::Kind;
use super::components::{badge, fact, panel, text};
use super::model::UiAction;
use super::state::Desktop;
use super::theme::{
    BLUE, DANGER_BG, INK, MUTED, RUST, RULE, SURFACE, SURFACE_SOFT, SUCCESS_BG, TEAL,
};
impl Desktop {

    pub(crate) fn overview(&self, cx: &Context<Self>) -> Div {
        let phase = match self.phase() {
            "idle" => "空闲",
            "forwarding_managed" => "接管中",
            "forwarding_scoped" => "诊断模式",
            "recovery_required" => "需要恢复",
            _ => "状态未知",
        };
        let color = if !self.status_valid || self.phase() == "recovery_required" {
            RUST
        } else if self.phase() == "forwarding_managed" {
            TEAL
        } else {
            INK
        };
        let mut choices = div().flex().flex_col().gap_2();
        if self.distributions.is_empty() {
            choices = choices.child(
                div()
                    .p_4()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .text_sm()
                    .text_color(rgb(MUTED))
                    .child("暂无 WSL。点击“刷新列表”；仅支持 WSL2。"),
            );
        }
        for (index, distro) in self.distributions.iter().enumerate() {
            let id = text(distro, "id", "");
            let name = text(distro, "name", "未命名发行版");
            let version = distro["version"].as_u64().unwrap_or(0);
            let selected = self.selected.as_deref() == Some(id.as_str());
            let witness = self.witness.as_deref() == Some(id.as_str());
            let row_background = if selected {
                0xeaf2ff
            } else if witness {
                0xeaf8f6
            } else {
                SURFACE_SOFT
            };
            let role = if selected {
                badge("目标 WSL", BLUE, 0xeaf2ff)
            } else if witness {
                badge("对照 WSL", TEAL, SUCCESS_BG)
            } else {
                badge("未选择", MUTED, SURFACE)
            };
            let target_id = id.clone();
            let witness_id = id;
            choices = choices.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_3()
                    .py_3()
                    .bg(rgb(row_background))
                    .border_1()
                    .border_color(rgb(RULE))
                    .rounded_md()
                    .child(
                        div().flex_1().min_w_0().child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(
                                    div()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(INK))
                                        .child(name),
                                )
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(rgb(MUTED))
                                        .child(format!("WSL {version}")),
                                ),
                        ),
                    )
                    .child(role)
                    .child(
                        Button::new(("select-target", index))
                            .label(if selected {
                                "已选目标"
                            } else {
                                "设为目标"
                            })
                            .disabled(self.locked() || version != 2)
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
                        Button::new(("select-witness", index))
                            .label(if witness {
                                "已选对照"
                            } else {
                                "设为对照"
                            })
                            .disabled(self.locked() || version != 2 || selected)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.witness = Some(witness_id.clone());
                                this.preflight = None;
                                this.preflight_key = None;
                                this.dirty = this.draft_is_dirty(cx);
                                cx.notify();
                            })),
                    ),
            );
        }
        let target_name = self
            .distributions
            .iter()
            .find(|d| d["id"].as_str() == self.selected.as_deref())
            .map(|d| text(d, "name", "未知"))
            .unwrap_or_else(|| "未选择".into());
        let witness_name = self
            .distributions
            .iter()
            .find(|d| d["id"].as_str() == self.witness.as_deref())
            .map(|d| text(d, "name", "未知"))
            .unwrap_or_else(|| "未选择".into());
        let (phase_status, phase_background) = if !self.status_valid || self.phase() == "recovery_required" {
            ("需关注", DANGER_BG)
        } else if self.phase() == "forwarding_managed" {
            ("运行中", SUCCESS_BG)
        } else {
            ("空闲", SURFACE_SOFT)
        };
        let mut state = panel("后台状态", "显示后台最后状态，不随页面选择变化")
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(
                                div()
                                    .text_2xl()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(color))
                                    .child(phase),
                            )
                            .child(badge(phase_status, color, phase_background)),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child(self.status_at.map(|_| "已有快照").unwrap_or("等待状态")),
                    ),
            )
            .child(fact(
                "当前目标",
                text(&self.status, "active_target", "无当前目标"),
                color,
            ))
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(fact("目标 WSL · 待生效", target_name, BLUE))
                    .child(fact("对照 WSL · 不接管", witness_name, TEAL)),
            )
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(fact(
                        "操作版本",
                        self.generation()
                            .map(|g| g.to_string())
                            .unwrap_or_else(|| "未确认".into()),
                        INK,
                    ))
                    .child(fact(
                        "配置版本",
                        self.status["config_generation"]
                            .as_u64()
                            .map(|g| g.to_string())
                            .unwrap_or_else(|| "无已确认运行配置".into()),
                        INK,
                    )),
            )
            .child(fact(
                "DNS 观测",
                self.dns_label(),
                if self.status["dns_managed"] == true {
                    TEAL
                } else {
                    RUST
                },
            ))
            .child(fact("公网出口", self.exit_label(), INK))
            .child(self.button(
                "probe-exit",
                "检测公网出口",
                UiAction::Probe,
                self.locked() || !self.status_valid || self.phase() != "forwarding_managed",
                cx,
            ))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(
                        self.button(
                            "start",
                            "启动接管",
                            UiAction::Prepare(Kind::Start),
                            self.locked() || !self.idle(),
                            cx,
                        )
                        .primary(),
                    )
                    .child(self.button(
                        "switch",
                        "切换至目标",
                        UiAction::Prepare(Kind::Switch),
                        self.locked() || !self.status_valid || self.phase() != "forwarding_managed",
                        cx,
                    ))
                    .child(
                        self.button(
                            "stop",
                            if self.phase() == "recovery_required" {
                                "恢复并停止"
                            } else {
                                "停止接管"
                            },
                            UiAction::Prepare(Kind::Stop),
                            self.locked() || !self.status_valid || self.idle(),
                            cx,
                        )
                        .danger(),
                    ),
            );
        if let Some(issue) = self.status["issue"].as_str() {
            state = state.child(
                div()
                    .text_sm()
                    .text_color(rgb(RUST))
                    .child(format!("问题：{issue}")),
            );
        }
        if self.phase() == "recovery_required" {
            state = state.child(fact(
                "记录目标 · 需恢复",
                text(&self.status, "recorded_target", "请查看诊断"),
                RUST,
            ));
        }
        let mut page = div()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .gap_4()
                    .items_start()
                    .child(
                        panel(
                            "目标与对照",
                            "选择不会接管；预检只读。",
                        )
                        .w(px(490.))
                        .child(choices)
                        .child(self.field(
                            "入口端口",
                            "范围：1024–65535。",
                            &self.fields.port,
                            false,
                        ))
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .child(self.button(
                                    "list",
                                    "刷新列表",
                                    UiAction::List,
                                    self.locked(),
                                    cx,
                                ))
                                .child(
                                    self.button(
                                        "preflight",
                                        "运行预检",
                                        UiAction::Preflight,
                                        self.locked(),
                                        cx,
                                    )
                                    .primary(),
                                ),
                        ),
                    )
                    .child(state.flex_1()),
            )
            .child(self.preflight_panel());
        if self.phase() == "recovery_required" {
            page = page.child(
                div()
                    .p_4()
                    .border_l_4()
                    .border_color(rgb(RUST))
                    .bg(rgb(0xfff4ed))
                    .child("检测到未完成操作。请查看诊断，然后执行“恢复并停止”。不会自动切换或清理其他目标。"),
            );
        }
        page
    }

    fn exit_label(&self) -> String {
        let exit = &self.status["recent_exit"];
        let Some(ip) = exit["ip"].as_str() else {
            return "未检测 · 目标 IP 不等于出口 IP".into();
        };
        let verified = match exit["matches_residential"].as_bool() {
            Some(true) => "匹配配置出口",
            Some(false) => "不匹配配置出口",
            None => "未比对配置出口",
        };
        format!(
            "{ip} · {} · {verified} · 检测时间 {} UTC",
            text(exit, "country", "地区未知"),
            exit["checked_unix_seconds"]
                .as_u64()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "未知".into())
        )
    }

    pub(crate) fn dns_label(&self) -> String {
        if !self.status_valid {
            "状态未知；无法确认 DNS 保护".into()
        } else if self.status["dns_managed"] == true {
            "系统 DNS 已接管；结果来自启动时检查".into()
        } else if self.idle() {
            "系统 DNS 未接管".into()
        } else {
            "DNS 状态未确认，请检查恢复与诊断".into()
        }
    }

    fn preflight_panel(&self) -> Div {
        let Some(result) = &self.preflight else {
            return div()
                .p_4()
                .bg(rgb(SURFACE_SOFT))
                .rounded_md()
                .text_sm()
                .text_color(rgb(MUTED))
                .child("预检尚未运行或选择已变更。启动前会再次检查；非直连 TCP 和系统 DNS 经双跳，其他 UDP 不代理。");
};
        let passed = result["passed"] == true;
        let mut panel = panel(
            "预检结果",
            if passed {
                "通过 · 仍需确认启动"
            } else {
                "未通过 · 未启动"
            },
        )
        .child(badge(
            if passed { "通过" } else { "有阻断" },
            if passed { TEAL } else { RUST },
            if passed { SUCCESS_BG } else { DANGER_BG },
        ));
        if let Some(blockers) = result["blockers"].as_array() {
            for blocker in blockers {
                if let Some(message) = blocker.as_str() {
                    panel = panel.child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(DANGER_BG))
                            .rounded_md()
                            .text_sm()
                            .text_color(rgb(RUST))
                            .child(message.to_owned()),
                    );
                }
            }
        }
        for (label, key) in [("目标身份", "target"), ("对照环境", "witness")] {
            let observation = &result[key];
            if observation.is_object() {
                let snapshot = &observation["snapshot"];
                let identity_valid = snapshot["identity_valid"] == true;
                let mut observation_panel = div()
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
                            .child(div().text_sm().font_weight(FontWeight::SEMIBOLD).child(format!(
                                "{label} · {}",
                                text(&observation["distribution"], "name", "未知")
                            )))
                            .child(badge(
                                if identity_valid { "身份验证通过" } else { "未确认" },
                                if identity_valid { TEAL } else { RUST },
                                if identity_valid { SUCCESS_BG } else { DANGER_BG },
                            )),
                    );
                if let Some(blockers) = snapshot["blockers"].as_array() {
                    for blocker in blockers {
                        if let Some(message) = blocker.as_str() {
                            observation_panel = observation_panel.child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(RUST))
                                    .child(message.to_owned()),
                            );
                        }
                    }
                }
                panel = panel.child(observation_panel);
            }
        }
        panel
    }

}
