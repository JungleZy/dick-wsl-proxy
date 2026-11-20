//! 总览页：选择目标/对照发行版、运行能力预检并展示后台实况。
use gpui::{prelude::*, *};
use gpui_component::{
    Disableable,
    button::{Button, ButtonVariants},
};

use super::backend::Kind;
use super::components::{badge, fact, panel, text};
use super::model::UiAction;
use super::state::Desktop;
use super::theme::{
    BLUE, DANGER_BG, INK, MUTED, RULE, RUST, SUCCESS_BG, SURFACE, SURFACE_SOFT, TARGET_BG, TEAL,
};
impl Desktop {
    pub(crate) fn overview(&self, cx: &Context<Self>) -> Div {
        let phase_id = self.phase();
        let phase = match phase_id {
            "idle" => "空闲待命",
            "forwarding_managed" => "保护接管中",
            "forwarding_scoped" => "诊断模式",
            "recovery_required" => "需要恢复",
            _ => "状态未知",
        };
        let active = phase_id == "forwarding_managed";
        let risk = !self.status_valid || phase_id == "recovery_required";
        let idle = self.idle();
        let locked = self.locked();
        let dns_managed = self.status["dns_managed"] == true;
        let state_color = if risk {
            RUST
        } else if active {
            TEAL
        } else {
            INK
        };
        let (state_label, state_background) = if risk {
            ("需要关注", DANGER_BG)
        } else if active {
            ("实时保护", SUCCESS_BG)
        } else {
            ("未接管", SURFACE_SOFT)
        };
        let target_name = self.distribution_name(self.selected.as_deref());
        let witness_name = self.distribution_name(self.witness.as_deref());

        let mut choices = div().flex().flex_col().gap_2();
        if self.distributions.is_empty() {
            choices = choices.child(
                div()
                    .p_4()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .text_sm()
                    .text_color(rgb(MUTED))
                    .child("没有发现 WSL2 发行版。刷新列表后再选择目标。"),
            );
        }
        for (index, distro) in self.distributions.iter().enumerate() {
            let id = text(distro, "id", "");
            let name = text(distro, "name", "未命名发行版");
            let version = distro["version"].as_u64().unwrap_or(0);
            let selected = self.selected.as_deref() == Some(id.as_str());
            let witness = self.witness.as_deref() == Some(id.as_str());
            let row_background = if selected {
                TARGET_BG
            } else if witness {
                SUCCESS_BG
            } else {
                SURFACE_SOFT
            };
            let role = if selected {
                badge("当前目标", BLUE, TARGET_BG)
            } else if witness {
                badge("见证环境", TEAL, SUCCESS_BG)
            } else {
                badge("未分配", MUTED, SURFACE)
            };
            let target_id = id.clone();
            let witness_id = id;
            let selection_disabled = locked || version != 2;
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
                                "目标已选"
                            } else {
                                "设为目标"
                            })
                            .disabled(selection_disabled)
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
                                "见证已选"
                            } else {
                                "设为见证"
                            })
                            .disabled(selection_disabled || selected)
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

        let mut status_panel = panel(
            "当前保护状态",
            "后台最后一次观测；页面选择不会改变已运行目标。",
        )
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
                                .text_color(rgb(state_color))
                                .child(phase),
                        )
                        .child(badge(state_label, state_color, state_background)),
                )
                .child(
                    div().text_xs().text_color(rgb(MUTED)).child(
                        self.status_at
                            .map(|_| "快照已记录")
                            .unwrap_or("等待后台状态"),
                    ),
                ),
        )
        .child(
            div()
                .flex()
                .gap_3()
                .child(fact(
                    "运行目标",
                    text(&self.status, "active_target", "无当前目标"),
                    state_color,
                ))
                .child(fact("目标候选", target_name, BLUE))
                .child(fact("见证环境", witness_name, TEAL)),
        )
        .child(
            div()
                .flex()
                .gap_3()
                .child(fact(
                    "DNS 观测",
                    self.dns_label(),
                    if dns_managed { TEAL } else { RUST },
                ))
                .child(fact("公网出口", self.exit_label(), INK))
                .child(fact(
                    "操作版本",
                    self.generation()
                        .map(|g| g.to_string())
                        .unwrap_or_else(|| "未确认".into()),
                    INK,
                )),
        )
        .child(
            div()
                .flex()
                .flex_wrap()
                .gap_2()
                .child(
                    self.button(
                        "start",
                        "启动保护接管",
                        UiAction::Prepare(Kind::Start),
                        locked || !idle,
                        cx,
                    )
                    .primary(),
                )
                .child(self.button(
                    "switch",
                    "切换至目标",
                    UiAction::Prepare(Kind::Switch),
                    locked || !self.status_valid || !active,
                    cx,
                ))
                .child(
                    self.button(
                        "stop",
                        if phase_id == "recovery_required" {
                            "恢复并停止"
                        } else {
                            "停止接管"
                        },
                        UiAction::Prepare(Kind::Stop),
                        locked || !self.status_valid || idle,
                        cx,
                    )
                    .danger(),
                )
                .child(self.button(
                    "probe-exit",
                    "复核公网出口",
                    UiAction::Probe,
                    locked || !self.status_valid || !active,
                    cx,
                )),
        );
        if let Some(issue) = self.status["issue"].as_str() {
            status_panel = status_panel.child(
                div()
                    .text_sm()
                    .text_color(rgb(RUST))
                    .child(format!("后台问题：{issue}")),
            );
        }

        let selection = panel("目标与启动准备", "选择只修改草稿；启动前会再次执行预检。")
            .child(
                div()
                    .text_xs()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(MUTED))
                    .child("选择目标与见证"),
            )
            .child(choices)
            .child(self.field("入口端口", "范围：1024–65535。", &self.fields.port, false))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(self.button("list", "刷新发行版列表", UiAction::List, locked, cx))
                    .child(
                        self.button("preflight", "运行启动预检", UiAction::Preflight, locked, cx)
                            .primary(),
                    ),
            );
        div().flex().flex_col().gap_4().child(status_panel).child(
            div()
                .flex()
                .gap_4()
                .items_start()
                .child(selection.w(px(490.)))
                .child(self.preflight_panel().flex_1()),
        )
    }

    fn distribution_name(&self, id: Option<&str>) -> String {
        self.distributions
            .iter()
            .find(|distribution| distribution["id"].as_str() == id)
            .map(|distribution| text(distribution, "name", "未知"))
            .unwrap_or_else(|| "未选择".into())
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
        let (result_label, result_color, result_background, result_caption) = if passed {
            ("通过", TEAL, SUCCESS_BG, "通过 · 仍需确认启动")
        } else {
            ("有阻断", RUST, DANGER_BG, "未通过 · 未启动")
        };
        let mut panel = panel("预检结果", result_caption).child(badge(
            result_label,
            result_color,
            result_background,
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
                let (identity_label, identity_color, identity_background) = if identity_valid {
                    ("身份验证通过", TEAL, SUCCESS_BG)
                } else {
                    ("未确认", RUST, DANGER_BG)
                };
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
                            .child(div().text_sm().font_weight(FontWeight::SEMIBOLD).child(
                                format!(
                                    "{label} · {}",
                                    text(&observation["distribution"], "name", "未知")
                                ),
                            ))
                            .child(badge(identity_label, identity_color, identity_background)),
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
