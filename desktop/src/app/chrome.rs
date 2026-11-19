//! 页面共享的交互壳层：按钮分发、字段包装和策略路径摘要。

use gpui::{prelude::*, *};
use gpui_component::{
    button::Button,
    input::{Input, InputState},
    Disableable,
};
use serde_json::{json, Value};

use super::backend::Kind;
use super::components::{badge, fact, text};
use super::model::UiAction;
use super::state::Desktop;
use super::theme::{BLUE, DANGER_BG, INK, MUTED, RUST, RULE, SURFACE_SOFT, SUCCESS_BG, TEAL};
impl Desktop {
    pub(crate) fn button(
        &self,
        id: &'static str,
        label: &'static str,
        action: UiAction,
        disabled: bool,
        cx: &Context<Self>,
    ) -> Button {
        Button::new(id)
            .label(label)
            .disabled(disabled)
            .on_click(cx.listener(move |this, _, window, cx| match action {
                UiAction::Page(page) => {
                    this.page = page;
                    cx.notify();
                }
                UiAction::Refresh => this.send(Kind::Status, json!({"command":"status"}), cx),
                UiAction::Reconnect => {
                    if this.dirty {
                        this.fail("有未保存更改，请先保存再重连。", cx);
                    } else {
                        this.send(Kind::Bootstrap, Value::Null, cx);
                    }
                }
                UiAction::List => this.send(Kind::List, json!({"command":"list"}), cx),
                UiAction::Preflight => this.preflight(cx),
                UiAction::Save => this.save(cx),
                UiAction::Pick => this.choose_env(window, cx),
                UiAction::Import => this.credentials(false, cx),
                UiAction::Forget => this.credentials(true, cx),
                UiAction::Probe => {
                    if this.phase() == "forwarding_managed" {
                        if let Some(generation) = this.generation() {
                            this.send(
                                Kind::Probe,
                                json!({"command":"probe_exit","expected_generation":generation}),
                                cx,
                            );
                        }
                    }
                }
                UiAction::Prepare(kind) => this.prepare(kind, cx),
                UiAction::Confirm => this.confirm(cx),
                UiAction::Cancel => {
                    this.confirmation = None;
                    cx.notify();
                }
                UiAction::Reveal => {
                    if let Some(path) = &this.export_path {
                        cx.reveal_path(std::path::Path::new(path));
                    }
                }
            }))
    }

    pub(crate) fn field(
        &self,
        label: &'static str,
        hint: &'static str,
        state: &Entity<InputState>,
        multiline: bool,
    ) -> Div {
        let input = Input::new(state).disabled(self.locked());
        div()
            .flex()
            .flex_col()
            .gap_2()
            .flex_1()
            .min_w_0()
            .child(
                div()
                    .text_sm()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(INK))
                    .child(label),
            )
            .child(if multiline {
                input.h(px(112.)).into_any_element()
            } else {
                input.into_any_element()
            })
            .child(div().text_xs().text_color(rgb(MUTED)).child(hint))
    }

    pub(crate) fn path_strip(&self) -> Div {
        let policy = if self.status["active_policy"].is_object() {
            &self.status["active_policy"]
        } else {
            &self.profile
        };
        let active = text(&self.status, "active_target", "无当前目标");
        let first_hop = text(policy, "first_hop", "未配置");
        let dns = text(policy, "dns_tls_name", "未配置");
        let (title, status, status_color, status_background) = if !self.status_valid {
            ("状态未知 · 路径未确认", "需确认", RUST, DANGER_BG)
        } else if self.status["active_policy"].is_object() {
            ("运行路径 · 双跳与 DNS", "运行中", TEAL, SUCCESS_BG)
        } else if self.profile_exists {
            ("已保存路径 · 等待启动", "待启动", BLUE, SURFACE_SOFT)
        } else {
            ("默认路径预览", "未配置", MUTED, SURFACE_SOFT)
        };
        div()
            .flex()
            .flex_col()
            .gap_3()
            .px_6()
            .py_5()
            .bg(rgb(SURFACE_SOFT))
            .border_b_1()
            .border_color(rgb(RULE))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().text_xs().font_weight(FontWeight::SEMIBOLD).child(title))
                            .child(badge(status, status_color, status_background)),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child("仅表示策略路径，不代表节点健康。"),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(fact("目标 WSL", active, INK))
                    .child(div().text_lg().text_color(rgb(MUTED)).child("→"))
                    .child(fact("宿主代理", first_hop, INK))
                    .child(div().text_lg().text_color(rgb(MUTED)).child("→"))
                    .child(fact("住宅出口", "凭据保存在 Windows · 不显示秘密", INK))
                    .child(div().text_lg().text_color(rgb(MUTED)).child("→"))
                    .child(fact("DNS", format!("DoH · {dns}"), INK)),
            )
    }

}

