//! 页面共享的交互壳层：按钮分发、字段包装和策略路径摘要。

use gpui_kit::component::{
    Disableable, Sizable as _,
    button::Button,
    input::{Input, Textarea},
};
use gpui_kit::{prelude::*, *};
use serde_json::json;

use super::backend::Kind;
use super::model::{Field, UiAction};
use super::state::Desktop;
use super::theme::{INK, MUTED};
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
            .on_click(
                cx.listener(move |this, _, window, cx| match action.clone() {
                    UiAction::List => this.send(Kind::List, json!({"command":"list"}), cx),
                    UiAction::Preflight => this.preflight(cx),
                    UiAction::Save => this.save(cx),
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
                    UiAction::Prepare(kind) => this.prepare(kind, window, cx),
                    UiAction::Reveal => {
                        if let Some(path) = &this.export_path {
                            cx.reveal_path(std::path::Path::new(path));
                        }
                    }
                    UiAction::EnvironmentCreate => this.environment_create(window, cx),
                    UiAction::EnvironmentSubmit => this.environment_submit(cx),
                    UiAction::EnvironmentCancel => this.environment_cancel(cx),
                    UiAction::EnvironmentPickSource => this.environment_pick_source(window, cx),
                    UiAction::EnvironmentPickInstall => this.environment_pick_install(window, cx),
                    UiAction::EnvironmentPickBackup => this.environment_pick_backup(window, cx),
                    UiAction::LogFilter(filter) => {
                        this.log_filter = filter;
                        cx.notify();
                    }
                }),
            )
    }

    pub(crate) fn field(
        &self,
        label: &'static str,
        hint: &'static str,
        state: &Field,
        multiline: bool,
    ) -> Div {
        let input = match state {
            Field::Single(state) => Input::new(state).disabled(self.locked()).into_any_element(),
            Field::Multi(state) => Textarea::new(state)
                .h(px(if multiline { 112. } else { 32. }))
                .disabled(self.locked())
                .into_any_element(),
        };
        div()
            .flex()
            .flex_col()
            .gap_2()
            .flex_1()
            .min_w_0()
            .child(
                div()
                    .text_base()
                    .font_weight(FontWeight::NORMAL)
                    .text_color(rgb(INK))
                    .child(label),
            )
            .child(input)
            .child(div().text_base().text_color(rgb(MUTED)).child(hint))
    }

    pub(crate) fn field_with_action(
        &self,
        label: &'static str,
        hint: &'static str,
        state: &Field,
        action: UiAction,
        button_id: &'static str,
        button_label: &'static str,
        disabled: bool,
        cx: &Context<Desktop>,
    ) -> Div {
        let input = match state {
            Field::Single(state) => Input::new(state).disabled(self.locked()).into_any_element(),
            Field::Multi(state) => Textarea::new(state)
                .h(px(32.))
                .disabled(self.locked())
                .into_any_element(),
        };
        div()
            .flex()
            .flex_col()
            .gap_2()
            .flex_1()
            .min_w_0()
            .child(
                div()
                    .text_base()
                    .font_weight(FontWeight::NORMAL)
                    .text_color(rgb(INK))
                    .child(label),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().flex_1().min_w_0().child(input))
                    .child(
                        self.button(button_id, button_label, action, disabled, cx)
                            .small()
                            .flex_shrink_0(),
                    ),
            )
            .child(div().text_base().text_color(rgb(MUTED)).child(hint))
    }
}
