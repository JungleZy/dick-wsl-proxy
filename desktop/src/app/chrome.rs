//! 页面共享的交互壳层：按钮分发、字段包装和策略路径摘要。

use gpui_kit::component::{
    Disableable, Sizable as _,
    button::Button,
    input::{Input, InputContentType, Textarea},
    tooltip::Tooltip,
};
use gpui_kit::{prelude::*, *};
use serde_json::json;

use super::backend::Kind;
use super::components::design_icon;
use super::model::{Field, UiAction};
use super::state::Desktop;
use super::theme::{INK, MUTED, app_rgb as rgb};
impl Desktop {
    pub(crate) fn field_label(
        &self,
        label: &'static str,
        tooltip_id: &'static str,
        tooltip_text: &'static str,
    ) -> Div {
        div()
            .flex()
            .items_center()
            .gap_1()
            .child(
                div()
                    .text_base()
                    .font_weight(FontWeight::NORMAL)
                    .text_color(rgb(INK))
                    .child(label),
            )
            .child(
                div()
                    .id(tooltip_id)
                    .child(design_icon("info", 14., MUTED))
                    .tooltip(move |window, cx| Tooltip::new(tooltip_text).build(window, cx)),
            )
    }

    pub(crate) fn compact_field(
        &self,
        label: &'static str,
        tooltip_id: &'static str,
        tooltip_text: &'static str,
        state: &Field,
    ) -> Div {
        let input = match state {
            Field::Single(state) => Input::new(state).disabled(self.locked()).into_any_element(),
            Field::Multi(state) => Textarea::new(state)
                .disabled(self.locked())
                .into_any_element(),
        };
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(self.field_label(label, tooltip_id, tooltip_text))
            .child(input)
    }

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
                    UiAction::Save => this.save(cx),
                    UiAction::Probe => this.probe(cx),
                    UiAction::Prepare(kind) => this.prepare(kind, window, cx),
                    UiAction::Reveal => {
                        if let Some(path) = &this.export_path {
                            cx.reveal_path(std::path::Path::new(path));
                        }
                    }
                    UiAction::EnvironmentCreate => this.environment_create(window, cx),
                    UiAction::EnvironmentSubmit => this.environment_submit(cx),
                    UiAction::EnvironmentCancel => this.environment_cancel(cx),
                    UiAction::EnvironmentPickInstall => this.environment_pick_install(window, cx),
                    UiAction::LogRefresh => this.refresh_logs(cx),
                    UiAction::LogLoadMore => this.load_more_logs(cx),
                    UiAction::LogFilter(filter) => {
                        this.log_filter = filter;
                        this.refresh_logs(cx);
                    }
                    UiAction::Export => {
                        this.send(Kind::Export, json!({"command":"export_diagnostics"}), cx)
                    }
                    UiAction::ConnectionFilter(filter) => {
                        if this.connection_filter != filter {
                            this.connection_filter = filter;
                            this.connection_history.reset();
                            this.refresh_connection_history(cx);
                        }
                        this.connections_scroll
                            .scroll_to_item(0, ScrollStrategy::Top);
                        cx.notify();
                    }
                    UiAction::ConnectionEnvironment(environment) => {
                        this.set_connection_environment(environment, cx);
                    }
                    UiAction::ConnectionLoadMore => this.load_more_connection_history(cx),
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

    pub(crate) fn compact_secret_field(
        &self,
        label: &'static str,
        tooltip_id: &'static str,
        tooltip_text: &'static str,
        state: &Field,
    ) -> Div {
        let input = match state {
            Field::Single(state) => Input::new(state)
                .mask_toggle()
                .content_type(InputContentType::NewPassword)
                .disabled(self.locked())
                .into_any_element(),
            Field::Multi(state) => Textarea::new(state)
                .disabled(self.locked())
                .into_any_element(),
        };
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(self.field_label(label, tooltip_id, tooltip_text))
            .child(input)
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
                            .icon(design_icon("folder", 15., MUTED))
                            .small()
                            .flex_shrink_0(),
                    ),
            )
            .child(div().text_base().text_color(rgb(MUTED)).child(hint))
    }
}
