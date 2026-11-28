//! 页面共享的交互壳层：按钮分发、字段包装和策略路径摘要。

use gpui_kit::component::{
    Disableable, Sizable as _,
    button::Button,
    input::{Input, InputContentType, Textarea},
};
use gpui_kit::{prelude::*, *};
use serde_json::json;

use super::backend::Kind;
use super::components::{badge, design_icon, text_tip};
use super::drafts::SaveScope;
use super::model::{Field, UiAction};
use super::state::Desktop;
use super::theme::{AMBER, DANGER_BG, INK, MUTED, RUST, WARNING_BG, app_rgb as rgb};

impl Desktop {
    /// 这一页的未保存和保存失败标签，各页用同一种样式；已保存时各页显示自己的状态，
    /// 返回 `None`。
    pub(crate) fn unsaved_badge(&self, scope: SaveScope) -> Option<Div> {
        if self.failed_saves.contains(scope) {
            Some(badge("保存失败", RUST, DANGER_BG))
        } else if self.unsaved.contains(scope) {
            Some(badge("有未保存修改", AMBER, WARNING_BG))
        } else {
            None
        }
    }

    pub(crate) fn field_label(
        &self,
        label: &'static str,
        tooltip_id: &'static str,
        tooltip_text: impl Into<SharedString>,
    ) -> Div {
        let tooltip_text = tooltip_text.into();
        div()
            .flex()
            .items_center()
            .gap_1()
            .child(
                div()
                    .text_sm()
                    .font_weight(FontWeight::NORMAL)
                    .text_color(rgb(INK))
                    .child(label),
            )
            .child(
                div()
                    .id(tooltip_id)
                    .child(design_icon("info", 14., MUTED))
                    .tooltip(move |window, cx| text_tip(tooltip_text.clone(), window, cx)),
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
                    UiAction::Save(scope) => this.save(scope, cx),
                    UiAction::Probe => this.probe(cx),
                    UiAction::PrepareFor(kind, target) => {
                        this.prepare_for(kind, target, window, cx)
                    }
                    UiAction::StartFor(target) => this.start_environment(target, cx),
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
                    UiAction::ResetDnsAliases => this.prepare_reset_dns_aliases(window, cx),
                    UiAction::WslPlatformCheck => this.check_wsl_platform(cx),
                    UiAction::WslUpdate => this.prompt_wsl_update(window, cx),
                    UiAction::ResidentialProbe => this.prompt_residential_probe(window, cx),
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
            // 多行输入框撑满所在栏剩下的高度（规则页三列随窗口拉高），最矮 112px。
            Field::Multi(state) if multiline => Textarea::new(state)
                .flex_1()
                .min_h(px(112.))
                .disabled(self.locked())
                .into_any_element(),
            Field::Multi(state) => Textarea::new(state)
                .h(px(32.))
                .disabled(self.locked())
                .into_any_element(),
        };
        let mut field = div()
            .flex()
            .flex_col()
            .gap_2()
            .flex_1()
            .min_w_0()
            .child(
                div()
                    .text_sm()
                    .font_weight(FontWeight::NORMAL)
                    .text_color(rgb(INK))
                    .child(label),
            )
            .child(input);
        // 空提示不占位：住宅代理的几行都传空字符串，之前每行下面都留一条
        // 空文本的高度，两行之间的间距看起来比别处大。
        if !hint.is_empty() {
            field = field.child(div().text_sm().text_color(rgb(MUTED)).child(hint));
        }
        field
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

    /// An input with a folder button beside it; `button` comes from `self.button`.
    pub(crate) fn field_with_action(
        &self,
        label: &'static str,
        tooltip_id: &'static str,
        tooltip_text: impl Into<SharedString>,
        state: &Field,
        button: Button,
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
            .child(self.field_label(label, tooltip_id, tooltip_text))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().flex_1().min_w_0().child(input))
                    .child(
                        button
                            .icon(design_icon("folder", 15., MUTED))
                            .small()
                            .flex_shrink_0(),
                    ),
            )
    }
}
