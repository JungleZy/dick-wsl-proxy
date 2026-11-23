//! 规则页：维护直连例外。

use gpui_kit::component::button::ButtonVariants as _;
use gpui_kit::{prelude::*, *};

use super::components::badge;
use super::model::UiAction;
use super::state::Desktop;
use super::theme::{
    MONO_FONT, MUTED, RULE, RUST, SUCCESS_BG, SURFACE, SURFACE_SOFT, TEAL, WARNING_BG,
    app_rgb as rgb,
};
use super::views::{card, card_header, key_value};

impl Desktop {
    pub(crate) fn policy_page(&self, cx: &Context<Self>) -> Div {
        let locked = self.locked();
        let (save_message, save_color, save_background) = if self.save_error {
            ("保存失败", RUST, WARNING_BG)
        } else if self.dirty {
            ("草稿未保存", RUST, WARNING_BG)
        } else if self.profile_exists {
            ("已保存", TEAL, SUCCESS_BG)
        } else {
            ("尚未保存", MUTED, SURFACE_SOFT)
        };
        let rule_field =
            |label: &'static str, hint: &'static str, state: &super::model::Field| -> Div {
                self.field(label, hint, state, true)
                    .min_w(px(340.))
                    .p_3()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
            };
        let exceptions = div()
            .flex()
            .flex_col()
            .gap_3()
            .flex_1()
            .min_w(px(520.))
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
                    .child(card_header("直连规则", "每行一个目标，按类型分别匹配。"))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(badge(save_message, save_color, save_background))
                            .child(
                                self.button(
                                    "save-policy",
                                    "保存规则",
                                    UiAction::Save,
                                    locked || self.profile_path.is_none(),
                                    cx,
                                )
                                .primary(),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(rule_field(
                        "IPv4 / CIDR",
                        "例如 192.0.2.0/24。",
                        &self.fields.direct_ips,
                    ))
                    .child(rule_field(
                        "精确域名",
                        "每行一个域名，不填写 URL。",
                        &self.fields.direct_domains,
                    ))
                    .child(rule_field(
                        "域名后缀",
                        "按域名边界匹配。",
                        &self.fields.direct_suffixes,
                    )),
            );

        let matching = card(
            "匹配逻辑",
            "命中任一条直连例外后，业务连接绕过代理链。",
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(key_value("IPv4 / CIDR", "按地址和网段匹配"))
                .child(key_value("精确域名", "完全匹配后直连"))
                .child(key_value("域名后缀", "按域名边界匹配")),
        )
        .flex_1()
        .min_w(px(260.));

        let notice = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_3()
            .p_3()
            .bg(rgb(SURFACE_SOFT))
            .rounded_md()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .flex_1()
                    .min_w(px(300.))
                    .child(div().text_sm().text_color(rgb(MUTED)).child("配置文件"))
                    .child(
                        div().font_family(MONO_FONT).truncate().child(
                            self.profile_path
                                .clone()
                                .unwrap_or_else(|| "等待 SQLite 配置路径。".into()),
                        ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .flex_1()
                    .min_w(px(300.))
                    .child(div().text_sm().text_color(rgb(MUTED)).child("后台提示"))
                    .child(
                        div()
                            .text_color(rgb(if self.error { RUST } else { MUTED }))
                            .truncate()
                            .child(self.notice.clone()),
                    ),
            );

        div()
            .flex()
            .flex_col()
            .h_full()
            .min_h_0()
            .gap_3()
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .flex_1()
                    .min_h_0()
                    .gap_3()
                    .child(exceptions)
                    .child(matching),
            )
            .child(notice)
    }
}
