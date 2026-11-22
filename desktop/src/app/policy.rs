//! 规则页：维护直连例外。

use gpui_kit::component::button::ButtonVariants as _;
use gpui_kit::{prelude::*, *};

use super::components::badge;
use super::model::UiAction;
use super::state::Desktop;
use super::theme::{
    MUTED, RULE, RUST, SUCCESS_BG, SURFACE, SURFACE_SOFT, TEAL, WARNING_BG, app_rgb as rgb,
};
use super::views::card_header;

impl Desktop {
    pub(crate) fn policy_page(&self, cx: &Context<Self>) -> Div {
        let locked = self.locked();
        let (save_message, save_color, save_background) = if self.error {
            ("保存失败", RUST, WARNING_BG)
        } else if self.dirty {
            ("草稿未保存", RUST, WARNING_BG)
        } else if self.profile_exists {
            ("已保存", TEAL, SUCCESS_BG)
        } else {
            ("尚未保存", MUTED, SURFACE_SOFT)
        };
        let exceptions = div()
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
                    .child(
                        self.field(
                            "IPv4 / CIDR",
                            "例如 192.0.2.0/24。",
                            &self.fields.direct_ips,
                            true,
                        )
                        .min_w(px(260.)),
                    )
                    .child(
                        self.field(
                            "精确域名",
                            "每行一个域名，不填写 URL。",
                            &self.fields.direct_domains,
                            true,
                        )
                        .min_w(px(260.)),
                    )
                    .child(
                        self.field(
                            "域名后缀",
                            "按域名边界匹配。",
                            &self.fields.direct_suffixes,
                            true,
                        )
                        .min_w(px(260.)),
                    ),
            );

        div().flex().flex_col().gap_3().child(exceptions).child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(
                    div().text_base().text_color(rgb(MUTED)).child(
                        self.profile_path
                            .clone()
                            .unwrap_or_else(|| "等待 SQLite 配置路径。".into()),
                    ),
                )
                .child(
                    div()
                        .flex_1()
                        .text_base()
                        .text_color(rgb(if self.error { RUST } else { MUTED }))
                        .child(self.notice.clone()),
                ),
        )
    }
}
