//! 规则页：维护直连例外。

use gpui_kit::{prelude::*, *};

use super::state::Desktop;
use super::theme::{RULE, SURFACE, SURFACE_SOFT, app_rgb as rgb};
use super::views::card_header;

impl Desktop {
    /// 「保存规则」在页面底部的固定栏里，保存结果显示在页面顶部，见 `views.rs`。
    /// 规则卡片占满整页高度，三列输入框随窗口拉高；窗口太矮放不下时整页滚动。
    pub(crate) fn policy_page(&self) -> Div {
        // 窗口固定 980 宽：三类规则并排成三列，不换行。
        let rule_field =
            |label: &'static str, hint: &'static str, state: &super::model::Field| -> Div {
                self.field(label, hint, state, true)
                    .p_3()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
            };
        div()
            .flex()
            .flex_col()
            .gap_3()
            // 至少一屏高、内容多时跟着变高，外层页面滚动接得住。
            .min_h_full()
            .p_3()
            .bg(rgb(SURFACE))
            .border_1()
            .border_color(rgb(RULE))
            .rounded_md()
            .child(card_header(
                "直连规则",
                "每行一个；命中任一条的连接直连，不走代理链。",
            ))
            .child(
                div()
                    .flex()
                    .flex_1()
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
            )
    }
}
