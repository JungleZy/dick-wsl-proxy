//! 规则页：维护路由、DNS 和直连例外。

use gpui_kit::component::button::ButtonVariants as _;
use gpui_kit::{prelude::*, *};

use super::components::{badge, panel};
use super::model::UiAction;
use super::state::Desktop;
use super::theme::{MUTED, RUST, SUCCESS_BG, SURFACE_SOFT, TEAL, WARNING_BG};

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

        let route =
            panel("路由", "默认流量经双跳，只有明确列入例外的目标才会直连。").child(self.field(
                "宿主 SOCKS5 代理",
                "填写 IPv4:端口。",
                &self.fields.first_hop,
                false,
            ));
        let dns = panel("DNS 保护", "系统 DNS 通过代理链访问 DoH。")
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(
                        self.field(
                            "DoH 上游 IPv4:端口",
                            "固定地址，通过宿主代理链访问 HTTPS。",
                            &self.fields.dns_upstream,
                            false,
                        )
                        .min_w(px(420.)),
                    )
                    .child(
                        self.field(
                            "DoH TLS 主机名",
                            "用于 SNI 和证书校验。",
                            &self.fields.dns_tls_name,
                            false,
                        )
                        .min_w(px(420.)),
                    ),
            )
            .child(self.field(
                "启动健康检查域名",
                "启动时验证链路，不加入直连例外。",
                &self.fields.health_domain,
                false,
            ));
        let exceptions = panel("直连例外", "每行一个目标，按类型分别匹配。").child(
            div()
                .flex()
                .gap_3()
                .child(self.field(
                    "IPv4 / CIDR",
                    "例如 192.0.2.0/24。",
                    &self.fields.direct_ips,
                    true,
                ))
                .child(self.field(
                    "精确域名",
                    "每行一个域名，不填写 URL。",
                    &self.fields.direct_domains,
                    true,
                ))
                .child(self.field(
                    "域名后缀",
                    "按域名边界匹配。",
                    &self.fields.direct_suffixes,
                    true,
                )),
        );

        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(div().flex().justify_end().child(badge(
                save_message,
                save_color,
                save_background,
            )))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(route.flex_1().min_w(px(420.)))
                    .child(dns.flex_1().min_w(px(420.))),
            )
            .child(exceptions)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        self.button(
                            "save-policy",
                            "保存规则",
                            UiAction::Save,
                            locked || self.profile_path.is_none(),
                            cx,
                        )
                        .primary(),
                    )
                    .child(
                        div().text_base().text_color(rgb(MUTED)).child(
                            self.profile_path
                                .clone()
                                .unwrap_or_else(|| "等待 SQLite 配置路径。".into()),
                        ),
                    ),
            )
    }
}
