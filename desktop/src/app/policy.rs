//! 策略页：编辑链路、DNS、直连例外并管理命名凭据。
use gpui::{prelude::*, *};
use gpui_component::{button::ButtonVariants, input::Input};

use super::components::{badge, panel};
use super::model::UiAction;
use super::state::Desktop;
use super::theme::{MUTED, RUST, SUCCESS_BG, SURFACE_SOFT, TEAL, WARNING_BG};
impl Desktop {

    pub(crate) fn policy_page(&self, cx: &Context<Self>) -> Div {
        let (save_message, save_color, save_background) = if self.dirty {
            ("未保存 · 不会生效", RUST, WARNING_BG)
        } else if self.profile_exists {
            ("已保存 · 可启动", TEAL, SUCCESS_BG)
        } else {
            ("未配置 · 不能启动", MUTED, SURFACE_SOFT)
        };
        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                panel(
                    "策略草稿",
                    "默认 TCP 和系统 DNS 经双跳；直连例外按规则匹配。保存不会立即改变当前接管。",
                )
                .child(
                    div()
                        .text_xs()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(MUTED))
                        .child("连接与解析"),
                )
                .child(
                    div()
                        .flex()
                        .gap_5()
                        .child(self.field(
                            "宿主 SOCKS5",
                            "IPv4:端口；不包含住宅凭据。",
                            &self.fields.first_hop,
                            false,
                        ))
                        .child(self.field(
                            "凭据名称",
                            "只填写名称，不填写账号、密码或地址。",
                            &self.fields.credential,
                            false,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .gap_5()
                        .child(self.field(
                            "DoH 上游 IPv4:端口",
                            "固定 IP；通过代理链访问 HTTPS。",
                            &self.fields.dns_upstream,
                            false,
                        ))
                        .child(self.field(
                            "DoH TLS 主机名",
                            "用于 SNI 和证书校验。",
                            &self.fields.dns_tls_name,
                            false,
                        )),
                )
                .child(self.field(
                    "健康检查域名",
                    "启动时使用；不要加入直连例外。",
                    &self.fields.health_domain,
                    false,
                ))
                .child(
                    div()
                        .text_xs()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(MUTED))
                        .child("直连例外"),
                )
                .child(
                    div()
                        .flex()
                        .gap_5()
                        .child(self.field(
                            "直连 IPv4 / CIDR",
                            "每行一条；空白行忽略。",
                            &self.fields.direct_ips,
                            true,
                        ))
                        .child(self.field(
                            "直连精确域名",
                            "每行一个域名；不接受 URL。",
                            &self.fields.direct_domains,
                            true,
                        ))
                        .child(self.field(
                            "直连域名后缀",
                            "每行一个后缀；按域名边界匹配。",
                            &self.fields.direct_suffixes,
                            true,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(
                            self.button(
                                "save",
                                "保存策略",
                                UiAction::Save,
                                self.locked() || self.profile_path.is_none(),
                                cx,
                            )
                            .primary(),
                        )
                        .child(badge(save_message, save_color, save_background)),
                )
                .child(
                    div()
                        .p_3()
                        .bg(rgb(SURFACE_SOFT))
                        .rounded_md()
                        .text_xs()
                        .font_family("Consolas")
                        .text_color(rgb(MUTED))
                        .child(self.profile_path.clone().unwrap_or_else(|| {
                            "等待后台返回配置路径。".into()
                        })),
                ),
            )
            .child(
                panel(
                    "凭据",
                    "仅在后台空闲时操作。选择文件不会读取内容；导入后写入当前用户的凭据管理器。",
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(div().text_sm().child(self.credential_notice.clone()))
                        .child(badge(
                            if self.idle() { "当前可操作" } else { "仅空闲时可操作" },
                            if self.idle() { TEAL } else { MUTED },
                            if self.idle() { SUCCESS_BG } else { SURFACE_SOFT },
                        )),
                )
                .child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(".env 文件路径"),
                )
                .child(Input::new(&self.fields.env_path).disabled(self.locked() || !self.idle()))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_2()
                        .child(self.button(
                            "pick-env",
                            "选择 .env…",
                            UiAction::Pick,
                            self.locked() || !self.idle(),
                            cx,
                        ))
                        .child(
                            self.button(
                                "import",
                                "导入凭据",
                                UiAction::Import,
                                self.locked() || !self.idle(),
                                cx,
                            )
                            .primary(),
                        )
                        .child(
                            self.button(
                                "forget",
                                "删除凭据",
                                UiAction::Forget,
                                self.locked() || !self.idle(),
                                cx,
                            )
                            .danger(),
                        ),
                )
                .child(
                    div()
                        .p_3()
                        .bg(rgb(SURFACE_SOFT))
                        .rounded_md()
                        .text_xs()
                        .text_color(rgb(MUTED))
                        .child("支持 ip / port / username / password；不显示内容，也不会删除源文件。"),
                ),
            )
    }

}
