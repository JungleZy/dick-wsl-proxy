//! 策略页：编辑链路、DNS、直连例外并管理命名凭据。
use gpui::{prelude::*, *};
use gpui_component::{button::ButtonVariants, input::Input};

use super::components::{badge, panel};
use super::model::UiAction;
use super::state::Desktop;
use super::theme::{MONO_FONT, MUTED, RUST, SUCCESS_BG, SURFACE_SOFT, TEAL, WARNING_BG};
impl Desktop {
    pub(crate) fn policy_page(&self, cx: &Context<Self>) -> Div {
        let locked = self.locked();
        let idle = self.idle();
        let credential_locked = locked || !idle;
        let (save_message, save_color, save_background) = if self.dirty {
            ("草稿未保存 · 不会生效", RUST, WARNING_BG)
        } else if self.profile_exists {
            ("已保存 · 可用于启动", TEAL, SUCCESS_BG)
        } else {
            ("尚未配置 · 无法启动", MUTED, SURFACE_SOFT)
        };
        let (credential_status, credential_color, credential_background) = if idle {
            ("现在可操作", TEAL, SUCCESS_BG)
        } else {
            ("后台运行中 · 需先停止", MUTED, SURFACE_SOFT)
        };
        let route = panel("路由", "默认流量走双跳；只有明确列入例外的目标才会直连。").child(
            div()
                .flex()
                .gap_5()
                .child(self.field(
                    "宿主 SOCKS5 代理",
                    "填写 IPv4:端口；住宅凭据不写在这里。",
                    &self.fields.first_hop,
                    false,
                ))
                .child(self.field(
                    "住宅凭据名称",
                    "只填写凭据名称；秘密留在 Windows 凭据库。",
                    &self.fields.credential,
                    false,
                )),
        );
        let dns = panel(
            "DNS 保护",
            "系统 DNS 通过代理链访问 DoH；TLS 主机名用于证书校验。",
        )
        .child(
            div()
                .flex()
                .gap_5()
                .child(self.field(
                    "DoH 上游 IPv4:端口",
                    "固定地址；通过宿主代理链访问 HTTPS。",
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
            "启动健康检查域名",
            "启动时验证链路；不要加入直连例外。",
            &self.fields.health_domain,
            false,
        ));
        let exceptions = panel(
            "直连例外",
            "仅把明确需要直连的目标放在这里；每行一条，匹配结果可在诊断中查看。",
        )
        .child(
            div()
                .flex()
                .gap_5()
                .child(self.field(
                    "IPv4 / CIDR",
                    "例如 192.0.2.0/24；空白行忽略。",
                    &self.fields.direct_ips,
                    true,
                ))
                .child(self.field(
                    "精确域名",
                    "每行一个域名；不填写 URL。",
                    &self.fields.direct_domains,
                    true,
                ))
                .child(self.field(
                    "域名后缀",
                    "按域名边界匹配；每行一个后缀。",
                    &self.fields.direct_suffixes,
                    true,
                )),
        );
        let credentials = panel(
            "住宅凭据",
            "只在后台空闲时操作。选择文件不会读取内容；导入后写入当前用户凭据管理器。",
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(div().text_sm().child(self.credential_notice.clone()))
                .child(badge(
                    credential_status,
                    credential_color,
                    credential_background,
                )),
        )
        .child(
            div()
                .text_sm()
                .font_weight(FontWeight::SEMIBOLD)
                .child(".env 文件路径"),
        )
        .child(Input::new(&self.fields.env_path).disabled(credential_locked))
        .child(
            div()
                .flex()
                .flex_wrap()
                .gap_2()
                .child(self.button(
                    "pick-env",
                    "选择凭据文件",
                    UiAction::Pick,
                    credential_locked,
                    cx,
                ))
                .child(
                    self.button(
                        "import",
                        "导入到凭据库",
                        UiAction::Import,
                        credential_locked,
                        cx,
                    )
                    .primary(),
                )
                .child(
                    self.button(
                        "forget",
                        "删除已保存凭据",
                        UiAction::Forget,
                        credential_locked,
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
        );
        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_xl()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child("策略工作台"),
                            )
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(MUTED))
                                    .child("保存只更新草稿；当前接管必须通过安全确认才会改变。"),
                            ),
                    )
                    .child(badge(save_message, save_color, save_background)),
            )
            .child(route)
            .child(dns)
            .child(exceptions)
            .child(credentials)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        self.button(
                            "save",
                            "保存策略草稿",
                            UiAction::Save,
                            locked || self.profile_path.is_none(),
                            cx,
                        )
                        .primary(),
                    )
                    .child(
                        div()
                            .text_xs()
                            .font_family(MONO_FONT)
                            .text_color(rgb(MUTED))
                            .child(
                                self.profile_path
                                    .clone()
                                    .unwrap_or_else(|| "等待后台返回配置路径。".into()),
                            ),
                    ),
            )
    }
}
