//! 诊断页：展示流量指标、DNS 健康、线程状态和有界连接记录。
use gpui::{prelude::*, *};
use gpui_component::{Disableable, button::Button};
use serde_json::json;

use super::backend::Kind;
use super::components::{badge, bytes, fact, panel, rate, text};
use super::model::UiAction;
use super::state::Desktop;
use super::theme::{
    BLUE, DANGER_BG, INK, MONO_FONT, MUTED, RUST, SUCCESS_BG, SURFACE, SURFACE_SOFT, TEAL,
};

fn connection_row() -> Div {
    div()
        .flex()
        .gap_3()
        .items_center()
        .px_2()
        .py_2()
        .bg(rgb(SURFACE_SOFT))
        .rounded_md()
        .text_xs()
}
impl Desktop {
    pub(crate) fn diagnostics(&self, cx: &Context<Self>) -> Div {
        let forwarding = &self.status["forwarding"];
        let traffic = &forwarding["traffic"];
        let active = forwarding["connections"]["active"].as_array();
        let recent = forwarding["connections"]["recent"].as_array();
        let has_connections = active.is_some_and(|rows| !rows.is_empty())
            || recent.is_some_and(|rows| !rows.is_empty());
        let dns_managed = self.status["dns_managed"] == true;
        let locked = self.locked();
        let mut rows = div().flex().flex_col().gap_1();
        for row in active
            .into_iter()
            .flatten()
            .chain(recent.into_iter().flatten())
            .take(384)
        {
            let route = match row["route"].as_str() {
                Some("direct") => "直连",
                Some("chain") => "双跳",
                Some("dns") => "DNS",
                Some("reject") => "拒绝",
                _ => "待判定",
            };
            let stage = match row["stage"].as_str() {
                Some("metadata") => "获取原始目标",
                Some("policy") => "策略判定",
                Some("connect") => "建立连接",
                Some("dns") => "DNS 转发",
                Some("relay") => "传输",
                _ => "未知阶段",
            };
            let status = match row["status"].as_str() {
                Some("active") => "活动",
                Some("completed") => "完成",
                Some("failed") => "失败",
                Some("stopped") => "已停止",
                _ => "未知",
            };
            let reason = match row["reason"].as_str() {
                Some("enumerated_origin") => "诊断目标",
                Some("domain_alias") => "域名例外",
                Some("ip_or_cidr") => "IP / CIDR 例外",
                Some("default_chain") => "默认双跳",
                Some("system_dns") => "系统 DNS",
                Some("policy_reject") => "策略拒绝",
                Some("metadata_unavailable") => "目标未识别",
                _ => "等待元数据",
            };
            let (route_color, route_background) = match route {
                "直连" => (BLUE, SURFACE),
                "拒绝" => (RUST, DANGER_BG),
                _ => (TEAL, SURFACE),
            };
            let status_color = if status == "失败" { RUST } else { INK };
            let failure_stage = row["failure_stage"]
                .as_str()
                .map(|value| format!(" · 失败阶段 {value}"))
                .unwrap_or_default();
            let tx = bytes(row["tx_bytes"].as_u64().unwrap_or(0));
            let rx = bytes(row["rx_bytes"].as_u64().unwrap_or(0));
            rows = rows.child(
                connection_row()
                    .child(
                        div()
                            .w(px(44.))
                            .font_family(MONO_FONT)
                            .text_color(rgb(MUTED))
                            .child(row["id"].as_u64().unwrap_or(0).to_string()),
                    )
                    .child(
                        div()
                            .w(px(42.))
                            .font_family(MONO_FONT)
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(text(row, "protocol", "—")),
                    )
                    .child(div().w(px(190.)).font_family(MONO_FONT).child(text(
                        row,
                        "destination",
                        "原始目标尚未验证",
                    )))
                    .child(
                        div()
                            .w(px(72.))
                            .child(badge(route, route_color, route_background)),
                    )
                    .child(
                        div()
                            .w(px(145.))
                            .text_color(rgb(status_color))
                            .child(format!("{status} · {stage}")),
                    )
                    .child(
                        div()
                            .w(px(142.))
                            .font_family(MONO_FONT)
                            .child(format!("↑ {tx} / ↓ {rx}")),
                    )
                    .child(
                        div()
                            .flex_1()
                            .text_color(rgb(MUTED))
                            .child(format!("{reason}{failure_stage}")),
                    ),
            );
        }
        let (health_label, health_color, health_background) = match forwarding["healthy"].as_bool()
        {
            Some(true) => ("工作线程运行中", TEAL, SUCCESS_BG),
            Some(false) => ("工作线程故障", RUST, DANGER_BG),
            None => ("暂无工作线程观测", MUTED, SURFACE_SOFT),
        };
        let observed = panel("现场观测", "以下数值来自后台快照；未观测到的值不会被推断。")
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(fact("上行速率", rate(&traffic["tx_bytes_per_sec"]), BLUE))
                    .child(fact("下行速率", rate(&traffic["rx_bytes_per_sec"]), TEAL))
                    .child(fact(
                        "累计上行",
                        traffic["tx_bytes"]
                            .as_u64()
                            .map(bytes)
                            .unwrap_or_else(|| "未采样".into()),
                        INK,
                    ))
                    .child(fact(
                        "累计下行",
                        traffic["rx_bytes"]
                            .as_u64()
                            .map(bytes)
                            .unwrap_or_else(|| "未采样".into()),
                        INK,
                    )),
            )
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(fact(
                        "DNS 实际观测",
                        self.dns_label(),
                        if dns_managed { TEAL } else { RUST },
                    ))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .flex_1()
                            .min_w_0()
                            .p_3()
                            .bg(rgb(health_background))
                            .rounded_md()
                            .child(badge(health_label, health_color, health_background)),
                    ),
            );
        let claims = panel(
            "策略声明",
            "这是当前配置要求，不等同于每条连接都已验证成功。",
        )
        .child(
            div()
                .flex()
                .gap_3()
                .child(fact("默认路由", "非例外 TCP · 双跳", BLUE))
                .child(fact("系统 DNS", "按策略经 DoH", TEAL))
                .child(fact(
                    "目标凭据",
                    text(&self.profile, "credential", "未命名"),
                    INK,
                )),
        )
        .child(
            div()
                .text_xs()
                .text_color(rgb(MUTED))
                .child("要确认出口是否匹配，请在总览执行“复核公网出口”；结果只代表该次观测。"),
        );
        let mut result = div()
            .flex()
            .flex_col()
            .gap_4()
            .child(observed)
            .child(claims)
            .child(
                panel(
                    "连接记录 · 有界窗口",
                    "仅显示后台已验证的 IPv4:端口、路由和阶段；最多保留 384 条记录。",
                )
                .child(
                    connection_row()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(MUTED))
                        .child(div().w(px(44.)).child("ID"))
                        .child(div().w(px(42.)).child("协议"))
                        .child(div().w(px(190.)).child("已观测目的端"))
                        .child(div().w(px(72.)).child("路由"))
                        .child(div().w(px(145.)).child("状态 / 阶段"))
                        .child(div().w(px(142.)).child("字节量"))
                        .child(div().flex_1().child("判定原因 / 失败阶段")),
                )
                .child(if !has_connections {
                    div()
                        .p_5()
                        .bg(rgb(SURFACE_SOFT))
                        .rounded_md()
                        .text_sm()
                        .text_color(rgb(MUTED))
                        .child("暂无已观测连接。启动接管并产生流量后，这里会显示记录。")
                        .into_any_element()
                } else {
                    rows.into_any_element()
                }),
            );
        if let Some(error) = forwarding["last_error"].as_str() {
            result = result.child(
                div()
                    .text_sm()
                    .text_color(rgb(RUST))
                    .child(format!("最后转发错误（后台报告）：{error}")),
            );
        }
        result = result.child(
            div()
                .flex()
                .gap_2()
                .child(
                    Button::new("export")
                        .label("导出脱敏诊断")
                        .disabled(locked)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.send(Kind::Export, json!({"command":"export_diagnostics"}), cx)
                        })),
                )
                .child(self.button(
                    "reveal",
                    "打开报告位置",
                    UiAction::Reveal,
                    self.export_path.is_none(),
                    cx,
                )),
        );
        if let Some(path) = &self.export_path {
            result = result.child(
                div()
                    .text_xs()
                    .font_family(MONO_FONT)
                    .text_color(rgb(MUTED))
                    .child(path.clone()),
            );
        }
        result
    }
}
