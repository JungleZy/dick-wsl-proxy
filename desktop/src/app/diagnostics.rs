//! 诊断页：展示流量指标、DNS 健康、线程状态和有界连接记录。
use gpui::{prelude::*, *};
use gpui_component::{button::Button, Disableable};
use serde_json::json;

use super::backend::Kind;
use super::components::{badge, bytes, fact, panel, rate, text};
use super::model::UiAction;
use super::state::Desktop;
use super::theme::{BLUE, DANGER_BG, INK, MUTED, RUST, SURFACE, SURFACE_SOFT, SUCCESS_BG, TEAL};
impl Desktop {

    pub(crate) fn diagnostics(&self, cx: &Context<Self>) -> Div {
        let forwarding = &self.status["forwarding"];
        let traffic = &forwarding["traffic"];
        let active = forwarding["connections"]["active"].as_array();
        let recent = forwarding["connections"]["recent"].as_array();
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
                _ => "未知",
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
                Some("metadata_unavailable") => "目标未知",
                _ => "等待元数据",
            };
            rows = rows.child(
                div()
                    .flex()
                    .gap_3()
                    .items_center()
                    .px_2()
                    .py_2()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .text_xs()
                    .child(
                        div()
                            .w(px(52.))
                            .font_family("Consolas")
                            .text_color(rgb(MUTED))
                            .child(row["id"].as_u64().unwrap_or(0).to_string()),
                    )
                    .child(
                        div()
                            .w(px(42.))
                            .font_family("Consolas")
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(text(row, "protocol", "—")),
                    )
                    .child(div().w(px(190.)).font_family("Consolas").child(text(
                        row,
                        "destination",
                        "原始目标尚未验证",
                    )))
                    .child(
                        div()
                            .w(px(72.))
                            .child(badge(
                                route,
                                if route == "直连" { BLUE } else if route == "拒绝" { RUST } else { TEAL },
                                if route == "拒绝" { DANGER_BG } else { SURFACE },
                            )),
                    )
                    .child(
                        div()
                            .w(px(160.))
                            .text_color(rgb(if status == "失败" { RUST } else { INK }))
                            .child(format!("{status} · {stage}")),
                    )
                    .child(div().w(px(142.)).font_family("Consolas").child(format!(
                        "↑ {} / ↓ {}",
                        bytes(row["tx_bytes"].as_u64().unwrap_or(0)),
                        bytes(row["rx_bytes"].as_u64().unwrap_or(0))
                    )))
                    .child(div().flex_1().text_color(rgb(MUTED)).child(format!(
                        "{reason}{}",
                        row["failure_stage"]
                            .as_str()
                            .map(|v| format!(" · 失败阶段 {v}"))
                            .unwrap_or_default()
                    ))),
            );
        }
        let (health_label, health_color, health_background) = match forwarding["healthy"].as_bool() {
            Some(true) => ("工作线程运行中", TEAL, SUCCESS_BG),
            Some(false) => ("工作线程故障", RUST, DANGER_BG),
            None => ("暂无工作线程观测", MUTED, SURFACE_SOFT),
        };
        let mut result = div()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                panel(
                    "连接与 DNS 诊断",
                    "上行＝WSL → 目的端；下行＝目的端 → WSL。速率为相邻采样差值。",
                )
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
                            "DNS 保护与健康",
                            self.dns_label(),
                            if self.status["dns_managed"] == true { TEAL } else { RUST },
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
                )
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(Button::new("export").label("导出脱敏诊断").disabled(self.locked()).on_click(
                            cx.listener(|this, _, _, cx| {
                                this.send(Kind::Export, json!({"command":"export_diagnostics"}), cx)
                            }),
                        ))
                        .child(self.button(
                            "reveal",
                            "打开报告位置",
                            UiAction::Reveal,
                            self.export_path.is_none(),
                            cx,
                        )),
                ),
            )
            .child(
                panel(
                    "连接记录",
                    "显示已验证的 IPv4:端口和路由，不猜测域名或进程。最多保留 384 条记录。",
                )
                .child(
                    div()
                        .flex()
                        .gap_3()
                        .items_center()
                        .px_2()
                        .py_2()
                        .bg(rgb(SURFACE_SOFT))
                        .rounded_md()
                        .text_xs()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(MUTED))
                        .child(div().w(px(52.)).child("ID"))
                        .child(div().w(px(42.)).child("协议"))
                        .child(div().w(px(190.)).child("原始目的端"))
                        .child(div().w(px(72.)).child("路由"))
                        .child(div().w(px(160.)).child("状态 / 阶段"))
                        .child(div().w(px(142.)).child("字节量"))
                        .child(div().flex_1().child("判定原因 / 失败阶段")),
                )
                .child(if active.is_none_or(Vec::is_empty) && recent.is_none_or(Vec::is_empty) {
                    div()
                        .p_5()
                        .bg(rgb(SURFACE_SOFT))
                        .rounded_md()
                        .text_sm()
                        .text_color(rgb(MUTED))
                        .child("暂无连接记录。启动接管并产生流量后，这里会显示连接。")
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
                    .child(format!("最后转发错误：{error}")),
            );
        }
        if let Some(path) = &self.export_path {
            result = result.child(div().text_xs().font_family("Consolas").child(path.clone()));
        }
        result
    }
}
