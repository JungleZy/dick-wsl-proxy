//! 首页监控页和环境预检摘要。

use gpui_kit::component::button::ButtonVariants as _;
use gpui_kit::component::chart::{BarChart, LineChart};
use gpui_kit::component::plot::shape::BarAlignment;
use gpui_kit::{prelude::*, *};
use serde_json::Value;

use super::backend::Kind;
use super::components::{badge, design_icon, panel, status_dot, text};
use super::model::UiAction;
use super::state::Desktop;
use super::theme::{
    AMBER, BLUE, DANGER_BG, MUTED, RULE, RUST, SUCCESS_BG, SURFACE, SURFACE_SOFT, TEAL,
};
use super::views::{card, card_header, chart_card, key_value, metric};

impl Desktop {
    pub(crate) fn overview(&self, cx: &Context<Self>) -> Div {
        let status_card = div()
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
                    .child(card_header("运行状态", "后台状态、接管目标和流量健康度"))
                    .child(
                        self.button(
                            "overview-start",
                            "启动接管",
                            UiAction::Prepare(Kind::Start),
                            self.locked() || !self.idle(),
                            cx,
                        )
                        .icon(design_icon("play", 15., super::theme::SURFACE))
                        .primary(),
                    ),
            )
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(metric(
                        "当前目标",
                        text(&self.status, "active_target", "未选择"),
                    ))
                    .child(metric(
                        "运行代数",
                        self.generation()
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "—".into()),
                    ))
                    .child(metric(
                        "DNS",
                        if self.status["dns_managed"] == true {
                            "已接管"
                        } else {
                            "未验证"
                        },
                    )),
            );

        let health = card(
            "流量与健康",
            "来自后台快照的当前指标",
            div()
                .flex()
                .flex_col()
                .child(key_value(
                    "入口",
                    if self.status_valid {
                        "已监听"
                    } else {
                        "未监听"
                    },
                ))
                .child(key_value(
                    "工作线程",
                    if self.status_valid {
                        "已观测"
                    } else {
                        "未接管"
                    },
                ))
                .child(key_value(
                    "最近错误",
                    text(&self.status["forwarding"], "last_error", "—"),
                )),
        );
        let path = card(
            "保护路径",
            "当前保存策略摘要",
            div()
                .flex()
                .flex_col()
                .child(key_value(
                    "下一跳",
                    text(&self.profile, "first_hop", "未配置"),
                ))
                .child(key_value(
                    "系统 DNS",
                    text(&self.profile, "dns_tls_name", "未配置"),
                ))
                .child(key_value(
                    "配置",
                    if self.profile_exists {
                        "SQLite · 已加载"
                    } else {
                        "SQLite · 待初始化"
                    },
                )),
        );
        let recent = card(
            "最近操作",
            "后台最近的状态变化",
            div()
                .flex()
                .flex_col()
                .gap_2()
                .child(div().text_base().child(self.notice.clone()))
                .child(
                    div()
                        .text_base()
                        .text_color(rgb(MUTED))
                        .child("保存规则后需要重新预检"),
                )
                .child(
                    div()
                        .text_base()
                        .text_color(rgb(MUTED))
                        .child("关闭窗口不会停止接管"),
                ),
        );

        let traffic = self.traffic_chart();
        let routes = self.route_chart();
        let dns = self.dns_chart();
        let timeline = self.timeline_card();

        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_start()
                    .flex_wrap()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .flex_1()
                            .flex_grow(1.6)
                            .min_w_0()
                            .min_w(px(500.))
                            .child(status_card)
                            .child(health),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .flex_1()
                            .flex_grow(1.0)
                            .min_w_0()
                            .min_w(px(320.))
                            .child(path)
                            .child(recent),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_start()
                    .flex_wrap()
                    .gap_3()
                    .child(traffic.flex_1().flex_grow(1.35).min_w_0().min_w(px(500.)))
                    .child(routes.flex_1().flex_grow(0.65).min_w_0().min_w(px(320.))),
            )
            .child(
                div()
                    .flex()
                    .items_start()
                    .flex_wrap()
                    .gap_3()
                    .child(dns.flex_1().flex_grow(1.35).min_w_0().min_w(px(500.)))
                    .child(timeline.flex_1().flex_grow(0.65).min_w_0().min_w(px(320.))),
            )
    }

    fn traffic_chart(&self) -> Div {
        if self.traffic_history.is_empty() {
            return chart_card(
                "流量趋势",
                "入口吞吐 · 最近 24 小时",
                div()
                    .p_4()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .text_base()
                    .text_color(rgb(MUTED))
                    .child("暂无流量样本，启动接管并产生流量后开始采样。"),
            );
        }
        let denominator = self.traffic_history.len().saturating_sub(1).max(1);
        let data = self
            .traffic_history
            .iter()
            .enumerate()
            .map(|(index, sample)| {
                (
                    format!("{:02}", index.saturating_mul(24) / denominator),
                    sample.tx,
                )
            })
            .collect::<Vec<_>>();
        let received_data = self
            .traffic_history
            .iter()
            .enumerate()
            .map(|(index, sample)| {
                (
                    format!("{:02}", index.saturating_mul(24) / denominator),
                    sample.rx,
                )
            })
            .collect::<Vec<_>>();
        chart_card(
            "流量趋势",
            "入口吞吐 · 最近 24 小时",
            div()
                .flex()
                .flex_col()
                .gap_2()
                .child(
                    div()
                        .relative()
                        .h(px(150.))
                        .child(
                            LineChart::new(data)
                                .id("traffic-trend")
                                .x(|point| point.0.clone())
                                .y(|point| point.1)
                                .stroke(rgb(BLUE))
                                .dot(),
                        )
                        .child(
                            div().absolute().inset_0().child(
                                LineChart::new(received_data)
                                    .id("traffic-trend-received")
                                    .x(|point| point.0.clone())
                                    .y(|point| point.1)
                                    .stroke(rgb(TEAL))
                                    .dot()
                                    .interactive(false)
                                    .x_axis(false)
                                    .grid(false),
                            ),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .text_base()
                        .text_color(rgb(MUTED))
                        .child(status_dot(BLUE))
                        .child("入口流量")
                        .child(status_dot(TEAL))
                        .child("转发流量"),
                ),
        )
    }

    fn route_chart(&self) -> Div {
        let counters = &self.status["forwarding"]["counters"];
        let values = [
            (
                "直连".to_owned(),
                counters["direct_tcp"].as_u64().unwrap_or_default() as f32
                    + counters["direct_udp"].as_u64().unwrap_or_default() as f32,
            ),
            (
                "住宅链路".to_owned(),
                counters["chain_tcp"].as_u64().unwrap_or_default() as f32
                    + counters["chain_udp"].as_u64().unwrap_or_default() as f32,
            ),
            (
                "DNS".to_owned(),
                counters["dns_tcp"].as_u64().unwrap_or_default() as f32
                    + counters["dns_udp"].as_u64().unwrap_or_default() as f32,
            ),
            (
                "拒绝".to_owned(),
                counters["rejected_tcp"].as_u64().unwrap_or_default() as f32
                    + counters["rejected_udp"].as_u64().unwrap_or_default() as f32,
            ),
        ];
        let total = values.iter().map(|(_, value)| *value).sum::<f32>();
        if total == 0. {
            return chart_card(
                "连接路由",
                "最近观测的流量去向",
                div()
                    .p_4()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .text_base()
                    .text_color(rgb(MUTED))
                    .child("暂无路由样本，产生连接后显示分布。"),
            );
        }
        let values = values
            .into_iter()
            .map(|(label, value)| (label, value / total * 100.))
            .collect::<Vec<_>>();
        chart_card(
            "连接路由",
            "最近观测的 TCP / UDP 流量去向",
            div().h(px(150.)).child(
                BarChart::new(values)
                    .id("route-distribution")
                    .band(|point| point.0.clone())
                    .value(|point| point.1)
                    .alignment(BarAlignment::Left)
                    .label(|point| format!("{:.0}%", point.1))
                    .fill(|point, _, _, _| match point.0.as_str() {
                        "直连" => rgb(BLUE),
                        "住宅链路" => rgb(TEAL),
                        "DNS" => rgb(AMBER),
                        "拒绝" => rgb(RUST),
                        _ => rgb(BLUE),
                    }),
            ),
        )
    }

    fn dns_chart(&self) -> Div {
        let latency = self.status["forwarding"]["traffic"]["dns_latency_ms"]
            .as_f64()
            .or_else(|| self.status["dns_latency_ms"].as_f64())
            .unwrap_or_default() as f32;
        let data = [
            ("1".to_owned(), latency),
            ("2".to_owned(), latency),
            ("3".to_owned(), latency),
            ("4".to_owned(), latency),
            ("5".to_owned(), latency),
            ("6".to_owned(), latency),
            ("7".to_owned(), latency),
            ("8".to_owned(), latency),
        ];
        if latency == 0. {
            return chart_card(
                "DNS 健康",
                "DoH 响应延迟 · 最近 8 次检查",
                div()
                    .p_4()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .text_base()
                    .text_color(rgb(MUTED))
                    .child("暂无 DNS 检查结果，运行预检后开始采样。"),
            );
        }
        chart_card(
            "DNS 健康",
            "DoH 响应延迟 · 最近 8 次检查",
            div()
                .flex()
                .flex_col()
                .gap_2()
                .child(
                    div()
                        .text_base()
                        .font_family(super::theme::MONO_FONT)
                        .child(if latency > 0. {
                            format!("{latency:.0} ms · 当前观测")
                        } else {
                            "— · 等待首次检查".into()
                        }),
                )
                .child(
                    div().h(px(118.)).child(
                        LineChart::new(data)
                            .id("dns-health")
                            .x(|point| point.0.clone())
                            .y(|point| point.1)
                            .stroke(rgb(TEAL))
                            .dot(),
                    ),
                ),
        )
    }

    fn timeline_card(&self) -> Div {
        let first_time = self
            .status_at
            .map(|time| {
                let seconds = time.elapsed().as_secs();
                if seconds < 60 {
                    "刚刚".to_owned()
                } else {
                    format!("{} 分钟", seconds / 60)
                }
            })
            .unwrap_or_else(|| "等待".to_owned());
        let (first_title, first_caption, first_color) = if self.status_valid {
            ("后台状态已连接", "最近快照可用", BLUE)
        } else {
            ("等待后台连接", "尚未收到状态快照", RUST)
        };
        let (second_title, second_caption) = if self.profile_exists {
            ("SQLite 配置已加载", "本机配置可用于保存")
        } else {
            ("等待 SQLite 配置", "保存配置后显示状态")
        };
        let (third_title, third_caption, third_color) = if self.preflight.is_some() {
            ("预检结果已更新", "请确认当前目标状态", TEAL)
        } else {
            ("等待环境预检", "目标 WSL 尚未确认", RUST)
        };
        let event = |time: String, title: &'static str, caption: &'static str, color| {
            div()
                .flex()
                .items_start()
                .gap_2()
                .min_h(px(44.))
                .child(
                    div()
                        .w(px(48.))
                        .text_base()
                        .text_color(rgb(MUTED))
                        .child(time),
                )
                .child(div().pt_1().child(super::components::status_dot(color)))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(div().text_base().child(title))
                        .child(div().text_base().text_color(rgb(MUTED)).child(caption)),
                )
        };
        chart_card(
            "事件时间线",
            "后台与接管状态变化",
            div()
                .flex()
                .flex_col()
                .child(event(first_time, first_title, first_caption, first_color))
                .child(event("2 分钟".into(), second_title, second_caption, TEAL))
                .child(event(
                    "5 分钟".into(),
                    third_title,
                    third_caption,
                    third_color,
                )),
        )
    }

    pub(crate) fn dns_label(&self) -> String {
        if !self.status_valid {
            "状态未知；无法确认 DNS 保护".into()
        } else if self.status["dns_managed"] == true {
            "系统 DNS 已接管".into()
        } else if self.idle() {
            "系统 DNS 未接管".into()
        } else {
            "DNS 状态未确认".into()
        }
    }

    pub(crate) fn preflight_panel(&self) -> Div {
        let Some(result) = &self.preflight else {
            return div()
                .p_3()
                .bg(rgb(SURFACE_SOFT))
                .rounded_md()
                .text_base()
                .text_color(rgb(MUTED))
                .child("选择目标和见证后运行预检。启动前会再次检查。");
        };
        let passed = result["passed"] == true;
        let (label, color, background) = if passed {
            ("通过", TEAL, SUCCESS_BG)
        } else {
            ("有阻断", RUST, DANGER_BG)
        };
        let mut body = div()
            .flex()
            .flex_col()
            .gap_2()
            .child(badge(label, color, background));
        if let Some(blockers) = result["blockers"].as_array() {
            for blocker in blockers.iter().filter_map(Value::as_str) {
                body = body.child(
                    div()
                        .text_base()
                        .text_color(rgb(RUST))
                        .child(blocker.to_owned()),
                );
            }
        }
        panel(
            "预检结果",
            if passed {
                "通过 · 仍需确认启动"
            } else {
                "未通过 · 未启动"
            },
        )
        .child(body)
    }
}
