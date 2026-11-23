//! 首页监控页和接管摘要。

use gpui_kit::component::button::ButtonVariants as _;
use gpui_kit::component::chart::{AreaChart, BarChart, LineChart};
use gpui_kit::component::plot::shape::BarAlignment;
use gpui_kit::{prelude::*, *};

use super::backend::{self, Kind};
use super::components::{bytes, design_icon, status_dot, text};
use super::model::{TrafficSample, UiAction};
use super::state::Desktop;
use super::theme::{AMBER, BLUE, MUTED, RULE, RUST, SURFACE, SURFACE_SOFT, TEAL, app_rgb as rgb};
use super::views::{card, card_header, chart_card, key_value, metric};

impl Desktop {
    pub(crate) fn overview(&self, cx: &Context<Self>) -> Div {
        let takeover_active = self.status_valid && !matches!(self.phase(), "idle" | "unknown");
        let (session_label, session_action, session_disabled, session_icon) = if takeover_active {
            (
                "退出接管",
                UiAction::Prepare(Kind::Stop),
                self.locked(),
                "close",
            )
        } else {
            (
                "启动接管",
                UiAction::Prepare(Kind::Start),
                self.locked() || !self.idle(),
                "play",
            )
        };
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
                            "overview-session-action",
                            session_label,
                            session_action,
                            session_disabled,
                            cx,
                        )
                        .icon(design_icon(session_icon, 15., super::theme::SURFACE))
                        .primary(),
                    ),
            )
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(metric(
                        "当前目标",
                        text(&self.status, "active_target", "无运行目标"),
                    ))
                    .child(metric(
                        "运行代数",
                        self.generation()
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "—".into()),
                    ))
                    .child(metric("DNS", self.dns_state_label()))
                    .child(metric("UDP", self.udp_state_label())),
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
                .child(key_value("最近错误", {
                    let error = text(&self.status["forwarding"], "last_error", "—");
                    if error == "—" {
                        error
                    } else {
                        backend::humanize_error(&error)
                    }
                })),
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
                        .child("启动接管前会自动预检"),
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
        const TITLE: &str = "流量趋势";
        const CAPTION: &str = "上行 / 下行速率 · 每次状态刷新采样一次（约 2 秒）";
        let empty = |message: &'static str| {
            chart_card(
                TITLE,
                CAPTION,
                div()
                    .p_4()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .text_base()
                    .text_color(rgb(MUTED))
                    .child(message),
            )
        };
        if !self.status_valid {
            return empty("后台状态未确认，暂停采样。");
        }
        let Some(first) = self.traffic_history.first() else {
            return empty("当前没有在转发，暂无流量样本。启动接管后开始采样。");
        };
        let per_second = |value: f64| format!("{}/s", bytes(value.max(0.) as u64));
        let span = first.at.elapsed().as_secs();
        let span = if span < 60 {
            format!("{span} 秒")
        } else {
            format!("{} 分 {} 秒", span / 60, span % 60)
        };
        let peak = |pick: fn(&TrafficSample) -> f32| {
            self.traffic_history.iter().map(pick).fold(0., f32::max) as f64
        };
        let summary = format!(
            "最近 {span}峰值 ↑ {} ↓ {}",
            per_second(peak(|sample| sample.tx)),
            per_second(peak(|sample| sample.rx)),
        );
        // 横轴按样本顺序等距排列，刻度写的是该样本距现在多久。
        let data = self
            .traffic_history
            .iter()
            .map(|sample| {
                let age = sample.at.elapsed().as_secs();
                let label = if age == 0 {
                    "刚刚".to_owned()
                } else {
                    format!("{age} 秒前")
                };
                (label, *sample)
            })
            .collect::<Vec<_>>();
        chart_card(
            TITLE,
            CAPTION,
            div()
                .flex()
                .flex_col()
                .gap_2()
                .child(
                    div()
                        .text_base()
                        .font_family(super::theme::MONO_FONT)
                        .truncate()
                        .child(summary),
                )
                .child(
                    div().relative().h(px(128.)).child(
                        AreaChart::new(data)
                            .id("traffic-trend")
                            .x(|point| point.0.clone())
                            .y(|point| point.1.tx)
                            .stroke(rgb(BLUE))
                            .fill(rgb(BLUE).opacity(0.14))
                            .name("上行")
                            .y(|point| point.1.rx)
                            .stroke(rgb(TEAL))
                            .fill(rgb(TEAL).opacity(0.12))
                            .name("下行")
                            .x_tick_count(5)
                            .tooltip_value(move |_, _, value| per_second(value).into()),
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
                        .child("上行")
                        .child(status_dot(TEAL))
                        .child("下行"),
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
                    .name("流量占比")
                    .label(|point| format!("{:.0}%", point.1))
                    .tooltip_value(|_, value| format!("{value:.0}%").into())
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
        let latency = self.dns_history.last().copied().unwrap_or_default();
        if self.dns_history.is_empty() {
            return chart_card(
                "DNS 健康",
                "DoH 响应延迟 · 最近 12 次检查",
                div()
                    .p_4()
                    .bg(rgb(SURFACE_SOFT))
                    .rounded_md()
                    .text_base()
                    .text_color(rgb(MUTED))
                    .child("暂无 DNS 检查结果，启动接管后开始采样。"),
            );
        }
        chart_card(
            "DNS 健康",
            "DoH 响应延迟 · 最近 12 次检查",
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
                        LineChart::new(
                            self.dns_history
                                .iter()
                                .enumerate()
                                .map(|(index, value)| ((index + 1).to_string(), *value))
                                .collect::<Vec<_>>(),
                        )
                        .id("dns-health")
                        .x(|point| point.0.clone())
                        .y(|point| point.1)
                        .stroke(rgb(TEAL))
                        .name("DoH 延迟")
                        .dot()
                        .x_tick_count(4)
                        .tooltip_value(|_, value| format!("{value:.0} ms").into()),
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
        } else if self.phase() == "recovery_required" {
            "DNS 需要恢复；系统 DNS 未接管。请先停止并恢复直连。".into()
        } else {
            "DNS 状态未确认".into()
        }
    }

    pub(crate) fn dns_state_label(&self) -> &'static str {
        if !self.status_valid {
            "未知"
        } else if self.status["dns_managed"] == true {
            "已接管"
        } else if self.idle() {
            "未接管"
        } else if self.phase() == "recovery_required" {
            "需要恢复"
        } else {
            "未确认"
        }
    }

    /// Non-whitelisted application UDP. Managed takeover starts even when the
    /// startup UDP probe fails; such UDP is then refused (never sent direct) for
    /// the session. System DNS on port 53 is managed separately.
    pub(crate) fn udp_state_label(&self) -> &'static str {
        if !self.status_valid {
            "未知"
        } else if self.phase() == "forwarding_managed" {
            match self.status["startup_verified"]["udp_supported"].as_bool() {
                Some(true) => "经代理链",
                Some(false) => "已阻断",
                None => "未确认",
            }
        } else if self.idle() {
            "未接管"
        } else if self.phase() == "recovery_required" {
            "需要恢复"
        } else {
            "未确认"
        }
    }
}
