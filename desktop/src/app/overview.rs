//! 首页：环境卡片横向排列（固定宽高，超出时横向滚动），下面左侧是流量和路由判定，
//! 右侧是后台运行日志里的最新事件。后台连接、DNS、转发线程的常驻状态在底部状态栏。

use gpui_kit::component::chart::AreaChart;
use gpui_kit::{prelude::*, *};
use serde_json::Value;

use super::components::{Tip, bytes, status_dot};
use super::model::TrafficSample;
use super::state::Desktop;
use super::theme::{
    AMBER, CHART_UP, INK, MONO_FONT, MUTED, ROUTE_DIRECT, RULE, RUST, SURFACE_SOFT, TEAL,
    app_rgb as rgb,
};
use super::views::chart_card;

impl Desktop {
    pub(crate) fn overview(&self, cx: &Context<Self>) -> Div {
        div()
            .flex()
            .flex_col()
            .gap_3()
            .h_full()
            .min_h_0()
            .child(self.home_environment_cards(cx))
            .child(
                div()
                    .flex()
                    .gap_3()
                    .flex_1()
                    .min_h_0()
                    .child(self.traffic_card().flex_1().min_w_0().h_full())
                    .child(
                        self.timeline_card()
                            .w(px(240.))
                            .flex_shrink_0()
                            .min_w_0()
                            .h_full(),
                    ),
            )
    }

    /// An environment that needs recovery and is no longer registered:
    /// nothing is left to stop, only its record to abandon.
    pub(crate) fn gone_scope(&self) -> Option<String> {
        self.owned_sessions()
            .into_iter()
            .find(|session| {
                session["phase"] == "recovery_required" && session["target_registered"] == false
            })
            .and_then(|session| session["scope"].as_str().map(str::to_owned))
    }

    /// 托盘要显示的状态和菜单里的主操作。
    pub(crate) fn tray_snapshot(&self) -> super::tray::Snapshot {
        use super::tray::{Look, Primary, Snapshot};
        // 多个环境同时接管时（决策 40），任一环境需要恢复就显示需要恢复。
        let owned: Vec<(&str, String)> = self
            .owned_sessions()
            .into_iter()
            .map(|session| {
                (
                    session["phase"].as_str().unwrap_or(""),
                    Self::session_name(session),
                )
            })
            .collect();
        let look = Look::of_sessions(
            self.status_valid,
            self.phase(),
            owned.iter().map(|(phase, _)| *phase),
        );
        // 和首页主按钮（`primary_action`）同一套选法：一个环境时按它的状态，
        // 多个时「停止全部接管」。
        let sessions = self.owned_sessions();
        let primary = match sessions.as_slice() {
            _ if !self.status_valid => Primary::Reconnect,
            [] => Primary::Environments,
            [session] if session["target_registered"] == false => Primary::Abandon,
            [session] if session["phase"] == "recovery_required" => Primary::Recover,
            _ => Primary::Stop,
        };
        // 只在后台确认有接管记录时写目标名（状态没确认时会话列表为空）；
        // 和状态说的是同一批环境，多个时写「N 个环境」。
        let target = look.target_label(&owned);
        let running = self.busy.or(self.reading_kind.filter(|_| self.reading));
        let busy = match running {
            Some(kind) => Some(format!("正在{}…", kind.label())),
            None if self.confirmation.is_some() => Some("等待在主窗口确认".to_owned()),
            None => None,
        };
        Snapshot {
            look,
            target,
            primary,
            busy,
            autostart: self.autostart_enabled,
            island: self.island_enabled,
            owned: self.owned_sessions().len(),
        }
    }

    /// 接管中交给状态岛的环境信息：公网出口、DNS、UDP、连接数，说法和首页一致，
    /// 再加上被接管环境里的图形应用。只在后台确认正在接管时给；其余情况岛不显示这些。
    /// 多个环境在接管或需要恢复时改成每个环境一行（出口和速率），不列应用：应用列表
    /// 只跟着一个接管目标，和一列环境放在一起分不清应用会在哪个环境里启动。
    pub(crate) fn island_details(&self) -> Option<super::island::Details> {
        let text = |value: &Value| value.as_str().map(str::to_owned);
        let owned = self.owned_sessions();
        if owned.len() > 1 {
            let environments = owned
                .into_iter()
                .map(|session| {
                    let exit = &session["recent_exit"];
                    let traffic = &session["forwarding"]["traffic"];
                    let rate = |key: &str| traffic[key].as_f64().unwrap_or_default().max(0.) as f32;
                    let recovering = session["phase"] == "recovery_required";
                    super::island::Environment {
                        name: Self::session_name(session),
                        exit_ip: text(&exit["ip"]),
                        exit_country: text(&exit["country"]),
                        exit_matches: exit["matches_residential"].as_bool(),
                        recovering,
                        rates: (!recovering && traffic.is_object()).then(|| super::island::Rates {
                            up: rate("tx_bytes_per_sec"),
                            down: rate("rx_bytes_per_sec"),
                        }),
                    }
                })
                .collect();
            return Some(super::island::Details {
                apps: super::island::Apps::Listed(Vec::new()),
                environments,
                ..Default::default()
            });
        }
        self.island_target()?;
        let exit = &self.status["recent_exit"];
        Some(super::island::Details {
            exit_ip: text(&exit["ip"]),
            exit_country: text(&exit["country"]),
            exit_matches: exit["matches_residential"].as_bool(),
            dns_managed: self.status["dns_managed"] == true,
            dns_latency_ms: self.status["startup_verified"]["dns_latency_ms"].as_f64(),
            udp: self.udp_state_label(),
            active_tcp: self.status["forwarding"]["active_tcp"].as_u64(),
            apps: self.island_apps_state(),
            launching: self.island_launching.clone(),
            environments: Vec::new(),
        })
    }

    /// 流量卡：速率曲线和本次接管的路由判定占比。没接管时也画一条 0 基线，
    /// 不是只显示一句空态。
    fn traffic_card(&self) -> Div {
        const TITLE: &str = "流量";
        const CAPTION: &str = "上行 / 下行速率，约 2 秒采样一次";
        if !self.status_valid {
            return chart_card(
                TITLE,
                CAPTION,
                div()
                    .flex()
                    .flex_1()
                    .items_center()
                    .justify_center()
                    .child(empty_note("后台状态未确认，暂停采样。")),
            );
        }
        let forwarding = self.forwarding();
        let idle = forwarding.is_none();
        let active = self
            .live_connections
            .iter()
            .filter(|row| row.active())
            .count();
        let per_second = |value: f64| format!("{}/s", bytes(value.max(0.) as u64));
        let summary = if idle {
            "未接管 · 启动接管后开始采样".to_owned()
        } else {
            match self.traffic_history.first() {
                Some(first) => {
                    let span = first.at.elapsed().as_secs();
                    let span = if span < 60 {
                        format!("{span} 秒")
                    } else {
                        format!("{} 分 {} 秒", span / 60, span % 60)
                    };
                    let peak = |pick: fn(&TrafficSample) -> f32| {
                        self.traffic_history.iter().map(pick).fold(0., f32::max) as f64
                    };
                    format!(
                        "活动连接 {active} · 最近 {span}峰值 ↑ {} ↓ {}",
                        per_second(peak(|sample| sample.tx)),
                        per_second(peak(|sample| sample.rx)),
                    )
                }
                None => format!("活动连接 {active} · 等待第一个采样"),
            }
        };
        // 横轴按样本顺序等距排列，刻度写的是该样本距现在多久。
        let mut data = self
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
        // 还没有样本时补一条 0 速率的基线：未接管和刚接管的头两秒也能看到图表。
        let placeholder = data.is_empty();
        if placeholder {
            let now = std::time::Instant::now();
            data = ["2 分钟前", "90 秒前", "60 秒前", "30 秒前", "现在"]
                .into_iter()
                .map(|label| {
                    (
                        label.to_owned(),
                        TrafficSample {
                            at: now,
                            tx: 0.,
                            rx: 0.,
                        },
                    )
                })
                .collect();
        }
        let mut chart = AreaChart::new(data)
            .id("traffic-trend")
            .x(|point| point.0.clone())
            .y(|point| point.1.tx)
            .stroke(rgb(CHART_UP))
            .fill(rgb(CHART_UP).opacity(0.14))
            .name("上行")
            .y(|point| point.1.rx)
            .stroke(rgb(INK))
            .fill(rgb(INK).opacity(0.12))
            .name("下行")
            .x_tick_count(5)
            .tooltip_value(move |_, _, value| per_second(value).into());
        if placeholder {
            // 全是 0 时曲线没有纵向范围，钉一个固定范围并留出底部空隙，让 0 基线画出来。
            chart = chart.y_domain(0f32, 1024f32).y_padding(10., 12.);
        }
        chart_card(
            TITLE,
            CAPTION,
            div()
                .id("overview-traffic-body")
                .flex()
                .flex_col()
                .gap_2()
                .flex_1()
                .min_h_0()
                .child(div().font_family(MONO_FONT).truncate().child(summary))
                .child(div().flex_1().min_h(px(96.)).child(chart))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .text_color(rgb(MUTED))
                        .child(status_dot(CHART_UP))
                        .child("上行")
                        .child(status_dot(INK))
                        .child("下行"),
                )
                .children(forwarding.map(route_section)),
        )
    }

    /// 后台运行日志里最新的几条，时间和内容都来自 SQLite，不受日志页筛选影响。
    fn timeline_card(&self) -> Div {
        const TITLE: &str = "事件时间线";
        const CAPTION: &str = "后台运行日志里最新的事件";
        if self.events.is_empty() {
            let (message, color) = match &self.events_error {
                Some(error) => (format!("读取运行事件失败：{error}"), RUST),
                None if !self.events_loaded => ("正在读取运行事件…".to_owned(), MUTED),
                None => ("暂无运行事件。".to_owned(), MUTED),
            };
            return chart_card(TITLE, CAPTION, empty_note(message).text_color(rgb(color)));
        }
        let mut list = div()
            .id("overview-timeline-list")
            .flex()
            .flex_col()
            .gap_2()
            .flex_1()
            .min_h_0()
            .overflow_y_scroll();
        if let Some(error) = &self.events_error {
            list = list.child(
                div()
                    .text_sm()
                    .text_color(rgb(RUST))
                    .truncate()
                    .child(format!("刷新失败，下面是上次读到的事件：{error}")),
            );
        }
        for event in &self.events {
            let color = match event.level.as_str() {
                "error" => RUST,
                "warning" => AMBER,
                _ => TEAL,
            };
            let time = event_time(&event.occurred_at);
            let context = event.context();
            let detail = if context.is_empty() {
                time.to_owned()
            } else {
                format!("{time} · {context}")
            };
            list = list.child(
                div()
                    .flex()
                    .items_start()
                    .gap_2()
                    .child(div().pt(px(7.)).flex_shrink_0().child(status_dot(color)))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .child(div().text_sm().truncate().child(event.message.clone()))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(MUTED))
                                    .truncate()
                                    .child(detail),
                            ),
                    ),
            );
        }
        chart_card(TITLE, CAPTION, list)
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

/// 本次接管以来各路由的判定次数：一条按占比分段的横条，加图例和悬停明细。
fn route_section(forwarding: &Value) -> Stateful<Div> {
    let counters = &forwarding["counters"];
    let count = |tcp: &str, udp: &str| {
        counters[tcp].as_u64().unwrap_or_default() + counters[udp].as_u64().unwrap_or_default()
    };
    // 「双跳」和连接页的路由名称一致。
    let counts = [
        ("直连", count("direct_tcp", "direct_udp"), ROUTE_DIRECT),
        ("双跳", count("chain_tcp", "chain_udp"), TEAL),
        ("DNS", count("dns_tcp", "dns_udp"), AMBER),
        ("拒绝", count("rejected_tcp", "rejected_udp"), RUST),
    ];
    let total = counts.iter().map(|(_, count, _)| count).sum::<u64>();
    let share = |count: u64| {
        if total == 0 {
            0.
        } else {
            count as f32 / total as f32
        }
    };
    let tip = counts
        .iter()
        .fold(
            Tip::new("路由判定（本次接管以来）"),
            |tip, (label, count, _)| tip.row(*label, format!("{count} 次")),
        )
        .note("TCP 每条连接计一次，UDP 每个数据报计一次")
        .note("所以这不是流量占比，也不是连接数占比");
    let header = div()
        .flex()
        .items_center()
        .justify_between()
        .child(div().text_color(rgb(MUTED)).child("路由判定"))
        .child(
            div()
                .font_family(MONO_FONT)
                .text_color(rgb(MUTED))
                .child(format!("共 {total} 次")),
        );
    let body = if total == 0 {
        div()
            .text_color(rgb(MUTED))
            .child("暂无路由样本，产生连接后显示占比。")
    } else {
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .flex()
                    .h(px(8.))
                    .w_full()
                    .rounded_full()
                    .overflow_hidden()
                    .bg(rgb(SURFACE_SOFT))
                    .children(counts.iter().filter(|(_, count, _)| *count > 0).map(
                        |(_, count, color)| {
                            div().h_full().w(relative(share(*count))).bg(rgb(*color))
                        },
                    )),
            )
            .child(div().flex().flex_wrap().gap_3().children(counts.iter().map(
                |(label, count, color)| {
                    div()
                        .flex()
                        .items_center()
                        .gap_1()
                        .child(status_dot(*color))
                        .child(format!("{label} {:.0}%", share(*count) * 100.))
                },
            )))
    };
    div()
        .id("route-section")
        .flex()
        .flex_col()
        .gap_1()
        .pt_2()
        .border_t_1()
        .border_color(rgb(RULE))
        .child(header)
        .child(body)
        .tooltip(move |window, cx| tip.build(window, cx))
}

/// 图表卡片里的空态说明。
fn empty_note(message: impl Into<SharedString>) -> Div {
    div()
        .p_4()
        .bg(rgb(SURFACE_SOFT))
        .rounded_md()
        .text_sm()
        .text_color(rgb(MUTED))
        .child(message.into())
}

/// 运行日志时间「2026-11-23 21:16:13」去掉年份；格式不符时原样返回。
fn event_time(occurred_at: &str) -> &str {
    occurred_at
        .get(5..)
        .filter(|_| occurred_at.len() == 19)
        .unwrap_or(occurred_at)
}
