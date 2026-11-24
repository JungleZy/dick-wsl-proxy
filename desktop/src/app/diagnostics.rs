//! 连接页（连接记录、出口复核、诊断导出）和常驻底栏的现场观测（流量、DNS、转发线程）。
use std::collections::{BTreeSet, HashSet};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use gpui_kit::base::Selectable as _;
use gpui_kit::component::{
    Sizable as _,
    button::{Button, ButtonGroup},
};
use gpui_kit::{prelude::*, *};
use serde_json::Value;

use super::backend;
use super::components::{
    StatusTone, Tip, badge, bytes, design_icon, fact, rate, status_icon, text_tip,
};
use super::model::{ConnectionFilter, ConnectionRow, UiAction};
use super::state::Desktop;
use super::theme::{
    ACCENT, AMBER, DANGER_BG, INK, MONO_FONT, MUTED, ROUTE_DIRECT, ROUTE_DIRECT_BG, RULE, RUST,
    SUCCESS_BG, SURFACE, SURFACE_SOFT, TEAL, WARNING_BG, app_rgb as rgb,
};

const ROW_HEIGHT: f32 = 48.;
const ENVIRONMENT_WIDTH: f32 = 112.;
const PROTOCOL_WIDTH: f32 = 36.;
const ROUTE_WIDTH: f32 = 72.;
const STATUS_WIDTH: f32 = 84.;
const BYTES_WIDTH: f32 = 96.;
const TIME_WIDTH: f32 = 112.;
fn route_label(route: Option<&str>) -> (&'static str, u32, u32) {
    match route {
        Some("direct") => ("直连", ROUTE_DIRECT, ROUTE_DIRECT_BG),
        Some("chain") => ("双跳", TEAL, SUCCESS_BG),
        Some("dns") => ("DNS", AMBER, WARNING_BG),
        Some("reject") => ("拒绝", RUST, DANGER_BG),
        _ => ("待判定", MUTED, SURFACE_SOFT),
    }
}

fn stage_label(stage: &str) -> &'static str {
    match stage {
        "metadata" => "获取原始目标",
        "policy" => "策略判定",
        "connect" => "建立连接",
        "dns" => "DNS 转发",
        "relay" => "传输",
        _ => "未知阶段",
    }
}

fn status_label(status: &str) -> (&'static str, u32) {
    match status {
        "active" => ("活动", ACCENT),
        "completed" => ("完成", INK),
        "failed" => ("失败", RUST),
        "stopped" => ("已停止", MUTED),
        _ => ("未知", MUTED),
    }
}

fn reason_label(reason: Option<&str>) -> &'static str {
    match reason {
        Some("enumerated_origin") => "诊断目标",
        Some("domain_alias") => "域名例外",
        Some("ip_or_cidr") => "IP / CIDR 例外",
        Some("default_chain") => "默认双跳",
        Some("fake_ip") => "双跳，住宅解析域名",
        Some("system_dns") => "系统 DNS",
        Some("policy_reject") => "策略拒绝",
        Some("metadata_unavailable") => "目标未识别",
        Some("capacity_limit") => "并发已满",
        Some("peer_busy") => "源端口未释放",
        Some("resource_limit") => "系统资源不足",
        _ => "等待元数据",
    }
}

fn ago(seconds: u64) -> String {
    match seconds {
        0..60 => format!("{seconds} 秒前"),
        60..3600 => format!("{} 分钟前", seconds / 60),
        3600..86400 => format!("{} 小时前", seconds / 3600),
        _ => format!("{} 天前", seconds / 86400),
    }
}

fn duration(milliseconds: u64) -> String {
    let seconds = milliseconds / 1000;
    match seconds {
        0..10 => format!("{:.1} 秒", milliseconds as f64 / 1000.),
        10..60 => format!("{seconds} 秒"),
        60..3600 => format!("{} 分 {} 秒", seconds / 60, seconds % 60),
        _ => format!("{} 时 {} 分", seconds / 3600, seconds % 3600 / 60),
    }
}

fn cell(width: f32) -> Div {
    div().w(px(width)).flex_shrink_0()
}

fn table_header() -> Div {
    div()
        .flex()
        .w_full()
        .h(px(32.))
        .px_2()
        .items_center()
        .gap_3()
        .border_b_1()
        .border_color(rgb(RULE))
        .text_color(rgb(MUTED))
        .child(cell(ENVIRONMENT_WIDTH).child("环境"))
        .child(cell(PROTOCOL_WIDTH).child("协议"))
        .child(div().flex_1().min_w_0().child("目的端 · 判定原因"))
        .child(cell(ROUTE_WIDTH).child("路由"))
        .child(cell(STATUS_WIDTH).child("状态 · 阶段"))
        .child(cell(BYTES_WIDTH).flex().justify_end().child("上行 / 下行"))
        .child(
            cell(TIME_WIDTH)
                .flex()
                .justify_end()
                .child("结束时间 · 时长"),
        )
}

fn connection_row(row: &ConnectionRow) -> Stateful<Div> {
    let (route, route_color, route_background) = route_label(row.route.as_deref());
    let (status, status_color) = status_label(&row.status);
    // 已结束的连接只看结果；活动连接显示当前阶段，失败连接显示失败时所处的阶段。
    let stage = if row.failed() {
        stage_label(row.failure_stage.as_deref().unwrap_or(&row.stage))
    } else if row.active() {
        stage_label(&row.stage)
    } else {
        ""
    };
    let destination = match &row.destination {
        Some(destination) => div().child(destination.clone()),
        None => div().text_color(rgb(MUTED)).child("原始目标未识别"),
    };
    // 已落盘的记录显示结束时间；还在内存里的连接没有结束时间。
    let (when, when_color) = match &row.ended_at {
        Some(ended_at) => (ended_at.clone(), INK),
        None if row.active() => ("进行中".to_owned(), ACCENT),
        None => ("刚结束".to_owned(), MUTED),
    };
    let id = match row.record_id {
        Some(record_id) => ElementId::from(("connection-record", record_id as u64)),
        None => ElementId::from(("connection-live", row.flow_id)),
    };
    div()
        .id(id)
        .flex()
        .w_full()
        .min_w_0()
        .h(px(ROW_HEIGHT))
        .px_2()
        .items_center()
        .gap_3()
        .border_b_1()
        .border_color(rgb(RULE))
        .hover(|style| style.bg(rgb(SURFACE_SOFT)))
        .child(match &row.target {
            Some(target) => cell(ENVIRONMENT_WIDTH).truncate().child(target.clone()),
            None => cell(ENVIRONMENT_WIDTH).text_color(rgb(MUTED)).child("—"),
        })
        .child(
            cell(PROTOCOL_WIDTH)
                .font_family(MONO_FONT)
                .child(row.protocol.to_uppercase()),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w_0()
                .child(destination.font_family(MONO_FONT).truncate())
                .child(
                    div()
                        .text_color(rgb(MUTED))
                        .truncate()
                        .child(reason_label(row.reason.as_deref())),
                ),
        )
        .child(cell(ROUTE_WIDTH).child(badge(route, route_color, route_background)))
        .child(
            cell(STATUS_WIDTH)
                .flex()
                .flex_col()
                .child(div().text_color(rgb(status_color)).child(status))
                .child(div().text_color(rgb(MUTED)).child(stage)),
        )
        .child(
            cell(BYTES_WIDTH)
                .flex()
                .flex_col()
                .items_end()
                .font_family(MONO_FONT)
                .child(format!("↑ {}", bytes(row.tx_bytes)))
                .child(format!("↓ {}", bytes(row.rx_bytes))),
        )
        .child(
            cell(TIME_WIDTH)
                .flex()
                .flex_col()
                .items_end()
                .child(
                    div()
                        .font_family(MONO_FONT)
                        .text_color(rgb(when_color))
                        .child(when),
                )
                .child(
                    div()
                        .text_color(rgb(MUTED))
                        .child(duration(row.duration_ms)),
                ),
        )
}

fn bar_separator() -> Div {
    div().w(px(1.)).h(px(14.)).flex_shrink_0().bg(rgb(RULE))
}

/// 底栏里的一项：内容尽量短，完整含义放在分行的悬停提示里。
fn bar_item(id: &'static str, tip: Tip, content: Div) -> Stateful<Div> {
    content
        .id(id)
        .flex_shrink_0()
        .tooltip(move |window, cx| tip.build(window, cx))
}

/// 箭头紧跟数值，按实际长度排。数值会自动换算成 KiB、MiB、GiB，最长也只有十来个字符，
/// 不预留固定宽度，免得短数值和前面的图标、箭头之间空出一大段。
fn arrow_value(arrow: &'static str, value: String) -> Div {
    div()
        .flex()
        .flex_shrink_0()
        .items_center()
        .gap_1()
        .child(div().text_color(rgb(MUTED)).child(arrow))
        .child(div().font_family(MONO_FONT).child(value))
}

impl Desktop {
    /// 只有最近一次快照有效、且后台确实在转发时才返回转发观测，避免把过期数据当成实时值。
    pub(crate) fn forwarding(&self) -> Option<&Value> {
        let forwarding = &self.status["forwarding"];
        (self.status_valid && forwarding.is_object()).then_some(forwarding)
    }

    /// 状态栏左侧图标组的后两个：DNS 和转发线程，只有图标，含义放在悬停提示里。
    pub(crate) fn health_icons(&self) -> [Stateful<Div>; 2] {
        const SNAPSHOT: &str = "来自后台最近一次状态快照";
        // 只有需要恢复才用故障色；诊断转发等合法状态下 DNS 未接管用待处理色提示。
        let (dns_tone, dns_tip) = if !self.status_valid {
            (
                StatusTone::Warn,
                Tip::new("系统 DNS")
                    .row("状态", "未知")
                    .note("后台状态未确认，无法确认 DNS 保护"),
            )
        } else if self.status["dns_managed"] == true {
            (
                StatusTone::Ok,
                Tip::new("系统 DNS").row("状态", "已接管").note(SNAPSHOT),
            )
        } else if self.idle() {
            (
                StatusTone::Off,
                Tip::new("系统 DNS").row("状态", "未接管").note(SNAPSHOT),
            )
        } else if self.phase() == "recovery_required" {
            (
                StatusTone::Error,
                Tip::new("系统 DNS")
                    .row("状态", "需要恢复")
                    .note("请先停止接管并恢复直连")
                    .note(SNAPSHOT),
            )
        } else {
            (
                StatusTone::Warn,
                Tip::new("系统 DNS").row("状态", "未确认").note(SNAPSHOT),
            )
        };
        let (worker_tone, worker_tip) = match self
            .forwarding()
            .map(|forwarding| forwarding["healthy"].as_bool())
        {
            Some(Some(true)) => (StatusTone::Ok, Tip::new("转发线程").row("状态", "运行中")),
            Some(Some(false)) => (
                StatusTone::Error,
                Tip::new("转发线程")
                    .row("状态", "故障")
                    .note("最后一次转发错误见连接页"),
            ),
            _ => (
                StatusTone::Off,
                Tip::new("转发线程")
                    .row("状态", "无观测")
                    .note("当前未接管或后台状态未确认"),
            ),
        };
        [
            status_icon("status-dns", "dns", dns_tip, dns_tone),
            status_icon("status-worker", "forward", worker_tip, worker_tone),
        ]
    }

    /// 状态栏的实时速率和累计流量。没有转发观测（未接管或状态未确认）时显示 0，
    /// 悬停提示说明原因；实时和累计用图标区分，不写文字。
    pub(crate) fn status_observations(&self) -> Div {
        const NO_DATA: &str = "未接管或后台状态未确认，显示 0";
        let forwarding = self.forwarding();
        let traffic = forwarding
            .map(|forwarding| &forwarding["traffic"])
            .unwrap_or(&Value::Null);
        let total = |key: &str| bytes(traffic[key].as_u64().unwrap_or_default());
        let (tx_rate, rx_rate) = (
            rate(&traffic["tx_bytes_per_sec"]),
            rate(&traffic["rx_bytes_per_sec"]),
        );
        let (tx_total, rx_total) = (total("tx_bytes"), total("rx_bytes"));
        let rate_tip = Tip::new("实时速率")
            .row("↑ 上行", tx_rate.clone())
            .row("↓ 下行", rx_rate.clone())
            .note("目标发行版经 Windows 入口收发的应用层数据")
            .note("按相邻两次状态快照计算")
            .note_if(forwarding.is_none(), NO_DATA);
        let total_tip = Tip::new("累计流量（本次接管以来）")
            .row("↑ 上行", tx_total.clone())
            .row("↓ 下行", rx_total.clone())
            .note("应用层字节，不含代理握手和 IP 包头")
            .note("重新启动接管后从零计")
            .note_if(forwarding.is_none(), NO_DATA);
        div()
            .flex()
            .flex_shrink_0()
            .items_center()
            .gap_3()
            .ml_2()
            .text_sm()
            .child(bar_separator())
            .child(bar_item(
                "status-rates",
                rate_tip,
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(design_icon("realtime", 15., MUTED))
                    .child(arrow_value("↑", tx_rate))
                    .child(arrow_value("↓", rx_rate)),
            ))
            .child(bar_separator())
            .child(bar_item(
                "status-totals",
                total_tip,
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(design_icon("total", 15., MUTED))
                    .child(arrow_value("↑", tx_total))
                    .child(arrow_value("↓", rx_total)),
            ))
    }

    fn exit_fact(&self) -> Stateful<Div> {
        let exit = &self.status["recent_exit"];
        let (label, value, color, tooltip): (String, String, u32, &'static str) =
            if self.status_valid && exit.is_object() {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|elapsed| elapsed.as_secs())
                    .unwrap_or_default();
                let checked = exit["checked_unix_seconds"]
                    .as_u64()
                    .map(|checked| format!("{}检测", ago(now.saturating_sub(checked))))
                    .unwrap_or_else(|| "检测时间未知".into());
                let (verdict, color, tooltip) = match exit["matches_residential"].as_bool() {
                    Some(true) => (
                        "已匹配",
                        TEAL,
                        "出口 IP 与设置里的住宅代理服务器地址相同。结果只代表该次观测。",
                    ),
                    Some(false) => (
                        "未匹配",
                        AMBER,
                        "出口 IP 与设置里的住宅代理服务器地址不同。结果只代表该次观测。",
                    ),
                    None => ("未比对", INK, "结果只代表该次观测。"),
                };
                (
                    format!("公网出口 · {checked}"),
                    format!(
                        "{} · {} · {verdict}",
                        exit["ip"].as_str().unwrap_or("—"),
                        exit["country"].as_str().unwrap_or("—"),
                    ),
                    color,
                    tooltip,
                )
            } else {
                (
                    "公网出口".into(),
                    "未检测".into(),
                    MUTED,
                    "接管中点「复核公网出口」检测一次；结果只代表该次观测。",
                )
            };
        div()
            .id("connection-exit")
            .flex()
            .flex_col()
            .gap_1()
            .flex_1()
            .flex_grow(2.)
            .min_w_0()
            .p_3()
            .bg(rgb(SURFACE_SOFT))
            .rounded_md()
            .child(div().text_color(rgb(MUTED)).truncate().child(label))
            .child(
                div()
                    .font_family(MONO_FONT)
                    .text_color(rgb(color))
                    .truncate()
                    .child(value),
            )
            .tooltip(move |window, cx| text_tip(tooltip, window, cx))
    }

    /// 页面上显示的行：进行中的连接（状态有效时）在前，已落盘的记录在后。
    /// 同一条连接既在快照里又已落盘时，以落盘的最终状态为准。
    pub(crate) fn visible_connections(&self) -> Vec<&ConnectionRow> {
        let filter = self.connection_filter;
        let environment = self.connection_environment.as_deref();
        let matches = |row: &&ConnectionRow| {
            filter.matches(row)
                && environment.is_none_or(|environment| row.target.as_deref() == Some(environment))
        };
        let history: &[ConnectionRow] = if filter.history() {
            &self.connection_history.rows
        } else {
            &[]
        };
        let persisted = history
            .iter()
            .map(ConnectionRow::key)
            .collect::<HashSet<_>>();
        let live: &[ConnectionRow] = if self.status_valid {
            &self.live_connections
        } else {
            &[]
        };
        live.iter()
            .filter(|row| matches(row) && !persisted.contains(&row.key()))
            .chain(history.iter().filter(matches))
            .collect()
    }

    fn connection_environment_options(&self) -> Vec<String> {
        let mut names = BTreeSet::new();
        if let Some(environment) = &self.connection_environment {
            names.insert(environment.clone());
        }
        names.extend(
            self.distributions
                .iter()
                .filter_map(|distro| distro["name"].as_str().map(str::to_owned)),
        );
        names.extend(
            self.live_connections
                .iter()
                .filter_map(|row| row.target.clone()),
        );
        names.extend(
            self.connection_history
                .rows
                .iter()
                .filter_map(|row| row.target.clone()),
        );
        names.into_iter().collect()
    }

    pub(crate) fn connection_page(&self, _window: &Window, cx: &Context<Self>) -> Div {
        let locked = self.locked();
        let history = &self.connection_history;
        let filter = self.connection_filter;
        let environment = self.connection_environment.clone();
        let active = self.status_valid.then(|| {
            self.live_connections
                .iter()
                .filter(|row| {
                    row.active()
                        && environment
                            .as_deref()
                            .is_none_or(|environment| row.target.as_deref() == Some(environment))
                })
                .count() as u64
        });
        let shown = |value: Option<u64>| {
            value
                .map(|value| value.to_string())
                .unwrap_or_else(|| "—".into())
        };
        let udp_color = if self.status["startup_verified"]["udp_supported"] == true
            && self.phase() == "forwarding_managed"
        {
            TEAL
        } else if self.idle() {
            MUTED
        } else {
            RUST
        };

        let header = div().flex().items_center().justify_end().gap_3().child(
            ButtonGroup::new("connection-actions")
                .child(
                    self.button(
                        "probe-exit",
                        "复核公网出口",
                        UiAction::Probe,
                        locked || self.phase() != "forwarding_managed",
                        cx,
                    )
                    .tooltip("检测目标发行版实际的公网出口；只有接管中可用，结果只代表该次观测。")
                    .small(),
                )
                .child(
                    self.button("export", "导出脱敏诊断", UiAction::Export, locked, cx)
                        .small(),
                )
                .child(
                    self.button(
                        "reset-dns-aliases",
                        "重置 DNS 别名",
                        UiAction::ResetDnsAliases,
                        locked || self.phase() != "idle",
                        cx,
                    )
                    .tooltip("只在提示 DNS 别名号段已用完时使用；需要先停止接管。")
                    .small(),
                )
                .child(
                    self.button(
                        "reveal",
                        "打开报告位置",
                        UiAction::Reveal,
                        self.export_path.is_none(),
                        cx,
                    )
                    .icon(design_icon("folder", 15., MUTED))
                    .small(),
                ),
        );

        let failed_total = history.failed_total;
        let facts = div()
            .flex()
            .gap_3()
            .child(fact("进行中", shown(active), INK))
            .child(fact("已记录", shown(history.total), INK))
            .child(fact(
                "已记录失败",
                shown(failed_total),
                if failed_total.unwrap_or_default() > 0 {
                    RUST
                } else {
                    INK
                },
            ))
            .child(fact("UDP", self.udp_state_label(), udp_color))
            .child(self.exit_fact());

        let mut banners = Vec::new();
        if let Some(error) = self
            .forwarding()
            .and_then(|forwarding| forwarding["last_error"].as_str())
        {
            banners.push(banner(
                "connection-last-error",
                format!(
                    "最后一次转发错误（后台报告）：{}",
                    backend::humanize_error(error)
                ),
                RUST,
                DANGER_BG,
            ));
        }
        if history.lost > 0 {
            banners.push(banner(
                "connection-history-lost",
                format!(
                    "本次后台运行期间有 {} 条连接没能写入 SQLite（写入跟不上或写入失败），历史里不会有这些记录。",
                    history.lost
                ),
                AMBER,
                WARNING_BG,
            ));
        }
        if let (Some(error), false) = (&history.error, history.rows.is_empty()) {
            banners.push(banner(
                "connection-history-error",
                format!("刷新连接记录失败，下面是上次读到的结果：{error}"),
                AMBER,
                WARNING_BG,
            ));
        }

        let retention = history
            .retention
            .map(|rows| {
                format!(
                    "保留最新 {} 条；记录目的 IP 和端口，不含域名和内容。",
                    grouped(rows)
                )
            })
            .unwrap_or_default();
        let filter_button = |id: &'static str, label: &'static str, value: ConnectionFilter| {
            self.button(id, label, UiAction::ConnectionFilter(value), false, cx)
                .outline()
                .small()
                .selected(filter == value)
        };
        let environment_options = self.connection_environment_options();
        let environment_filter_buttons = environment_options
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                let selected = environment.as_deref() == Some(name.as_str());
                let value = Some(name.clone());
                Button::new(("connection-filter-environment", index))
                    .label(name)
                    .outline()
                    .small()
                    .selected(selected)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.set_connection_environment(value.clone(), cx);
                    }))
            })
            .collect::<Vec<_>>();
        let rows = self.visible_connections();
        let visible = rows.len();
        let load_more = filter.history() && history.has_more;
        let body = if visible == 0 {
            let empty: SharedString = if filter.history()
                && let Some(error) = &history.error
            {
                format!("读取连接记录失败：{error}").into()
            } else if filter.history() && !history.loaded {
                "正在读取连接记录…".into()
            } else {
                match filter {
                    ConnectionFilter::Active if !self.status_valid => {
                        "后台状态未确认，暂不显示进行中的连接。".into()
                    }
                    ConnectionFilter::Active if self.idle() => {
                        "当前未接管，没有进行中的连接。".into()
                    }
                    ConnectionFilter::Active => "当前没有进行中的连接。".into(),
                    ConnectionFilter::Failed => "没有失败的连接记录。".into(),
                    ConnectionFilter::All => "还没有连接记录。连接结束后会保存在这里。".into(),
                }
            };
            div()
                .w_full()
                .flex_1()
                .min_h(px(ROW_HEIGHT * 3.))
                .flex()
                .items_center()
                .justify_center()
                .text_color(rgb(MUTED))
                .child(empty)
                .into_any_element()
        } else {
            let item_sizes = Rc::new(vec![size(px(1.), px(ROW_HEIGHT)); visible]);
            let list = gpui_kit::base::v_virtual_list(
                cx.entity(),
                "connection-list",
                item_sizes,
                |this, range, _, _| {
                    this.visible_connections()
                        .into_iter()
                        .skip(range.start)
                        .take(range.len())
                        .map(connection_row)
                        .collect::<Vec<_>>()
                },
            );
            div()
                .id("connection-viewport")
                .w_full()
                .flex_1()
                .min_h_0()
                .overflow_x_hidden()
                .child(list.track_scroll(&self.connections_scroll).size_full())
                .into_any_element()
        };
        let mut records = div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .p_3()
            .bg(rgb(SURFACE))
            .border_1()
            .border_color(rgb(RULE))
            .rounded_md()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .mb_2()
                    .child(div().flex_shrink_0().child("连接记录"))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_color(rgb(MUTED))
                            .truncate()
                            .child(retention),
                    )
                    .child(filter_button(
                        "connection-filter-all",
                        "全部",
                        ConnectionFilter::All,
                    ))
                    .child(filter_button(
                        "connection-filter-active",
                        "进行中",
                        ConnectionFilter::Active,
                    ))
                    .child(filter_button(
                        "connection-filter-failed",
                        "失败",
                        ConnectionFilter::Failed,
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap_2()
                    .mb_2()
                    .child(div().flex_shrink_0().text_color(rgb(MUTED)).child("环境"))
                    .child(
                        self.button(
                            "connection-filter-environment-all",
                            "全部环境",
                            UiAction::ConnectionEnvironment(None),
                            false,
                            cx,
                        )
                        .outline()
                        .small()
                        .selected(environment.is_none()),
                    )
                    .children(environment_filter_buttons),
            )
            .child(table_header())
            .child(body);
        if load_more {
            records = records.child(
                div().flex().justify_center().pt_2().child(
                    self.button(
                        "connection-load-more",
                        "加载更早",
                        UiAction::ConnectionLoadMore,
                        history.requested.is_some(),
                        cx,
                    )
                    .outline()
                    .small(),
                ),
            );
        }

        div()
            .flex()
            .flex_col()
            .h_full()
            .min_h_0()
            .gap_3()
            .child(header)
            .child(facts)
            .children(banners)
            .child(records)
    }
}

fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

/// 页面上的单行提示条；全文放在 tooltip，避免长错误把表格挤出首屏。
fn banner(id: &'static str, text: String, color: u32, background: u32) -> Stateful<Div> {
    let tooltip: SharedString = text.clone().into();
    div()
        .id(id)
        .flex()
        .items_center()
        .gap_2()
        .p_3()
        .bg(rgb(background))
        .rounded_md()
        .text_color(rgb(color))
        .child(design_icon("info", 16., color))
        .child(div().flex_1().min_w_0().truncate().child(text))
        .tooltip(move |window, cx| text_tip(tooltip.clone(), window, cx))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ago, duration, grouped, route_label, stage_label};
    use crate::app::components::{bytes, rate};
    use crate::app::model::{ConnectionFilter, ConnectionHistory, ConnectionRow};

    #[test]
    fn live_rows_show_active_newest_first_and_recent_only_without_persistence() {
        let mut connections = json!({
            "session": 7,
            "persisted": true,
            "active": [
                {"id": 1, "protocol": "tcp", "status": "active", "stage": "relay", "age_ms": 1200},
                {"id": 2, "protocol": "udp", "status": "active", "stage": "connect"},
            ],
            "recent": [
                {"id": 9, "protocol": "tcp", "status": "failed", "stage": "connect", "failure_stage": "connect"},
            ],
        });
        let rows = ConnectionRow::live_list(&connections, Some("Test-Target"));
        assert_eq!(
            rows.iter().map(|row| row.flow_id).collect::<Vec<_>>(),
            [2, 1]
        );
        assert!(
            rows.iter()
                .all(|row| row.target.as_deref() == Some("Test-Target"))
        );
        assert_eq!(rows[1].key(), (7, 1));
        assert_eq!(rows[1].duration_ms, 1200);
        assert!(rows.iter().all(|row| ConnectionFilter::Active.matches(row)));
        connections["persisted"] = json!(false);
        let rows = ConnectionRow::live_list(&connections, None);
        assert_eq!(
            rows.iter().map(|row| row.flow_id).collect::<Vec<_>>(),
            [2, 1, 9]
        );
        assert!(ConnectionFilter::Failed.matches(&rows[2]));
        assert!(ConnectionRow::live_list(&serde_json::Value::Null, None).is_empty());
    }

    fn page(ids: std::ops::RangeInclusive<i64>, has_more: bool) -> serde_json::Value {
        let records = ids
            .rev()
            .map(|id| {
                json!({
                    "id": id, "session": 5, "flow_id": id as u64, "protocol": "tcp",
                    "status": "completed", "stage": "relay", "duration_ms": 1500,
                    "ended_at": "11-22 14:02:31", "target": "Test-Target",
                })
            })
            .collect::<Vec<_>>();
        let oldest = records.last().and_then(|row| row["id"].as_i64());
        json!({
            "records": records, "total": 99, "failed_total": 3, "has_more": has_more,
            "next_before_id": if has_more { oldest } else { None }, "retention_rows": 50000,
            "queue_dropped": 1, "write_failures": 2,
        })
    }

    fn ids(history: &ConnectionHistory) -> Vec<i64> {
        history
            .rows
            .iter()
            .filter_map(|row| row.record_id)
            .collect()
    }

    #[test]
    fn history_pages_append_and_refreshes_keep_older_rows_only_when_contiguous() {
        let mut history = ConnectionHistory::default();
        history.accept(&page(8..=10, true), false);
        assert_eq!(ids(&history), [10, 9, 8]);
        assert_eq!(
            (history.total, history.failed_total, history.lost),
            (Some(99), Some(3), 3)
        );
        assert_eq!(history.rows[0].ended_at.as_deref(), Some("11-22 14:02:31"));
        assert_eq!(history.before_id, Some(8));
        history.accept(&page(5..=7, true), true);
        assert_eq!(ids(&history), [10, 9, 8, 7, 6, 5]);
        assert_eq!(history.before_id, Some(5));
        // 两次刷新之间新增 2 条：第一页仍含此前最新的 10，已加载的更早记录保留。
        history.accept(&page(10..=12, true), false);
        assert_eq!(ids(&history), [12, 11, 10, 9, 8, 7, 6, 5]);
        assert_eq!(history.before_id, Some(5));
        // 新增太多、第一页与已加载的记录接不上：只留第一页并重置分页。
        history.accept(&page(20..=22, true), false);
        assert_eq!(ids(&history), [22, 21, 20]);
        assert_eq!(history.before_id, Some(20));
        assert!(!history.extended);
        history.requested = Some((ConnectionFilter::All, None, true));
        history.reset();
        assert!(history.rows.is_empty() && !history.loaded);
        assert_eq!(history.total, Some(99));
        assert!(
            history.requested == Some((ConnectionFilter::All, None, true)),
            "an in-flight request stays marked so its reply is discarded"
        );
    }

    #[test]
    fn formats_labels_and_quantities_for_the_page() {
        assert_eq!(route_label(Some("chain")).0, "双跳");
        assert_eq!(route_label(None).0, "待判定");
        assert_eq!(stage_label("metadata"), "获取原始目标");
        assert_eq!(ago(59), "59 秒前");
        assert_eq!(ago(60), "1 分钟前");
        assert_eq!(ago(7200), "2 小时前");
        assert_eq!(duration(1500), "1.5 秒");
        assert_eq!(duration(65_000), "1 分 5 秒");
        assert_eq!(duration(7_380_000), "2 时 3 分");
        assert_eq!(grouped(50_000), "50,000");
        assert_eq!(grouped(999), "999");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
        assert_eq!(rate(&json!(2048.0)), "2.0 KiB/s");
        assert_eq!(rate(&serde_json::Value::Null), "0 B/s");
        assert_eq!(rate(&json!(-5.0)), "0 B/s");
    }
}
