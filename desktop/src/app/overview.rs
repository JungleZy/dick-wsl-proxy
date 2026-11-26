//! 首页：一眼看清有没有在保护、保护的是谁、链路是否正常，以及下一步该做什么。
//!
//! 上方是保护状态卡（状态、唯一的主操作、保护链路），下方左侧是流量和路由判定，
//! 右侧是后台运行日志里的最新事件。后台连接、DNS、转发线程的常驻状态在底部状态栏。

use gpui_kit::component::Disableable as _;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::chart::AreaChart;
use gpui_kit::{prelude::*, *};
use serde_json::Value;

use super::backend::{self, Kind};
use super::components::{StatusTone, Tip, bytes, design_icon, status_dot, text};
use super::drafts::SaveScope;
use super::model::{Page, TrafficSample, UiAction};
use super::state::Desktop;
use super::theme::{
    AMBER, CHART_UP, DANGER_BG, INK, MONO_FONT, MUTED, ROUTE_DIRECT, RULE, RUST, SURFACE,
    SURFACE_SOFT, TEAL, app_rgb as rgb,
};
use super::views::chart_card;

/// 保护链路上的一个节点：标签、值、一句状态，按状态着色，悬停看细节。
struct PathNode {
    id: &'static str,
    label: &'static str,
    value: String,
    detail: String,
    tone: StatusTone,
    tip: Tip,
}

impl Desktop {
    pub(crate) fn overview(&self, cx: &Context<Self>) -> Div {
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.protection_card(cx))
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(self.traffic_card().flex_1().flex_grow(1.6).min_w_0())
                    .child(self.timeline_card().flex_1().min_w_0()),
            )
    }

    /// 首页主卡：一句话状态、唯一的主操作、最近的转发错误和保护链路。
    fn protection_card(&self, cx: &Context<Self>) -> Div {
        let (tone, title, summary) = self.protection_summary();
        let (color, background) = tone.colors();
        let last_error = self
            .forwarding()
            .and_then(|forwarding| forwarding["last_error"].as_str())
            .map(backend::humanize_error);
        div()
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
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .flex_shrink_0()
                            .items_center()
                            .justify_center()
                            .size(px(40.))
                            .rounded_lg()
                            .bg(rgb(background.unwrap_or(SURFACE_SOFT)))
                            .child(design_icon("idle", 22., color)),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .text_color(rgb(if tone == StatusTone::Off {
                                        INK
                                    } else {
                                        color
                                    }))
                                    .child(title),
                            )
                            .child(div().text_color(rgb(MUTED)).truncate().child(summary)),
                    )
                    .child(div().flex_shrink_0().child(self.protection_action(cx))),
            )
            .children(last_error.map(|error| {
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .bg(rgb(DANGER_BG))
                    .text_color(rgb(RUST))
                    .child(design_icon("info", 15., RUST))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .child(format!("最近一次转发错误：{error}")),
                    )
            }))
            .child(self.protection_path())
    }

    /// 目标发行版已不在 WSL 注册表里：正常停止清不掉它的规则，只能放弃本次记录。
    pub(crate) fn target_gone(&self) -> bool {
        self.phase() == "recovery_required" && self.status["target_registered"] == false
    }

    /// 状态色、一句话状态和一句说明。
    fn protection_summary(&self) -> (StatusTone, &'static str, String) {
        if !self.status_valid {
            let since = match self.status_at {
                Some(at) => format!("上次收到状态是 {}", ago(at.elapsed().as_secs())),
                None => "还没有收到后台状态".to_owned(),
            };
            // 状态无效不一定是连不上：后台返回的状态缺字段、操作后读状态失败也会这样，
            // 所以只说「未确认」，原因看页面顶部的错误条。
            return (
                StatusTone::Error,
                "后台状态未确认",
                format!("无法确认接管状态；{since}。"),
            );
        }
        let target = self.status_target().unwrap_or("目标发行版").to_owned();
        let generation = self
            .generation()
            .map(|generation| format!(" · 代次 {generation}"))
            .unwrap_or_default();
        match self.phase() {
            "forwarding_managed" => (
                StatusTone::Ok,
                "接管中",
                format!("{target} 的 TCP 和系统 DNS 正经双跳代理出网{generation}"),
            ),
            "forwarding_scoped" => (
                StatusTone::Warn,
                "诊断转发中",
                format!("{target} 处于诊断转发，系统 DNS 没有接管{generation}"),
            ),
            "recovery_required" if self.target_gone() => (
                StatusTone::Error,
                "需要恢复",
                "目标发行版已不在 WSL 注册表里，只能放弃本次接管记录。".to_owned(),
            ),
            "recovery_required" => (
                StatusTone::Error,
                "需要恢复",
                recovery_reason(self.status["issue"].as_str().unwrap_or(""), &target),
            ),
            "idle" => (StatusTone::Off, "未接管", self.idle_hint()),
            _ => (
                StatusTone::Warn,
                "状态未确认",
                "后台返回了未知的阶段，请刷新后再操作。".to_owned(),
            ),
        }
    }

    /// 后台状态里的接管目标。需要恢复时 `active_target` 可能为空（例如客机检查没通过），
    /// 真正要恢复的发行版记在 `recorded_target`，它可能不是界面上选中的那个。
    fn status_target(&self) -> Option<&str> {
        self.status["active_target"].as_str().or_else(|| {
            (self.phase() == "recovery_required")
                .then(|| self.status["recorded_target"].as_str())
                .flatten()
        })
    }

    /// 空闲时告诉用户离启动还差什么，顺序和启动前的检查一致。
    fn idle_hint(&self) -> String {
        match &self.selected {
            None => "还没有设定目标 WSL：到「环境」页把要保护的发行版设为目标。".to_owned(),
            Some(_) if self.unsaved_message().is_some() => match self.unsaved.pages() {
                Some(pages) => format!("{pages}有未保存的修改，在该页保存后才能启动接管。"),
                None => "配置还没有保存过，到「环境」页设定接管目标后才能启动接管。".to_owned(),
            },
            Some(target) => format!(
                "将接管 {}；启动前会自动预检，通过后再请你确认。",
                self.environment_display_name(target)
            ),
        }
    }

    /// 唯一的主操作，跟着状态走：先连上后台，再选目标、保存，最后启动或停止。
    /// 托盘菜单的主操作（[`Self::tray_snapshot`]）照同样的顺序选。
    fn protection_action(&self, cx: &Context<Self>) -> Button {
        let locked = self.locked();
        if !self.status_valid {
            return Button::new("overview-reconnect")
                .label("重新连接")
                .icon(design_icon("refresh", 15., SURFACE))
                .primary()
                .disabled(locked)
                .on_click(cx.listener(|this, _, _, cx| this.refresh_or_reconnect(cx)));
        }
        if self.target_gone() {
            return self
                .button(
                    "overview-session-action",
                    "放弃本次记录",
                    UiAction::Prepare(Kind::Abandon),
                    locked,
                    cx,
                )
                .icon(design_icon("close", 15., SURFACE))
                .primary();
        }
        if self.phase() != "idle" {
            return self
                .button(
                    "overview-session-action",
                    "停止接管",
                    UiAction::Prepare(Kind::Stop),
                    locked,
                    cx,
                )
                .icon(design_icon("close", 15., SURFACE))
                .primary();
        }
        if self.selected.is_none() {
            return Button::new("overview-choose-target")
                .label("去选择目标")
                .icon(design_icon("environment", 15., SURFACE))
                .primary()
                .on_click(cx.listener(|this, _, _, cx| this.open_page(Page::Environment, cx)));
        }
        // 首页不保存任何内容：带用户去有未保存修改的那一页，在那里看清改了什么再保存。
        if self.unsaved_message().is_some() {
            let page = self.unsaved_page();
            return Button::new("overview-go-save")
                .label("去保存修改")
                .icon(design_icon("save", 15., SURFACE))
                .primary()
                .on_click(cx.listener(move |this, _, _, cx| this.open_page(page, cx)));
        }
        self.button(
            "overview-session-action",
            "启动接管",
            UiAction::Prepare(Kind::Start),
            locked,
            cx,
        )
        .icon(design_icon("play", 15., SURFACE))
        .primary()
    }

    /// 有未保存修改的那一页；规则页、设置页都没有时是环境页（配置还没保存过）。
    pub(crate) fn unsaved_page(&self) -> Page {
        match self.unsaved.first() {
            Some(SaveScope::Settings) => Page::Settings,
            Some(SaveScope::Policy) => Page::Policy,
            Some(SaveScope::Environment) | None => Page::Environment,
        }
    }

    /// 托盘要显示的状态和菜单里的主操作。主操作和 [`Self::protection_action`] 的选择一致，
    /// 改其中一个时两边一起改。
    pub(crate) fn tray_snapshot(&self) -> super::tray::Snapshot {
        use super::tray::{Look, Primary, Snapshot};
        let look = Look::from_status(self.status_valid, self.phase());
        let primary = if !self.status_valid {
            Primary::Reconnect
        } else if self.target_gone() {
            Primary::Abandon
        } else if self.phase() != "idle" {
            Primary::Stop
        } else if self.selected.is_none() {
            Primary::ChooseTarget
        } else if self.unsaved_message().is_some() {
            Primary::GoSave
        } else {
            Primary::Start
        };
        // 只在后台确认有接管记录时写目标名；状态没确认时那份状态已经过时。
        let target = matches!(look, Look::Managed | Look::Scoped | Look::Recovery)
            .then(|| self.status_target())
            .flatten()
            .map(str::to_owned);
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
        }
    }

    /// 接管中交给状态岛的环境信息：公网出口、DNS、UDP、连接数，说法和首页一致。
    /// 只在后台确认正在接管时给；其余情况岛不显示这些。
    pub(crate) fn island_details(&self) -> Option<super::island::Details> {
        if !self.status_valid || self.phase() != "forwarding_managed" {
            return None;
        }
        let exit = &self.status["recent_exit"];
        let text = |value: &Value| value.as_str().map(str::to_owned);
        Some(super::island::Details {
            exit_ip: text(&exit["ip"]),
            exit_country: text(&exit["country"]),
            exit_matches: exit["matches_residential"].as_bool(),
            dns_managed: self.status["dns_managed"] == true,
            dns_latency_ms: self.status["startup_verified"]["dns_latency_ms"].as_f64(),
            udp: self.udp_state_label(),
            active_tcp: self.status["forwarding"]["active_tcp"].as_u64(),
        })
    }

    /// 保护链路：目标 WSL → Windows 入口 → 宿主 SOCKS5 → 住宅出口，竖线后是系统 DNS。
    fn protection_path(&self) -> Div {
        let nodes = self.path_nodes();
        let last = nodes.len() - 1;
        let mut row = div().flex().gap_2();
        for (index, node) in nodes.into_iter().enumerate() {
            if index == last {
                row = row.child(div().flex_shrink_0().w(px(1.)).mx_1().bg(rgb(RULE)));
            } else if index > 0 {
                row = row.child(
                    div()
                        .flex()
                        .flex_shrink_0()
                        .items_center()
                        .text_color(rgb(MUTED))
                        .child("→"),
                );
            }
            row = row.child(path_node(node));
        }
        row
    }

    /// 接管中各节点按实际状态着色，值取正在运行的配置；没在转发时显示已保存的配置，
    /// 节点为未启用。需要恢复时转发观测可能还在，但链路不算正常，不能显示成绿色。
    fn path_nodes(&self) -> Vec<PathNode> {
        let valid = self.status_valid;
        let phase = self.phase();
        let forwarding = self.forwarding().is_some();
        let managed = valid && phase == "forwarding_managed";
        let healthy = forwarding && matches!(phase, "forwarding_managed" | "forwarding_scoped");
        let live = |in_use: bool| {
            if !in_use {
                StatusTone::Off
            } else if healthy {
                StatusTone::Ok
            } else {
                StatusTone::Warn
            }
        };
        // 接管中后台用的是启动时的策略（`active_policy`）；之后保存的新值要下次启动才生效。
        let active_policy = &self.status["active_policy"];
        let running_policy = forwarding && active_policy.is_object();
        let config = |key: &str| {
            let saved = text(&self.profile, key, "");
            if running_policy {
                let running = text(active_policy, key, "");
                let pending = (!saved.is_empty() && saved != running).then_some(saved);
                (running, pending)
            } else {
                (saved, None)
            }
        };

        let running = valid.then(|| self.status_target()).flatten();
        let planned = self
            .selected
            .as_deref()
            .map(|id| self.environment_display_name(id));
        let (target_value, target_detail, target_tone) = match (running, &planned) {
            (Some(name), _) if healthy => (name.to_owned(), "接管中", StatusTone::Ok),
            (Some(name), _) => (name.to_owned(), "需要恢复", StatusTone::Error),
            (None, Some(name)) => (name.clone(), "已设为目标", StatusTone::Off),
            (None, None) => (
                "未设定".to_owned(),
                "到「环境」页设为目标",
                StatusTone::Warn,
            ),
        };
        let target_tip = Tip::new("目标 WSL")
            .row("接管中", running.unwrap_or("—"))
            .row("已选择", planned.clone().unwrap_or_else(|| "未设定".into()))
            .note("接管只作用于这一个发行版");

        let ingress = valid.then(|| self.status["ingress"].as_str()).flatten();
        let (ingress_value, ingress_detail, ingress_tone) = if forwarding {
            (ingress.unwrap_or("—").to_owned(), "监听中", live(true))
        } else if valid && self.status["port_reserved"] == true {
            (
                ingress.unwrap_or("—").to_owned(),
                "端口仍保留",
                StatusTone::Warn,
            )
        } else if valid {
            (
                format!("端口 {}", self.saved_port),
                "未监听",
                StatusTone::Off,
            )
        } else {
            // 状态未确认时可能仍在转发，不能说「未监听」。
            (
                format!("端口 {}", self.saved_port),
                "状态未知",
                StatusTone::Off,
            )
        };
        let ingress_tip = Tip::new("Windows 入口")
            .row("地址", ingress_value.clone())
            .note("目标发行版的流量从这里进入代理")
            .note_if(!forwarding, "启动接管后才会监听");

        let (first_hop, hop_pending) = config("first_hop");
        let (hop_value, hop_detail, hop_tone) = if first_hop.is_empty() {
            ("未配置".to_owned(), "第一跳", StatusTone::Warn)
        } else if hop_pending.is_some() {
            (first_hop, "新值下次启动生效", live(forwarding))
        } else {
            (first_hop, "第一跳", live(forwarding))
        };
        let hop_tip = Tip::new("宿主 SOCKS5")
            .row(
                if running_policy {
                    "运行中"
                } else {
                    "地址"
                },
                hop_value.clone(),
            )
            .row_some("已保存", hop_pending)
            .note("双跳代理的第一跳，在「设置」页修改")
            .note_if(running_policy, "接管中改的设置要下次启动接管才生效");

        // 后台解析住宅地址前会去掉首尾空格，库里存的是原样输入。
        let residential_ip = text(&self.residential, "ip", "").trim().to_owned();
        let residential_port = Self::profile_field_value(&self.residential, "port", false);
        let saved_residential = if residential_ip.is_empty() || residential_port.is_empty() {
            residential_ip
        } else {
            format!("{residential_ip}:{residential_port}")
        };
        // 出口核对比的是运行中的住宅地址，所以接管中显示它；之后保存的新地址下次启动才生效。
        let running_residential = running_policy
            .then(|| active_policy["residential"].as_str())
            .flatten();
        let (residential, residential_pending) =
            residential_address(saved_residential, running_residential);
        let exit = &self.status["recent_exit"];
        let exit_verdict =
            (valid && exit.is_object()).then(|| exit["matches_residential"].as_bool());
        let udp = self.udp_state_label();
        let (exit_value, exit_detail, exit_tone) = if residential.is_empty() {
            ("未配置".to_owned(), "第二跳".to_owned(), StatusTone::Warn)
        } else {
            let value = residential;
            // UDP 已阻断是本次接管的已知限制（不会直连），但不是正常状态：
            // 用待处理色，并且复核过出口后也照样显示，不只留在悬停提示里。
            let udp_blocked = managed && self.status["startup_verified"]["udp_supported"] == false;
            match exit_verdict {
                Some(Some(false)) => (value, "出口与住宅地址不一致".to_owned(), StatusTone::Warn),
                Some(Some(true)) if udp_blocked => (
                    value,
                    "出口已核对 · UDP 已阻断".to_owned(),
                    StatusTone::Warn,
                ),
                _ if udp_blocked => (value, "UDP 已阻断".to_owned(), StatusTone::Warn),
                _ if residential_pending.is_some() => {
                    (value, "新值下次启动生效".to_owned(), live(forwarding))
                }
                Some(Some(true)) => (value, "出口已核对".to_owned(), live(forwarding)),
                _ if managed => (value, format!("UDP {udp}"), live(forwarding)),
                _ => (value, "第二跳".to_owned(), live(forwarding)),
            }
        };
        let exit_summary = match exit_verdict {
            Some(verdict) => format!(
                "{} · {} · {}",
                exit["ip"].as_str().unwrap_or("—"),
                exit["country"].as_str().unwrap_or("—"),
                match verdict {
                    Some(true) => "与住宅地址一致",
                    Some(false) => "与住宅地址不一致",
                    None => "未比对",
                }
            ),
            None => "未检测".to_owned(),
        };
        let exit_tip = Tip::new("住宅出口")
            .row(
                if running_residential.is_some() {
                    "运行中"
                } else {
                    "地址"
                },
                exit_value.clone(),
            )
            .row_some("已保存", residential_pending)
            .row("公网出口", exit_summary)
            .row("UDP", udp)
            .note("双跳代理的第二跳，流量最终从这里出网")
            .note("接管中可以在「连接」页复核公网出口")
            .note_if(
                running_residential.is_some(),
                "接管中改的设置要下次启动接管才生效",
            );

        let (dns_host, dns_host_pending) = config("dns_tls_name");
        let (dns_upstream, dns_upstream_pending) = config("dns_upstream");
        let latency = self.status["startup_verified"]["dns_latency_ms"]
            .as_f64()
            .filter(|_| valid);
        let (dns_detail, dns_tone) = if !valid {
            ("状态未知".to_owned(), StatusTone::Warn)
        } else if self.status["dns_managed"] == true {
            (
                latency
                    .map(|ms| format!("已接管 · {ms:.0} ms"))
                    .unwrap_or_else(|| "已接管".into()),
                StatusTone::Ok,
            )
        } else if self.idle() {
            ("未接管".to_owned(), StatusTone::Off)
        } else if self.phase() == "recovery_required" {
            ("需要恢复".to_owned(), StatusTone::Error)
        } else {
            ("未确认".to_owned(), StatusTone::Warn)
        };
        let history = self
            .dns_history
            .iter()
            .rev()
            .take(5)
            .map(|ms| format!("{ms:.0}"))
            .collect::<Vec<_>>();
        let dns_tip = Tip::new("系统 DNS")
            .row(
                "DoH 主机",
                if dns_host.is_empty() {
                    "未配置".to_owned()
                } else {
                    dns_host.clone()
                },
            )
            .row_some("已保存的主机", dns_host_pending)
            .row(
                "DoH 上游",
                if dns_upstream.is_empty() {
                    "未配置".to_owned()
                } else {
                    dns_upstream
                },
            )
            .row_some("已保存的上游", dns_upstream_pending)
            .row(
                "最近几次启动",
                if history.is_empty() {
                    "—".to_owned()
                } else {
                    format!("{} ms", history.join(" / "))
                },
            )
            .note("接管时，目标发行版的系统 DNS 经 DoH 解析")
            .note("延迟在每次启动接管时测一次")
            .note_if(running_policy, "接管中显示的是正在运行的配置");

        vec![
            PathNode {
                id: "path-target",
                label: "目标 WSL",
                value: target_value,
                detail: target_detail.to_owned(),
                tone: target_tone,
                tip: target_tip,
            },
            PathNode {
                id: "path-ingress",
                label: "Windows 入口",
                value: ingress_value,
                detail: ingress_detail.to_owned(),
                tone: ingress_tone,
                tip: ingress_tip,
            },
            PathNode {
                id: "path-first-hop",
                label: "宿主 SOCKS5",
                value: hop_value,
                detail: hop_detail.to_owned(),
                tone: hop_tone,
                tip: hop_tip,
            },
            PathNode {
                id: "path-exit",
                label: "住宅出口",
                value: exit_value,
                detail: exit_detail,
                tone: exit_tone,
                tip: exit_tip,
            },
            PathNode {
                id: "path-dns",
                label: "系统 DNS",
                value: if dns_host.is_empty() {
                    "未配置".to_owned()
                } else {
                    dns_host
                },
                detail: dns_detail,
                tone: dns_tone,
                tip: dns_tip,
            },
        ]
    }

    /// 流量卡：速率曲线和本次接管的路由判定占比。没在转发时只显示一句空态。
    fn traffic_card(&self) -> Div {
        const TITLE: &str = "流量";
        const CAPTION: &str = "上行 / 下行速率，约 2 秒采样一次";
        if !self.status_valid {
            return chart_card(TITLE, CAPTION, empty_note("后台状态未确认，暂停采样。"));
        }
        let Some(forwarding) = self.forwarding() else {
            return chart_card(
                TITLE,
                CAPTION,
                empty_note("当前未接管，没有流量。启动接管后开始采样。"),
            );
        };
        let active = self
            .live_connections
            .iter()
            .filter(|row| row.active())
            .count();
        let per_second = |value: f64| format!("{}/s", bytes(value.max(0.) as u64));
        let summary = match self.traffic_history.first() {
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
        };
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
        let chart = if data.is_empty() {
            empty_note("等待第一个采样。")
        } else {
            div().h(px(132.)).child(
                AreaChart::new(data)
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
                    .tooltip_value(move |_, _, value| per_second(value).into()),
            )
        };
        chart_card(
            TITLE,
            CAPTION,
            div()
                .flex()
                .flex_col()
                .gap_2()
                .child(div().font_family(MONO_FONT).truncate().child(summary))
                .child(chart)
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
                .child(route_section(forwarding)),
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
        let mut list = div().flex().flex_col().gap_2();
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

/// 保护链路上的一个节点。
fn path_node(node: PathNode) -> Stateful<Div> {
    let (color, _) = node.tone.colors();
    let tip = node.tip;
    div()
        .id(node.id)
        .flex()
        .flex_col()
        .gap_1()
        .flex_1()
        .min_w_0()
        .p_2()
        .rounded_md()
        .bg(rgb(SURFACE_SOFT))
        .child(
            div()
                .flex()
                .items_center()
                .gap_1()
                .child(status_dot(color))
                .child(div().text_color(rgb(MUTED)).truncate().child(node.label)),
        )
        .child(div().font_family(MONO_FONT).truncate().child(node.value))
        .child(
            div()
                .text_color(rgb(if node.tone == StatusTone::Off {
                    MUTED
                } else {
                    color
                }))
                .truncate()
                .child(node.detail),
        )
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
/// 需要恢复的原因。接管中规则失效（目标或 WSL 重启、规则缺失、环境变了）和上次接管
/// 没有正常结束不是一回事：前者说明此刻目标的新连接可能已不经代理。
/// 措辞和后台运行日志（`protection_lost_message`）一致。
fn recovery_reason(issue: &str, target: &str) -> String {
    if issue.starts_with("managed_install_unverified:container_networks_unavailable") {
        return format!(
            "{target}：读不出目标里 Docker 的网络，目标本机的流量已阻断，但目标的容器没有被拦住，可能直连。请停止接管并恢复直连，确认 Docker 正常后再启动。"
        );
    }
    let Some(lost) = issue.strip_prefix("protection_lost: ") else {
        return format!("{target} 的上次接管没有正常结束，请停止接管并恢复直连。");
    };
    let cause = match lost.split(':').next().unwrap_or("") {
        "restarted" => "目标发行版或 WSL 重启过，本次接管的规则已不再生效",
        "rules_incomplete" | "rules_missing" => "目标里本次接管的规则已缺失或不完整",
        "environment_changed" => "目标的环境变了，无法再确认本次接管覆盖它的全部流量",
        _ => "无法再确认本次接管仍然有效",
    };
    format!("{target}：{cause}，新连接可能已不经代理。请停止接管并恢复直连，再重新启动接管。")
}

fn event_time(occurred_at: &str) -> &str {
    occurred_at
        .get(5..)
        .filter(|_| occurred_at.len() == 19)
        .unwrap_or(occurred_at)
}

/// 距今多久，用于状态快照。
fn ago(seconds: u64) -> String {
    match seconds {
        0..3 => "刚刚".to_owned(),
        3..60 => format!("{seconds} 秒前"),
        60..3600 => format!("{} 分钟前", seconds / 60),
        _ => format!("{} 小时前", seconds / 3600),
    }
}

/// 住宅节点显示的地址和待生效的新值。接管中是运行中的地址（出口核对比的就是它），
/// 已保存的不同就是下次启动才生效的新值；没在接管时就是已保存的地址。
fn residential_address(saved: String, running: Option<&str>) -> (String, Option<String>) {
    match running.filter(|running| !running.is_empty()) {
        Some(running) if running != saved => {
            let pending = if saved.is_empty() {
                "未配置".to_owned()
            } else {
                saved
            };
            (running.to_owned(), Some(pending))
        }
        Some(running) => (running.to_owned(), None),
        None => (saved, None),
    }
}

#[cfg(test)]
mod tests {
    use super::{ago, event_time, recovery_reason, residential_address};

    #[test]
    fn a_takeover_shows_the_residential_address_it_runs_with() {
        // 接管中改了住宅地址：显示运行中的旧地址，新地址作为下次启动生效的值。
        assert_eq!(
            residential_address("203.0.113.7:1080".into(), Some("198.51.100.9:1080")),
            (
                "198.51.100.9:1080".to_owned(),
                Some("203.0.113.7:1080".to_owned())
            )
        );
        assert_eq!(
            residential_address("198.51.100.9:1080".into(), Some("198.51.100.9:1080")),
            ("198.51.100.9:1080".to_owned(), None)
        );
        // 接管中清空了住宅设置：本次接管仍用原地址。
        assert_eq!(
            residential_address(String::new(), Some("198.51.100.9:1080")),
            ("198.51.100.9:1080".to_owned(), Some("未配置".to_owned()))
        );
        // 没在接管，或后台没报运行中的地址：显示已保存的。
        assert_eq!(
            residential_address("203.0.113.7:1080".into(), None),
            ("203.0.113.7:1080".to_owned(), None)
        );
        assert_eq!(
            residential_address("203.0.113.7:1080".into(), Some("")),
            ("203.0.113.7:1080".to_owned(), None)
        );
    }

    #[test]
    fn tells_a_lost_takeover_from_one_that_did_not_end_cleanly() {
        assert_eq!(
            recovery_reason(
                "protection_lost: restarted: the target or the WSL VM restarted; this takeover's rules no longer apply",
                "Dev"
            ),
            "Dev：目标发行版或 WSL 重启过，本次接管的规则已不再生效，新连接可能已不经代理。请停止接管并恢复直连，再重新启动接管。"
        );
        assert!(
            recovery_reason("protection_lost: mapping_integrity: x: y", "Dev")
                .starts_with("Dev：无法再确认本次接管仍然有效，")
        );
        assert_eq!(
            recovery_reason("", "Dev"),
            "Dev 的上次接管没有正常结束，请停止接管并恢复直连。"
        );
        assert_eq!(
            recovery_reason("managed_readiness_failed: dns", "Dev"),
            "Dev 的上次接管没有正常结束，请停止接管并恢复直连。"
        );
        assert!(
            recovery_reason(
                "managed_install_unverified:container_networks_unavailable:install:docker_networks_unavailable; ingress_stop:None",
                "Dev"
            )
            .starts_with("Dev：读不出目标里 Docker 的网络，目标本机的流量已阻断，但目标的容器没有被拦住，可能直连。")
        );
    }

    #[test]
    fn formats_event_times_and_snapshot_ages() {
        assert_eq!(event_time("2026-11-23 21:16:13"), "11-23 21:16:13");
        assert_eq!(event_time("21:16"), "21:16");
        assert_eq!(event_time(""), "");
        assert_eq!(ago(2), "刚刚");
        assert_eq!(ago(42), "42 秒前");
        assert_eq!(ago(125), "2 分钟前");
        assert_eq!(ago(7_200), "2 小时前");
    }
}
