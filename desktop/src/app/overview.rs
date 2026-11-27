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
    /// 同时有多个环境在接管或需要恢复时，主卡下面逐个列出，每个带自己的按钮（决策 40）。
    fn protection_card(&self, cx: &Context<Self>) -> Div {
        let (tone, title, summary) = self.protection_summary();
        let (color, background) = tone.colors();
        let owned = self.owned_sessions();
        let several = owned.len() > 1;
        // 多个时转发错误跟着各自那一行显示，不在这里只挑一个。
        let last_error = self
            .forwarding()
            .filter(|_| !several)
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
            .children(several.then(|| self.session_list(&owned, cx)))
            .child(self.protection_path())
    }

    /// 接管中或需要恢复的各环境，一行一个：名字、阶段、入口地址、需要恢复的原因、
    /// 最近一次转发错误，右侧是只作用于这个环境的按钮。
    fn session_list(&self, owned: &[&Value], cx: &Context<Self>) -> Div {
        let locked = self.locked();
        let mut list = div().flex().flex_col().gap_2();
        for (index, session) in owned.iter().enumerate() {
            let (label, tone) = session_phase(session);
            let (color, _) = tone.colors();
            let reason = session_reason(session);
            let last_error = session["forwarding"]["last_error"]
                .as_str()
                .map(backend::humanize_error);
            let action = session["scope"].as_str().map(|scope| {
                let (label, kind) = session_action(session);
                self.button(
                    "overview-session-action",
                    label,
                    UiAction::PrepareFor(kind, scope.to_owned()),
                    locked,
                    cx,
                )
            });
            list = list.child(
                div()
                    .id(("overview-session", index))
                    .flex()
                    .items_center()
                    .gap_3()
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .bg(rgb(SURFACE_SOFT))
                    .child(div().flex_shrink_0().child(status_dot(color)))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .min_w_0()
                                    .child(
                                        div()
                                            .text_color(rgb(INK))
                                            .truncate()
                                            .child(Self::session_name(session)),
                                    )
                                    .child(
                                        div().flex_shrink_0().text_color(rgb(color)).child(label),
                                    )
                                    .child(
                                        div()
                                            .flex_shrink_0()
                                            .font_family(MONO_FONT)
                                            .text_color(rgb(MUTED))
                                            .child(
                                                session["ingress"]
                                                    .as_str()
                                                    .unwrap_or("—")
                                                    .to_owned(),
                                            ),
                                    ),
                            )
                            // 原因是完整的一句话，换行显示，不截成半句。
                            .children(
                                reason.map(|reason| div().text_color(rgb(RUST)).child(reason)),
                            )
                            .children(last_error.map(|error| {
                                div()
                                    .text_color(rgb(RUST))
                                    .child(format!("最近一次转发错误：{error}"))
                            })),
                    )
                    .children(action.map(|action| div().flex_shrink_0().child(action))),
            );
        }
        list
    }

    /// 目标发行版已不在 WSL 注册表里：正常停止清不掉它的规则，只能放弃本次记录。
    pub(crate) fn target_gone(&self) -> bool {
        self.gone_scope().is_some()
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
        let owned = self.owned_sessions();
        if owned.len() > 1 {
            return several_summary(&owned);
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
                recovery_reason(
                    self.status["issue"].as_str().unwrap_or(""),
                    block_state(&self.status["protection_check"]["fallback_block"]),
                    &target,
                ),
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

    /// 空闲时告诉用户怎么开始：接管在各环境的页面上启动（决策 40）。
    fn idle_hint(&self) -> String {
        if let Some(pages) = self.unsaved.pages() {
            return format!("{pages}有未保存的修改，保存后才会生效。");
        }
        let configured = self
            .environments
            .iter()
            .filter(|row| super::drafts::residential_configured(Some(row)))
            .count();
        if configured == 0 {
            "还没有环境配好住宅代理：到「环境」页选一个发行版，填写它的住宅代理后启动接管。"
                .to_owned()
        } else {
            format!(
                "{configured} 个环境已配好住宅代理；到「环境」页启动接管，多个环境可以同时接管。"
            )
        }
    }

    /// 唯一的主操作，跟着状态走：先连上后台；有多个环境在接管时停止全部，只有一个时
    /// 只作用于那一个，空闲时带用户去环境页启动。
    /// 托盘菜单的主操作（[`Self::tray_snapshot`]）照同样的顺序选。
    fn protection_action(&self, cx: &Context<Self>) -> Button {
        let locked = self.locked();
        let owned = self.owned_sessions();
        match primary_action(self.status_valid, &owned) {
            Primary::Reconnect => Button::new("overview-reconnect")
                .label("重新连接")
                .icon(design_icon("refresh", 15., SURFACE))
                .primary()
                .disabled(locked)
                .on_click(cx.listener(|this, _, _, cx| this.refresh_or_reconnect(cx))),
            Primary::StopAll => self
                .button(
                    "overview-stop-all",
                    "停止全部接管",
                    UiAction::StopAll,
                    locked,
                    cx,
                )
                .icon(design_icon("close", 15., SURFACE))
                .primary(),
            Primary::One { label, kind, scope } => self
                .button(
                    "overview-session-action",
                    label,
                    match scope {
                        Some(scope) => UiAction::PrepareFor(kind, scope),
                        None => UiAction::Prepare(kind),
                    },
                    locked,
                    cx,
                )
                .icon(design_icon("close", 15., SURFACE))
                .primary(),
            // 首页不启动接管：启动在各环境的页面上，带用户过去。
            Primary::Environments => Button::new("overview-environments")
                .label("去环境页")
                .icon(design_icon("environment", 15., SURFACE))
                .primary()
                .on_click(cx.listener(|this, _, _, cx| this.open_page(Page::Environment, cx))),
        }
    }

    /// 托盘要显示的状态和菜单里的主操作。主操作和 [`Self::protection_action`] 的选择一致，
    /// 改其中一个时两边一起改。
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
    ///
    /// 有多个环境在接管时，`self.status` 只是挑出来的一个：目标、入口、住宅出口、
    /// 系统 DNS 改为汇总，颜色取最差的那个，各环境的值放进悬停提示。
    fn path_nodes(&self) -> Vec<PathNode> {
        let valid = self.status_valid;
        let phase = self.phase();
        let owned = self.owned_sessions();
        let several = owned.len() > 1;
        let forwarding = self.forwarding().is_some();
        let managed = valid && phase == "forwarding_managed";
        let healthy = if several {
            owned.iter().all(|session| session_forwarding(session))
        } else {
            forwarding && matches!(phase, "forwarding_managed" | "forwarding_scoped")
        };
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
        let (target_value, target_detail, target_tone) = match running {
            _ if several => several_target(&owned),
            Some(name) if healthy => (name.to_owned(), "接管中".to_owned(), StatusTone::Ok),
            Some(name) => (name.to_owned(), "需要恢复".to_owned(), StatusTone::Error),
            None => (
                "未接管".to_owned(),
                "在「环境」页启动".to_owned(),
                StatusTone::Off,
            ),
        };
        let target_tip = if several {
            owned.iter().fold(Tip::new("目标 WSL"), |tip, session| {
                tip.row(Self::session_name(session), session_phase(session).0)
            })
        } else {
            Tip::new("目标 WSL").row("接管中", running.unwrap_or("—"))
        }
        .note("接管在各环境的页面上启动和停止")
        .note("多个环境可以同时接管，互不影响");

        let ingress = valid.then(|| self.status["ingress"].as_str()).flatten();
        let (ingress_value, ingress_detail, ingress_tone) = if several {
            let listening = owned
                .iter()
                .filter(|session| session_forwarding(session))
                .count();
            let detail = if listening == owned.len() {
                "各自监听中".to_owned()
            } else {
                format!("{listening}/{} 个监听中", owned.len())
            };
            ("各环境不同".to_owned(), detail, live(true))
        } else if forwarding {
            (
                ingress.unwrap_or("—").to_owned(),
                "监听中".to_owned(),
                live(true),
            )
        } else if valid && self.status["port_reserved"] == true {
            (
                ingress.unwrap_or("—").to_owned(),
                "端口仍保留".to_owned(),
                StatusTone::Warn,
            )
        } else if valid {
            ("—".to_owned(), "未监听".to_owned(), StatusTone::Off)
        } else {
            // 状态未确认时可能仍在转发，不能说「未监听」。
            ("—".to_owned(), "状态未知".to_owned(), StatusTone::Off)
        };
        let ingress_tip = if several {
            owned.iter().fold(Tip::new("Windows 入口"), |tip, session| {
                tip.row(
                    Self::session_name(session),
                    session["ingress"].as_str().unwrap_or("—").to_owned(),
                )
            })
        } else {
            Tip::new("Windows 入口").row("地址", ingress_value.clone())
        }
        .note("目标发行版的流量从这里进入代理")
        .note("每个环境有自己的端口，在「环境」页查看和修改")
        .note_if(!forwarding && !several, "启动接管后才会监听");

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

        // 只有一个环境在接管（或需要恢复）时显示它的住宅代理；多个时各环境不同，
        // 汇总在下面，各自的值在悬停提示里。各环境保存的值在「环境」页看。
        // 后台解析住宅地址前会去掉首尾空格，库里存的是原样输入。
        let active_residential = self
            .active_distro_id()
            .and_then(|id| super::drafts::environment_row(&self.environments, &id))
            .map(|row| row["residential"].clone())
            .unwrap_or(Value::Null);
        let residential_ip = text(&active_residential, "ip", "").trim().to_owned();
        let residential_port = Self::profile_field_value(&active_residential, "port", false);
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
        let (exit_value, exit_detail, exit_tone) = if residential.is_empty() && self.idle() {
            (
                "按环境配置".to_owned(),
                "第二跳".to_owned(),
                StatusTone::Off,
            )
        } else if residential.is_empty() {
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
            .note("每个环境有自己的住宅代理，在「环境」页修改")
            .note("接管中可以在「连接」页复核公网出口")
            .note_if(
                running_residential.is_some(),
                "接管中改的设置要下次启动接管才生效",
            );
        // 公网出口和 UDP 是每个环境各自的，不能拿挑出来的那一个代表全部。
        let (exit_value, exit_detail, exit_tone, exit_tip) = if several {
            let (value, detail, tone) = several_exit(&owned);
            let tip = owned
                .iter()
                .fold(Tip::new("住宅出口"), |tip, session| {
                    tip.row(Self::session_name(session), session_exit(session))
                })
                .note("双跳代理的第二跳，流量最终从这里出网")
                .note("每个环境有自己的住宅代理，在「环境」页修改")
                .note("接管中可以在「连接」页复核公网出口");
            (value, detail, tone, tip)
        } else {
            (exit_value, exit_detail, exit_tone, exit_tip)
        };

        let (dns_host, dns_host_pending) = config("dns_tls_name");
        let (dns_upstream, dns_upstream_pending) = config("dns_upstream");
        let latency = self.status["startup_verified"]["dns_latency_ms"]
            .as_f64()
            .filter(|_| valid);
        let (dns_detail, dns_tone) = if !valid {
            ("状态未知".to_owned(), StatusTone::Warn)
        } else if several {
            several_dns(&owned)
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
        let dns_tip = owned
            .iter()
            .filter(|_| several)
            .fold(Tip::new("系统 DNS"), |tip, session| {
                tip.row(Self::session_name(session), session_dns(session))
            })
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
                detail: target_detail,
                tone: target_tone,
                tip: target_tip,
            },
            PathNode {
                id: "path-ingress",
                label: "Windows 入口",
                value: ingress_value,
                detail: ingress_detail,
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

/// 首页的主操作。
enum Primary {
    Reconnect,
    StopAll,
    /// 只有一个环境在接管或需要恢复：只作用于它（`scope` 缺失时退回作用于当前接管）。
    One {
        label: &'static str,
        kind: Kind,
        scope: Option<String>,
    },
    Environments,
}

/// 主操作的选择：后台没连上先重连；不止一个环境在接管或需要恢复时停止全部；
/// 只有一个时针对它；都没有时去环境页启动。
fn primary_action(valid: bool, owned: &[&Value]) -> Primary {
    match owned {
        _ if !valid => Primary::Reconnect,
        [] => Primary::Environments,
        [session] => {
            let (label, kind) = session_action(session);
            Primary::One {
                label,
                kind,
                scope: session["scope"].as_str().map(str::to_owned),
            }
        }
        _ => Primary::StopAll,
    }
}

/// 这个环境正在转发（接管中或诊断转发），并且有转发观测。
fn session_forwarding(session: &Value) -> bool {
    session["phase"]
        .as_str()
        .is_some_and(|phase| phase.starts_with("forwarding"))
        && session["forwarding"].is_object()
}

/// 一个环境的阶段标签和颜色。
fn session_phase(session: &Value) -> (&'static str, StatusTone) {
    match session["phase"].as_str() {
        Some("forwarding_managed") => ("接管中", StatusTone::Ok),
        Some("forwarding_scoped") => ("诊断转发中", StatusTone::Warn),
        Some("recovery_required") => ("需要恢复", StatusTone::Error),
        Some("idle") => ("未接管", StatusTone::Off),
        _ => ("状态未确认", StatusTone::Warn),
    }
}

/// 只作用于这个环境的按钮，和环境页的说法一致：目标已不在 WSL 注册表里只能放弃记录，
/// 需要恢复时恢复直连，接管中停止。
fn session_action(session: &Value) -> (&'static str, Kind) {
    if session["target_registered"] == false {
        ("放弃本次记录", Kind::Abandon)
    } else if session["phase"] == "recovery_required" {
        ("恢复直连", Kind::Stop)
    } else {
        ("停止接管", Kind::Stop)
    }
}

/// 需要恢复的环境的原因；其余阶段为 `None`。
fn session_reason(session: &Value) -> Option<String> {
    if session["phase"] != "recovery_required" {
        return None;
    }
    let name = Desktop::session_name(session);
    Some(if session["target_registered"] == false {
        format!("{name} 已不在 WSL 注册表里，只能放弃本次接管记录。")
    } else {
        recovery_reason(
            session["issue"].as_str().unwrap_or(""),
            block_state(&session["protection_check"]["fallback_block"]),
            &name,
        )
    })
}

/// 各阶段的环境名，「、」连接；没有时为 `None`。
fn names_in(owned: &[&Value], phase: impl Fn(&str) -> bool) -> Option<(usize, String)> {
    let names: Vec<String> = owned
        .iter()
        .filter(|session| phase(session["phase"].as_str().unwrap_or("")))
        .map(|session| Desktop::session_name(session))
        .collect();
    (!names.is_empty()).then(|| (names.len(), names.join("、")))
}

/// 不止一个环境在接管或需要恢复时的状态色、一句话状态和说明。颜色取最差的那个。
fn several_summary(owned: &[&Value]) -> (StatusTone, &'static str, String) {
    let total = owned.len();
    let managed = names_in(owned, |phase| phase == "forwarding_managed");
    let scoped = names_in(owned, |phase| phase == "forwarding_scoped");
    let recovering = names_in(owned, |phase| phase == "recovery_required");
    let unknown = names_in(owned, |phase| {
        !matches!(
            phase,
            "forwarding_managed" | "forwarding_scoped" | "recovery_required"
        )
    });
    let parts = [
        managed.as_ref().map(|(_, names)| format!("{names} 接管中")),
        scoped
            .as_ref()
            .map(|(_, names)| format!("{names} 诊断转发中（系统 DNS 没有接管）")),
        recovering
            .as_ref()
            .map(|(_, names)| format!("{names} 需要恢复")),
        unknown
            .as_ref()
            .map(|(_, names)| format!("{names} 状态未确认")),
    ];
    let detail = parts.into_iter().flatten().collect::<Vec<_>>().join("；");
    if let Some((count, _)) = recovering {
        (
            StatusTone::Error,
            "需要恢复",
            format!("{total} 个环境里有 {count} 个需要恢复：{detail}。在下面逐个处理。"),
        )
    } else if unknown.is_some() {
        (
            StatusTone::Warn,
            "状态未确认",
            format!("{total} 个环境：{detail}。请刷新后再操作。"),
        )
    } else if scoped.is_some() {
        (
            StatusTone::Warn,
            "接管中",
            format!("{total} 个环境在转发：{detail}。"),
        )
    } else {
        (
            StatusTone::Ok,
            "接管中",
            format!("{total} 个环境接管中：{detail}，TCP 和系统 DNS 各自经双跳代理出网。"),
        )
    }
}

/// 多个环境时的目标节点：值是个数，说明和颜色按最差的那个。
fn several_target(owned: &[&Value]) -> (String, String, StatusTone) {
    let total = owned.len();
    let value = format!("{total} 个环境");
    let forwarding = owned
        .iter()
        .filter(|session| session_forwarding(session))
        .count();
    match names_in(owned, |phase| phase == "recovery_required") {
        Some((count, _)) => (
            value,
            format!("{forwarding} 个接管中 · {count} 个需要恢复"),
            StatusTone::Error,
        ),
        None if forwarding == total => (value, "接管中".to_owned(), StatusTone::Ok),
        None => (value, format!("{forwarding} 个接管中"), StatusTone::Warn),
    }
}

/// 这个环境的住宅出口有没有问题：公网出口和住宅地址不一致，或者本次接管 UDP 已阻断。
fn exit_issue(session: &Value) -> bool {
    session["recent_exit"]["matches_residential"] == false
        || (session["phase"] == "forwarding_managed"
            && session["startup_verified"]["udp_supported"] == false)
}

/// 多个环境时的住宅出口节点：每个环境的住宅代理不同，只说有没有问题。
fn several_exit(owned: &[&Value]) -> (String, String, StatusTone) {
    let value = "各环境不同".to_owned();
    let issues = owned.iter().filter(|session| exit_issue(session)).count();
    if issues > 0 {
        (value, format!("{issues} 个环境需要留意"), StatusTone::Warn)
    } else if owned.iter().all(|session| session_forwarding(session)) {
        (value, "第二跳".to_owned(), StatusTone::Ok)
    } else {
        (value, "第二跳".to_owned(), StatusTone::Warn)
    }
}

/// 悬停提示里一个环境的住宅出口：运行中的住宅地址、公网出口和核对结果、UDP。
fn session_exit(session: &Value) -> String {
    let residential = session["active_policy"]["residential"]
        .as_str()
        .filter(|address| !address.is_empty())
        .unwrap_or("—");
    let exit = &session["recent_exit"];
    let verdict = if !exit.is_object() {
        "出口未检测".to_owned()
    } else {
        format!(
            "出口 {} {}",
            exit["ip"].as_str().unwrap_or("—"),
            match exit["matches_residential"].as_bool() {
                Some(true) => "一致",
                Some(false) => "不一致",
                None => "未比对",
            }
        )
    };
    let udp = if session["phase"] == "forwarding_managed"
        && session["startup_verified"]["udp_supported"] == false
    {
        " · UDP 已阻断"
    } else {
        ""
    };
    format!("{residential} · {verdict}{udp}")
}

/// 多个环境时的系统 DNS 节点。
fn several_dns(owned: &[&Value]) -> (String, StatusTone) {
    let total = owned.len();
    let managed = owned
        .iter()
        .filter(|session| session["dns_managed"] == true)
        .count();
    if owned
        .iter()
        .any(|session| session["phase"] == "recovery_required")
    {
        (
            format!("{managed}/{total} 已接管 · 有需要恢复"),
            StatusTone::Error,
        )
    } else if managed == total {
        ("均已接管".to_owned(), StatusTone::Ok)
    } else {
        (format!("{managed}/{total} 已接管"), StatusTone::Warn)
    }
}

/// 悬停提示里一个环境的系统 DNS。
fn session_dns(session: &Value) -> String {
    if session["dns_managed"] == true {
        session["startup_verified"]["dns_latency_ms"]
            .as_f64()
            .map(|ms| format!("已接管 · {ms:.0} ms"))
            .unwrap_or_else(|| "已接管".to_owned())
    } else if session["phase"] == "recovery_required" {
        "需要恢复".to_owned()
    } else {
        "未接管".to_owned()
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
///
/// `block` 是后台在目标里断网的结果（决策 33）：`installed`、`failed`、
/// `target_stopped`，还没断过时为 `None`。断网时目标记下的 Docker 网络转发出去的流量也一并丢弃，`bridges` 为空时容器不在其内。
/// The block's state for [`recovery_reason`]: an installed block that also
/// drops what the target's Docker bridges forward reads apart (decision 33).
fn block_state(block: &serde_json::Value) -> Option<&str> {
    match block["state"].as_str() {
        Some("installed")
            if block["bridges"]
                .as_array()
                .is_some_and(|bridges| !bridges.is_empty()) =>
        {
            Some("installed_with_containers")
        }
        state => state,
    }
}

fn recovery_reason(issue: &str, block: Option<&str>, target: &str) -> String {
    if issue.starts_with("managed_install_unverified:container_networks_unavailable") {
        return format!(
            "{target}：读不出目标里 Docker 的网络，目标本机的流量已阻断，但目标的容器没有被拦住，可能直连。请停止接管并恢复直连，确认 Docker 正常后再启动。"
        );
    }
    let cause = match issue.strip_prefix("protection_lost: ") {
        Some(lost) => match lost.split(':').next().unwrap_or("") {
            "restarted" => "目标发行版或 WSL 重启过，本次接管的规则已不再生效",
            "rules_incomplete" | "rules_missing" => "目标里本次接管的规则已缺失或不完整",
            "environment_changed" => "目标的环境变了，无法再确认本次接管覆盖它的全部流量",
            _ => "无法再确认本次接管仍然有效",
        },
        // A controller that started again only blocks once the rules are gone.
        None if block.is_some() => "上次接管没有正常结束，本次接管的规则已失效",
        None => return format!("{target} 的上次接管没有正常结束，请停止接管并恢复直连。"),
    };
    let then = "请停止接管并恢复直连，再重新启动接管。";
    match block {
        Some("installed_with_containers") => format!(
            "{target}：{cause}。已在目标里断网：目标本机进程的新连接一律丢弃，目标的 Docker 容器转发出去的也一并丢弃（接管期间没见过的网络除外）。{then}"
        ),
        Some("installed") => format!(
            "{target}：{cause}。已在目标里断网：目标本机进程的新连接一律丢弃，但没有记下目标的 Docker 网络，若目标里有容器，它们可能直连。{then}"
        ),
        Some("failed") => {
            format!("{target}：{cause}，在目标里断网没有成功，新连接可能直连。{then}")
        }
        Some("target_stopped") => {
            format!(
                "{target}：{cause}。目标现在没有运行；它再启动后，要等下一轮核对（最长约 30 秒）才会在里面断网，此前新连接可能直连。{then}"
            )
        }
        _ => format!("{target}：{cause}，新连接可能已不经代理。{then}"),
    }
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
    use super::{
        Kind, Primary, StatusTone, ago, block_state, event_time, primary_action, recovery_reason,
        residential_address, session_action, session_exit, session_reason, several_dns,
        several_exit, several_summary, several_target,
    };
    use serde_json::{Value, json};

    fn managed(scope: &str, name: &str, ingress: &str) -> Value {
        json!({
            "scope": scope,
            "phase": "forwarding_managed",
            "active_target": name,
            "ingress": ingress,
            "dns_managed": true,
            "target_registered": true,
            "forwarding": {"active_tcp": 1},
            "active_policy": {"residential": "198.51.100.9:1080"},
            "startup_verified": {"udp_supported": true, "dns_latency_ms": 12.0},
        })
    }

    fn recovering(scope: &str, name: &str) -> Value {
        json!({
            "scope": scope,
            "phase": "recovery_required",
            "recorded_target": name,
            "issue": "",
            "target_registered": true,
        })
    }

    #[test]
    fn the_main_action_follows_how_many_environments_are_taken_over() {
        let dev = managed("aaaa", "Dev", "127.0.0.1:41000");
        let work = recovering("bbbb", "Work");
        assert!(matches!(primary_action(false, &[&dev]), Primary::Reconnect));
        assert!(matches!(primary_action(true, &[]), Primary::Environments));
        assert!(matches!(
            primary_action(true, &[&dev, &work]),
            Primary::StopAll
        ));
        match primary_action(true, &[&work]) {
            Primary::One { label, kind, scope } => {
                assert_eq!(label, "恢复直连");
                assert!(kind == Kind::Stop);
                assert_eq!(scope.as_deref(), Some("bbbb"));
            }
            _ => panic!("one environment needs recovery"),
        }
        // A gone target among several still leaves the main action at stop all.
        let mut gone = recovering("cccc", "Old");
        gone["target_registered"] = json!(false);
        assert!(matches!(
            primary_action(true, &[&dev, &gone]),
            Primary::StopAll
        ));
    }

    #[test]
    fn each_environment_gets_its_own_button_and_reason() {
        let dev = managed("aaaa", "Dev", "127.0.0.1:41000");
        let work = recovering("bbbb", "Work");
        let mut gone = recovering("cccc", "Old");
        gone["target_registered"] = json!(false);
        let (label, kind) = session_action(&dev);
        assert!(label == "停止接管" && kind == Kind::Stop);
        let (label, kind) = session_action(&work);
        assert!(label == "恢复直连" && kind == Kind::Stop);
        let (label, kind) = session_action(&gone);
        assert!(label == "放弃本次记录" && kind == Kind::Abandon);
        assert_eq!(session_reason(&dev), None);
        assert_eq!(
            session_reason(&work).as_deref(),
            Some("Work 的上次接管没有正常结束，请停止接管并恢复直连。")
        );
        assert_eq!(
            session_reason(&gone).as_deref(),
            Some("Old 已不在 WSL 注册表里，只能放弃本次接管记录。")
        );
    }

    #[test]
    fn several_takeovers_are_summed_up_by_the_worst_one() {
        let dev = managed("aaaa", "Dev", "127.0.0.1:41000");
        let lab = managed("dddd", "Lab", "127.0.0.1:41001");
        let work = recovering("bbbb", "Work");

        let (tone, title, summary) = several_summary(&[&dev, &lab]);
        assert!(tone == StatusTone::Ok);
        assert_eq!(title, "接管中");
        assert!(
            summary.starts_with("2 个环境接管中：Dev、Lab 接管中"),
            "{summary}"
        );

        let (tone, title, summary) = several_summary(&[&dev, &work]);
        assert!(tone == StatusTone::Error);
        assert_eq!(title, "需要恢复");
        assert!(summary.contains("2 个环境里有 1 个需要恢复"), "{summary}");
        assert!(summary.contains("Dev 接管中；Work 需要恢复"), "{summary}");

        let (value, detail, tone) = several_target(&[&dev, &work]);
        assert_eq!(value, "2 个环境");
        assert_eq!(detail, "1 个接管中 · 1 个需要恢复");
        assert!(tone == StatusTone::Error);
        let (_, detail, tone) = several_target(&[&dev, &lab]);
        assert_eq!(detail, "接管中");
        assert!(tone == StatusTone::Ok);

        let (dns, tone) = several_dns(&[&dev, &lab]);
        assert_eq!(dns, "均已接管");
        assert!(tone == StatusTone::Ok);
        let (dns, tone) = several_dns(&[&dev, &work]);
        assert_eq!(dns, "1/2 已接管 · 有需要恢复");
        assert!(tone == StatusTone::Error);
    }

    #[test]
    fn several_exits_do_not_borrow_one_environments_address() {
        let dev = managed("aaaa", "Dev", "127.0.0.1:41000");
        let mut lab = managed("dddd", "Lab", "127.0.0.1:41001");
        let (value, _, tone) = several_exit(&[&dev, &lab]);
        assert_eq!(value, "各环境不同");
        assert!(tone == StatusTone::Ok);
        lab["recent_exit"] =
            json!({"ip": "203.0.113.50", "country": "US", "matches_residential": false});
        let (_, detail, tone) = several_exit(&[&dev, &lab]);
        assert_eq!(detail, "1 个环境需要留意");
        assert!(tone == StatusTone::Warn);
        assert_eq!(session_exit(&dev), "198.51.100.9:1080 · 出口未检测");
        assert_eq!(
            session_exit(&lab),
            "198.51.100.9:1080 · 出口 203.0.113.50 不一致"
        );
    }

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
                None,
                "Dev"
            ),
            "Dev：目标发行版或 WSL 重启过，本次接管的规则已不再生效，新连接可能已不经代理。请停止接管并恢复直连，再重新启动接管。"
        );
        assert!(
            recovery_reason("protection_lost: mapping_integrity: x: y", None, "Dev")
                .starts_with("Dev：无法再确认本次接管仍然有效，")
        );
        assert_eq!(
            recovery_reason("", None, "Dev"),
            "Dev 的上次接管没有正常结束，请停止接管并恢复直连。"
        );
        assert_eq!(
            recovery_reason("managed_readiness_failed: dns", None, "Dev"),
            "Dev 的上次接管没有正常结束，请停止接管并恢复直连。"
        );
        assert!(
            recovery_reason(
                "managed_install_unverified:container_networks_unavailable:install:docker_networks_unavailable; ingress_stop:None",
                None,
                "Dev"
            )
            .starts_with("Dev：读不出目标里 Docker 的网络，目标本机的流量已阻断，但目标的容器没有被拦住，可能直连。")
        );
    }

    #[test]
    fn says_how_the_block_after_a_loss_went() {
        let lost = "protection_lost: restarted: the target or the WSL VM restarted; this takeover's rules no longer apply";
        let installed = recovery_reason(lost, Some("installed"), "Dev");
        assert!(installed.contains("已在目标里断网"), "{installed}");
        assert!(
            installed.contains("没有记下目标的 Docker 网络"),
            "{installed}"
        );
        let covered = recovery_reason(lost, Some("installed_with_containers"), "Dev");
        assert!(covered.contains("容器转发出去的也一并丢弃"), "{covered}");
        assert_eq!(
            block_state(&serde_json::json!({"state": "installed", "bridges": ["docker0"]})),
            Some("installed_with_containers")
        );
        assert_eq!(
            block_state(&serde_json::json!({"state": "installed", "bridges": []})),
            Some("installed")
        );
        assert_eq!(block_state(&serde_json::json!(null)), None);
        assert!(
            recovery_reason(lost, Some("failed"), "Dev").contains("断网没有成功，新连接可能直连")
        );
        assert!(recovery_reason(lost, Some("target_stopped"), "Dev").contains("目标现在没有运行"));
        // A controller that started again after the one that ran it ended.
        assert!(
            recovery_reason("", Some("installed"), "Dev")
                .starts_with("Dev：上次接管没有正常结束，本次接管的规则已失效。已在目标里断网")
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
