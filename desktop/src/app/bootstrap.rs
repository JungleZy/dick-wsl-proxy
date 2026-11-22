//! 负责窗口初始化、后台轮询和后台返回值归并，不承载页面布局。

use std::time::{Duration, Instant};

const UI_TICK_INTERVAL: Duration = Duration::from_millis(200);
const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(2);

use gpui_kit::component::WindowExt as _;
use gpui_kit::component::input::{InputEvent, InputState, TextareaState};
use gpui_kit::component::notification::{Notification, NotificationType};
use gpui_kit::component::select::{SelectEvent, SelectState};
use gpui_kit::{prelude::*, *};
use serde_json::{Value, json};

use super::backend::{Job, Kind, worker};
use super::model::{Field, Fields, LogFilter, Page};
use super::state::Desktop;

fn input(window: &mut Window, cx: &mut App, hint: &'static str, multiline: bool) -> Field {
    if multiline {
        Field::Multi(cx.new(|cx| TextareaState::new(window, cx).placeholder(hint)))
    } else {
        Field::Single(cx.new(|cx| InputState::new(window, cx).placeholder(hint)))
    }
}

impl Desktop {
    pub(crate) fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let nav_focus = std::array::from_fn(|_| cx.focus_handle().tab_stop(true));
        let fields = Fields {
            first_hop: input(window, cx, "宿主 SOCKS5：IPv4:端口", false),
            residential_ip: input(window, cx, "住宅服务器 IPv4", false),
            residential_port: input(window, cx, "住宅服务器端口", false),
            residential_username: input(window, cx, "用户名", false),
            residential_password: input(window, cx, "密码", false),
            dns_upstream: input(window, cx, "DoH 上游：IPv4:端口", false),
            dns_tls_name: input(window, cx, "TLS 主机名，例如 dns.google", false),
            health_domain: input(window, cx, "健康检查域名", false),
            direct_ips: input(window, cx, "每行一个 IPv4 或 CIDR", true),
            direct_domains: input(window, cx, "每行一个精确域名", true),
            direct_suffixes: input(window, cx, "每行一个域名后缀", true),
            port: Field::Single(cx.new(|cx| InputState::new(window, cx).default_value("43531"))),
            environment_name: input(window, cx, "例如 Ubuntu-Dev", false),
            environment_distribution: input(window, cx, "发行版，例如 Ubuntu-24.04", false),
            environment_install: input(
                window,
                cx,
                "Windows 绝对目录，例如 D:\\WSL\\Ubuntu-Dev",
                false,
            ),
            environment_backup: input(
                window,
                cx,
                "Windows 绝对路径，例如 D:\\Backup\\Ubuntu-Dev.tar",
                false,
            ),
            environment_username: input(window, cx, "例如 dev", false),
            environment_password: input(window, cx, "设置默认用户密码", false),
            environment_timezone: input(window, cx, "例如 Asia/Shanghai 或 Etc/UTC", false),
        };
        let mut subscriptions = Vec::new();
        for field in [
            &fields.first_hop,
            &fields.residential_ip,
            &fields.residential_port,
            &fields.residential_username,
            &fields.residential_password,
            &fields.dns_upstream,
            &fields.dns_tls_name,
            &fields.health_domain,
            &fields.direct_ips,
            &fields.direct_domains,
            &fields.direct_suffixes,
            &fields.port,
            &fields.environment_name,
            &fields.environment_distribution,
            &fields.environment_install,
            &fields.environment_backup,
            &fields.environment_username,
            &fields.environment_password,
            &fields.environment_timezone,
        ] {
            if let Field::Single(field) = field {
                subscriptions.push(cx.subscribe(field, |this, _, event, cx| {
                    if matches!(event, InputEvent::Change) && !this.loading_fields {
                        this.preflight = None;
                        this.pending_prepare = None;
                        this.dirty = this.draft_is_dirty(cx);
                        cx.notify();
                    }
                }));
            }
        }
        for field in [
            &fields.direct_ips,
            &fields.direct_domains,
            &fields.direct_suffixes,
        ] {
            if let Field::Multi(field) = field {
                subscriptions.push(cx.subscribe(field, |this, _, event, cx| {
                    if matches!(event, InputEvent::Change) && !this.loading_fields {
                        this.preflight = None;
                        this.pending_prepare = None;
                        this.dirty = this.draft_is_dirty(cx);
                        cx.notify();
                    }
                }));
            }
        }
        let timezone_select = cx.new(|cx| {
            SelectState::new(super::timezones::timezone_groups(), None, window, cx).searchable(true)
        });
        subscriptions.push(cx.subscribe_in(
            &timezone_select,
            window,
            |this, _, event, window, cx| {
                if let SelectEvent::Confirm(Some(value)) = event {
                    this.fields
                        .environment_timezone
                        .set_value((*value).to_owned(), window, cx);
                    cx.notify();
                }
            },
        ));
        let environment_distribution_select = cx.new(|cx| {
            SelectState::new(
                super::distributions::official_distributions(),
                None,
                window,
                cx,
            )
            .searchable(true)
        });
        subscriptions.push(cx.subscribe_in(
            &environment_distribution_select,
            window,
            |this, _, event, window, cx| {
                if let SelectEvent::Confirm(Some(value)) = event {
                    this.fields
                        .environment_distribution
                        .set_value((*value).to_owned(), window, cx);
                    cx.notify();
                }
            },
        ));
        let (sender, replies) = worker();
        let mut this = Self {
            page: Page::Overview,
            log_filter: LogFilter::All,
            nav_focus,
            fields,
            timezone_select,
            environment_distribution_select,
            _subscriptions: subscriptions,
            sender,
            replies,
            epoch: 0,
            busy: None,
            reading: false,
            refreshing: false,
            last_poll: Instant::now(),
            saved_port: "43531".into(),
            status: Value::Null,
            status_at: None,
            status_valid: false,
            traffic_history: Vec::new(),
            dns_history: Vec::new(),
            dns_checked_at: None,
            distributions: Vec::new(),
            selected: None,
            saved_selected: None,
            profile: Value::Null,
            residential: Value::Null,
            profile_path: None,
            revision: Value::Null,
            profile_exists: false,
            dirty: false,
            loading_fields: false,
            preflight: None,
            pending_prepare: None,
            notice: "正在连接后台；关闭窗口不会停止接管。".into(),
            error: false,
            autostart_enabled: super::autostart::enabled().unwrap_or(false),
            confirmation: None,
            export_path: None,
            environment_editor: None,
            environment_edit_target: None,
            environment_selected: None,
            environment_detail: None,
            environment_started: None,
            loading_dialog_open: false,
            backup_dialog_open: false,
            environment_backup_target: None,
            backup_result_dialog_open: false,
            backup_result_path: None,
            backup_result_pending: false,
            timezone_dialog_open: false,
            environment_zsh: true,
            environment_chrome: false,
            environment_chinese: true,
        };
        this.send(Kind::Bootstrap, Value::Null, cx);
        cx.spawn_in(window, async move |view, cx| {
            loop {
                cx.background_executor().timer(UI_TICK_INTERVAL).await;
                if view
                    .update_in(cx, |this, window, cx| this.tick(window, cx))
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        this
    }
    pub(crate) fn send(&mut self, kind: Kind, request: Value, cx: &mut Context<Self>) {
        if kind.mutation() {
            if self.busy.is_some() || self.reading {
                return;
            }
            self.epoch += 1;
            self.busy = Some(kind);
            self.confirmation = None;
        } else if kind == Kind::Status {
            if self.refreshing || self.reading || self.busy.is_some() {
                return;
            }
            self.refreshing = true;
        } else {
            if self.reading || self.busy.is_some() {
                return;
            }
            self.reading = true;
        }
        if self
            .sender
            .send(Job {
                kind,
                epoch: self.epoch,
                request,
            })
            .is_err()
        {
            self.busy = None;
            self.reading = false;
            self.refreshing = false;
            self.pending_prepare = None;
            self.status_valid = false;
            self.fail("后台通信线程已退出，请重新打开窗口。", cx);
        } else {
            if kind != Kind::Status {
                self.notice = match kind {
                    Kind::EnvironmentCreate => "正在创建环境并安装组件…".into(),
                    Kind::EnvironmentEdit => "正在安装组件并刷新环境能力…".into(),
                    _ => format!("{}中…", kind.label()),
                };
                self.error = false;
            }
            cx.notify();
        }
    }

    fn tick(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        while let Ok(reply) = self.replies.try_recv() {
            if reply.kind == Kind::Status {
                self.refreshing = false;
                if reply.epoch != self.epoch || self.busy.is_some() {
                    continue;
                }
            } else if reply.kind.mutation() {
                self.busy = None;
                if matches!(reply.kind, Kind::EnvironmentCreate | Kind::EnvironmentEdit) {
                    self.environment_started = None;
                }
            } else {
                self.reading = false;
            }
            let mut status_error = None;
            if let Some(status) = reply.status {
                match status {
                    Ok(status) => self.accept_status(status),
                    Err(error) => {
                        self.status_valid = false;
                        status_error = Some(format!(
                            "操作后无法确认状态：{}。请刷新。",
                            super::backend::humanize_error(&error)
                        ));
                    }
                }
            }
            let environment_operation = matches!(
                reply.kind,
                Kind::EnvironmentCreate | Kind::EnvironmentEdit | Kind::EnvironmentDelete
            );
            let result_succeeded = reply.result.is_ok();
            match reply.result {
                Err(error) => {
                    if matches!(reply.kind, Kind::Status | Kind::Bootstrap) {
                        self.status_valid = false;
                    }
                    if reply.kind == Kind::Preflight {
                        self.pending_prepare = None;
                    }
                    let readable_error = super::backend::humanize_error(&error);
                    let message = match reply.kind {
                        Kind::EnvironmentCreate => {
                            format!("环境创建失败，组件安装未完成：{readable_error}")
                        }
                        Kind::EnvironmentEdit => {
                            format!("组件安装失败，环境设置未更新：{readable_error}")
                        }
                        Kind::EnvironmentDelete => format!("环境删除失败：{readable_error}"),
                        _ => format!("{}失败：{readable_error}", reply.kind.label()),
                    };
                    self.fail(message, cx);
                }
                Ok(value) => match reply.kind {
                    Kind::Bootstrap => {
                        self.distributions = value["distributions"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default();
                        self.accept_profile(&value["profile"], window, cx);
                        self.accept_status(value["status"].clone());
                        self.notice = "后台已连接。请选择目标，然后启动接管。".into();
                        self.error = false;
                    }
                    Kind::Status => {
                        self.accept_status(value);
                    }
                    Kind::List => {
                        self.distributions = value.as_array().cloned().unwrap_or_default();
                        let valid = |id: &Option<String>| {
                            id.as_ref().is_some_and(|id| {
                                self.distributions.iter().any(|distro| {
                                    distro["id"].as_str() == Some(id) && distro["version"] == 2
                                })
                            })
                        };
                        if !valid(&self.selected) {
                            self.selected = None;
                        }
                        self.preflight = None;
                        self.pending_prepare = None;
                        self.dirty = self.draft_is_dirty(cx);
                        self.notice = "列表已刷新；未启动 WSL。".into();
                    }
                    Kind::Save => {
                        self.accept_profile(&value, window, cx);
                        self.notice = if self.page == Page::Environment {
                            "环境选择已保存；不会立即改变当前接管。"
                        } else {
                            "策略已保存；不会立即改变当前接管。"
                        }
                        .into();
                    }
                    Kind::Preflight => {
                        let passed = value["passed"] == true;
                        let blockers = value["blockers"]
                            .as_array()
                            .map(|items| {
                                items
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_owned)
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();
                        self.preflight = Some(value);
                        let pending = self.pending_prepare.take();
                        if passed {
                            self.error = false;
                            if let Some(pending) = pending {
                                let selection_matches = matches!(
                                    self.selection(cx),
                                    Ok((target, port))
                                        if target == pending.target && port == pending.port
                                );
                                if self.generation() == Some(pending.generation)
                                    && selection_matches
                                {
                                    self.notice = "预检通过，请确认后启动接管。".into();
                                    self.open_prepare_confirmation(pending, window, cx);
                                } else {
                                    self.fail("启动前状态已变化，请重新启动接管。", cx);
                                }
                            } else {
                                self.notice = "预检通过。".into();
                            }
                        } else {
                            self.error = true;
                            self.notice = if blockers.is_empty() {
                                "预检未通过，请检查当前环境。".into()
                            } else {
                                format!("预检未通过：{}", blockers.join("；"))
                            };
                        }
                    }
                    Kind::Export => {
                        self.export_path = value["path"].as_str().map(str::to_owned);
                        self.notice = "诊断已导出；请按内部资料处理。".into();
                    }
                    Kind::Probe => {
                        self.accept_status(value);
                        self.notice = "出口检测完成；仅代表本次结果。".into();
                    }
                    Kind::EnvironmentView => {
                        self.accept_environment_detail(value, window, cx);
                        self.error = false;
                        self.notice = "环境详情已刷新。".into();
                    }
                    Kind::EnvironmentCreate => {
                        self.environment_detail = value.get("environment").cloned();
                        self.environment_selected =
                            value["environment"]["name"].as_str().map(str::to_owned);
                        self.distributions = value["distributions"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default();
                        self.environment_editor = None;
                        self.environment_edit_target = None;
                        self.error = false;
                        self.notice = "环境创建成功，组件安装已完成。".into();
                    }
                    Kind::EnvironmentEdit => {
                        if let Some(environment) = value.get("environment").cloned() {
                            self.accept_environment_detail(environment, window, cx);
                        }
                        self.environment_detail = value.get("environment").cloned();
                        self.environment_selected =
                            value["environment"]["name"].as_str().map(str::to_owned);
                        self.environment_editor = None;
                        self.environment_edit_target = None;
                        self.error = false;
                        self.notice = "组件安装成功，环境能力已刷新。".into();
                    }
                    Kind::EnvironmentBackup => {
                        self.export_path = value["backup"]["path"].as_str().map(str::to_owned);
                        self.backup_result_path = self.export_path.clone();
                        self.backup_result_pending = true;
                        self.error = false;
                        self.notice = "环境备份已完成。".into();
                    }
                    Kind::EnvironmentDelete => {
                        self.distributions = value["distributions"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default();
                        let deleted_id = value["environment"]["id"].as_str();
                        if deleted_id.is_some_and(|id| self.selected.as_deref() == Some(id)) {
                            self.selected = None;
                            self.preflight = None;
                            self.pending_prepare = None;
                            self.dirty = self.draft_is_dirty(cx);
                        }
                        self.environment_selected = None;
                        self.environment_detail = None;
                        self.environment_editor = None;
                        self.environment_edit_target = None;
                        self.environment_backup_target = None;
                        self.backup_result_path = None;
                        self.notice = "环境已删除。".into();
                        self.error = false;
                    }
                    Kind::Start | Kind::Switch | Kind::Stop => {
                        if value["passed"] == false {
                            self.preflight = Some(value);
                            self.fail("操作前预检未通过；请查看阻断项。", cx);
                        } else {
                            self.notice =
                                format!("{}已完成；请以后台状态为准。", reply.kind.label());
                            self.preflight = None;
                        }
                    }
                },
            }
            if let Some(error) = status_error {
                self.fail(error, cx);
            }
            if environment_operation {
                let succeeded = result_succeeded && !self.error;
                let notification_type = if succeeded {
                    NotificationType::Success
                } else {
                    NotificationType::Error
                };
                let title = if succeeded {
                    "环境操作完成"
                } else {
                    "环境操作失败"
                };
                window.push_notification(
                    Notification::new()
                        .with_type(notification_type)
                        .title(title)
                        .message(self.notice.clone())
                        .autohide(true),
                    cx,
                );
            }
            cx.notify();
        }
        if let Some(action) = super::tray::consume_action() {
            match action {
                super::tray::TrayAction::Refresh => {
                    self.send(Kind::Status, json!({"command":"status"}), cx);
                }
                super::tray::TrayAction::Start => {
                    self.page = Page::Overview;
                    match self.phase() {
                        "idle" => self.prepare(Kind::Start, window, cx),
                        "unknown" => self.fail("后台状态未确认，请先刷新。", cx),
                        _ => self.fail("当前已有接管任务，请先停止接管并恢复直连。", cx),
                    }
                }
                super::tray::TrayAction::Stop => {
                    self.page = Page::Overview;
                    if self.phase() == "idle" {
                        self.notice = "当前没有正在接管的目标。".into();
                        self.error = false;
                        cx.notify();
                    } else {
                        self.prepare(Kind::Stop, window, cx);
                    }
                }
                super::tray::TrayAction::Probe => {
                    self.page = Page::Connection;
                    self.probe(cx);
                }
            }
        }
        if self.last_poll.elapsed() >= STATUS_POLL_INTERVAL {
            self.last_poll = Instant::now();
            self.send(Kind::Status, json!({"command":"status"}), cx);
        }
        let operation_active = self.busy.is_some() || self.reading;
        if self.loading_dialog_open && !operation_active {
            window.close_dialog(cx);
            self.loading_dialog_open = false;
        } else if operation_active && !self.loading_dialog_open {
            self.open_loading_dialog(window, cx);
        }
        if self.backup_result_pending
            && !self.loading_dialog_open
            && !self.backup_result_dialog_open
        {
            self.backup_result_pending = false;
            self.open_backup_result_dialog(window, cx);
        }
        if matches!(
            self.busy,
            Some(Kind::EnvironmentCreate | Kind::EnvironmentEdit)
        ) {
            cx.notify();
        }
    }

    fn accept_status(&mut self, status: Value) {
        if status["phase"].is_string() && status["operation_generation"].is_u64() {
            let tx = status["forwarding"]["traffic"]["tx_bytes_per_sec"]
                .as_u64()
                .unwrap_or_default() as f32;
            let rx = status["forwarding"]["traffic"]["rx_bytes_per_sec"]
                .as_u64()
                .unwrap_or_default() as f32;
            if tx > 0. || rx > 0. {
                self.traffic_history
                    .push(super::model::TrafficSample { tx, rx });
                if self.traffic_history.len() > 24 {
                    let excess = self.traffic_history.len() - 24;
                    self.traffic_history.drain(0..excess);
                }
            }
            let dns_latency = status["startup_verified"]["dns_latency_ms"]
                .as_f64()
                .or_else(|| status["forwarding"]["traffic"]["dns_latency_ms"].as_f64())
                .or_else(|| status["dns_latency_ms"].as_f64())
                .unwrap_or_default() as f32;
            let checked_at = status["startup_verified"]["checked_unix_seconds"].as_u64();
            if dns_latency > 0. && checked_at != self.dns_checked_at {
                self.dns_history.push(dns_latency);
                self.dns_checked_at = checked_at;
                if self.dns_history.len() > 12 {
                    let excess = self.dns_history.len() - 12;
                    self.dns_history.drain(0..excess);
                }
            }
            self.status = status;
            self.status_valid = true;
            self.status_at = Some(Instant::now());
        } else {
            self.status_valid = false;
            self.error = true;
            self.notice = "后台返回的状态缺少阶段或操作代数，已禁用接管操作。".into();
        }
    }

    fn accept_environment_detail(
        &mut self,
        value: Value,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.environment_detail = Some(value.clone());
        if let Some(features) = value.get("features") {
            self.environment_zsh = features["zsh"].as_bool().unwrap_or(false);
            self.environment_chrome = features["chrome"].as_bool().unwrap_or(false);
            self.environment_chinese = features["chinese"].as_bool().unwrap_or(false)
                || features["input_method"].as_bool().unwrap_or(false);
            self.fields.environment_timezone.set_value(
                features["timezone"].as_str().unwrap_or_default(),
                window,
                cx,
            );
        }
    }

    fn accept_profile(&mut self, result: &Value, window: &mut Window, cx: &mut Context<Self>) {
        self.profile = result["profile"].clone();
        self.revision = result["revision"].clone();
        self.profile_exists = result["exists"].as_bool().unwrap_or(false);
        // The daemon validates and owns this stable AppData location; never synthesize a CWD path.
        self.profile_path = result["path"].as_str().map(str::to_owned);
        self.residential = result["residential"].clone();
        self.loading_fields = true;
        for (field, key, array) in [
            (&self.fields.first_hop, "first_hop", false),
            (&self.fields.dns_upstream, "dns_upstream", false),
            (&self.fields.dns_tls_name, "dns_tls_name", false),
            (&self.fields.health_domain, "health_domain", false),
            (&self.fields.direct_ips, "direct_ips", true),
            (&self.fields.direct_domains, "direct_domains", true),
            (&self.fields.direct_suffixes, "direct_suffixes", true),
        ] {
            let value = if array {
                self.profile[key]
                    .as_array()
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default()
            } else {
                self.profile[key].as_str().unwrap_or_default().to_owned()
            };
            field.set_value(value, window, cx);
        }
        for (field, key) in [
            (&self.fields.residential_ip, "ip"),
            (&self.fields.residential_port, "port"),
            (&self.fields.residential_username, "username"),
            (&self.fields.residential_password, "password"),
        ] {
            let value = self.residential[key]
                .as_str()
                .map(str::to_owned)
                .or_else(|| self.residential[key].as_u64().map(|v| v.to_string()))
                .unwrap_or_default();
            field.set_value(value, window, cx);
        }
        self.selected = None;
        if let Some(desktop) = result.get("desktop") {
            self.selected = desktop["target"].as_str().map(str::to_owned);
            if let Some(port) = desktop["port"].as_u64() {
                self.fields.port.set_value(port.to_string(), window, cx);
            }
        }
        self.saved_selected = self.selected.clone();
        self.saved_port = Self::field_value(&self.fields.port, cx);
        self.loading_fields = false;
        self.dirty = false;
    }
}
