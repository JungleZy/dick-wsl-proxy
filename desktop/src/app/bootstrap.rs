//! 负责窗口初始化、后台轮询和后台返回值归并，不承载页面布局。

use std::time::{Duration, Instant};

const UI_TICK_INTERVAL: Duration = Duration::from_millis(200);
const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// 按 2 秒一次的状态轮询，约保留最近 2 分钟的速率样本。
const TRAFFIC_SAMPLE_LIMIT: usize = 60;

use gpui_kit::component::WindowExt as _;
use gpui_kit::component::input::{InputEvent, InputState, TextareaState};
use gpui_kit::component::select::{SelectEvent, SelectState};
use gpui_kit::{prelude::*, *};
use serde_json::{Value, json};

use super::backend::{Job, Kind, worker};
use super::model::{EnvironmentResult, Field, Fields, LogFilter, Page, RuntimeLog};
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
            log_search: input(window, cx, "搜索消息、来源或目标", false),
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
            max_tcp_connections: input(window, cx, "留空为默认 256", false),
            tcp_idle_timeout: input(window, cx, "留空为默认 1800", false),
            tcp_half_close_timeout: input(window, cx, "留空为默认 60", false),
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
            &fields.max_tcp_connections,
            &fields.tcp_idle_timeout,
            &fields.tcp_half_close_timeout,
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
                        this.save_error = false;
                        cx.notify();
                    }
                }));
            }
        }
        if let Field::Single(field) = &fields.log_search {
            subscriptions.push(cx.subscribe(field, |this, _, event, cx| {
                if matches!(event, InputEvent::Change) {
                    this.refresh_logs(cx);
                }
            }));
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
                        this.save_error = false;
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
            logs: Vec::new(),
            logs_total: 0,
            logs_has_more: false,
            logs_refresh_pending: false,
            logs_before_id: None,
            logs_loading_more: false,
            logs_scroll: gpui_kit::base::VirtualListScrollHandle::new(),
            live_connections: Vec::new(),
            connection_history: Default::default(),
            connection_filter: super::model::ConnectionFilter::All,
            connection_environment: None,
            connections_scroll: gpui_kit::base::VirtualListScrollHandle::new(),
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
            save_error: false,
            autostart_enabled: super::autostart::enabled().unwrap_or(false),
            confirmation: None,
            confirmation_pending: false,
            export_path: None,
            environment_editor: None,
            environment_edit_target: None,
            environment_selected: None,
            environment_detail: None,
            environment_started: None,
            environment_timezone_only: false,
            loading_dialog_open: false,
            environment_result_dialog_open: false,
            environment_result_pending: None,
            backup_dialog_open: false,
            environment_backup_target: None,
            backup_result_dialog_open: false,
            backup_result_path: None,
            backup_result_pending: false,
            timezone_dialog_open: false,
            environment_zsh: true,
            environment_chrome: true,
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
    /// 后台在线时刷新状态；连不上时重新拉起后台并重新加载，例如后台已退出。
    pub(crate) fn refresh_or_reconnect(&mut self, cx: &mut Context<Self>) {
        if self.status_valid {
            self.send(Kind::Status, json!({"command":"status"}), cx);
        } else {
            self.send(Kind::Bootstrap, Value::Null, cx);
        }
    }

    pub(crate) fn send(&mut self, kind: Kind, request: Value, cx: &mut Context<Self>) {
        if kind.mutation() {
            if self.busy.is_some() || self.reading {
                return;
            }
            self.epoch += 1;
            self.busy = Some(kind);
            self.confirmation = None;
            self.confirmation_pending = false;
        } else if kind == Kind::Status {
            if self.refreshing || self.reading || self.busy.is_some() {
                return;
            }
            self.refreshing = true;
        } else if kind == Kind::Connections {
            // 后台静默读取：不置 reading，不弹加载框，也不改页面提示。
        } else {
            if self.reading || self.busy.is_some() {
                return;
            }
            self.reading = true;
        }
        if kind == Kind::Save {
            self.save_error = false;
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
            if kind == Kind::EnvironmentEdit {
                self.environment_timezone_only = false;
            }
            self.status_valid = false;
            if kind == Kind::Save {
                self.save_error = true;
            }
            if kind == Kind::Logs {
                self.logs_loading_more = false;
            }
            self.fail("后台通信线程已退出，请重新打开窗口。", cx);
        } else {
            if !matches!(kind, Kind::Status | Kind::Connections) {
                self.notice = match kind {
                    Kind::EnvironmentCreate => "正在创建环境并安装组件…".into(),
                    Kind::EnvironmentEdit if self.environment_timezone_only => {
                        "正在更新时区并刷新环境详情…".into()
                    }
                    Kind::EnvironmentEdit => "正在安装组件并刷新环境能力…".into(),
                    _ => format!("{}中…", kind.label()),
                };
                self.error = false;
            }
            cx.notify();
        }
    }

    pub(crate) fn refresh_logs(&mut self, cx: &mut Context<Self>) {
        if self.reading || self.busy.is_some() {
            self.logs_refresh_pending = true;
            return;
        }
        self.logs_refresh_pending = false;
        self.logs_before_id = None;
        self.logs_loading_more = false;
        let search = Self::field_value(&self.fields.log_search, cx)
            .trim()
            .to_owned();
        self.send(
            Kind::Logs,
            json!({
                "command": "runtime_logs",
                "level": self.log_filter.level(),
                "search": search,
                "limit": 500,
            }),
            cx,
        );
    }

    pub(crate) fn load_more_logs(&mut self, cx: &mut Context<Self>) {
        if self.logs_loading_more || !self.logs_has_more || self.reading || self.busy.is_some() {
            return;
        }
        let search = Self::field_value(&self.fields.log_search, cx)
            .trim()
            .to_owned();
        self.logs_loading_more = true;
        self.send(
            Kind::Logs,
            json!({
                "command": "runtime_logs",
                "level": self.log_filter.level(),
                "search": search,
                "before_id": self.logs_before_id,
                "limit": 500,
            }),
            cx,
        );
    }

    /// 读取已落盘的连接记录第一页；同一时间只有一个在途请求。「进行中」筛选不显示
    /// 历史，但仍读取第一页，让页面上的记录总数保持最新。
    pub(crate) fn refresh_connection_history(&mut self, cx: &mut Context<Self>) {
        let filter = self.connection_filter;
        let environment = self.connection_environment.clone();
        if self.connection_history.requested.is_some() {
            return;
        }
        self.connection_history.requested = Some((filter, environment.clone(), false));
        self.send(
            Kind::Connections,
            json!({
                "command": "connection_records",
                "status": filter.status(),
                "target": environment,
                "limit": 200
            }),
            cx,
        );
    }

    pub(crate) fn set_connection_environment(
        &mut self,
        environment: Option<String>,
        cx: &mut Context<Self>,
    ) {
        if self.connection_environment == environment {
            return;
        }
        self.connection_environment = environment;
        self.connection_history.reset();
        self.refresh_connection_history(cx);
        self.connections_scroll
            .scroll_to_item(0, ScrollStrategy::Top);
        cx.notify();
    }

    pub(crate) fn load_more_connection_history(&mut self, cx: &mut Context<Self>) {
        let filter = self.connection_filter;
        let environment = self.connection_environment.clone();
        let history = &self.connection_history;
        if !filter.history() || history.requested.is_some() || !history.has_more {
            return;
        }
        let before_id = history.before_id;
        self.connection_history.requested = Some((filter, environment.clone(), true));
        self.send(
            Kind::Connections,
            json!({
                "command": "connection_records",
                "status": filter.status(),
                "target": environment,
                "before_id": before_id,
                "limit": 200,
            }),
            cx,
        );
    }

    /// 读取失败只写在连接页上，不改全局提示，也不影响状态是否有效。
    fn accept_connection_history(&mut self, result: Result<Value, String>, cx: &mut Context<Self>) {
        let requested = self.connection_history.requested.take();
        match requested {
            Some((filter, environment, append))
                if filter == self.connection_filter
                    && environment == self.connection_environment =>
            {
                match result {
                    Ok(value) => self.connection_history.accept(&value, append),
                    Err(error) => {
                        self.connection_history.error =
                            Some(super::backend::humanize_error(&error));
                    }
                }
            }
            // 请求发出后换了筛选：丢弃旧结果，按当前筛选重读。
            _ if self.page == Page::Connection => self.refresh_connection_history(cx),
            _ => {}
        }
    }

    fn tick(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        while let Ok(reply) = self.replies.try_recv() {
            if reply.kind == Kind::Connections {
                self.accept_connection_history(reply.result, cx);
                cx.notify();
                continue;
            }
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
                    if reply.kind == Kind::Logs {
                        self.logs_loading_more = false;
                    }
                    if reply.kind == Kind::Save {
                        self.save_error = true;
                    }
                    let readable_error = super::backend::humanize_error(&error);
                    let message = match reply.kind {
                        Kind::EnvironmentCreate => {
                            format!("环境创建失败，组件安装未完成：{readable_error}")
                        }
                        Kind::EnvironmentEdit if self.environment_timezone_only => {
                            format!("时区更新失败，环境设置未更新：{readable_error}")
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
                        if let Some(distributions) = value["distributions"].as_array() {
                            self.distributions = distributions.clone();
                        }
                        // A reconnect keeps edits the user has not saved yet.
                        if !(self.dirty && self.profile_path.is_some()) {
                            self.accept_profile(&value["profile"], window, cx);
                        }
                        self.accept_status(value["status"].clone());
                        self.accept_logs(&value["logs"], false);
                        self.notice = "后台已连接。请选择目标，然后启动接管。".into();
                        self.error = false;
                        // 关窗期间开始的环境操作仍在后台执行。
                        let job = &value["status"]["environment_job"];
                        if job["state"] == "running" {
                            let operation = match job["command"].as_str() {
                                Some("environment_create") => "新建环境",
                                Some("environment_edit") => "编辑环境",
                                Some("environment_backup") => "备份环境",
                                Some("environment_delete") => "删除环境",
                                _ => "环境操作",
                            };
                            self.notice = format!(
                                "后台正在{operation}（{}），完成前不能启动接管或管理环境；结果见运行日志。",
                                job["target"].as_str().unwrap_or("未知环境")
                            );
                        }
                        // 连接记录独立于当前接管状态，后台空闲时也要预先读取，
                        // 这样打开连接页可以直接看到历史记录。
                        self.refresh_connection_history(cx);
                    }
                    Kind::Status => {
                        self.accept_status(value);
                        if self.page == Page::Connection {
                            self.refresh_connection_history(cx);
                        }
                    }
                    // 已在循环开头单独处理，不会走到这里。
                    Kind::Connections => {}
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
                    Kind::Logs => {
                        let append = self.logs_loading_more;
                        self.logs_loading_more = false;
                        self.accept_logs(&value, append);
                    }
                    Kind::Save => {
                        self.accept_profile(&value, window, cx);
                        self.save_error = false;
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
                                    self.open_prepare_confirmation(pending, cx);
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
                    Kind::Abandon => {
                        self.accept_status(value);
                        self.notice =
                            "已放弃本次接管记录。下次启动接管前，请先执行一次 wsl --shutdown。"
                                .into();
                        self.error = false;
                    }
                    Kind::ResetDnsAliases => {
                        self.notice = "DNS 别名记录已清空，下次启动接管时重新分配。".into();
                        self.error = false;
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
                        if let Some(distributions) = value["distributions"].as_array() {
                            self.distributions = distributions.clone();
                        } else {
                            // Listing failed after a successful create: add the new
                            // environment from the reply (it carries the list fields).
                            let environment = &value["environment"];
                            let id = environment["id"].as_str();
                            if id.is_some()
                                && !self
                                    .distributions
                                    .iter()
                                    .any(|distro| distro["id"].as_str() == id)
                            {
                                self.distributions.push(json!({
                                    "id": environment["id"].clone(),
                                    "name": environment["name"].clone(),
                                    "base_path": environment["base_path"].clone(),
                                    "version": environment["version"].clone(),
                                }));
                            }
                        }
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
                        self.notice = if self.environment_timezone_only {
                            "时区已更新，环境能力已刷新。".into()
                        } else {
                            "组件安装成功，环境能力已刷新。".into()
                        };
                    }
                    Kind::EnvironmentBackup => {
                        self.export_path = value["backup"]["path"].as_str().map(str::to_owned);
                        self.backup_result_path = self.export_path.clone();
                        self.backup_result_pending = true;
                        self.error = false;
                        self.notice = "环境备份已完成。".into();
                    }
                    Kind::EnvironmentDelete => {
                        let deleted_id = value["environment"]["id"].as_str();
                        if let Some(distributions) = value["distributions"].as_array() {
                            self.distributions = distributions.clone();
                        } else {
                            // Listing failed after a successful delete: drop only
                            // the removed entry instead of the whole list.
                            self.distributions
                                .retain(|distro| distro["id"].as_str() != deleted_id);
                        }
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
                            self.notice = if reply.kind != Kind::Stop
                                && value["startup_verified"]["udp_supported"] == false
                            {
                                format!(
                                    "{}已完成，但住宅出口没有通过 UDP 探测：非白名单 UDP（含 QUIC）已阻断，不会直连；TCP 和系统 DNS 照常经代理链。",
                                    reply.kind.label()
                                )
                            } else {
                                format!("{}已完成；请以后台状态为准。", reply.kind.label())
                            };
                            self.preflight = None;
                        }
                    }
                },
            }
            if let Some(error) = status_error {
                self.fail(error, cx);
            }
            if environment_operation {
                self.environment_result_pending = Some(EnvironmentResult {
                    kind: reply.kind,
                    success: result_succeeded && !self.error,
                    message: self.notice.clone(),
                    timezone_only: self.environment_timezone_only,
                });
                if reply.kind == Kind::EnvironmentEdit {
                    self.environment_timezone_only = false;
                }
            }
            if self.page == Page::Logs
                && matches!(
                    reply.kind,
                    Kind::Preflight
                        | Kind::Save
                        | Kind::Start
                        | Kind::Switch
                        | Kind::Stop
                        | Kind::Export
                        | Kind::Probe
                        | Kind::EnvironmentCreate
                        | Kind::EnvironmentEdit
                        | Kind::EnvironmentBackup
                        | Kind::EnvironmentDelete
                        | Kind::ResetDnsAliases
                        | Kind::Abandon
                )
            {
                self.logs_refresh_pending = true;
            }
            if self.logs_refresh_pending && self.busy.is_none() && !self.reading {
                self.refresh_logs(cx);
            }
            if matches!(reply.kind, Kind::Bootstrap | Kind::List | Kind::Save)
                && self.page == Page::Environment
            {
                self.open_target_environment(window, cx);
            }
            cx.notify();
        }
        if let Some(action) = super::tray::consume_action() {
            match action {
                super::tray::TrayAction::Refresh => self.refresh_or_reconnect(cx),
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
        if self.confirmation_pending && !self.loading_dialog_open {
            self.confirmation_pending = false;
            self.open_confirmation_dialog(window, cx);
        }
        if self.backup_result_pending
            && !self.loading_dialog_open
            && !self.backup_result_dialog_open
        {
            self.backup_result_pending = false;
            self.open_backup_result_dialog(window, cx);
        }
        if self.environment_result_pending.is_some()
            && !self.loading_dialog_open
            && !self.environment_result_dialog_open
        {
            self.open_environment_result_dialog(window, cx);
        }
        if matches!(
            self.busy,
            Some(Kind::EnvironmentCreate | Kind::EnvironmentEdit)
        ) {
            cx.notify();
        }
    }

    /// 后台按新到旧返回一页，页面照此显示：最新的在顶部，「加载更早」接在底部。
    fn accept_logs(&mut self, value: &Value, append: bool) {
        let logs = value["logs"]
            .as_array()
            .map(|items| items.iter().filter_map(RuntimeLog::from_value).collect())
            .unwrap_or_default();
        if append {
            self.logs.extend(logs);
        } else {
            self.logs = logs;
            // 刷新后回到顶部，停在最新的一条。
            self.logs_scroll.scroll_to_item(0, ScrollStrategy::Top);
        }
        self.logs_total = value["total"].as_u64().unwrap_or(self.logs.len() as u64);
        self.logs_has_more = value["has_more"].as_bool().unwrap_or(false);
        self.logs_before_id = value["next_before_id"].as_i64();
    }

    fn accept_status(&mut self, status: Value) {
        if status["phase"].is_string() && status["operation_generation"].is_u64() {
            let traffic = &status["forwarding"]["traffic"];
            if traffic.is_object() {
                // 后台的速率是浮点数。每次有效快照都采样（包括 0），横轴才对应真实时间。
                let rate = |key: &str| traffic[key].as_f64().unwrap_or_default().max(0.) as f32;
                self.traffic_history.push(super::model::TrafficSample {
                    at: Instant::now(),
                    tx: rate("tx_bytes_per_sec"),
                    rx: rate("rx_bytes_per_sec"),
                });
                if self.traffic_history.len() > TRAFFIC_SAMPLE_LIMIT {
                    let excess = self.traffic_history.len() - TRAFFIC_SAMPLE_LIMIT;
                    self.traffic_history.drain(0..excess);
                }
            } else {
                // 未接管或需要恢复时没有转发观测，不保留上一次接管的曲线。
                self.traffic_history.clear();
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
            self.live_connections = super::model::ConnectionRow::live_list(
                &status["forwarding"]["connections"],
                status["active_target"].as_str(),
            );
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
        self.save_error = false;
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
        // 留空表示用默认值；后台不保存默认值，所以默认时这里是空的。
        for (field, key) in [
            (&self.fields.max_tcp_connections, "max_tcp_connections"),
            (&self.fields.tcp_idle_timeout, "tcp_idle_timeout_seconds"),
            (
                &self.fields.tcp_half_close_timeout,
                "tcp_half_close_timeout_seconds",
            ),
        ] {
            let value = self.profile[key]
                .as_u64()
                .map(|value| value.to_string())
                .unwrap_or_default();
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
