//! 负责窗口初始化、后台轮询和后台返回值归并，不承载页面布局。

use std::time::{Duration, Instant};

const UI_TICK_INTERVAL: Duration = Duration::from_millis(200);
const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// 按 2 秒一次的状态轮询，约保留最近 2 分钟的速率样本。
const TRAFFIC_SAMPLE_LIMIT: usize = 60;
/// 首页事件时间线显示的运行日志条数。
const EVENT_LIMIT: usize = 5;

use gpui_kit::component::WindowExt as _;
use gpui_kit::component::input::{InputEvent, InputState, TextareaState};
use gpui_kit::component::notification::Notification;
use gpui_kit::component::select::{SelectEvent, SelectState};
use gpui_kit::{prelude::*, *};
use serde_json::{Value, json};

use super::backend::{Job, Kind, Reply, worker};
use super::components::design_icon;
use super::drafts::{
    FailedSaves, SaveScope, Unsaved, names_target, profile_fields, saved_fake_ip,
    saved_residential_text, saved_text, target_missing,
};
use super::model::{
    EnvironmentProgress, EnvironmentResult, Field, Fields, LogFilter, Page, RuntimeLog,
    progress_marker,
};
use super::state::{Desktop, Reminder};
use super::theme::{RUST, TEAL};

/// 保存结果通知的编号：同一时间只留一条，新的结果顶替旧的。
struct SaveNotice;

/// 弹出保存结果通知（gpui-kit Notification，悬浮在窗口右上角）。成功 5 秒后自动消失；
/// 失败要用户自己关掉，免得原因还没看完就没了。不设通知类型：设了类型组件就用类型自带的
/// 图标，颜色取 `theme.success`，而这个应用把它设成了浅底色，图标会看不清。
fn push_save_notice(result: Result<String, String>, window: &mut Window, cx: &mut App) {
    let notification = match result {
        Ok(message) => Notification::new()
            .message(message)
            .icon(design_icon("check", 16., TEAL)),
        Err(message) => Notification::new()
            .message(message)
            .icon(design_icon("info", 16., RUST))
            .autohide(false),
    }
    .id::<SaveNotice>();
    window.remove_notification::<SaveNotice>(cx);
    window.push_notification(notification, cx);
}

/// 提醒通知的编号：和保存结果分开，两种通知互不顶替。
struct ReminderNotice;

/// 弹出提醒：警告类（如 UDP 已阻断）要用户自己关掉，其余 5 秒后自动消失。
/// 同保存结果通知一样不设通知类型，图标颜色自己给。
fn push_reminder(reminder: Reminder, window: &mut Window, cx: &mut App) {
    let notification = if reminder.warning {
        Notification::new()
            .message(reminder.message)
            .icon(design_icon("info", 16., RUST))
            .autohide(false)
    } else {
        Notification::new()
            .message(reminder.message)
            .icon(design_icon("info", 16., TEAL))
    }
    .id::<ReminderNotice>();
    window.remove_notification::<ReminderNotice>(cx);
    window.push_notification(notification, cx);
}

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
            direct_dns_upstream: input(window, cx, "国内 DoH：IPv4:端口，留空则关闭", false),
            direct_dns_tls_name: input(window, cx, "留空为默认 dns.alidns.com", false),
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
        // 每个输入框属于哪一页的保存；环境表单的输入框不属于任何一页的保存。
        let settings = Some(SaveScope::Settings);
        for (field, scope) in [
            (&fields.first_hop, settings),
            (&fields.residential_ip, settings),
            (&fields.residential_port, settings),
            (&fields.residential_username, settings),
            (&fields.residential_password, settings),
            (&fields.dns_upstream, settings),
            (&fields.dns_tls_name, settings),
            (&fields.health_domain, settings),
            (&fields.direct_dns_upstream, settings),
            (&fields.direct_dns_tls_name, settings),
            (&fields.max_tcp_connections, settings),
            (&fields.tcp_idle_timeout, settings),
            (&fields.tcp_half_close_timeout, settings),
            (&fields.port, settings),
            (&fields.environment_name, None),
            (&fields.environment_distribution, None),
            (&fields.environment_install, None),
            (&fields.environment_backup, None),
            (&fields.environment_username, None),
            (&fields.environment_password, None),
            (&fields.environment_timezone, None),
        ] {
            if let Field::Single(field) = field {
                subscriptions.push(cx.subscribe(field, move |this, _, event, cx| {
                    if matches!(event, InputEvent::Change) && !this.loading_fields {
                        this.input_edited(scope, cx);
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
                        this.input_edited(Some(SaveScope::Policy), cx);
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
            logs_in_flight: false,
            logs_error: None,
            events: Vec::new(),
            events_loaded: false,
            events_in_flight: false,
            events_error: None,
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
            reading_kind: None,
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
            unsaved: Unsaved::default(),
            saving: None,
            clearing_target: false,
            loading_fields: false,
            preflight: None,
            pending_prepare: None,
            notice: "正在连接后台；关闭窗口只会收进托盘，从托盘退出才会停止接管并关闭后台。".into(),
            error: false,
            failed_saves: FailedSaves::default(),
            dialog_error: None,
            autostart_enabled: super::autostart::enabled().unwrap_or(false),
            fake_ip_draft: true,
            confirmation: None,
            confirmation_pending: false,
            kernel_prepare_offered: false,
            exiting: false,
            exit_anyway_pending: false,
            exit_anyway_reason: None,
            export_path: None,
            environment_editor: None,
            environment_edit_target: None,
            environment_selected: None,
            environment_detail: None,
            environment_started: None,
            environment_progress_snapshot: None,
            environment_progress_reading: false,
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
            wsl_platform: None,
            wsl_platform_error: None,
            wsl_platform_at: None,
            wsl_platform_checking: false,
            wsl_update_result: None,
            residential_probe: None,
            residential_probe_error: None,
            residential_probe_at: None,
            residential_probe_checking: false,
            save_notice: None,
            reminder: None,
            island_enabled: super::island::enabled_preference(),
            updater: super::update::Updater::new(),
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
        } else if matches!(kind, Kind::Connections | Kind::Logs) {
            // 后台静默读取：不置 reading，不弹加载框，也不改页面提示。
            // 在途请求各自用 `connection_history.requested` 和 `logs_in_flight` 标记。
        } else if kind == Kind::WslPlatform {
            // 平台检查同样是后台静默读取；卡片自己显示「检查中」，结果只写进卡片。
            self.wsl_platform_checking = true;
            self.wsl_platform_error = None;
        } else if kind == Kind::ResidentialProbe {
            // 住宅代理检测同样静默：不锁界面，卡片自己显示「检测中」，结果只写进卡片。
            self.residential_probe_checking = true;
            self.residential_probe_error = None;
        } else {
            if self.reading || self.busy.is_some() {
                return;
            }
            self.reading = true;
            self.reading_kind = Some(kind);
        }
        // 重新保存这一页时先去掉它的「保存失败」；别的页保持原样。
        if kind == Kind::Save
            && let Some(scope) = self.saving
        {
            self.failed_saves.remove(scope);
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
            self.reading_kind = None;
            self.refreshing = false;
            self.pending_prepare = None;
            if kind == Kind::EnvironmentEdit {
                self.environment_timezone_only = false;
            }
            self.status_valid = false;
            if kind == Kind::Save
                && let Some(scope) = self.saving.take()
            {
                self.failed_saves.insert(scope);
            }
            if kind == Kind::Logs {
                self.logs_loading_more = false;
                self.logs_in_flight = false;
            }
            // 否则 WSL 平台卡片会一直停在「检查中」，「检查」按钮也一直禁用。
            if kind == Kind::WslPlatform {
                self.wsl_platform_checking = false;
            }
            if kind == Kind::ResidentialProbe {
                self.residential_probe_checking = false;
            }
            self.fail("后台通信线程已退出，请重新打开窗口。", cx);
        } else {
            // 页面提示文字记录用户操作的进展和结果。读日志、读环境详情是切页面时
            // 自动发出的，不能覆盖它，否则「预检未通过」这类原因会被冲掉。
            if !matches!(
                kind,
                Kind::Status
                    | Kind::Connections
                    | Kind::Logs
                    | Kind::EnvironmentView
                    | Kind::WslPlatform
                    | Kind::ResidentialProbe
            ) {
                self.notice = match kind {
                    Kind::EnvironmentCreate => "正在创建环境并安装组件…".into(),
                    Kind::EnvironmentEdit if self.environment_timezone_only => {
                        "正在更新时区并刷新环境详情…".into()
                    }
                    Kind::EnvironmentEdit => "正在安装组件并刷新环境能力…".into(),
                    Kind::WslUpdate => {
                        "正在运行 wsl --update 升级 WSL；期间 WSL 会重启，所有发行版中的程序都会停止。"
                            .into()
                    }
                    _ => format!("{}中…", kind.label()),
                };
                self.error = false;
            }
            cx.notify();
        }
    }

    /// 读取日志第一页。已有请求在途（例如连续输入搜索词）或有操作在执行时只记下
    /// 「待刷新」，等在途回复或操作结束后再按当前筛选读一次，同一时间最多一个请求。
    pub(crate) fn refresh_logs(&mut self, cx: &mut Context<Self>) {
        if self.logs_in_flight || self.busy.is_some() {
            self.logs_refresh_pending = true;
            return;
        }
        self.logs_refresh_pending = false;
        self.logs_before_id = None;
        self.logs_loading_more = false;
        let search = Self::field_value(&self.fields.log_search, cx)
            .trim()
            .to_owned();
        self.logs_in_flight = true;
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
        if self.logs_loading_more
            || !self.logs_has_more
            || self.logs_in_flight
            || self.busy.is_some()
        {
            return;
        }
        let search = Self::field_value(&self.fields.log_search, cx)
            .trim()
            .to_owned();
        self.logs_loading_more = true;
        self.logs_in_flight = true;
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

    /// 读取首页时间线用的最新几条运行日志。直接交给后台线程而不经过 `send`：这是静默
    /// 读取，不置 `reading`、不改页面提示，发送失败也不改「状态是否有效」。
    /// 同一时间只有一个在途请求。
    pub(crate) fn refresh_events(&mut self, cx: &mut Context<Self>) {
        if self.events_in_flight {
            return;
        }
        let job = Job {
            kind: Kind::Events,
            epoch: self.epoch,
            request: json!({"command": "runtime_logs", "limit": EVENT_LIMIT}),
        };
        if self.sender.send(job).is_err() {
            self.events_error = Some("后台通信线程已退出，请重新打开窗口。".into());
            cx.notify();
            return;
        }
        self.events_in_flight = true;
    }

    /// 后台按新到旧返回日志，取最前面几条。
    fn accept_events(&mut self, value: &Value) {
        self.events = value["logs"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(RuntimeLog::from_value)
            .take(EVENT_LIMIT)
            .collect();
        self.events_loaded = true;
        self.events_error = None;
    }

    /// 读取失败只写在时间线卡片里，保留上次读到的事件。
    fn accept_events_reply(&mut self, result: Result<Value, String>) {
        self.events_in_flight = false;
        match result {
            Ok(value) => self.accept_events(&value),
            Err(error) => self.events_error = Some(super::backend::humanize_error(&error)),
        }
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

    /// 日志读取的回复。失败只写在日志页上，不改全局提示。请求在途时又要求过刷新
    /// （换了筛选、改了搜索词或有操作完成），这次结果已经过时：丢弃并按当前条件重读。
    fn accept_logs_reply(&mut self, result: Result<Value, String>, cx: &mut Context<Self>) {
        self.logs_in_flight = false;
        let append = std::mem::take(&mut self.logs_loading_more);
        if self.logs_refresh_pending {
            if self.busy.is_none() {
                self.refresh_logs(cx);
            }
            return;
        }
        match result {
            Ok(value) => {
                self.logs_error = None;
                self.accept_logs(&value, append);
            }
            Err(error) => self.logs_error = Some(super::backend::humanize_error(&error)),
        }
    }

    /// 平台检查是静默读取：结果只写进设置页卡片，不动页面提示和全局错误条。
    fn accept_wsl_platform(&mut self, result: Result<Value, String>) {
        self.wsl_platform_checking = false;
        match result {
            Ok(value) => {
                self.wsl_platform = Some(value);
                self.wsl_platform_at = Some(Instant::now());
                self.wsl_platform_error = None;
            }
            Err(error) => {
                self.wsl_platform_error = Some(super::backend::humanize_error(&error));
            }
        }
    }

    /// 住宅代理检测同样是静默的：结果只写进设置页住宅代理卡片，不动页面提示和全局错误条。
    fn accept_residential_probe(&mut self, result: Result<Value, String>) {
        self.residential_probe_checking = false;
        match result {
            Ok(value) => {
                self.residential_probe = Some(value["residential_probe"].clone());
                self.residential_probe_at = Some(Instant::now());
                self.residential_probe_error = None;
            }
            Err(error) => {
                self.residential_probe_error = Some(super::backend::humanize_error(&error));
            }
        }
    }

    /// 环境操作进行中时，在后台线程读进度文件和安装目录，结果写进 `environment_progress_snapshot`。
    /// 字段值和路径在 UI 线程上取好，后台只做文件系统调用。
    fn refresh_environment_progress(&mut self, cx: &mut Context<Self>) {
        let creating = self.busy == Some(Kind::EnvironmentCreate);
        if !creating && self.busy != Some(Kind::EnvironmentEdit)
            || self.environment_timezone_only
            || self.environment_progress_reading
        {
            return;
        }
        let name = if creating {
            Self::field_value(&self.fields.environment_name, cx)
        } else {
            self.environment_edit_target.clone().unwrap_or_default()
        };
        if name.is_empty() {
            return;
        }
        let install = if creating {
            let base = Self::field_value(&self.fields.environment_install, cx);
            (!base.is_empty()).then(|| Self::environment_install_path(&base, &name))
        } else {
            None
        };
        // The controller writes this file beside its EXE, which is this EXE's sibling.
        let progress_file = wsl_proxyctl::paths::data_dir()
            .ok()
            .map(|directory| directory.join(format!("environment-progress-{name}.json")));
        let epoch = self.epoch;
        self.environment_progress_reading = true;
        cx.spawn(async move |view, cx| {
            let progress = cx
                .background_executor()
                .spawn(async move {
                    EnvironmentProgress {
                        epoch,
                        target_ready: install
                            .is_some_and(|path| std::path::Path::new(&path).is_dir()),
                        marker: progress_file
                            .and_then(|path| std::fs::read_to_string(path).ok())
                            .and_then(|text| progress_marker(&text)),
                    }
                })
                .await;
            let _ = view.update(cx, |this, cx| {
                this.environment_progress_reading = false;
                // 读的期间这次操作已经结束或换了一次，结果作废。
                if progress.epoch == this.epoch && this.busy.is_some() {
                    this.environment_progress_snapshot = Some(progress);
                    cx.notify();
                }
            });
        })
        .detach();
    }

    fn tick(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.refresh_environment_progress(cx);
        self.update_tick(window, cx);
        while let Ok(reply) = self.replies.try_recv() {
            self.handle_reply(reply, window, cx);
        }
        let operation_active = self.busy.is_some() || self.reading;
        if self.loading_dialog_open && !operation_active {
            window.close_dialog(cx);
            self.loading_dialog_open = false;
        } else if operation_active && !self.loading_dialog_open {
            self.open_loading_dialog(window, cx);
        }
        // 托盘动作放在关加载框之后：`close_dialog` 关的是最上层的对话框，
        // 托盘「停止」在同一帧打开的确认框会被当成加载框关掉，留下关不掉的加载框。
        self.handle_tray_action(window, cx);
        // 每次都发布：窗口藏在托盘里时不重绘，托盘图标和状态岛只能靠这里跟上状态。
        let snapshot = self.tray_snapshot();
        let rates = self
            .traffic_history
            .last()
            .map(|sample| super::island::Rates {
                up: sample.tx,
                down: sample.rx,
            });
        let details = self.island_details();
        super::island::sync(&snapshot, rates, details, super::theme::is_dark(), cx);
        super::tray::publish(snapshot);
        // 退出进行中不轮询：后台关闭后再查状态只会报连不上。
        if !self.exiting && self.last_poll.elapsed() >= STATUS_POLL_INTERVAL {
            self.last_poll = Instant::now();
            self.send(Kind::Status, json!({"command":"status"}), cx);
        }
        if self.confirmation_pending && !self.loading_dialog_open {
            self.confirmation_pending = false;
            self.open_confirmation_dialog(window, cx);
        }
        if self.exit_anyway_pending && !self.loading_dialog_open {
            self.exit_anyway_pending = false;
            self.open_exit_anyway_dialog(window, cx);
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
        if let Some(result) = self.save_notice.take() {
            push_save_notice(result, window, cx);
        }
        if let Some(reminder) = self.reminder.take() {
            super::island::notify(&reminder.message, reminder.warning, cx);
            push_reminder(reminder, window, cx);
        }
        if matches!(
            self.busy,
            Some(Kind::EnvironmentCreate | Kind::EnvironmentEdit)
        ) {
            cx.notify();
        }
    }

    /// 处理后台的一条回复。各类读取的结果先单独处理；其余按成功或失败更新页面，
    /// 再统一收尾（状态错误、退出流程、环境结果框、日志刷新），收尾部分依赖这里的顺序。
    fn handle_reply(&mut self, reply: Reply, window: &mut Window, cx: &mut Context<Self>) {
        if reply.kind == Kind::Connections {
            self.accept_connection_history(reply.result, cx);
            cx.notify();
            return;
        }
        if reply.kind == Kind::Events {
            self.accept_events_reply(reply.result);
            cx.notify();
            return;
        }
        if reply.kind == Kind::Logs {
            self.accept_logs_reply(reply.result, cx);
            cx.notify();
            return;
        }
        if reply.kind == Kind::WslPlatform {
            self.accept_wsl_platform(reply.result);
            cx.notify();
            return;
        }
        if reply.kind == Kind::ResidentialProbe {
            self.accept_residential_probe(reply.result);
            cx.notify();
            return;
        }
        if reply.kind == Kind::Status {
            self.refreshing = false;
            if reply.epoch != self.epoch || self.busy.is_some() {
                return;
            }
        } else if reply.kind.mutation() {
            self.busy = None;
            if matches!(reply.kind, Kind::EnvironmentCreate | Kind::EnvironmentEdit) {
                self.environment_started = None;
                self.environment_progress_snapshot = None;
            }
        } else {
            self.reading = false;
            self.reading_kind = None;
        }
        if reply.kind == Kind::Shutdown {
            self.finish_exit(reply.result, cx);
            cx.notify();
            return;
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
            Kind::EnvironmentCreate
                | Kind::EnvironmentEdit
                | Kind::EnvironmentDelete
                | Kind::WslUpdate
        );
        let result_succeeded = reply.result.is_ok();
        // 这次回复让发行版列表变成了后台的最新结果。删除环境后列表读取失败时，
        // 本地列表只去掉被删的那一个，同样可以用来判断目标还在不在。
        let distributions_known = match (&reply.result, reply.kind) {
            (Ok(value), Kind::Bootstrap) => value["distributions"].is_array(),
            (Ok(value), Kind::List) => value.is_array(),
            (Ok(_), Kind::EnvironmentDelete) => true,
            _ => false,
        };
        match reply.result {
            Err(error) => self.on_reply_error(reply.kind, error, cx),
            Ok(value) => self.on_reply_value(reply.kind, value, window, cx),
        }
        if let Some(error) = status_error {
            self.fail(error, cx);
        }
        if self.exiting && reply.kind == Kind::Stop {
            self.continue_exit_after_stop(result_succeeded, cx);
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
        // 放在环境结果框记下提示之后，免得结果框里显示成「保存修改中…」。
        if distributions_known {
            self.clear_missing_target(cx);
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
        if self.logs_refresh_pending && self.busy.is_none() && !self.logs_in_flight {
            self.refresh_logs(cx);
        }
        cx.notify();
    }

    /// 后台拒绝或执行失败：标记失败的保存页，按操作类型写失败提示。
    fn on_reply_error(&mut self, kind: Kind, error: String, cx: &mut Context<Self>) {
        if matches!(kind, Kind::Status | Kind::Bootstrap) {
            self.status_valid = false;
        }
        if kind == Kind::Preflight {
            self.pending_prepare = None;
        }
        let failed_save = if kind == Kind::Save {
            self.saving.take()
        } else {
            None
        };
        if let Some(scope) = failed_save {
            self.failed_saves.insert(scope);
        }
        let readable_error = super::backend::humanize_error(&error);
        let clearing_target = kind == Kind::Save && std::mem::take(&mut self.clearing_target);
        let message = match kind {
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
            Kind::WslUpdate => readable_error,
            Kind::Save if clearing_target => {
                format!("原接管目标已不在 WSL 里，但自动清除保存的目标失败：{readable_error}")
            }
            Kind::Save => format!(
                "{}失败：{readable_error}",
                failed_save.map_or("保存修改", SaveScope::action)
            ),
            _ => format!("{}失败：{readable_error}", kind.label()),
        };
        // 用户发起的保存用保存结果通知提示，不再弹全局错误条。
        // 自动清除失效目标不是用户发起的，失败仍走全局错误条。
        if failed_save.is_some() && !clearing_target {
            self.save_notice = Some(Err(message.clone()));
            self.notice = message;
            self.error = false;
            cx.notify();
        } else {
            self.fail(message, cx);
        }
    }

    /// 后台成功返回：按操作类型更新页面。
    fn on_reply_value(
        &mut self,
        kind: Kind,
        value: Value,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match kind {
            Kind::Bootstrap => {
                if let Some(distributions) = value["distributions"].as_array() {
                    self.distributions = distributions.clone();
                    self.forget_missing_environment();
                }
                // 重连时保留没保存的输入：有改动的页不动输入框，其余页和版本号都换成
                // 后台最新的，之后的保存不会因为版本号过期被拒。
                self.accept_profile_keeping_edits(&value["profile"], window, cx);
                self.accept_status(value["status"].clone());
                self.accept_logs(&value["logs"], false);
                // 连接时读到的就是未筛选的最新日志，首页时间线直接用它。
                // 读日志失败时两处都显示读取失败，不能当成「暂无记录」。
                match value["logs"]["error"].as_str() {
                    Some(error) => {
                        let error = super::backend::humanize_error(error);
                        self.logs_error = Some(error.clone());
                        self.events_error = Some(error);
                    }
                    None => {
                        self.logs_error = None;
                        self.accept_events(&value["logs"]);
                    }
                }
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
                        Some("wsl_platform_update") => "升级 WSL 平台",
                        _ => "环境操作",
                    };
                    self.notice = if job["command"] == "wsl_platform_update" {
                        format!(
                            "后台正在{operation}，完成前不能启动接管或管理环境；结果见运行日志。"
                        )
                    } else {
                        format!(
                            "后台正在{operation}（{}），完成前不能启动接管或管理环境；结果见运行日志。",
                            job["target"].as_str().unwrap_or("未知环境")
                        )
                    };
                    self.reminder = Some(Reminder {
                        message: self.notice.clone(),
                        warning: true,
                    });
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
                // 首页打开时跟着状态轮询刷新时间线，状态切换和操作结果几秒内出现。
                if self.page == Page::Overview {
                    self.refresh_events(cx);
                }
            }
            // 已在循环开头单独处理，不会走到这里。
            Kind::Events => {}
            // 已在循环开头单独处理，不会走到这里。
            Kind::Connections => {}
            // 已在循环开头单独处理，不会走到这里。
            Kind::WslPlatform => {}
            // 已在循环开头单独处理，不会走到这里。
            Kind::ResidentialProbe => {}
            Kind::List => {
                self.distributions = value.as_array().cloned().unwrap_or_default();
                // 和自动清除用同一条规则判断目标还在不在，界面和库里才不会不一致。
                if target_missing(self.selected.as_deref(), &self.distributions) {
                    self.selected = None;
                }
                self.forget_missing_environment();
                self.preflight = None;
                self.pending_prepare = None;
                self.unsaved = self.draft_unsaved(cx);
                self.notice = "列表已刷新；未启动 WSL。".into();
            }
            // 已在循环开头单独处理，不会走到这里。
            Kind::Logs => {}
            // 只重置这次保存的那一页；其他页没保存的输入原样保留。
            Kind::Save => match self.saving.take() {
                Some(scope) => {
                    self.accept_record(&value);
                    self.load_saved_fields(scope, window, cx);
                    self.unsaved = self.draft_unsaved(cx);
                    self.failed_saves.remove(scope);
                    if scope == SaveScope::Environment {
                        self.preflight = None;
                        self.pending_prepare = None;
                    }
                    let clearing_target = std::mem::take(&mut self.clearing_target);
                    self.notice = if clearing_target {
                        format!(
                            "{}原接管目标已不在 WSL 里，已自动清除；请到「环境」页重新设定目标。",
                            self.notice
                        )
                    } else {
                        match self.unsaved.pages() {
                            Some(pages) => {
                                format!("{}{pages}还有未保存的修改。", scope.saved_notice())
                            }
                            None => scope.saved_notice().into(),
                        }
                    };
                    // 用户发起的保存（含环境页「设为目标」）用保存结果通知提示；
                    // 自动清除目标不是用户发起的，作为提醒弹出，要用户自己关掉。
                    if clearing_target {
                        self.reminder = Some(Reminder {
                            message: self.notice.clone(),
                            warning: true,
                        });
                    } else {
                        self.save_notice = Some(Ok(self.notice.clone()));
                    }
                }
                // 不知道保存的是哪一页时按已保存的配置全部重置。
                None => {
                    self.accept_profile(&value, window, cx);
                    self.notice = "配置已保存；不会立即改变当前接管。".into();
                }
            },
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
                if passed {
                    self.kernel_prepare_offered = false;
                    self.error = false;
                    if let Some(pending) = self.pending_prepare.take() {
                        let selection_matches = matches!(
                            self.selection(cx),
                            Ok((target, port))
                                if target == pending.target && port == pending.port
                        );
                        if self.generation() == Some(pending.generation) && selection_matches {
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
                    let kernel_gap = super::backend::kernel_gap(&blockers);
                    let pending_kind = self.pending_prepare.as_ref().map(|pending| pending.kind);
                    // 切换时旧目标还在接管中，不能加载模块；只有从空闲启动才询问。
                    if super::backend::offer_kernel_prepare(
                        pending_kind,
                        self.kernel_prepare_offered,
                        &blockers,
                    ) {
                        self.kernel_prepare_offered = true;
                        let pending = self
                            .pending_prepare
                            .take()
                            .expect("pending was checked above");
                        self.prompt_kernel_prepare(pending, cx);
                    } else {
                        let switch_blocked = kernel_gap && pending_kind == Some(Kind::Switch);
                        self.pending_prepare = None;
                        let mut notice = if let Some(notice) =
                            super::backend::kernel_release_notice(&blockers)
                        {
                            notice
                        } else if blockers.is_empty() {
                            "预检未通过，请检查当前环境。".into()
                        } else {
                            format!("预检未通过：{}", blockers.join("；"))
                        };
                        if switch_blocked {
                            notice
                                .push_str("。目标内核能力未就绪；需要先停止当前接管，再重新开始。");
                        }
                        self.notice = notice;
                    }
                }
            }
            Kind::PrepareKernel => {
                self.preflight = None;
                let (notice, needs_attention) = super::backend::kernel_prepare_notice(&value);
                self.notice = notice;
                self.error = needs_attention;
                let ready = value["preparation"]["ok"] == true
                    && value["preparation"]["modules_failed"]
                        .as_array()
                        .is_none_or(|items| items.is_empty())
                    && value["inspection_error"].is_null();
                if ready {
                    // 预检因为缺少内核能力而停在这里：加载成功后自动重跑，
                    // 通过就接着弹启动确认，不要求用户再点一次启动。
                    if let Some((target, port)) = self
                        .pending_prepare
                        .as_ref()
                        .map(|pending| (pending.target.clone(), pending.port))
                    {
                        self.send(
                            Kind::Preflight,
                            json!({"command":"preflight","target":target,"port":port}),
                            cx,
                        );
                        if self.reading {
                            self.notice = "内核能力已就绪，正在重新预检…".into();
                        }
                    }
                } else {
                    self.pending_prepare = None;
                }
            }
            Kind::Export => {
                self.export_path = value["path"].as_str().map(str::to_owned);
                self.notice = "诊断已导出；请按内部资料处理。".into();
            }
            Kind::Abandon => {
                self.accept_status(value);
                self.notice =
                    "已放弃本次接管记录。下次启动接管前，请先执行一次 wsl --shutdown。".into();
                self.error = false;
            }
            Kind::ResetDnsAliases => {
                self.notice = "DNS 别名记录已清空，下次启动接管时重新分配。".into();
                self.error = false;
            }
            // 已在循环开头单独处理，不会走到这里。
            Kind::Shutdown => {}
            Kind::Probe => {
                self.accept_status(value);
                self.notice = "出口检测完成；仅代表本次结果。".into();
            }
            // 读详情是切页面、点列表时自动发出的，不改页面提示，保留之前操作的结果。
            Kind::EnvironmentView => self.accept_environment_detail(value, window, cx),
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
                if self
                    .selected
                    .as_deref()
                    .is_some_and(|target| names_target(&value["environment"], target))
                {
                    self.selected = None;
                    self.preflight = None;
                    self.pending_prepare = None;
                    self.unsaved = self.draft_unsaved(cx);
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
            Kind::WslUpdate => {
                // 升级结果按版本前后变化说明；随后重新检查，卡片显示升级后的版本。
                let update = value["update"].clone();
                self.notice = super::backend::wsl_update_notice(&update);
                self.error = false;
                self.wsl_update_result = Some(update);
                self.wsl_platform = None;
                self.wsl_platform_at = None;
                self.wsl_platform_error = None;
                self.check_wsl_platform(cx);
            }
            Kind::Start | Kind::Switch | Kind::Stop => {
                if value["passed"] == false {
                    let blockers: Vec<String> = value["blockers"]
                        .as_array()
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(|item| item.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    // 改时区并重启之后的那次预检没过：时区已经改了，接管没有启动。
                    let restarted = value["timezone_synced"]
                        .as_str()
                        .map(|timezone| format!("目标时区已改为 {timezone} 并已重启目标，但重启后的预检没有通过，接管没有启动。"))
                        .unwrap_or_default();
                    self.preflight = Some(value);
                    match super::backend::kernel_release_notice(&blockers) {
                        Some(notice) => self.fail(format!("{restarted}{notice}"), cx),
                        None => {
                            self.fail(format!("{restarted}操作前预检未通过；请查看阻断项。"), cx)
                        }
                    }
                } else {
                    let udp_blocked =
                        kind != Kind::Stop && value["startup_verified"]["udp_supported"] == false;
                    self.notice = if udp_blocked {
                        format!(
                            "{}已完成，但住宅出口没有通过 UDP 探测：UDP（含 QUIC，直连例外也一样）已阻断，不会直连；TCP 和系统 DNS 照常经代理链。",
                            kind.label()
                        )
                    } else {
                        format!("{}已完成；请以后台状态为准。", kind.label())
                    };
                    if let Some(timezone) = value["timezone_synced"].as_str() {
                        self.notice =
                            format!("目标时区已改为 {timezone} 并已重启目标。{}", self.notice);
                    }
                    if udp_blocked {
                        self.reminder = Some(Reminder {
                            message: self.notice.clone(),
                            warning: true,
                        });
                    }
                    self.preflight = None;
                }
            }
        }
    }

    /// 托盘菜单的动作。退出进行中不再响应：后台可能已经关闭。
    /// 菜单是按点开那一刻的状态画的，到这里状态可能已经变了，所以每个动作照旧自己检查。
    fn handle_tray_action(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        use super::tray::Command;
        let Some(action) = super::tray::consume_action().filter(|_| !self.exiting) else {
            return;
        };
        match action {
            // 托盘自己打开窗口，不经过界面。
            Command::Open => {}
            Command::Exit => self.request_exit(cx),
            Command::Reconnect => self.refresh_or_reconnect(cx),
            Command::ChooseTarget => self.open_page(Page::Environment, cx),
            Command::GoSave => self.open_page(self.unsaved_page(), cx),
            Command::Connections => self.open_page(Page::Connection, cx),
            Command::Logs => self.open_page(Page::Logs, cx),
            Command::Start => {
                self.page = Page::Overview;
                match self.phase() {
                    "idle" => self.prepare(Kind::Start, window, cx),
                    "unknown" => self.fail("后台状态未确认，请先刷新。", cx),
                    _ => self.fail("当前已有接管任务，请先停止接管并恢复直连。", cx),
                }
            }
            Command::Stop => {
                self.page = Page::Overview;
                if self.phase() == "idle" {
                    self.notice = "当前没有正在接管的目标。".into();
                    self.error = false;
                    self.reminder = Some(Reminder {
                        message: self.notice.clone(),
                        warning: false,
                    });
                    cx.notify();
                } else {
                    self.prepare(Kind::Stop, window, cx);
                }
            }
            Command::Abandon => {
                self.page = Page::Overview;
                if self.target_gone() {
                    self.prepare(Kind::Abandon, window, cx);
                } else {
                    self.fail(
                        "目标发行版仍在 WSL 注册表里，不需要放弃记录；请用「停止并恢复直连」。",
                        cx,
                    );
                }
            }
            Command::Probe => {
                self.page = Page::Connection;
                self.probe(cx);
            }
            Command::Island => {
                let wanted = !self.island_enabled;
                self.set_island(wanted, cx);
            }
            Command::Autostart => {
                let wanted = !self.autostart_enabled;
                self.set_autostart(wanted, cx);
                // 没改成：窗口还藏在托盘里，叫出来让用户看到错误条。
                if self.autostart_enabled != wanted {
                    super::tray::show_main_window();
                }
            }
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

    /// 列表里已经没有正在查看的环境（比如在别处删掉了）：右侧详情一起清掉，
    /// 免得对着不存在的环境点编辑、备份、删除。
    fn forget_missing_environment(&mut self) {
        let gone = self
            .environment_selected
            .as_deref()
            .is_some_and(|selected| {
                !self
                    .distributions
                    .iter()
                    .any(|distro| names_target(distro, selected))
            });
        if gone {
            self.environment_selected = None;
            self.environment_detail = None;
            self.environment_backup_target = None;
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

    /// 后台返回的已保存配置；全部输入框都按它重置。
    fn accept_profile(&mut self, result: &Value, window: &mut Window, cx: &mut Context<Self>) {
        self.accept_record(result);
        for scope in [
            SaveScope::Environment,
            SaveScope::Policy,
            SaveScope::Settings,
        ] {
            self.load_saved_fields(scope, window, cx);
        }
        self.unsaved = Unsaved::default();
        self.failed_saves = FailedSaves::default();
    }

    /// 后台返回的已保存配置；有未保存输入的页面保留输入框，其余页面按它重置。
    fn accept_profile_keeping_edits(
        &mut self,
        result: &Value,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let unsaved = self.unsaved;
        self.accept_record(result);
        for scope in unsaved.clean_pages() {
            self.load_saved_fields(scope, window, cx);
            self.failed_saves.remove(scope);
        }
        self.unsaved = self.draft_unsaved(cx);
    }

    /// 记下后台返回的已保存配置，不动输入框。
    fn accept_record(&mut self, result: &Value) {
        self.profile = result["profile"].clone();
        self.revision = result["revision"].clone();
        self.profile_exists = result["exists"].as_bool().unwrap_or(false);
        // The daemon validates and owns this stable AppData location; never synthesize a CWD path.
        self.profile_path = result["path"].as_str().map(str::to_owned);
        self.residential = result["residential"].clone();
        let desktop = result.get("desktop");
        self.saved_selected = desktop
            .and_then(|desktop| desktop["target"].as_str())
            .map(str::to_owned);
        if let Some(port) = desktop.and_then(|desktop| desktop["port"].as_u64()) {
            self.saved_port = port.to_string();
        }
    }

    /// 把一页的输入框重置成已保存的值。
    fn load_saved_fields(&mut self, scope: SaveScope, window: &mut Window, cx: &mut Context<Self>) {
        self.loading_fields = true;
        // 留空表示用默认值；后台不保存默认值，所以默认时这里是空的。
        for field in profile_fields(scope) {
            let value = saved_text(&self.profile, field);
            self.profile_input(field).set_value(value, window, cx);
        }
        match scope {
            SaveScope::Environment => self.selected = self.saved_selected.clone(),
            SaveScope::Policy => {}
            SaveScope::Settings => {
                self.fields
                    .port
                    .set_value(self.saved_port.clone(), window, cx);
                self.fake_ip_draft = saved_fake_ip(&self.profile);
                for (field, key) in self.residential_inputs() {
                    let value = saved_residential_text(&self.residential, key);
                    field.set_value(value, window, cx);
                }
            }
        }
        self.loading_fields = false;
    }
}
