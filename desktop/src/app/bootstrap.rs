//! 负责窗口初始化、后台轮询和后台返回值归并，不承载页面布局。

use std::time::{Duration, Instant};

const UI_TICK_INTERVAL: Duration = Duration::from_millis(200);
const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(2);

use gpui::{prelude::*, *};
use gpui_component::input::{InputEvent, InputState};
use serde_json::{Value, json};

use super::backend::{worker, Job, Kind};
use super::model::{Fields, Page};
use super::state::Desktop;

fn input(
    window: &mut Window,
    cx: &mut App,
    hint: &'static str,
    multiline: bool,
) -> Entity<InputState> {
    cx.new(|cx| {
        InputState::new(window, cx)
            .placeholder(hint)
            .multi_line(multiline)
    })
}

impl Desktop {
    pub(crate) fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let fields = Fields {
            first_hop: input(window, cx, "宿主 SOCKS5：IPv4:端口", false),
            credential: input(window, cx, "凭据名称", false),
            dns_upstream: input(window, cx, "DoH 上游：IPv4:端口", false),
            dns_tls_name: input(window, cx, "TLS 主机名，例如 dns.google", false),
            health_domain: input(window, cx, "健康检查域名", false),
            direct_ips: input(window, cx, "每行一个 IPv4 或 CIDR", true),
            direct_domains: input(window, cx, "每行一个精确域名", true),
            direct_suffixes: input(window, cx, "每行一个域名后缀", true),
            port: cx.new(|cx| InputState::new(window, cx).default_value("43531")),
            env_path: input(window, cx, "选择 .env 或输入绝对 Windows 路径", false),
        };
        let mut subscriptions = Vec::new();
        for field in [
            &fields.first_hop,
            &fields.credential,
            &fields.dns_upstream,
            &fields.dns_tls_name,
            &fields.health_domain,
            &fields.direct_ips,
            &fields.direct_domains,
            &fields.direct_suffixes,
        ] {
            subscriptions.push(cx.subscribe(field, |this, _, event, cx| {
                if matches!(event, InputEvent::Change) && !this.loading_fields {
                    this.preflight = None;
                    this.preflight_key = None;
                    this.dirty = this.draft_is_dirty(cx);
                    cx.notify();
                }
            }));
        }
        subscriptions.push(cx.subscribe(&fields.port, |this, _field, event, cx| {
            if matches!(event, InputEvent::Change) && !this.loading_fields {
                this.preflight = None;
                this.preflight_key = None;
                this.dirty = this.draft_is_dirty(cx);
                cx.notify();
            }
        }));
        let (sender, replies) = worker();
        let mut this = Self {
            page: Page::Overview,
            fields,
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
            distributions: Vec::new(),
            selected: None,
            witness: None,
            saved_selected: None,
            saved_witness: None,
            profile: Value::Null,
            profile_path: None,
            revision: Value::Null,
            profile_exists: false,
            dirty: false,
            loading_fields: false,
            preflight: None,
            preflight_key: None,
            notice: "正在连接后台；关闭窗口不会停止接管。".into(),
            error: false,
            confirmation: None,
            export_path: None,
            credential_notice: "只保存凭据名称，不显示秘密。".into(),
        };
        this.send(Kind::Bootstrap, Value::Null, cx);
        cx.spawn_in(window, async move |view, cx| {
            loop {
                Timer::after(UI_TICK_INTERVAL).await;
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
            self.status_valid = false;
            self.fail("后台通信线程已退出，请重新打开窗口。", cx);
        } else {
            if kind != Kind::Status {
                self.notice = format!("{}中…", kind.label());
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
            } else {
                self.reading = false;
            }
            let mut status_error = None;
            if let Some(status) = reply.status {
                match status {
                    Ok(status) => self.accept_status(status),
                    Err(error) => {
                        self.status_valid = false;
                        status_error = Some(format!("操作后无法确认状态：{error}。请刷新。"));
                    }
                }
            }
            match reply.result {
                Err(error) => {
                    if matches!(reply.kind, Kind::Status | Kind::Bootstrap) {
                        self.status_valid = false;
                    }
                    self.fail(format!("{}失败：{error}", reply.kind.label()), cx);
                }
                Ok(value) => match reply.kind {
                    Kind::Bootstrap => {
                        self.distributions = value["distributions"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default();
                        self.accept_profile(&value["profile"], window, cx);
                        self.accept_status(value["status"].clone());
                        self.notice = "后台已连接。请选择目标和对照，然后运行预检。".into();
                        self.error = false;
                    }
                    Kind::Status => {
                        self.accept_status(value);
                    }
                    Kind::List => {
                        self.notice = "列表已刷新；未启动 WSL。".into();
                    }
                    Kind::Save => {
                        self.accept_profile(&value, window, cx);
                        self.notice = "策略已保存；不会立即改变当前接管。".into();
                    }
                    Kind::Preflight => {
                        self.notice = if value["passed"] == true {
                            "预检通过；仍需确认启动。"
                        } else {
                            "预检未通过；请查看阻断项。"
                        }
                        .into();
                        self.preflight = Some(value);
                    }
                    Kind::Import => {
                        self.fields
                            .env_path
                            .update(cx, |state, cx| state.set_value("", window, cx));
                        self.credential_notice = "凭据已写入 Windows 凭据管理器；源文件未删除。".into();
                        self.notice = "凭据已导入；秘密不会显示。".into();
                    }
                    Kind::Forget => {
                        self.credential_notice = "凭据已删除；源文件未删除。".into();
                        self.notice = "凭据已删除。".into();
                    }
                    Kind::Export => {
                        self.export_path = value["path"].as_str().map(str::to_owned);
                        self.notice = "诊断已导出；请按内部资料处理。".into();
                    }
                    Kind::Probe => {
                        self.accept_status(value);
                        self.notice = "出口检测完成；仅代表本次结果。".into();
                    }
                    Kind::Start | Kind::Switch | Kind::Stop => {
                        if value["passed"] == false {
                            self.preflight = Some(value);
                            self.fail("操作前预检未通过；请查看阻断项。", cx);
                        } else {
                            self.notice = format!("{}已完成；请以后台状态为准。", reply.kind.label());
                            self.preflight = None;
                        }
                    }
                },
            }
            if let Some(error) = status_error {
                self.fail(error, cx);
            }
            cx.notify();
        }
        if self.last_poll.elapsed() >= STATUS_POLL_INTERVAL {
            self.last_poll = Instant::now();
            self.send(Kind::Status, json!({"command":"status"}), cx);
        }
    }

    fn accept_status(&mut self, status: Value) {
        if status["phase"].is_string() && status["operation_generation"].is_u64() {
            self.status = status;
            self.status_valid = true;
            self.status_at = Some(Instant::now());
        } else {
            self.status_valid = false;
            self.error = true;
            self.notice = "后台返回的状态缺少阶段或操作代数，已禁用接管操作。".into();
        }
    }

    fn accept_profile(&mut self, result: &Value, window: &mut Window, cx: &mut Context<Self>) {
        self.profile = result["profile"].clone();
        self.revision = result["revision"].clone();
        self.profile_exists = result["exists"].as_bool().unwrap_or(false);
        // The daemon validates and owns this stable AppData location; never synthesize a CWD path.
        self.profile_path = result["path"].as_str().map(str::to_owned);
        self.loading_fields = true;
        for (field, key, array) in [
            (&self.fields.first_hop, "first_hop", false),
            (&self.fields.credential, "credential", false),
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
            field.update(cx, |state, cx| state.set_value(value, window, cx));
        }
        self.selected = None;
        self.witness = None;
        if let Some(desktop) = result.get("desktop") {
            self.selected = desktop["target"].as_str().map(str::to_owned);
            self.witness = desktop["witness"].as_str().map(str::to_owned);
            if let Some(port) = desktop["port"].as_u64() {
                self.fields.port.update(cx, |state, cx| {
                    state.set_value(port.to_string(), window, cx)
                });
            }
        }
        self.saved_selected = self.selected.clone();
        self.saved_witness = self.witness.clone();
        self.saved_port = Self::field_value(&self.fields.port, cx);
        self.loading_fields = false;
        self.dirty = false;
    }

}
