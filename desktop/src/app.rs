use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use gpui::{prelude::*, *};
use gpui_component::{
    Disableable, Root, Theme, ThemeMode,
    button::{Button, ButtonVariants},
    input::{Input, InputEvent, InputState},
};
use serde_json::{Value, json};

const INK: u32 = 0x18374a;
const PAPER: u32 = 0xeff4f7;
const BLUE: u32 = 0x225f88;
const TEAL: u32 = 0x08776d;
const RUST: u32 = 0xa64e24;
const RULE: u32 = 0xcbdbe2;
const TITLE: &str = "WSL 代理控制台 · 单目标管理";

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Overview,
    Policy,
    Diagnostics,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Bootstrap,
    Status,
    List,
    Preflight,
    Save,
    Import,
    Forget,
    Start,
    Switch,
    Stop,
    Export,
    Probe,
}

impl Kind {
    fn mutation(self) -> bool {
        matches!(
            self,
            Self::Save
                | Self::Import
                | Self::Forget
                | Self::Start
                | Self::Switch
                | Self::Stop
                | Self::Probe
        )
    }
    fn label(self) -> &'static str {
        match self {
            Self::Bootstrap => "连接后台",
            Self::Status => "刷新状态",
            Self::List => "枚举 WSL",
            Self::Preflight => "能力预检",
            Self::Save => "保存策略",
            Self::Import => "导入凭据",
            Self::Forget => "忘记凭据",
            Self::Start => "开始接管",
            Self::Switch => "切换目标",
            Self::Stop => "停止并恢复直连",
            Self::Export => "导出诊断",
            Self::Probe => "检测出口",
        }
    }
}

struct Job {
    kind: Kind,
    epoch: u64,
    request: Value,
}
struct Reply {
    kind: Kind,
    epoch: u64,
    result: Result<Value, String>,
    status: Option<Result<Value, String>>,
}

fn request(value: &Value) -> Result<Value, String> {
    let reply = wsl_proxyctl::ipc::request(value)?;
    if let Some(message) = reply.get("message").and_then(Value::as_str) {
        if let Some(code) = reply.get("code").and_then(Value::as_str) {
            return Err(format!("{code} · {message}"));
        }
    }
    Ok(reply)
}

fn worker() -> (Sender<Job>, Receiver<Reply>) {
    let (send, jobs) = mpsc::channel::<Job>();
    let (replies, receive) = mpsc::channel();
    std::thread::spawn(move || {
        for job in jobs {
            let result = if job.kind == Kind::Bootstrap {
                wsl_proxyctl::ipc::ensure_daemon().and_then(|()| {
                    Ok(json!({
                        "distributions": request(&json!({"command":"list"}))?,
                        "profile": request(&json!({"command":"profile_get"}))?,
                        "status": request(&json!({"command":"status"}))?
                    }))
                })
            } else {
                request(&job.request)
            };
            // A failed mutation may still have advanced recovery state. Never replay it.
            let status = job
                .kind
                .mutation()
                .then(|| request(&json!({"command":"status"})));
            if replies
                .send(Reply {
                    kind: job.kind,
                    epoch: job.epoch,
                    result,
                    status,
                })
                .is_err()
            {
                break;
            }
        }
        // Dropping a window is deliberately not a stop or daemon shutdown command.
    });
    (send, receive)
}

struct Fields {
    first_hop: Entity<InputState>,
    credential: Entity<InputState>,
    dns_upstream: Entity<InputState>,
    dns_tls_name: Entity<InputState>,
    health_domain: Entity<InputState>,
    direct_ips: Entity<InputState>,
    direct_domains: Entity<InputState>,
    direct_suffixes: Entity<InputState>,
    port: Entity<InputState>,
    env_path: Entity<InputState>,
}

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

struct Confirmation {
    kind: Kind,
    request: Value,
    generation: u64,
    message: String,
}

struct Desktop {
    page: Page,
    fields: Fields,
    _subscriptions: Vec<Subscription>,
    sender: Sender<Job>,
    replies: Receiver<Reply>,
    epoch: u64,
    busy: Option<Kind>,
    reading: bool,
    refreshing: bool,
    last_poll: Instant,
    status: Value,
    status_at: Option<Instant>,
    status_valid: bool,
    distributions: Vec<Value>,
    selected: Option<String>,
    witness: Option<String>,
    profile: Value,
    profile_path: Option<String>,
    revision: Value,
    profile_exists: bool,
    dirty: bool,
    loading_fields: bool,
    saved_port: String,
    preflight: Option<Value>,
    preflight_key: Option<(String, String, u16)>,
    notice: String,
    error: bool,
    confirmation: Option<Confirmation>,
    export_path: Option<String>,
    credential_notice: String,
}

impl Desktop {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let fields = Fields {
            first_hop: input(window, cx, "IPv4:端口（宿主 SOCKS5）", false),
            credential: input(window, cx, "Windows 凭据引用名", false),
            dns_upstream: input(window, cx, "DoH IPv4:443", false),
            dns_tls_name: input(window, cx, "TLS 主机名，例如 dns.google", false),
            health_domain: input(window, cx, "用于启动验证的域名", false),
            direct_ips: input(window, cx, "每行一个 IPv4 或 CIDR", true),
            direct_domains: input(window, cx, "每行一个精确域名", true),
            direct_suffixes: input(window, cx, "每行一个域名后缀", true),
            port: cx.new(|cx| InputState::new(window, cx).default_value("43531")),
            env_path: input(window, cx, "选择 .env，或粘贴绝对 Windows 路径", false),
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
                if matches!(event, InputEvent::Change)
                    && !this.loading_fields
                    && this.draft(cx) != this.profile
                {
                    this.dirty = true;
                    cx.notify();
                }
            }));
        }
        subscriptions.push(cx.subscribe(&fields.port, |this, _, event, cx| {
            if matches!(event, InputEvent::Change)
                && !this.loading_fields
                && Self::field_value(&this.fields.port, cx) != this.saved_port
            {
                this.preflight = None;
                this.preflight_key = None;
                this.dirty = true;
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
            profile: Value::Null,
            profile_path: None,
            revision: Value::Null,
            profile_exists: false,
            dirty: false,
            loading_fields: false,
            preflight: None,
            preflight_key: None,
            notice: "正在连接同用户独立后台；关闭窗口不会停止代理。".into(),
            error: false,
            confirmation: None,
            export_path: None,
            credential_notice: "仅保存引用名，不读取或显示住宅出口、用户名和密码。".into(),
        };
        this.send(Kind::Bootstrap, Value::Null, cx);
        cx.spawn_in(window, async move |view, cx| {
            loop {
                Timer::after(Duration::from_millis(100)).await;
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

    fn send(&mut self, kind: Kind, request: Value, cx: &mut Context<Self>) {
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
            self.fail(
                "后台通信工作线程已退出。请重新打开窗口；不会自动重试任何操作。",
                cx,
            );
        } else {
            if kind != Kind::Status {
                self.notice = format!("{}中… 不会自动重试。", kind.label());
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
                        status_error = Some(format!(
                            "操作后状态无法确认：{error}。请刷新状态，不要重复提交。"
                        ));
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
                        self.notice =
                            "后台已连接。先选择候选目标和隔离见证，再运行能力预检。".into();
                        self.error = false;
                    }
                    Kind::Status => {
                        self.accept_status(value);
                    }
                    Kind::List => {
                        self.distributions = value.as_array().cloned().unwrap_or_default();
                        self.notice = "已重新枚举注册的 WSL；未启动任何发行版。".into();
                    }
                    Kind::Save => {
                        self.accept_profile(&value, window, cx);
                        self.notice =
                            "策略已保存。当前接管不会被修改；下次开始或切换时使用此已保存版本。"
                                .into();
                    }
                    Kind::Preflight => {
                        self.notice = if value["passed"] == true {
                            "能力预检通过。尚未接管任何新目标。"
                        } else {
                            "能力预检未通过。请查看下方阻断项。"
                        }
                        .into();
                        self.error = value["passed"] != true;
                        self.preflight = Some(value);
                    }
                    Kind::Import => {
                        self.fields
                            .env_path
                            .update(cx, |state, cx| state.set_value("", window, cx));
                        self.credential_notice =
                            "所选引用的凭据已导入 Windows 凭据管理器；源文件未被删除。".into();
                        self.notice = "凭据已导入。界面不会显示秘密值。".into();
                    }
                    Kind::Forget => {
                        self.credential_notice =
                            "所选引用的凭据已忘记。再次开始前需要重新导入。".into();
                        self.notice = "仅已删除所选 wsl-proxyctl 凭据；源文件未被删除。".into();
                    }
                    Kind::Export => {
                        self.export_path = value["path"].as_str().map(str::to_owned);
                        self.notice = "已导出脱敏诊断。报告仍含网络目标，请按内部资料处理。".into();
                    }
                    Kind::Probe => {
                        self.accept_status(value);
                        self.notice =
                            "出口探测已完成；这是此次显式测量结果，不代表持续健康。".into();
                    }
                    Kind::Start | Kind::Switch | Kind::Stop => {
                        if value["passed"] == false {
                            self.preflight = Some(value);
                            self.fail("操作前预检拒绝。请检查阻断项；状态以后台最后观测为准。", cx);
                        } else {
                            self.notice =
                                format!("{}已返回；请以下方后台实况为准。", reply.kind.label());
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
        if self.last_poll.elapsed() >= Duration::from_secs(2) {
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
        if let Some(desktop) = result.get("desktop") {
            self.selected = desktop["target"].as_str().map(str::to_owned);
            self.witness = desktop["witness"].as_str().map(str::to_owned);
            if let Some(port) = desktop["port"].as_u64() {
                self.fields.port.update(cx, |state, cx| {
                    state.set_value(port.to_string(), window, cx)
                });
            }
        }
        self.saved_port = Self::field_value(&self.fields.port, cx);
        self.loading_fields = false;
        self.dirty = false;
    }

    fn fail(&mut self, error: impl Into<String>, cx: &mut Context<Self>) {
        self.notice = error.into();
        self.error = true;
        cx.notify();
    }
    fn phase(&self) -> &str {
        if self.status_valid {
            self.status["phase"].as_str().unwrap_or("unknown")
        } else {
            "unknown"
        }
    }
    fn idle(&self) -> bool {
        self.status_valid && self.phase() == "idle"
    }
    fn generation(&self) -> Option<u64> {
        self.status_valid
            .then(|| self.status["operation_generation"].as_u64())
            .flatten()
    }
    fn locked(&self) -> bool {
        self.busy.is_some() || self.reading || self.confirmation.is_some()
    }
    fn field_value(field: &Entity<InputState>, cx: &App) -> String {
        field.read(cx).value().trim().to_owned()
    }
    fn port(&self, cx: &App) -> Result<u16, &'static str> {
        Self::field_value(&self.fields.port, cx)
            .parse::<u16>()
            .ok()
            .filter(|port| *port >= 1024)
            .ok_or("入口端口必须是 1024–65535 的整数。")
    }
    fn selection(&self, cx: &App) -> Result<(String, String, u16), String> {
        let target = self.selected.clone().ok_or("请选择候选目标 WSL。")?;
        if self.phase() == "forwarding_managed" {
            let owner = self.status["active_target"]
                .as_str()
                .and_then(|name| {
                    self.distributions
                        .iter()
                        .find(|d| d["name"].as_str() == Some(name))
                })
                .and_then(|d| d["id"].as_str())
                .ok_or("当前接管者无法核对，请刷新发行版列表。")?;
            if owner != target {
                return Ok((target, owner.to_owned(), self.port(cx)?));
            }
        }
        let witness = self
            .witness
            .clone()
            .ok_or("请选择不同于目标的 WSL2 隔离见证。")?;
        if target == witness {
            return Err("目标与隔离见证不能相同。".into());
        }
        Ok((target, witness, self.port(cx)?))
    }
    fn draft(&self, cx: &App) -> Value {
        let mut profile = self.profile.as_object().cloned().unwrap_or_default();
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
            let text = Self::field_value(field, cx);
            profile.insert(
                key.into(),
                if array {
                    json!(
                        text.lines()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                    )
                } else {
                    json!(text)
                },
            );
        }
        Value::Object(profile)
    }

    fn preflight(&mut self, cx: &mut Context<Self>) {
        match self.selection(cx) {
            Ok((target, witness, port)) => {
                self.preflight_key = Some((target.clone(), witness.clone(), port));
                self.send(
                    Kind::Preflight,
                    json!({"command":"preflight","target":target,"witness":witness,"port":port}),
                    cx,
                );
            }
            Err(error) => self.fail(error, cx),
        }
    }

    fn prepare(&mut self, kind: Kind, cx: &mut Context<Self>) {
        if self.locked() {
            return;
        }
        let Some(generation) = self.generation() else {
            self.fail("后台状态未确认。请先刷新状态。", cx);
            return;
        };
        if kind == Kind::Stop {
            self.confirmation = Some(Confirmation {
                kind, generation, request: json!({"command":"stop","expected_generation":generation}),
                message: "将停止当前接管并恢复记录中目标的直连状态（恢复失败时仍须处理恢复状态）。现有 TCP 连接会中断，应用需要重新连接。只清理本控制器拥有的规则，不操作其他 WSL。".into(),
            });
            cx.notify();
            return;
        }
        if self.dirty || !self.profile_exists || self.profile_path.is_none() {
            self.fail(
                "请先在“策略”页显式保存当前草稿与选择。未保存的输入不会用于接管。",
                cx,
            );
            return;
        }
        let (target, witness, port) = match self.selection(cx) {
            Ok(value) => value,
            Err(error) => {
                self.fail(error, cx);
                return;
            }
        };
        if self.preflight_key.as_ref() != Some(&(target.clone(), witness.clone(), port))
            || self.preflight.as_ref().is_none_or(|p| p["passed"] != true)
        {
            self.fail("请先对当前候选目标、隔离见证和端口运行能力预检。", cx);
            return;
        }
        let command = if kind == Kind::Start {
            "start"
        } else {
            "switch"
        };
        let mut request = json!({"command":command,"target":target,"port":port,"profile":self.profile_path,"profile_revision":self.revision,"expected_generation":generation});
        if kind == Kind::Start {
            request["witness"] = json!(witness);
        }
        self.confirmation = Some(Confirmation {
            kind,
            generation,
            request,
            message: if kind == Kind::Switch {
                format!(
                    "将把接管从 {} 切换至 {target}。旧目标先恢复直连；现有 TCP 连接会中断并需要重连。切换失败不会假装旧目标仍被接管，请以恢复状态为准。",
                    text(&self.status, "active_target", "记录中的目标")
                )
            } else {
                format!(
                    "将接管 {target} 的默认 TCP 与系统 DNS，默认经宿主代理 → 住宅出口；直连仅命中已保存的例外。隔离见证 {witness} 只用于验证作用域。"
                )
            },
        });
        cx.notify();
    }

    fn confirm(&mut self, cx: &mut Context<Self>) {
        let Some(confirmation) = self.confirmation.take() else {
            return;
        };
        if self.generation() != Some(confirmation.generation) {
            self.fail("确认期间后台代数已变化。请检查最新状态后重新操作。", cx);
            return;
        }
        self.send(confirmation.kind, confirmation.request, cx);
    }

    fn save(&mut self, cx: &mut Context<Self>) {
        let port = match self.port(cx) {
            Ok(port) => port,
            Err(error) => {
                self.fail(error, cx);
                return;
            }
        };
        self.send(Kind::Save, json!({"command":"profile_save","profile":self.draft(cx),"expected_revision":self.revision,
            "desktop":{"target":self.selected,"witness":self.witness,"port":port}}), cx);
    }

    fn credentials(&mut self, forget: bool, cx: &mut Context<Self>) {
        if !self.idle() {
            self.fail("凭据只允许在后台已确认空闲时导入或忘记。", cx);
            return;
        }
        let name = Self::field_value(&self.fields.credential, cx);
        if name.is_empty() {
            self.fail("请先填写凭据引用名。", cx);
            return;
        }
        if forget {
            self.send(
                Kind::Forget,
                json!({"command":"forget_credential","name":name}),
                cx,
            );
        } else {
            let path = Self::field_value(&self.fields.env_path, cx);
            if path.is_empty() {
                self.fail("请选择明确的 .env 文件，或填写绝对 Windows 路径。", cx);
                return;
            }
            self.send(
                Kind::Import,
                json!({"command":"import_credential","name":name,"env_file":path}),
                cx,
            );
        }
    }

    fn choose_env(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let picker = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("选择住宅代理凭据 .env（不显示内容）".into()),
        });
        cx.spawn_in(window, async move |view, cx| match picker.await {
            Ok(Ok(Some(paths))) => {
                if let Some(path) = paths.first() {
                    let path = path.to_string_lossy().into_owned();
                    let _ = view.update_in(cx, |this, window, cx| {
                        this.fields
                            .env_path
                            .update(cx, |state, cx| state.set_value(path, window, cx));
                        this.notice = "已选择凭据文件。点击“导入命名凭据”才会由后台读取。".into();
                        cx.notify();
                    });
                }
            }
            Ok(Ok(None)) => {}
            _ => {
                let _ = view.update_in(cx, |this, _, cx| {
                    this.fail("无法打开文件选择器。可直接粘贴绝对 Windows 路径。", cx)
                });
            }
        })
        .detach();
    }
}

fn text(value: &Value, key: &str, fallback: &str) -> String {
    value[key].as_str().unwrap_or(fallback).to_owned()
}
fn bytes(value: u64) -> String {
    if value >= 1024 * 1024 {
        format!("{:.1} MiB", value as f64 / 1048576.)
    } else if value >= 1024 {
        format!("{:.1} KiB", value as f64 / 1024.)
    } else {
        format!("{value} B")
    }
}
fn rate(value: &Value) -> String {
    value
        .as_f64()
        .map(|v| format!("{}/s", bytes(v.max(0.) as u64)))
        .unwrap_or_else(|| "未采样".into())
}

#[derive(Clone)]
enum UiAction {
    Page(Page),
    Refresh,
    Reconnect,
    List,
    Preflight,
    Save,
    Pick,
    Import,
    Forget,
    Probe,
    Prepare(Kind),
    Confirm,
    Cancel,
    Reveal,
}

fn panel(title: &'static str, caption: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_5()
        .bg(rgb(0xffffff))
        .border_1()
        .border_color(rgb(RULE))
        .rounded_md()
        .child(
            div()
                .text_lg()
                .font_weight(FontWeight::SEMIBOLD)
                .child(title),
        )
        .child(div().text_sm().text_color(rgb(BLUE)).child(caption.into()))
}
fn fact(label: &'static str, value: impl Into<SharedString>, color: u32) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .flex_1()
        .min_w_0()
        .child(div().text_xs().text_color(rgb(BLUE)).child(label))
        .child(div().text_base().text_color(rgb(color)).child(value.into()))
}

impl Desktop {
    fn button(
        &self,
        id: &'static str,
        label: &'static str,
        action: UiAction,
        disabled: bool,
        cx: &Context<Self>,
    ) -> Button {
        Button::new(id)
            .label(label)
            .disabled(disabled)
            .on_click(cx.listener(move |this, _, window, cx| match action {
                UiAction::Page(page) => {
                    this.page = page;
                    cx.notify();
                }
                UiAction::Refresh => this.send(Kind::Status, json!({"command":"status"}), cx),
                UiAction::Reconnect => {
                    if this.dirty {
                        this.fail(
                            "有未保存的草稿。请先显式保存，再重新连接，避免覆盖输入。",
                            cx,
                        );
                    } else {
                        this.send(Kind::Bootstrap, Value::Null, cx);
                    }
                }
                UiAction::List => this.send(Kind::List, json!({"command":"list"}), cx),
                UiAction::Preflight => this.preflight(cx),
                UiAction::Save => this.save(cx),
                UiAction::Pick => this.choose_env(window, cx),
                UiAction::Import => this.credentials(false, cx),
                UiAction::Forget => this.credentials(true, cx),
                UiAction::Probe => {
                    if this.phase() == "forwarding_managed" {
                        if let Some(generation) = this.generation() {
                            this.send(
                                Kind::Probe,
                                json!({"command":"probe_exit","expected_generation":generation}),
                                cx,
                            );
                        }
                    }
                }
                UiAction::Prepare(kind) => this.prepare(kind, cx),
                UiAction::Confirm => this.confirm(cx),
                UiAction::Cancel => {
                    this.confirmation = None;
                    cx.notify();
                }
                UiAction::Reveal => {
                    if let Some(path) = &this.export_path {
                        cx.reveal_path(std::path::Path::new(path));
                    }
                }
            }))
    }

    fn field(
        &self,
        label: &'static str,
        hint: &'static str,
        state: &Entity<InputState>,
        multiline: bool,
    ) -> Div {
        let input = Input::new(state).disabled(self.locked());
        div()
            .flex()
            .flex_col()
            .gap_2()
            .flex_1()
            .min_w_0()
            .child(div().text_sm().font_weight(FontWeight::MEDIUM).child(label))
            .child(if multiline {
                input.h(px(112.)).into_any_element()
            } else {
                input.into_any_element()
            })
            .child(div().text_xs().text_color(rgb(BLUE)).child(hint))
    }

    fn path_strip(&self) -> Div {
        let policy = if self.status["active_policy"].is_object() {
            &self.status["active_policy"]
        } else {
            &self.profile
        };
        let active = text(&self.status, "active_target", "无已确认目标");
        let first_hop = text(policy, "first_hop", "尚未配置");
        let dns = text(policy, "dns_tls_name", "尚未配置");
        div()
            .flex()
            .flex_col()
            .gap_3()
            .px_6()
            .py_4()
            .bg(rgb(0xe2ecf1))
            .border_b_1()
            .border_color(rgb(RULE))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(div().text_xs().font_weight(FontWeight::SEMIBOLD).child(
                        if !self.status_valid {
                            "后台状态未知 · 路径未经确认"
                        } else if self.status["active_policy"].is_object() {
                            "运行策略路径 · 默认双跳与受管 DNS"
                        } else if self.profile_exists {
                            "已保存策略路径 · 尚未确认接管"
                        } else {
                            "默认策略预览 · 尚未保存或接管"
                        },
                    ))
                    .child(
                        div()
                            .text_xs()
                            .child("箭头表示策略，不代表节点健康或出口实测"),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_4()
                    .child(fact("目标 WSL", active, INK))
                    .child("→")
                    .child(fact("宿主代理", first_hop, INK))
                    .child("→")
                    .child(fact("住宅出口", "凭据保存在 Windows · 不显示秘密", INK))
                    .child("→")
                    .child(fact("DNS", format!("DoH · {dns}"), INK)),
            )
    }

    fn overview(&self, cx: &Context<Self>) -> Div {
        let phase = match self.phase() {
            "idle" => "空闲 · 未接管",
            "forwarding_managed" => "正在接管 · 默认双跳与 DNS",
            "forwarding_scoped" => "诊断作用域 · 非完整策略",
            "recovery_required" => "需要恢复 · 不是空闲",
            _ => "状态未知 · 禁止提交接管",
        };
        let color = if !self.status_valid || self.phase() == "recovery_required" {
            RUST
        } else if self.phase() == "forwarding_managed" {
            TEAL
        } else {
            INK
        };
        let mut choices = div().flex().flex_col().gap_2();
        if self.distributions.is_empty() {
            choices = choices.child(
                div()
                    .text_sm()
                    .child("尚无已枚举的 WSL。点击“重新枚举”；仅支持 WSL2。"),
            );
        }
        for (index, distro) in self.distributions.iter().enumerate() {
            let id = text(distro, "id", "");
            let name = text(distro, "name", "未命名发行版");
            let version = distro["version"].as_u64().unwrap_or(0);
            let selected = self.selected.as_deref() == Some(id.as_str());
            let witness = self.witness.as_deref() == Some(id.as_str());
            let target_id = id.clone();
            let witness_id = id;
            choices = choices.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .py_2()
                    .border_b_1()
                    .border_color(rgb(RULE))
                    .child(
                        div().flex_1().min_w_0().child(name).child(
                            div()
                                .text_xs()
                                .text_color(rgb(BLUE))
                                .child(format!("WSL {version}")),
                        ),
                    )
                    .child(
                        Button::new(("select-target", index))
                            .label(if selected {
                                "已选候选"
                            } else {
                                "选作候选"
                            })
                            .disabled(self.locked() || version != 2)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.selected = Some(target_id.clone());
                                if this.witness == this.selected {
                                    this.witness = None;
                                }
                                this.preflight = None;
                                this.preflight_key = None;
                                this.dirty = true;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new(("select-witness", index))
                            .label(if witness {
                                "已选见证"
                            } else {
                                "隔离见证"
                            })
                            .disabled(self.locked() || version != 2 || selected)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.witness = Some(witness_id.clone());
                                this.preflight = None;
                                this.preflight_key = None;
                                this.dirty = true;
                                cx.notify();
                            })),
                    ),
            );
        }
        let target_name = self
            .distributions
            .iter()
            .find(|d| d["id"].as_str() == self.selected.as_deref())
            .map(|d| text(d, "name", "未知"))
            .unwrap_or_else(|| "尚未选择".into());
        let witness_name = self
            .distributions
            .iter()
            .find(|d| d["id"].as_str() == self.witness.as_deref())
            .map(|d| text(d, "name", "未知"))
            .unwrap_or_else(|| "尚未选择".into());
        let mut state = panel("后台实况", "只反映后台最后观测，不跟随候选选择改变")
            .child(
                div()
                    .text_2xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(color))
                    .child(phase),
            )
            .child(fact(
                "实际接管目标",
                text(&self.status, "active_target", "无已确认目标"),
                color,
            ))
            .child(
                div()
                    .flex()
                    .gap_5()
                    .child(fact("候选目标 · 尚未生效", target_name, BLUE))
                    .child(fact("隔离见证 · 不接管", witness_name, BLUE)),
            )
            .child(fact(
                "操作代数",
                self.generation()
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "未确认".into()),
                INK,
            ))
            .child(fact(
                "运行配置代数",
                self.status["config_generation"]
                    .as_u64()
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "无已确认运行配置".into()),
                INK,
            ))
            .child(fact(
                "DNS 观测",
                self.dns_label(),
                if self.status["dns_managed"] == true {
                    TEAL
                } else {
                    RUST
                },
            ))
            .child(fact("住宅公网出口 IP", self.exit_label(), INK))
            .child(self.button(
                "probe-exit",
                "检测出口（访问 IPPure）",
                UiAction::Probe,
                self.locked() || !self.status_valid || self.phase() != "forwarding_managed",
                cx,
            ))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(
                        self.button(
                            "start",
                            "开始接管",
                            UiAction::Prepare(Kind::Start),
                            self.locked() || !self.idle(),
                            cx,
                        )
                        .primary(),
                    )
                    .child(self.button(
                        "switch",
                        "切换至候选",
                        UiAction::Prepare(Kind::Switch),
                        self.locked() || !self.status_valid || self.phase() != "forwarding_managed",
                        cx,
                    ))
                    .child(
                        self.button(
                            "stop",
                            if self.phase() == "recovery_required" {
                                "恢复并停止"
                            } else {
                                "停止接管"
                            },
                            UiAction::Prepare(Kind::Stop),
                            self.locked() || !self.status_valid || self.idle(),
                            cx,
                        )
                        .danger(),
                    ),
            );
        if let Some(issue) = self.status["issue"].as_str() {
            state = state.child(
                div()
                    .text_sm()
                    .text_color(rgb(RUST))
                    .child(format!("后台问题：{issue}")),
            );
        }
        if self.phase() == "recovery_required" {
            state = state.child(fact(
                "记录中的目标 · 不等同于仍受保护",
                text(&self.status, "recorded_target", "请检查未完成操作与诊断"),
                RUST,
            ));
        }
        let mut page = div()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .gap_4()
                    .items_start()
                    .child(
                        panel(
                            "候选与隔离见证",
                            "选择不是接管。预检可能启动这两个 WSL，但不会修改网络规则。",
                        )
                        .w(px(490.))
                        .child(choices)
                        .child(self.field(
                            "宿主入口端口",
                            "仅接受 1024–65535；切换使用此端口。",
                            &self.fields.port,
                            false,
                        ))
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .child(self.button(
                                    "list",
                                    "重新枚举",
                                    UiAction::List,
                                    self.locked(),
                                    cx,
                                ))
                                .child(
                                    self.button(
                                        "preflight",
                                        "运行能力预检",
                                        UiAction::Preflight,
                                        self.locked(),
                                        cx,
                                    )
                                    .primary(),
                                ),
                        ),
                    )
                    .child(state.flex_1()),
            )
            .child(self.preflight_panel());
        if self.phase() == "recovery_required" {
            page = page.child(div().p_4().border_l_4().border_color(rgb(RUST)).bg(rgb(0xfff4ed))
                .child("检测到残留记录或未完成操作。此时不是空闲：请检查诊断，然后显式“恢复并停止”。不会自动切换或清理其他目标。"));
        }
        page
    }

    fn exit_label(&self) -> String {
        let exit = &self.status["recent_exit"];
        let Some(ip) = exit["ip"].as_str() else {
            return "未测量 · 不把原始目标 IP 当成出口 IP".into();
        };
        let verified = match exit["matches_residential"].as_bool() {
            Some(true) => "与住宅出口一致",
            Some(false) => "与配置住宅出口不一致",
            None => "未比对住宅出口",
        };
        format!(
            "{ip} · {} · {verified} · 检测时间 {} UTC Unix 秒",
            text(exit, "country", "地区未知"),
            exit["checked_unix_seconds"]
                .as_u64()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "未知".into())
        )
    }

    fn dns_label(&self) -> String {
        if !self.status_valid {
            "状态未知；不能确认 DNS 保护".into()
        } else if self.status["dns_managed"] == true {
            "系统 DNS 已接管；启动时经上游验证，非持续可达性保证".into()
        } else if self.idle() {
            "未接管系统 DNS".into()
        } else {
            "未确认受管 DNS；请检查恢复与诊断".into()
        }
    }

    fn preflight_panel(&self) -> Div {
        let Some(result) = &self.preflight else {
            return div().text_sm().text_color(rgb(BLUE)).child("预检尚未运行或候选已改变。开始前会再次检查能力与操作代数。直连例外之外的默认 TCP 与系统 DNS 均使用双跳。非 DNS UDP 不代理。");
        };
        let mut panel = panel(
            "能力预检结果",
            if result["passed"] == true {
                "通过 · 仍需明确开始接管"
            } else {
                "阻断 · 未执行接管"
            },
        );
        if let Some(blockers) = result["blockers"].as_array() {
            for blocker in blockers {
                if let Some(message) = blocker.as_str() {
                    panel = panel.child(
                        div()
                            .text_sm()
                            .text_color(rgb(RUST))
                            .child(message.to_owned()),
                    );
                }
            }
        }
        for (label, key) in [("候选身份与内核", "target"), ("隔离见证", "witness")] {
            let observation = &result[key];
            if observation.is_object() {
                let snapshot = &observation["snapshot"];
                panel = panel.child(div().text_sm().child(format!(
                    "{label}：{} · 身份验证 {}",
                    text(&observation["distribution"], "name", "未知"),
                    if snapshot["identity_valid"] == true {
                        "通过"
                    } else {
                        "未确认"
                    }
                )));
                if let Some(blockers) = snapshot["blockers"].as_array() {
                    for blocker in blockers {
                        if let Some(message) = blocker.as_str() {
                            panel = panel.child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(RUST))
                                    .child(message.to_owned()),
                            );
                        }
                    }
                }
            }
        }
        panel
    }

    fn policy_page(&self, cx: &Context<Self>) -> Div {
        div().flex().flex_col().gap_4()
            .child(panel("策略草稿", "默认 TCP 与系统 DNS 经双跳；直连例外采用命中规则，不改变默认路径。保存不会立即替换正在运行的策略。")
                .child(div().flex().gap_5()
                    .child(self.field("宿主第一跳 SOCKS5", "明文 IPv4:端口；不是住宅凭据。", &self.fields.first_hop, false))
                    .child(self.field("住宅凭据引用", "只输入命名引用，不填写用户名、密码或住宅地址。", &self.fields.credential, false)))
                .child(div().flex().gap_5()
                    .child(self.field("DoH 上游 IPv4:端口", "固定 IP 避免 DNS 引导依赖；经双跳传输 HTTPS。", &self.fields.dns_upstream, false))
                    .child(self.field("DoH TLS 主机名", "用于 SNI 与证书验证，不能用 IP 冒充主机名。", &self.fields.dns_tls_name, false)))
                .child(self.field("健康验证域名", "启动验证使用；不要把此域名设成直连例外。", &self.fields.health_domain, false))
                .child(div().flex().gap_5()
                    .child(self.field("直连 IPv4 / CIDR", "每行一条；空白行忽略。", &self.fields.direct_ips, true))
                    .child(self.field("直连精确域名", "每行一个域名；不接受 URL。", &self.fields.direct_domains, true))
                    .child(self.field("直连域名后缀", "每行一个后缀；按域名边界匹配。", &self.fields.direct_suffixes, true)))
                .child(div().flex().items_center().gap_4()
                    .child(self.button("save", "显式保存策略与选择", UiAction::Save, self.locked() || self.profile_path.is_none(), cx).primary())
                    .child(div().text_sm().text_color(rgb(if self.dirty { RUST } else { TEAL })).child(if self.dirty { "有未保存更改 · 不会用于接管" } else if self.profile_exists { "已保存 · 下次接管使用" } else { "尚未保存 · 不能开始接管" })))
                .child(div().text_xs().font_family("Consolas").child(self.profile_path.clone().unwrap_or_else(|| "等待后台返回经验证的 AppData 路径；不会使用当前目录。".into()))))
            .child(panel("住宅凭据", "仅在后台确认空闲时允许导入与忘记。选择文件不读取文件；导入由后台读取并写入当前 Windows 用户的凭据管理器。")
                .child(div().text_sm().child(self.credential_notice.clone()))
                .child(Input::new(&self.fields.env_path).disabled(self.locked() || !self.idle()))
                .child(div().flex().flex_wrap().gap_2()
                    .child(self.button("pick-env", "选择 .env 文件…", UiAction::Pick, self.locked() || !self.idle(), cx))
                    .child(self.button("import", "导入命名凭据", UiAction::Import, self.locked() || !self.idle(), cx).primary())
                    .child(self.button("forget", "忘记此引用的凭据", UiAction::Forget, self.locked() || !self.idle(), cx).danger()))
                .child(div().text_xs().text_color(rgb(BLUE)).child("源文件仅支持 ip / port / username / password；界面从不预览文件内容，也不会删除源文件。")))
    }

    fn diagnostics(&self, cx: &Context<Self>) -> Div {
        let forwarding = &self.status["forwarding"];
        let traffic = &forwarding["traffic"];
        let active = forwarding["connections"]["active"].as_array();
        let recent = forwarding["connections"]["recent"].as_array();
        let mut rows = div().flex().flex_col().gap_1();
        for row in active
            .into_iter()
            .flatten()
            .chain(recent.into_iter().flatten())
            .take(384)
        {
            let route = match row["route"].as_str() {
                Some("direct") => "直连",
                Some("chain") => "双跳",
                Some("dns") => "DNS",
                Some("reject") => "拒绝",
                _ => "待判定",
            };
            let stage = match row["stage"].as_str() {
                Some("metadata") => "获取原始目标",
                Some("policy") => "策略判定",
                Some("connect") => "建立连接",
                Some("dns") => "DNS 转发",
                Some("relay") => "传输",
                _ => "未知",
            };
            let status = match row["status"].as_str() {
                Some("active") => "活动",
                Some("completed") => "完成",
                Some("failed") => "失败",
                Some("stopped") => "已停止",
                _ => "未知",
            };
            let reason = match row["reason"].as_str() {
                Some("enumerated_origin") => "诊断枚举目标",
                Some("domain_alias") => "域名例外映射",
                Some("ip_or_cidr") => "IP / CIDR 例外",
                Some("default_chain") => "默认双跳",
                Some("system_dns") => "系统 DNS",
                Some("policy_reject") => "策略拒绝",
                Some("metadata_unavailable") => "无法取得原始目标",
                _ => "等待元数据",
            };
            rows = rows.child(
                div()
                    .flex()
                    .gap_3()
                    .items_center()
                    .py_2()
                    .border_b_1()
                    .border_color(rgb(RULE))
                    .text_xs()
                    .child(
                        div()
                            .w(px(52.))
                            .font_family("Consolas")
                            .child(row["id"].as_u64().unwrap_or(0).to_string()),
                    )
                    .child(
                        div()
                            .w(px(42.))
                            .font_family("Consolas")
                            .child(text(row, "protocol", "—")),
                    )
                    .child(div().w(px(190.)).font_family("Consolas").child(text(
                        row,
                        "destination",
                        "原始目标尚未验证",
                    )))
                    .child(
                        div()
                            .w(px(46.))
                            .text_color(rgb(if route == "直连" {
                                BLUE
                            } else if route == "拒绝" {
                                RUST
                            } else {
                                TEAL
                            }))
                            .child(route),
                    )
                    .child(div().w(px(140.)).child(format!("{status} · {stage}")))
                    .child(div().w(px(142.)).font_family("Consolas").child(format!(
                        "↑ {} / ↓ {}",
                        bytes(row["tx_bytes"].as_u64().unwrap_or(0)),
                        bytes(row["rx_bytes"].as_u64().unwrap_or(0))
                    )))
                    .child(div().flex_1().child(format!(
                            "{reason}{}",
                            row["failure_stage"]
                                .as_str()
                                .map(|v| format!(" · 失败阶段 {v}"))
                                .unwrap_or_default()
                        ))),
            );
        }
        let mut result = div().flex().flex_col().gap_4()
            .child(panel("连接与 DNS 诊断", "上行＝WSL → 目的端；下行＝目的端 → WSL。速率是后台相邻采样的成功转发字节差，不是终身平均值。")
                .child(div().flex().gap_5()
                    .child(fact("上行速率", rate(&traffic["tx_bytes_per_sec"]), BLUE))
                    .child(fact("下行速率", rate(&traffic["rx_bytes_per_sec"]), TEAL))
                    .child(fact("累计上行", traffic["tx_bytes"].as_u64().map(bytes).unwrap_or_else(|| "未采样".into()), INK))
                    .child(fact("累计下行", traffic["rx_bytes"].as_u64().map(bytes).unwrap_or_else(|| "未采样".into()), INK)))
                .child(fact("DNS 保护与健康", self.dns_label(), if self.status["dns_managed"] == true { TEAL } else { RUST }))
                .child(fact("转发工作线程", match forwarding["healthy"].as_bool() { Some(true) => "运行中（不等同于公网健康）", Some(false) => "出现故障，请检查恢复状态", None => "无活动转发观测" }, INK))
                .child(div().flex().gap_2()
                    .child(Button::new("export").label("导出脱敏诊断").disabled(self.locked()).on_click(cx.listener(|this, _, _, cx| this.send(Kind::Export, json!({"command":"export_diagnostics"}), cx))))
                    .child(self.button("reveal", "打开报告位置", UiAction::Reveal, self.export_path.is_none(), cx))))
            .child(panel("连接记录", "仅显示经验证的原始 IPv4:端口，不猜测域名、进程或地理位置。活动最多 256 条，最近最多 128 条、保留 5 分钟。")
                .child(div().text_xs().text_color(rgb(BLUE)).child("ID       协议     原始目的端                         路由     状态 / 阶段                      字节量                       判定原因 / 失败阶段"))
                .child(if active.is_none_or(Vec::is_empty) && recent.is_none_or(Vec::is_empty) {
                    div().py_5().text_sm().child("当前没有连接记录。空列表不表示公网健康；开始接管后由 WSL 发起实际流量，再查看此处。").into_any_element()
                } else { rows.into_any_element() }));
        if let Some(error) = forwarding["last_error"].as_str() {
            result = result.child(
                div()
                    .text_sm()
                    .text_color(rgb(RUST))
                    .child(format!("最后转发错误：{error}")),
            );
        }
        if let Some(path) = &self.export_path {
            result = result.child(div().text_xs().font_family("Consolas").child(path.clone()));
        }
        result
    }
}

impl Render for Desktop {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let age = self
            .status_at
            .map(|time| format!("{} 秒前观测", time.elapsed().as_secs()))
            .unwrap_or_else(|| "尚未取得状态".into());
        let mut body = div()
            .size_full()
            .flex()
            .flex_col()
            .font_family("Microsoft YaHei UI")
            .text_base()
            .text_color(rgb(INK))
            .bg(rgb(PAPER))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .px_6()
                    .py_4()
                    .bg(rgb(0xffffff))
                    .border_b_1()
                    .border_color(rgb(RULE))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_2xl()
                                    .font_family("DengXian")
                                    .font_weight(FontWeight::BOLD)
                                    .child("WSL 代理控制台"),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(BLUE))
                                    .child("单目标控制 / 独立后台 / 明确恢复"),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(div().text_xs().child(format!(
                                "{} · {age}",
                                if self.status_valid {
                                    "后台已连接"
                                } else {
                                    "状态未确认"
                                }
                            )))
                            .child(self.button(
                                "refresh",
                                "刷新状态",
                                UiAction::Refresh,
                                self.locked() || self.refreshing,
                                cx,
                            ))
                            .child(self.button(
                                "reconnect",
                                "重新连接后台",
                                UiAction::Reconnect,
                                self.locked() || self.refreshing,
                                cx,
                            )),
                    ),
            )
            .child(self.path_strip())
            .child(
                div()
                    .flex()
                    .gap_2()
                    .px_6()
                    .py_3()
                    .border_b_1()
                    .border_color(rgb(RULE))
                    .children(
                        [
                            (Page::Overview, "总览", "tab-overview"),
                            (Page::Policy, "策略", "tab-policy"),
                            (Page::Diagnostics, "连接与诊断", "tab-diagnostics"),
                        ]
                        .into_iter()
                        .map(|(page, label, id)| {
                            let button = self.button(id, label, UiAction::Page(page), false, cx);
                            if self.page == page {
                                button.primary()
                            } else {
                                button.ghost()
                            }
                        }),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(if self.dirty { RUST } else { BLUE }))
                            .child(if self.dirty {
                                "策略或选择尚未保存"
                            } else {
                                "草稿与后台实况分离"
                            }),
                    ),
            )
            .child(
                div()
                    .id("page-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p_6()
                    .child(match self.page {
                        Page::Overview => self.overview(cx),
                        Page::Policy => self.policy_page(cx),
                        Page::Diagnostics => self.diagnostics(cx),
                    }),
            );
        if let Some(confirmation) = &self.confirmation {
            body = body.child(
                div()
                    .px_6()
                    .py_4()
                    .bg(rgb(0xfff4ed))
                    .border_t_2()
                    .border_color(rgb(RUST))
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(RUST))
                            .child(format!(
                                "确认{} · 代数 {}",
                                confirmation.kind.label(),
                                confirmation.generation
                            )),
                    )
                    .child(confirmation.message.clone())
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                self.button(
                                    "confirm",
                                    "确认执行",
                                    UiAction::Confirm,
                                    self.busy.is_some(),
                                    cx,
                                )
                                .danger(),
                            )
                            .child(self.button("cancel", "取消", UiAction::Cancel, false, cx)),
                    ),
            );
        }
        body.child(
            div()
                .px_6()
                .py_3()
                .bg(rgb(0xffffff))
                .border_t_1()
                .border_color(rgb(RULE))
                .flex()
                .items_center()
                .gap_4()
                .child(
                    div()
                        .flex_1()
                        .text_sm()
                        .text_color(rgb(if self.error { RUST } else { INK }))
                        .child(self.notice.clone()),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(rgb(if self.busy.is_some() || self.reading {
                            RUST
                        } else {
                            BLUE
                        }))
                        .child(self.busy.map(Kind::label).unwrap_or(if self.reading {
                            "读取中"
                        } else {
                            "关闭窗口不停止接管"
                        })),
                ),
        )
    }
}

pub fn run() {
    Application::new().run(|cx: &mut App| {
        gpui_component::init(cx);
        gpui_component::set_locale("zh-CN");
        Theme::change(ThemeMode::Light, None, cx);
        let theme = Theme::global_mut(cx);
        theme.font_family = "Microsoft YaHei UI".into();
        theme.font_size = px(14.);
        theme.mono_font_family = "Consolas".into();
        theme.background = rgb(PAPER).into();
        theme.foreground = rgb(INK).into();
        theme.primary = rgb(BLUE).into();
        theme.primary_hover = rgb(0x194c70).into();
        theme.primary_active = rgb(INK).into();
        theme.border = rgb(RULE).into();
        theme.input = rgb(RULE).into();
        theme.ring = rgb(BLUE).into();
        theme.caret = rgb(BLUE).into();
        theme.danger = rgb(RUST).into();
        theme.danger_hover = rgb(0x8e401d).into();
        theme.selection = rgb(RULE).into();
        theme.radius = px(5.);
        theme.shadow = false;
        let bounds = Bounds::centered(None, size(px(1220.), px(900.)), cx);
        let opened = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(1080.), px(700.))),
                ..Default::default()
            },
            |window, cx| {
                window.set_window_title(TITLE);
                let view = cx.new(|cx| Desktop::new(window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            },
        );
        if let Err(error) = opened {
            eprintln!("无法打开 WSL 代理控制台：{error}");
        }
        cx.activate(true);
    });
}
