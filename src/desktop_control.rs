use crate::{
    controller,
    desktop_store::{self, ResidentialSettings},
    environment::{self, InstallOptions},
    host,
    policy::{Config, profile::Preferences},
    wsl_platform,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::thread::JoinHandle;

/// One environment operation (create, edit, back up, delete) running off the
/// request thread. Such an operation can take many minutes; the request
/// returns at once and the desktop polls `environment_job` for the result.
struct EnvironmentJob {
    command: &'static str,
    target: String,
    worker: Option<JoinHandle<Result<Value, String>>>,
}

impl EnvironmentJob {
    fn running(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
    }

    fn view(&self) -> Value {
        json!({
            "state": if self.running() { "running" } else { "finished" },
            "command": self.command,
            "target": self.target,
        })
    }
}

static ENVIRONMENT_JOB: Mutex<Option<EnvironmentJob>> = Mutex::new(None);

fn environment_job() -> MutexGuard<'static, Option<EnvironmentJob>> {
    ENVIRONMENT_JOB
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// Commands refused while an environment operation runs: they would start,
/// inspect or reshape a distribution that is being created or changed.
fn blocked_by_environment_job(command: &str, request: &Value, target: &str) -> bool {
    matches!(
        command,
        "start"
            | "switch"
            | "preflight"
            | "prepare_kernel"
            | "probe_exit"
            | "shutdown_daemon"
            | "environment_create"
            | "environment_edit"
            | "environment_backup"
            | "environment_delete"
            | "wsl_platform_update"
    ) || (command == "environment_view" && request["name"].as_str() == Some(target))
}

fn start_environment_job(
    command: &'static str,
    target: String,
    work: impl FnOnce() -> Result<Value, String> + Send + 'static,
) -> Result<Value, crate::command::Failure> {
    let mut job = environment_job();
    // A finished job nobody collected is replaced; its result is in the log.
    if job.as_ref().is_some_and(EnvironmentJob::running) {
        return Err(crate::command::Failure::new(
            "environment_job_running",
            "Another environment operation is still running",
        ));
    }
    let worker = std::thread::Builder::new()
        .name("environment-job".into())
        .spawn(move || {
            let result = work();
            log_environment_result(command, &result);
            result
        })
        .map_err(|error| {
            crate::command::Failure::new(
                "desktop_request_failed",
                format!("environment_job_start:{error}"),
            )
        })?;
    // Always "running": a job that fails at once must still be collected with
    // `environment_job`, never mistaken for a finished result here.
    let view = json!({"state":"running","command":command,"target":target});
    *job = Some(EnvironmentJob {
        command,
        target,
        worker: Some(worker),
    });
    Ok(json!({"job":view}))
}

/// The running job's state, or its result exactly once after it ends.
fn poll_environment_job() -> Result<Value, crate::command::Failure> {
    let mut slot = environment_job();
    let Some(job) = slot.as_mut() else {
        return Err(crate::command::Failure::new(
            "environment_job_missing",
            "No environment operation result is waiting",
        ));
    };
    if job.running() {
        return Ok(json!({"job":job.view()}));
    }
    let worker = job.worker.take();
    *slot = None;
    match worker.map(JoinHandle::join) {
        Some(Ok(Ok(value))) => Ok(value),
        Some(Ok(Err(error))) => Err(crate::command::Failure::new(
            "desktop_request_failed",
            error,
        )),
        _ => Err(crate::command::Failure::new(
            "desktop_request_failed",
            "environment_job_panicked",
        )),
    }
}

/// Written when the operation ends, whether or not a window is still open.
fn log_environment_result(command: &str, result: &Result<Value, String>) {
    // Unit tests must not write into the real per-user store.
    if cfg!(test) {
        return;
    }
    let Ok(path) = profile_path() else {
        return;
    };
    let response = match result {
        Ok(value) => value.clone(),
        Err(error) => json!({"code":"desktop_request_failed","message":error}),
    };
    let (level, source, message) = command_log(command, &response);
    let _ = desktop_store::append_runtime_log(&path, level, &source, &message, None, None, None);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SqliteSave {
    profile: Config,
    desktop: Preferences,
    #[serde(default)]
    residential: Option<ResidentialSettings>,
    expected_revision: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentCreate {
    name: String,
    distribution: String,
    install_path: String,
    username: String,
    password: String,
    #[serde(default)]
    install_zsh: bool,
    #[serde(default)]
    install_chrome: bool,
    #[serde(default)]
    install_chinese: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentEdit {
    name: String,
    #[serde(default)]
    install_zsh: bool,
    #[serde(default)]
    install_chrome: bool,
    #[serde(default)]
    install_chinese: bool,
    #[serde(default)]
    timezone: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentKey {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentBackup {
    name: String,
    backup_path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentDelete {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeLogs {
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    before_id: Option<i64>,
    #[serde(default = "default_runtime_log_limit")]
    limit: u32,
}

fn default_runtime_log_limit() -> u32 {
    500
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionRecords {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    before_id: Option<i64>,
    #[serde(default = "default_connection_record_limit")]
    limit: u32,
}

fn default_connection_record_limit() -> u32 {
    200
}

fn environment_options(
    zsh: bool,
    chrome: bool,
    chinese: bool,
    username: Option<String>,
    password: Option<String>,
    timezone: Option<String>,
) -> InstallOptions {
    InstallOptions {
        zsh,
        chrome,
        chinese,
        username,
        password,
        timezone,
    }
}

fn require_idle(controller: &mut controller::Controller) -> Result<(), crate::command::Failure> {
    let phase = controller
        .status()
        .map_err(|error| crate::command::Failure::new("controller_error", error))?["phase"]
        .as_str()
        .unwrap_or("unknown")
        .to_owned();
    if phase != "idle" {
        return Err(crate::command::Failure::new(
            "environment_requires_idle",
            "先停止接管并恢复直连，再管理 WSL 环境",
        ));
    }
    Ok(())
}
fn profile_path() -> Result<PathBuf, String> {
    desktop_store::path()
}

/// 用已保存的配置检测住宅代理：直连和经宿主 SOCKS5 各走一遍。只读配置库，不碰接管状态。
/// 结果带上检测时的配置版本，桌面端据此判断结果是否已经过时。
/// Decision 25: the direct path of the residential check sends the
/// residential credentials in clear text without the first hop, so the
/// request must say the user confirmed it, as `wsl_platform_update` does. A
/// caller of the same account can still pass it; this records intent, it is
/// not an access control.
fn residential_probe_confirmed(request: &Value) -> Result<(), crate::command::Failure> {
    if request["confirm"].as_bool() == Some(true) {
        return Ok(());
    }
    Err(crate::command::Failure::new(
        "confirmation_required",
        "Pass confirm: the direct path sends the residential credentials in clear text without the first hop",
    ))
}

fn residential_probe() -> Result<Value, String> {
    let path = profile_path()?;
    let revision = desktop_store::revision(&path)?;
    let (config, residential) = desktop_store::load_runtime(&path)?;
    let policy = crate::policy::Policy::assemble_for_store(
        crate::policy::Validated::new(config)?,
        residential,
    )?;
    let mut report = policy.probe_residential();
    report["revision"] = json!(revision.to_string());
    Ok(json!({"residential_probe": report}))
}

fn sqlite_view(path: &Path) -> Result<Value, String> {
    let record = desktop_store::ensure(path)?;
    Ok(desktop_store::view(path, &record))
}

fn sqlite_save(path: &Path, req: SqliteSave) -> Result<Value, String> {
    let record = desktop_store::save(
        path,
        req.profile,
        req.desktop,
        req.residential,
        req.expected_revision,
    )?;
    Ok(desktop_store::view(path, &record))
}

fn log_command(command: &str) -> bool {
    matches!(
        command,
        "profile_save"
            | "preflight"
            | "prepare_kernel"
            | "start"
            | "switch"
            | "stop"
            | "probe_exit"
            | "residential_probe"
            | "export_diagnostics"
            | "environment_create"
            | "environment_edit"
            | "environment_backup"
            | "environment_delete"
            | "import_credential"
            | "forget_credential"
            | "reset_dns_aliases"
            | "abandon"
    )
}

/// 运行日志的来源。WSL 平台检查与升级统一记为 `wsl`，失败时不显示成命令名。
fn log_source(command: &str) -> String {
    match command {
        "wsl_platform" | "wsl_platform_update" => "wsl".into(),
        other => other.to_owned(),
    }
}

/// The code a failure is logged under. Environment jobs and some requests
/// wrap theirs in `desktop_request_failed` (or `controller_error`) with the
/// specific code leading the message (`environment_name_exists`,
/// `environment_setup_failed:…`); the wrapper alone says nothing, and the
/// desktop sends the user to this log while such a job runs. Only the code
/// is logged, never the rest of the message: that can carry wsl.exe or guest
/// script output, paths and what the user typed.
fn failure_code(response: &Value) -> Option<&str> {
    let code = response.get("code")?.as_str()?;
    if !matches!(code, "desktop_request_failed" | "controller_error") {
        return Some(code);
    }
    // Like the desktop's `humanize_error`: a code is the whole message or
    // what comes before its first ':', and has an underscore, so a message
    // that is plain prose ("cannot connect to …") keeps the wrapper.
    let inner = response["message"].as_str().and_then(|message| {
        let message = message.trim();
        let token = message.split_once(':').map_or(message, |(code, _)| code);
        (token.contains('_')
            && token
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
        .then_some(token)
    });
    Some(inner.unwrap_or(code))
}

/// What failed, in the run log's words.
fn failed_action(command: &str) -> &'static str {
    match command {
        "environment_create" => "新建环境",
        "environment_edit" => "编辑环境",
        "environment_backup" => "备份环境",
        "environment_delete" => "删除环境",
        "wsl_platform_update" => "升级 WSL",
        "start" => "启动接管",
        "switch" => "切换目标",
        "stop" => "停止接管",
        "preflight" => "预检",
        "prepare_kernel" => "准备内核环境",
        "profile_save" => "保存配置",
        _ => "操作",
    }
}

fn command_log(command: &str, response: &Value) -> (&'static str, String, String) {
    if let Some(code) = failure_code(response) {
        let action = failed_action(command);
        // 「升级 WSL 失败」：西文和中文之间留空格。
        let gap = if action.ends_with(|c: char| c.is_ascii_alphanumeric()) {
            " "
        } else {
            ""
        };
        return (
            "error",
            log_source(command),
            format!("{action}{gap}失败（{code}）"),
        );
    }
    if matches!(command, "start" | "switch" | "stop") && response["passed"] == false {
        let blockers = response["blockers"].as_array().map_or(0, Vec::len);
        return (
            "warning",
            "preflight".into(),
            format!("操作前预检未通过（{blockers} 个阻断项）"),
        );
    }
    match command {
        "profile_save" => ("info", "desktop_store".into(), "配置已保存到 SQLite".into()),
        "preflight" if response["passed"] == true => {
            ("info", "preflight".into(), "预检通过".into())
        }
        "preflight" => {
            let blockers = response["blockers"].as_array().map_or(0, Vec::len);
            (
                "warning",
                "preflight".into(),
                format!("预检未通过（{blockers} 个阻断项）"),
            )
        }
        "prepare_kernel" => {
            let preparation = &response["preparation"];
            let added = preparation["modules_added"].as_array().map_or(0, Vec::len);
            let failed = preparation["modules_failed"].as_array().map_or(0, Vec::len);
            let blockers = response["blockers"].as_array().map_or(0, Vec::len);
            let level = if preparation["ok"] == true && failed == 0 {
                "info"
            } else {
                "warning"
            };
            (
                level,
                "kernel".into(),
                format!(
                    "内核环境准备：新增 {added} 个模块，{failed} 个未加载，剩余 {blockers} 个阻断项"
                ),
            )
        }
        "start" | "switch"
            if response["protection_check"]["legacy_foreign_rules"]
                .as_u64()
                .unwrap_or(0)
                > 0
                && response["unproven_mappings_left"].as_u64().unwrap_or(0) == 0 =>
        {
            let count = response["protection_check"]["legacy_foreign_rules"]
                .as_u64()
                .unwrap_or(0);
            (
                "warning",
                "lifecycle".into(),
                format!(
                    "{}。{}",
                    if command == "start" {
                        "已开始接管"
                    } else {
                        "已切换接管目标"
                    },
                    crate::controller::legacy_rules_warning(
                        u32::try_from(count).unwrap_or(u32::MAX)
                    )
                ),
            )
        }
        "start" => ("info", "lifecycle".into(), "已开始接管".into()),
        "switch" | "stop" if response["unproven_mappings_left"].as_u64().unwrap_or(0) > 0 => (
            "warning",
            "lifecycle".into(),
            format!(
                "{}；旧目标里还留着 {} 条带本次接管标记、但无法证明归属的连接跟踪记录，按设计没有删除。它们只会让各自原有的连接失败，不影响新连接，连接跟踪超时后自行消失。",
                if command == "stop" {
                    "已停止接管并恢复直连"
                } else {
                    "已切换接管目标"
                },
                response["unproven_mappings_left"]
            ),
        ),
        "switch" => ("info", "lifecycle".into(), "已切换接管目标".into()),
        "stop" => ("info", "lifecycle".into(), "已停止接管并恢复直连".into()),
        "probe_exit" => ("info", "diagnostics".into(), "出口检测完成".into()),
        // 只记结论，不记服务器地址和账号。
        "residential_probe" => {
            let (level, text) = match response["residential_probe"]["verdict"].as_str() {
                Some("both") => ("info", "直连和经宿主 SOCKS5 都能用"),
                Some("needs_first_hop") => ("info", "需要经宿主 SOCKS5，直连不通"),
                Some("direct_only") => ("warning", "只能直连，经宿主 SOCKS5 不通"),
                Some("credential_rejected") => ("warning", "住宅服务器拒绝了登录"),
                _ => ("warning", "直连和经宿主 SOCKS5 都不通"),
            };
            (level, "residential".into(), format!("住宅代理检测：{text}"))
        }
        "export_diagnostics" => ("info", "diagnostics".into(), "诊断报告已导出".into()),
        "environment_create" => ("info", "environment".into(), "环境创建完成".into()),
        "environment_edit" => ("info", "environment".into(), "环境设置已更新".into()),
        "environment_backup" => ("info", "environment".into(), "环境备份完成".into()),
        "environment_delete" => ("info", "environment".into(), "环境已删除".into()),
        "wsl_platform_update" => {
            let update = &response["update"];
            let before = update["before"]["version"].as_str().unwrap_or("未知");
            let after = update["after"]["version"].as_str().unwrap_or("未知");
            let (level, message) = if update["updated"] == true {
                ("info", format!("WSL 已升级：{before} → {after}"))
            } else if before == "未知" || after == "未知" {
                (
                    "warning",
                    "WSL 升级命令已执行，但没有读到版本变化，无法确认是否升级".to_owned(),
                )
            } else {
                ("info", format!("WSL 已是最新（{after}）"))
            };
            (level, "wsl".into(), message)
        }
        "import_credential" => (
            "info",
            "desktop_store".into(),
            "住宅设置已写入本地 SQLite".into(),
        ),
        "forget_credential" => (
            "info",
            "desktop_store".into(),
            "本地 SQLite 中的住宅设置已清空".into(),
        ),
        "reset_dns_aliases" => ("info", "dns".into(), "DNS 别名缓存已重置".into()),
        "abandon" => (
            "warning",
            "lifecycle".into(),
            "已放弃已注销目标的接管记录；下次启动前请执行 wsl --shutdown".into(),
        ),
        _ => ("info", command.to_owned(), "操作完成".into()),
    }
}

fn response_status(response: &Value) -> Option<&Value> {
    if response["phase"].is_string() {
        Some(response)
    } else {
        response.get("controller")
    }
}

fn record_runtime_result(command: &str, response: &Value, controller: &controller::Controller) {
    if !log_command(command) && command != "status" {
        return;
    }
    let Ok(path) = profile_path() else {
        return;
    };
    // An error reply carries no state. Asking again would repeat the guest
    // inspection in recovery_required, so failures are logged without context.
    let status = response_status(response).cloned().or_else(|| {
        if response.get("code").is_some() {
            None
        } else {
            controller.status().ok()
        }
    });
    if let Some(status) = status.as_ref() {
        let _ = desktop_store::record_runtime_snapshot(&path, status);
    }
    if !log_command(command) {
        return;
    }
    let (level, source, message) = command_log(command, response);
    let status = status.as_ref();
    let _ = desktop_store::append_runtime_log(
        &path,
        level,
        &source,
        &message,
        status.and_then(|value| value["phase"].as_str()),
        status.and_then(|value| value["active_target"].as_str()),
        status.and_then(|value| value["operation_generation"].as_u64()),
    );
}
// Diagnostics are an allowlist, not a recursive 'remove password' filter. No free-form
// strings, flow addresses, hostnames, distribution names, paths, or credential references.
fn sanitized(s: &Value) -> Value {
    let phase = s["phase"]
        .as_str()
        .filter(|p| {
            matches!(
                *p,
                "idle" | "recovery_required" | "forwarding_managed" | "forwarding_scoped"
            )
        })
        .unwrap_or("unknown");
    let mut counters = serde_json::Map::new();
    for k in [
        "chain_tcp",
        "direct_tcp",
        "direct_udp",
        "dns_tcp",
        "dns_udp",
        "chain_udp",
        "rejected_tcp",
        "rejected_udp",
        "tcp_capacity_rejections",
        "metadata_queries",
        "metadata_successes",
        "metadata_transport_failures",
        "tcp_failures",
        "tcp_client_resets",
        "udp_failures",
    ] {
        if let Some(n) = s["forwarding"]["counters"][k].as_u64() {
            counters.insert(k.into(), n.into());
        }
    }
    json!({"schema":1,"phase":phase,"operation_generation":s["operation_generation"].as_u64(),"dns_managed":s["dns_managed"].as_bool(),"fresh_udp_dns":s["startup_verified"]["fresh_udp_dns"].as_bool(),"fresh_tcp_dns":s["startup_verified"]["fresh_tcp_dns"].as_bool(),"udp_supported":s["startup_verified"]["udp_supported"].as_bool(),"https_status":s["startup_verified"]["https_status"].as_u64(),"tx_bytes":s["forwarding"]["traffic"]["tx_bytes"].as_u64(),"rx_bytes":s["forwarding"]["traffic"]["rx_bytes"].as_u64(),"counters":counters})
}
fn export(controller: &controller::Controller) -> Result<Value, String> {
    let doc = sanitized(&controller.status()?);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "invalid_clock")?
        .as_nanos();
    let path = host::data_dir()?.join(format!("diagnostics-{now}.json"));
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(&mut f, &doc).map_err(|e| e.to_string())?;
    f.flush().map_err(|e| e.to_string())?;
    Ok(json!({"path":path}))
}

/// Parses a desktop request's fields. Any malformed request reports only
/// `code`: requests can carry passwords, so serde's text must not travel back.
fn fields<T: DeserializeOwned>(
    request: &mut Value,
    code: &'static str,
) -> Result<T, crate::command::Failure> {
    let bad = || crate::command::Failure::new("desktop_request_failed", code);
    let object = request.as_object_mut().ok_or_else(bad)?;
    object.remove("command");
    serde_json::from_value(Value::Object(std::mem::take(object))).map_err(|_| bad())
}

pub fn handle(mut request: Value, controller: &mut controller::Controller) -> (Value, bool) {
    let command = request
        .get("command")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let result = (|| -> Result<(Value, bool), crate::command::Failure> {
        let bad = |m: String| crate::command::Failure::new("desktop_request_failed", m);
        let cmd = request
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("missing_command".into()))?
            .to_owned();
        if let Some(job) = environment_job().as_ref().filter(|job| job.running())
            && blocked_by_environment_job(&cmd, &request, &job.target)
        {
            return Err(crate::command::Failure::new(
                "environment_job_running",
                format!("{} is still running for {}", job.command, job.target),
            ));
        }
        let data = match cmd.as_str() {
            "profile_get" => {
                let p = profile_path().map_err(bad)?;
                sqlite_view(&p).map_err(bad)?
            }
            "profile_save" => {
                let req: SqliteSave = fields(&mut request, "invalid_desktop_profile_fields")?;
                sqlite_save(&profile_path().map_err(bad)?, req).map_err(bad)?
            }
            "runtime_logs" => {
                let req: RuntimeLogs = fields(&mut request, "invalid_runtime_log_fields")?;
                desktop_store::runtime_logs(
                    &profile_path().map_err(bad)?,
                    req.level.as_deref(),
                    req.search.as_deref(),
                    req.before_id,
                    req.limit,
                )
                .map_err(bad)?
            }
            "connection_records" => {
                let req: ConnectionRecords =
                    fields(&mut request, "invalid_connection_record_fields")?;
                let mut records = desktop_store::connection_records(
                    &profile_path().map_err(bad)?,
                    req.status.as_deref(),
                    req.target.as_deref(),
                    req.before_id,
                    req.limit,
                )
                .map_err(bad)?;
                records["queue_dropped"] = json!(crate::ingress::flow_sink_dropped());
                records
            }
            "environment_view" => {
                let req: EnvironmentKey = fields(&mut request, "invalid_environment_fields")?;
                environment::view(&req.name).map_err(bad)?
            }
            "environment_create" => {
                require_idle(controller)?;
                let req: EnvironmentCreate = fields(&mut request, "invalid_environment_fields")?;
                let target = req.name.clone();
                start_environment_job("environment_create", target, move || {
                    let environment = environment::create(
                        &req.name,
                        &req.distribution,
                        &req.install_path,
                        environment_options(
                            req.install_zsh,
                            req.install_chrome,
                            req.install_chinese,
                            Some(req.username.clone()),
                            Some(req.password.clone()),
                            None,
                        ),
                    )?;
                    let mut response = json!({"environment":environment});
                    if let Ok(distributions) = host::distributions() {
                        response["distributions"] = json!(distributions);
                    }
                    Ok(response)
                })?
            }
            "environment_edit" => {
                require_idle(controller)?;
                let req: EnvironmentEdit = fields(&mut request, "invalid_environment_fields")?;
                let target = req.name.clone();
                start_environment_job("environment_edit", target, move || {
                    let environment = environment::edit(
                        &req.name,
                        environment_options(
                            req.install_zsh,
                            req.install_chrome,
                            req.install_chinese,
                            None,
                            None,
                            req.timezone,
                        ),
                    )?;
                    Ok(json!({"environment":environment}))
                })?
            }
            "environment_backup" => {
                require_idle(controller)?;
                let req: EnvironmentBackup = fields(&mut request, "invalid_environment_fields")?;
                let target = req.name.clone();
                start_environment_job("environment_backup", target, move || {
                    let backup = environment::backup(&req.name, &req.backup_path)?;
                    Ok(json!({"backup":backup}))
                })?
            }
            "environment_delete" => {
                require_idle(controller)?;
                let req: EnvironmentDelete = fields(&mut request, "invalid_environment_fields")?;
                let target = req.name.clone();
                start_environment_job("environment_delete", target, move || {
                    let environment = environment::remove(&req.name)?;
                    let mut response = json!({"environment":environment});
                    if let Ok(distributions) = host::distributions() {
                        response["distributions"] = json!(distributions);
                    }
                    Ok(response)
                })?
            }
            "environment_job" => poll_environment_job()?,
            "wsl_platform_update" => {
                let confirm = request["confirm"].as_bool().unwrap_or(false);
                crate::command::wsl_update_ready(controller, confirm)?;
                start_environment_job("wsl_platform_update", "WSL".into(), || {
                    let update = wsl_platform::update()?;
                    Ok(json!({"update":update}))
                })?
            }
            "export_diagnostics" => export(controller).map_err(bad)?,
            "residential_probe" => {
                residential_probe_confirmed(&request)?;
                residential_probe().map_err(bad)?
            }
            "probe_exit" => {
                let generation = request["expected_generation"]
                    .as_u64()
                    .ok_or_else(|| bad("expected_generation_required".into()))?;
                controller.probe_exit(generation).map_err(bad)?;
                controller.status().map_err(bad)?
            }
            "shutdown_daemon" => {
                if controller.status().map_err(bad)?["phase"] != "idle" {
                    return Err(bad("stop_and_restore_before_daemon_shutdown".into()));
                }
                return Ok((json!({"shutdown":true}), true));
            }
            "list" | "status" | "preflight" | "prepare_kernel" | "import_credential"
            | "forget_credential" | "start" | "switch" | "stop" | "abandon"
            | "reset_dns_aliases" | "wsl_platform" => {
                if matches!(&*cmd, "start" | "switch" | "stop" | "abandon")
                    && request["expected_generation"].as_u64().is_none()
                {
                    return Err(bad("expected_generation_required".into()));
                }
                if matches!(&*cmd, "start" | "switch") && request["profile"].is_string() {
                    let path = profile_path().map_err(bad)?;
                    let expect = request.as_object_mut().unwrap().remove("profile_revision");
                    let current_revision = desktop_store::revision(&path).map_err(bad)?;
                    let current_revision = current_revision.to_string();
                    if request["profile"].as_str().map(Path::new) != Some(path.as_path())
                        || current_revision == "0"
                        || expect.as_ref().and_then(Value::as_str)
                            != Some(current_revision.as_str())
                    {
                        return Err(bad("saved_profile_revision_required".into()));
                    }
                }
                let req = serde_json::from_value::<crate::command::Command>(request)
                    .map_err(|_| bad("invalid_request_fields".into()))?;
                let (_, mut value) = crate::command::dispatch_result(req, controller)?;
                // A reopened window learns that an environment operation is running.
                if cmd == "status"
                    && let Some(job) = environment_job().as_ref()
                {
                    value["environment_job"] = job.view();
                }
                return Ok((value, false));
            }
            _ => return Err(bad("command_not_available_on_desktop_channel".into())),
        };
        Ok((data, false))
    })();
    let response = result.unwrap_or_else(|e| (json!({"code":e.code,"message":e.message}), false));
    if let Some(command) = command.as_deref() {
        // A started environment job logs its own outcome when it ends.
        if response.0["job"]["state"] != "running" {
            record_runtime_result(command, &response.0, controller);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_residential_check_needs_an_explicit_confirm() {
        for request in [
            json!({"command":"residential_probe"}),
            json!({"command":"residential_probe","confirm":false}),
            json!({"command":"residential_probe","confirm":"true"}),
        ] {
            assert_eq!(
                residential_probe_confirmed(&request).map_err(|e| e.code),
                Err("confirmation_required"),
                "{request}"
            );
        }
        assert!(
            residential_probe_confirmed(&json!({"command":"residential_probe","confirm":true}))
                .is_ok()
        );
    }

    #[test]
    fn a_failure_is_logged_with_its_own_code_and_no_free_text() {
        // An environment job reports its failure wrapped; the log names the
        // operation and the inner code, not the wsl.exe output or the path.
        let (level, source, message) = command_log(
            "environment_create",
            &json!({"code":"desktop_request_failed","message":"environment_distribution_install_failed:Wsl/InstallDistro/0x80072ee7 C:\\Users\\someone\\WSL"}),
        );
        assert_eq!(
            (level, source.as_str(), message.as_str()),
            (
                "error",
                "environment_create",
                "新建环境失败（environment_distribution_install_failed）"
            )
        );
        let (_, _, message) = command_log(
            "environment_backup",
            &json!({"code":"desktop_request_failed","message":"environment_backup_exists"}),
        );
        assert_eq!(message, "备份环境失败（environment_backup_exists）");
        let (_, source, message) = command_log(
            "wsl_platform_update",
            &json!({"code":"desktop_request_failed","message":"wsl_update_command_failed: exit 1"}),
        );
        assert_eq!(
            (source.as_str(), message.as_str()),
            ("wsl", "升级 WSL 失败（wsl_update_command_failed）")
        );
        // A specific code is kept as it is.
        let (_, _, message) = command_log(
            "start",
            &json!({"code":"timezone_sync_failed","message":"timezone_lookup_failed"}),
        );
        assert_eq!(message, "启动接管失败（timezone_sync_failed）");
        // A wrapped message that does not lead with a code keeps the wrapper:
        // no word of prose is logged as if it were one.
        for prose in [
            "Windows error 5",
            "cannot connect to first-hop for residential UDP",
            "policy contains an endpoint loop",
            "policy: endpoint loop",
            "wsl_exit_failed 1",
        ] {
            let (_, _, message) = command_log(
                "environment_delete",
                &json!({"code":"desktop_request_failed","message":prose}),
            );
            assert_eq!(message, "删除环境失败（desktop_request_failed）", "{prose}");
        }
    }

    #[test]
    fn a_stop_that_left_unprovable_mappings_is_logged_as_a_warning() {
        let (level, source, message) =
            command_log("stop", &json!({"phase":"idle","unproven_mappings_left":2}));
        assert_eq!((level, source.as_str()), ("warning", "lifecycle"));
        assert!(
            message.starts_with("已停止接管并恢复直连；旧目标里还留着 2 条"),
            "{message}"
        );
        let (level, _, message) = command_log("stop", &json!({"phase":"idle"}));
        assert_eq!((level, message.as_str()), ("info", "已停止接管并恢复直连"));
        let (level, _, message) = command_log("switch", &json!({"unproven_mappings_left":1}));
        assert_eq!(level, "warning");
        assert!(message.starts_with("已切换接管目标；"), "{message}");
    }

    #[test]
    fn a_start_next_to_foreign_legacy_rules_is_logged_as_a_warning() {
        let started =
            json!({"phase":"forwarding_managed","protection_check":{"legacy_foreign_rules":3}});
        let (level, source, message) = command_log("start", &started);
        assert_eq!((level, source.as_str()), ("warning", "lifecycle"));
        assert!(
            message.starts_with("已开始接管。共享网络里的 legacy iptables 表有 3 条"),
            "{message}"
        );
        let (level, _, message) = command_log("switch", &started);
        assert_eq!(level, "warning");
        assert!(message.starts_with("已切换接管目标。"), "{message}");
        let clean =
            json!({"phase":"forwarding_managed","protection_check":{"legacy_foreign_rules":0}});
        assert_eq!(command_log("start", &clean).2, "已开始接管");
        assert_eq!(command_log("start", &json!({})).2, "已开始接管");
    }

    #[test]
    fn an_environment_job_runs_once_reports_once_and_blocks_conflicting_requests() {
        let (release, gate) = std::sync::mpsc::channel::<()>();
        let started = start_environment_job("environment_create", "Dev".into(), move || {
            gate.recv().unwrap();
            Ok(json!({"environment":{"name":"Dev"}}))
        })
        .map_err(|error| error.code)
        .unwrap();
        assert_eq!(started["job"]["state"], "running");
        assert_eq!(
            poll_environment_job().map_err(|e| e.code).unwrap()["job"]["state"],
            "running"
        );
        assert_eq!(
            start_environment_job("environment_edit", "Other".into(), || Ok(json!({})))
                .map_err(|error| error.code)
                .unwrap_err(),
            "environment_job_running"
        );
        let request = json!({"command":"environment_view","name":"Dev"});
        assert!(blocked_by_environment_job("start", &request, "Dev"));
        assert!(blocked_by_environment_job(
            "environment_view",
            &request,
            "Dev"
        ));
        assert!(!blocked_by_environment_job(
            "environment_view",
            &request,
            "Other"
        ));
        assert!(!blocked_by_environment_job("status", &request, "Dev"));

        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let result = loop {
            let value = poll_environment_job().map_err(|error| error.code).unwrap();
            if value["job"]["state"] != "running" {
                break value;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(result["environment"]["name"], "Dev");
        // The result is handed out once; a failed job reports its error.
        assert_eq!(
            poll_environment_job().map_err(|e| e.code).unwrap_err(),
            "environment_job_missing"
        );
        start_environment_job("environment_delete", "Dev".into(), || {
            Err("environment_not_found:Dev".into())
        })
        .map_err(|error| error.code)
        .unwrap();
        let failure = loop {
            match poll_environment_job() {
                Ok(value) if value["job"]["state"] == "running" => {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                other => break other.map_err(|error| error.message).unwrap_err(),
            }
        };
        assert_eq!(failure, "environment_not_found:Dev");

        // A job that fails before the reply is built still starts as running.
        let started = start_environment_job("environment_create", "Dup".into(), || {
            Err("environment_name_exists".into())
        })
        .map_err(|error| error.code)
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(started["job"]["state"], "running");
        let failure = loop {
            match poll_environment_job() {
                Ok(value) if value.get("job").is_some() => {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                other => break other.map_err(|error| error.message).unwrap_err(),
            }
        };
        assert_eq!(failure, "environment_name_exists");
    }
    #[test]
    fn exported_diagnostic_omits_network_identifiers_and_free_text() {
        let v = sanitized(
            &json!({"phase":"forwarding_managed","active_target":"secret","issue":"secret","active_policy":{"credential":"secret"},"forwarding":{"traffic":{"tx_bytes":12},"connections":{"recent":[{"destination":"secret"}]},"counters":{"chain_tcp":4,"last_error":"secret"}}}),
        );
        assert!(!v.to_string().contains("secret"));
        assert_eq!(v["tx_bytes"], 12);
        assert_eq!(v["counters"]["chain_tcp"], 4);
    }
}
