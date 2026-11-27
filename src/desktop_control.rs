use crate::{
    controller,
    desktop_store::{self, ResidentialSettings},
    environment::{self, InstallOptions},
    host,
    policy::Config,
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
fn blocked_by_environment_job(command: &str, request: &Value, job: &EnvironmentJob) -> bool {
    let target = job.target.as_str();
    // Listing or starting apps runs `wsl.exe` in the distribution: not while
    // that one is being changed, nor while `wsl --update` restarts WSL.
    let in_distribution = matches!(
        command,
        "environment_view" | "environment_apps" | "environment_launch"
    );
    if in_distribution
        && (job.command == "wsl_platform_update" || request["name"].as_str() == Some(target))
    {
        return true;
    }
    matches!(
        command,
        "start"
            | "preflight"
            | "prepare_kernel"
            | "install_nftables"
            | "probe_exit"
            | "shutdown_daemon"
            | "environment_create"
            | "environment_edit"
            | "environment_backup"
            | "environment_delete"
            | "wsl_platform_update"
    )
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
    expected_revision: Option<String>,
}

/// One environment's residential proxy and ingress port (decision 40).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentResidentialSave {
    distro_id: String,
    residential: ResidentialSettings,
    #[serde(default)]
    ingress_port: Option<u16>,
    expected_revision: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentResidentialAssign {
    distro_id: String,
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
struct EnvironmentLaunch {
    name: String,
    app: String,
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

/// Editing, backing up or deleting an environment needs only that one to be
/// idle (decision 40): the others keep their takeovers.
fn require_idle(
    controller: &controller::Controller,
    name: &str,
) -> Result<(), crate::command::Failure> {
    let failure = |error: String| crate::command::Failure::new("controller_error", error);
    let distributions = host::distributions().map_err(failure)?;
    let Some(distro) = distributions.iter().find(|d| d.name == name) else {
        return Ok(());
    };
    if controller.owned(&distro.id).map_err(failure)? {
        return Err(crate::command::Failure::new(
            "environment_requires_idle",
            "先停止这个环境的接管并恢复直连，再管理它",
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

fn residential_probe(distro_id: &str) -> Result<Value, String> {
    let path = profile_path()?;
    let revision = desktop_store::environment(&path, distro_id)?
        .ok_or("residential_credential_incomplete")?
        .revision;
    let (config, residential, _) = desktop_store::load_runtime(&path, distro_id)?;
    let policy = crate::policy::Policy::assemble_for_store(
        crate::policy::Validated::new(config)?,
        residential,
    )?;
    let mut report = policy.probe_residential();
    report["revision"] = json!(revision.to_string());
    report["distro_id"] = json!(distro_id.to_ascii_lowercase());
    // The first hop is in the shared profile: a later save there also makes
    // this result stale.
    report["profile_revision"] = json!(desktop_store::revision(&path)?.to_string());
    Ok(json!({"residential_probe": report}))
}

/// The saved profile and every environment's residential row. A store from
/// before decision 40 first gives its single proxy to the environment it was
/// saved for, when that one is still registered.
fn sqlite_view(path: &Path) -> Result<Value, String> {
    if let Ok(distributions) = host::distributions() {
        desktop_store::adopt_legacy_residential(path, &distributions)?;
    }
    let record = desktop_store::ensure(path)?;
    desktop_store::view(path, &record)
}

fn sqlite_save(path: &Path, req: SqliteSave) -> Result<Value, String> {
    let record = desktop_store::save(path, req.profile, req.expected_revision)?;
    desktop_store::view(path, &record)
}

/// A live or recorded takeover's proxy and port change only after it stops.
fn environment_residential_save(req: EnvironmentResidentialSave) -> Result<Value, String> {
    if crate::command::owned_by(&req.distro_id)? {
        return Err(
            "environment_residential_in_use: stop this environment's takeover first".into(),
        );
    }
    let path = profile_path()?;
    desktop_store::save_environment(
        &path,
        &req.distro_id,
        req.residential,
        req.ingress_port,
        req.expected_revision,
    )?;
    sqlite_view(&path)
}

fn log_command(command: &str) -> bool {
    matches!(
        command,
        "profile_save"
            | "preflight"
            | "prepare_kernel"
            | "install_nftables"
            | "start"
            | "stop"
            | "probe_exit"
            | "residential_probe"
            | "export_diagnostics"
            | "environment_create"
            | "environment_edit"
            | "environment_backup"
            | "environment_delete"
            | "environment_residential_save"
            | "environment_residential_assign"
            | "environment_residential_discard"
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
        "environment_residential_save" => "保存住宅代理",
        "environment_residential_assign" => "分配住宅代理",
        "environment_residential_discard" => "丢弃住宅代理",
        "stop" => "停止接管",
        "preflight" => "预检",
        "prepare_kernel" => "准备内核环境",
        "install_nftables" => "安装 nftables",
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
    if matches!(command, "start" | "stop") && response["passed"] == false {
        let blockers = response["blockers"].as_array().map_or(0, Vec::len);
        return (
            "warning",
            "preflight".into(),
            format!("操作前预检未通过（{blockers} 个阻断项）"),
        );
    }
    match command {
        "profile_save" => ("info", "desktop_store".into(), "配置已保存到 SQLite".into()),
        "environment_residential_save" => (
            "info",
            "desktop_store".into(),
            "环境的住宅代理已保存到 SQLite".into(),
        ),
        "environment_residential_assign" => (
            "info",
            "desktop_store".into(),
            "未分配的住宅代理已分配给环境".into(),
        ),
        "environment_residential_discard" => (
            "info",
            "desktop_store".into(),
            "未分配的住宅代理已丢弃".into(),
        ),
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
        "start" => ("info", "lifecycle".into(), "已开始接管".into()),
        "install_nftables" => (
            "info",
            "kernel".into(),
            if response["nftables"] == "installed" {
                format!(
                    "已在 {} 里安装 nftables",
                    response["target"].as_str().unwrap_or("目标")
                )
            } else {
                format!(
                    "{} 里已有 nftables",
                    response["target"].as_str().unwrap_or("目标")
                )
            },
        ),
        "stop" if response["unproven_mappings_left"].as_u64().unwrap_or(0) > 0 => (
            "warning",
            "lifecycle".into(),
            format!(
                "已停止接管并恢复直连；旧目标里还留着 {} 条带本次接管标记、但无法证明归属的连接跟踪记录，按设计没有删除。它们只会让各自原有的连接失败，不影响新连接，连接跟踪超时后自行消失。",
                response["unproven_mappings_left"]
            ),
        ),
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
        status.and_then(|value| {
            value["active_target"]
                .as_str()
                .or_else(|| value["recorded_target"].as_str())
                .or_else(|| value["last_target"].as_str())
        }),
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
/// One sanitized entry per environment with records (decision 40); the
/// scope (a registry GUID) is left out like every other identifier.
fn sanitized_sessions(status: &Value) -> Value {
    let sessions: Vec<Value> = status["sessions"]
        .as_array()
        .map(|sessions| sessions.iter().map(sanitized).collect())
        .unwrap_or_default();
    json!({"schema":2,"sessions":sessions})
}

fn export(controller: &controller::Controller) -> Result<Value, String> {
    let doc = sanitized_sessions(&controller.status()?);
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
            && blocked_by_environment_job(&cmd, &request, job)
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
            "environment_residential_save" => {
                let req: EnvironmentResidentialSave =
                    fields(&mut request, "invalid_environment_residential_fields")?;
                environment_residential_save(req).map_err(bad)?
            }
            "environment_residential_assign" => {
                let req: EnvironmentResidentialAssign =
                    fields(&mut request, "invalid_environment_residential_fields")?;
                let path = profile_path().map_err(bad)?;
                desktop_store::assign_legacy_residential(&path, &req.distro_id).map_err(bad)?;
                sqlite_view(&path).map_err(bad)?
            }
            "environment_residential_discard" => {
                let path = profile_path().map_err(bad)?;
                desktop_store::discard_legacy_residential(&path).map_err(bad)?;
                sqlite_view(&path).map_err(bad)?
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
            // Neither needs an idle controller: starting apps inside the
            // environment being taken over is the point.
            "environment_apps" => {
                let req: EnvironmentKey = fields(&mut request, "invalid_environment_fields")?;
                environment::apps::list(&req.name).map_err(bad)?
            }
            "environment_launch" => {
                let req: EnvironmentLaunch = fields(&mut request, "invalid_environment_fields")?;
                environment::apps::launch(&req.name, &req.app).map_err(bad)?
            }
            // A new distribution touches no takeover: its setup's legacy
            // iptables writes cannot reach the private tables (decision 41).
            "environment_create" => {
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
                let req: EnvironmentEdit = fields(&mut request, "invalid_environment_fields")?;
                require_idle(controller, &req.name)?;
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
                let req: EnvironmentBackup = fields(&mut request, "invalid_environment_fields")?;
                require_idle(controller, &req.name)?;
                let target = req.name.clone();
                start_environment_job("environment_backup", target, move || {
                    let backup = environment::backup(&req.name, &req.backup_path)?;
                    Ok(json!({"backup":backup}))
                })?
            }
            "environment_delete" => {
                let req: EnvironmentDelete = fields(&mut request, "invalid_environment_fields")?;
                require_idle(controller, &req.name)?;
                let target = req.name.clone();
                // Read before the job: the registry entry is gone afterwards.
                let distro_id = host::distributions()
                    .ok()
                    .and_then(|all| all.into_iter().find(|d| d.name == req.name))
                    .map(|d| d.id);
                start_environment_job("environment_delete", target, move || {
                    let environment = environment::remove(&req.name)?;
                    // Its residential proxy and port go with it.
                    if let Some(id) = distro_id
                        && let Ok(path) = profile_path()
                    {
                        let _ = desktop_store::delete_environment(&path, &id);
                    }
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
                let distro_id = request["distro_id"]
                    .as_str()
                    .ok_or_else(|| bad("distro_id_required".into()))?;
                residential_probe(distro_id).map_err(bad)?
            }
            "probe_exit" => {
                let generation = request["expected_generation"]
                    .as_u64()
                    .ok_or_else(|| bad("expected_generation_required".into()))?;
                let scope = controller
                    .resolve(request["target"].as_str())
                    .map_err(bad)?;
                controller
                    .session(&scope)
                    .probe_exit(generation)
                    .map_err(bad)?;
                controller.session_status(&scope).map_err(bad)?
            }
            "shutdown_daemon" => {
                if controller.any_owned().map_err(bad)? {
                    return Err(bad("stop_and_restore_before_daemon_shutdown".into()));
                }
                return Ok((json!({"shutdown":true}), true));
            }
            "list" | "status" | "preflight" | "prepare_kernel" | "install_nftables"
            | "import_credential" | "forget_credential" | "start" | "stop" | "abandon"
            | "reset_dns_aliases" | "wsl_platform" => {
                if matches!(&*cmd, "start" | "stop" | "abandon")
                    && request["expected_generation"].as_u64().is_none()
                {
                    return Err(bad("expected_generation_required".into()));
                }
                if cmd == "start" && request["profile"].is_string() {
                    // The desktop starts exactly what it showed as saved: the
                    // shared profile and this environment's row.
                    let path = profile_path().map_err(bad)?;
                    let object = request.as_object_mut().unwrap();
                    let expect = object.remove("profile_revision");
                    let expect_environment = object.remove("residential_revision");
                    let current_revision = desktop_store::revision(&path).map_err(bad)?;
                    let current_revision = current_revision.to_string();
                    if request["profile"].as_str().map(Path::new) != Some(path.as_path())
                        || current_revision == "0"
                        || expect.as_ref().and_then(Value::as_str)
                            != Some(current_revision.as_str())
                    {
                        return Err(bad("saved_profile_revision_required".into()));
                    }
                    let saved = request["target"]
                        .as_str()
                        .and_then(|target| {
                            host::distributions()
                                .ok()?
                                .into_iter()
                                .find(|d| d.name == target || d.id.eq_ignore_ascii_case(target))
                        })
                        .and_then(|d| desktop_store::environment(&path, &d.id).ok().flatten());
                    if saved.map(|row| row.revision.to_string())
                        != expect_environment
                            .as_ref()
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    {
                        return Err(bad("saved_environment_revision_required".into()));
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
    fn the_desktop_requests_for_one_environment_parse() {
        // The shapes `drafts::environment_save_request` and the takeover card send.
        let mut save = json!({
            "command":"environment_residential_save",
            "distro_id":"{44444444-4444-4444-4444-444444444444}",
            "residential":{"protocol":"http","ip":"203.0.113.9","port":8080,"username":"fixture-user","password":"fixture-password"},
            "ingress_port":null,
            "expected_revision":null,
        });
        let request: EnvironmentResidentialSave =
            fields(&mut save, "bad").map_err(|e| e.code).unwrap();
        assert_eq!(request.ingress_port, None);
        assert_eq!(request.expected_revision, None);
        let mut later = json!({
            "command":"environment_residential_save",
            "distro_id":"{4444}",
            "residential":{"protocol":"socks5","ip":"","port":0,"username":"","password":""},
            "ingress_port":44000,
            "expected_revision":"3",
        });
        let request: EnvironmentResidentialSave =
            fields(&mut later, "bad").map_err(|e| e.code).unwrap();
        assert_eq!(request.ingress_port, Some(44000));
        let mut assign = json!({"command":"environment_residential_assign","distro_id":"{4444}"});
        assert!(fields::<EnvironmentResidentialAssign>(&mut assign, "bad").is_ok());
        // A desktop from before decision 40 still sends the target and port with
        // the profile: refused, not silently dropped.
        let mut old = json!({
            "command":"profile_save",
            "profile":{},
            "desktop":{"target":"Target","port":43531},
            "expected_revision":"1",
        });
        assert!(fields::<SqliteSave>(&mut old, "bad").is_err());
        // A start without a port uses the one saved for the environment.
        let start: crate::command::Command = serde_json::from_value(json!({
            "command":"start",
            "target":"{4444}",
            "profile":"C:\\WSL Proxy\\desktop.sqlite",
            "expected_generation":7,
        }))
        .unwrap();
        assert!(matches!(
            start,
            crate::command::Command::Start { port: None, .. }
        ));
        // `switch` is gone from the desktop channel.
        assert!(
            serde_json::from_value::<crate::command::Command>(json!({
                "command":"switch","target":"{4444}","expected_generation":7
            }))
            .is_err()
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
        let job = |command: &'static str, target: &str| EnvironmentJob {
            command,
            target: target.into(),
            worker: None,
        };
        let edit_dev = job("environment_edit", "Dev");
        let edit_other = job("environment_edit", "Other");
        let wsl_update = job("wsl_platform_update", "WSL");
        let request = json!({"command":"environment_view","name":"Dev"});
        assert!(blocked_by_environment_job("start", &request, &edit_dev));
        assert!(!blocked_by_environment_job("status", &request, &edit_dev));
        for command in ["environment_view", "environment_apps", "environment_launch"] {
            assert!(blocked_by_environment_job(command, &request, &edit_dev));
            assert!(!blocked_by_environment_job(command, &request, &edit_other));
            // `wsl --update` restarts WSL, so no distribution is safe to touch.
            assert!(blocked_by_environment_job(command, &request, &wsl_update));
        }

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
        let all = sanitized_sessions(&json!({"sessions":[
            {"scope":"05312bc5-8849-43bc-83bd-a7feda8d165f","phase":"idle","active_target":"secret"},
            {"scope":"63536b91-140f-4b7a-8118-a69fcd568827","phase":"forwarding_managed","active_target":"secret"}
        ]}));
        assert_eq!(all["sessions"].as_array().unwrap().len(), 2);
        assert!(!all.to_string().contains("secret"));
        assert!(!all.to_string().contains("05312bc5"));
    }
}
