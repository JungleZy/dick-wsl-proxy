//! 负责与 wsl-proxyctl 后台通信；不包含窗口状态或页面布局。
use std::sync::mpsc::{self, Receiver, Sender};

use serde_json::{Value, json};

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Kind {
    Bootstrap,
    Status,
    /// Background read of persisted connection records: never locks the UI or touches the notice.
    Connections,
    List,
    Logs,
    Preflight,
    Save,
    Start,
    Switch,
    Stop,
    Export,
    Probe,
    EnvironmentView,
    EnvironmentCreate,
    EnvironmentEdit,
    EnvironmentBackup,
    EnvironmentDelete,
    ResetDnsAliases,
    Abandon,
}

impl Kind {
    pub(crate) fn mutation(self) -> bool {
        matches!(
            self,
            Self::Save
                | Self::Start
                | Self::Switch
                | Self::Stop
                | Self::Probe
                | Self::EnvironmentCreate
                | Self::EnvironmentEdit
                | Self::EnvironmentBackup
                | Self::EnvironmentDelete
                | Self::ResetDnsAliases
                | Self::Abandon
        )
    }
    /// 环境操作在后台单独执行，请求立刻返回，结果要轮询。
    pub(crate) fn environment_job(self) -> bool {
        matches!(
            self,
            Self::EnvironmentCreate
                | Self::EnvironmentEdit
                | Self::EnvironmentBackup
                | Self::EnvironmentDelete
        )
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Bootstrap => "连接后台",
            Self::Status => "刷新状态",
            Self::List => "刷新列表",
            Self::Connections => "读取连接记录",
            Self::Logs => "刷新日志",
            Self::Preflight => "启动前检查",
            Self::Save => "保存策略",
            Self::Start => "启动接管",
            Self::Switch => "切换目标",
            Self::Stop => "停止并恢复",
            Self::Export => "导出诊断",
            Self::Probe => "检测出口",
            Self::EnvironmentView => "查看环境",
            Self::EnvironmentCreate => "新增环境",
            Self::EnvironmentEdit => "编辑环境",
            Self::EnvironmentBackup => "备份环境",
            Self::EnvironmentDelete => "删除环境",
            Self::ResetDnsAliases => "重置 DNS 别名",
            Self::Abandon => "放弃本次记录",
        }
    }
}
pub(crate) struct Job {
    pub(crate) kind: Kind,
    pub(crate) epoch: u64,
    pub(crate) request: Value,
}
pub(crate) struct Reply {
    pub(crate) kind: Kind,
    pub(crate) epoch: u64,
    pub(crate) result: Result<Value, String>,
    pub(crate) status: Option<Result<Value, String>>,
}

pub(crate) fn humanize_error(error: &str) -> String {
    let error = error.trim();
    if let Some((code, message)) = error.split_once(" · ") {
        return humanize_code(code.trim(), message.trim());
    }
    if let Some((code, message)) = error.split_once(':')
        && code
            .chars()
            .all(|character| character.is_ascii_lowercase() || character == '_')
    {
        return humanize_code(code, message.trim());
    }
    if error
        .chars()
        .all(|character| character.is_ascii_lowercase() || character == '_')
    {
        return humanize_code(error, "");
    }
    humanize_detail(error)
}

fn humanize_code(code: &str, message: &str) -> String {
    match code {
        "desktop_request_failed" | "controller_error" => humanize_error(message),
        "not_registered" => "找不到指定的 WSL 环境，请刷新列表后重试。".into(),
        "ambiguous_target" => "目标 WSL 名称不唯一，请刷新列表后重试。".into(),
        "not_wsl2" => "该发行版不是 WSL 2，无法执行此操作。".into(),
        "enumeration_failed" => "读取 WSL 环境列表失败，请检查 WSL 服务状态。".into(),
        "probe_failed" => "检查目标 WSL 失败，请确认发行版可以正常启动。".into(),
        "target_already_owned" => "当前已有接管任务，请先停止接管并恢复直连。".into(),
        "environment_requires_idle" => "请先停止接管并恢复直连，再管理 WSL 环境。".into(),
        "same_target" => "当前目标没有变化。".into(),
        "environment_name_invalid" => "环境名称只能使用字母、数字、点、下划线和短横线。".into(),
        "environment_name_exists" => "环境名称已经存在，请换一个名称。".into(),
        "environment_distribution_invalid" => "发行版选择无效，请从列表中重新选择。".into(),
        "environment_distribution_download_failed" => {
            "下载发行版失败，请检查网络和 WSL 状态后重试。".into()
        }
        "environment_wsl_update_required" => {
            "当前 WSL 版本不支持按名称和位置安装发行版，请在 Windows 终端运行 wsl --update 后重试。"
                .into()
        }
        "environment_distribution_install_failed" => {
            "安装微软发行版失败，请检查网络、权限和 WSL 状态后重试。".into()
        }
        "environment_not_registered" => "发行版安装完成但没有注册成功，请检查 WSL 状态。".into(),
        "environment_not_wsl2" => "安装的发行版不是 WSL 2，无法继续初始化。".into(),
        "environment_distribution_not_registered" => {
            "发行版下载完成但没有注册成功，请检查 WSL 状态后重试。".into()
        }
        "environment_distribution_export_failed" => {
            "准备发行版文件失败，请检查磁盘空间和 WSL 状态。".into()
        }
        "environment_distribution_cleanup_failed" => {
            "清理临时发行版失败，请检查 WSL 状态后重试。".into()
        }
        "environment_install_dir_exists" => {
            "实际环境目录已经存在，请换一个父目录或环境名称。".into()
        }
        "environment_install_dir_parent_not_found" => {
            "安装目录的父目录不存在，请选择有效的父目录。".into()
        }
        "environment_install_dir_reparse_point" => {
            "安装目录位于链接目录中，请选择普通本地目录。".into()
        }
        "environment_username_required" | "environment_password_required" => {
            "请输入默认用户和密码。".into()
        }
        "environment_username_invalid" => {
            "默认用户名格式无效，请使用小写字母、数字、下划线或短横线。".into()
        }
        "environment_password_invalid" => "默认用户密码不能为空，且不能包含换行。".into(),
        "environment_timezone_invalid" => "时区格式无效，请从时区列表中选择。".into(),
        "environment_timezone_not_found" => "所选时区在发行版中不可用，请换一个时区。".into(),
        "environment_setup_failed" => "环境初始化失败，已尝试撤销本次导入。".into(),
        "environment_import_rolled_back" => "环境初始化失败，本次导入已撤销。".into(),
        "environment_backup_required" | "environment_backup_parent_not_found" => {
            "备份路径无效，请选择存在的父目录。".into()
        }
        "environment_backup_exists" => "备份文件已经存在，请换一个文件名。".into(),
        "environment_backup_output_missing" => "备份没有生成，请检查磁盘空间后重试。".into(),
        "autostart_open_failed" | "autostart_read_failed" | "autostart_write_failed" => {
            "开机自启设置失败，请检查系统权限。".into()
        }
        "stale_profile_revision" => "配置已被其他操作更新，请刷新后重试。".into(),
        "udp_chain_unavailable" => UDP_CHAIN_UNAVAILABLE.into(),
        "tcp_capacity_reached" => tcp_capacity_reached(message),
        "dns_alias_space_exhausted" => {
            "DNS 别名号段已用完，白名单域名暂时解析失败，不会改走直连。请停止接管，在连接页点「重置 DNS 别名」，再重新启动接管。".into()
        }
        "dns_alias_session_full" => {
            "本次接管的 DNS 别名已用满，白名单域名暂时解析失败，不会改走直连。请停止接管后重新启动。".into()
        }
        "dns_alias_ledger_pending" => {
            "DNS 别名记录有一次没写完的修改，白名单域名暂时解析失败，不会改走直连。请停止接管，在连接页点「重置 DNS 别名」，再重新启动接管。".into()
        }
        "confirmation_required" => "需要先确认才能执行。".into(),
        "environment_job_running" => {
            "后台正在执行环境操作，请等它完成后再试。".into()
        }
        "environment_job_missing" => {
            "后台没有这次环境操作的结果（后台可能重启过），请刷新环境列表确认。".into()
        }
        "abandon_requires_unregistered_target" => {
            "目标发行版仍在注册表里，请用「退出接管」正常停止。".into()
        }
        "abandon_nothing_recorded" => "没有可放弃的接管记录。".into(),
        "journal_distribution_no_longer_matches_registration" => {
            "目标发行版已被注销，无法正常停止。请在概览页点「放弃本次记录」。".into()
        }
        "tcp_peer_still_registered" => {
            "同一源端口的上一条连接还没关闭完，新连接被直接断开，不会直连；应用重试即可。".into()
        }
        "managed_install_unverified" => {
            "接管规则安装结果未确认，当前状态需要恢复；请先停止并恢复直连后重试。".into()
        }
        "managed_readiness_failed" => {
            if message.contains("target_https_probe_failed") {
                "目标 HTTPS 健康探测失败，当前状态需要恢复；请先停止并恢复直连后重试。".into()
            } else if message.contains("_dns_") || message.contains("dns_") {
                "系统 DNS 就绪探测失败，当前状态需要恢复；请先停止并恢复直连后重试。".into()
            } else {
                "接管就绪探测未通过，当前状态需要恢复；请先停止并恢复直连后重试。".into()
            }
        }
        "unsupported_platform" => "当前系统不支持此操作。".into(),
        _ => humanize_detail(message),
    }
}

const UDP_CHAIN_UNAVAILABLE: &str = "住宅出口没有通过 UDP 探测，非白名单 UDP（含 QUIC）已阻断，不会直连；下次启动或切换目标时重新探测。";
/// 上限来自这次接管的策略，所以从后台的消息里取，不写死。
fn tcp_capacity_reached(message: &str) -> String {
    let limit = message
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .map(|limit| format!("（上限 {limit} 条）"))
        .unwrap_or_default();
    format!(
        "并发 TCP 连接已满{limit}，新连接被直接断开，不会直连；现有连接结束后自动恢复。可在设置页调高上限，下次启动接管时生效。"
    )
}

fn humanize_detail(detail: &str) -> String {
    let detail = detail.trim();
    if detail.is_empty() {
        return "操作失败，请重试。".into();
    }
    if detail
        .chars()
        .any(|character| ('\u{4e00}'..='\u{9fff}').contains(&character))
    {
        return detail.to_owned();
    }
    let lower = detail.to_ascii_lowercase();
    // IPv6 flows wrap the code in a longer message, so match it anywhere.
    if lower.contains("udp_chain_unavailable") {
        return UDP_CHAIN_UNAVAILABLE.into();
    }
    if lower.contains("already exists") {
        return "目标环境或目录已经存在，请换一个名称或路径。".into();
    }
    if lower.contains("access is denied") || lower.contains("requires elevation") {
        return "WSL 需要更高权限，请以管理员身份运行后重试。".into();
    }
    if lower.contains("not found") || lower.contains("no such file") {
        return "找不到所需的 WSL 环境或文件，请检查选择是否正确。".into();
    }
    if lower.starts_with("wsl_exit_failed") || lower.starts_with("wsl_start_failed") {
        return "WSL 命令执行失败，请检查 WSL 状态和网络后重试。".into();
    }
    "操作失败，请检查当前状态后重试。".into()
}

pub(crate) fn request(value: &Value) -> Result<Value, String> {
    let reply = wsl_proxyctl::ipc::request(value)?;
    if let Some(message) = reply.get("message").and_then(Value::as_str)
        && let Some(code) = reply.get("code").and_then(Value::as_str)
    {
        return Err(humanize_code(code, message));
    }
    Ok(reply)
}

/// 等后台环境任务结束，返回和以前同步执行时一样的结果。通信偶尔失败时重试，
/// 任务本身失败才结束；后台一直连不上约 30 秒后放弃（后台可能已退出）。
fn wait_environment_job(started: Value) -> Result<Value, String> {
    // 带 job 的回复只表示「已开始」或「进行中」，结果只能从 environment_job 取。
    if started.get("job").is_none() {
        return Ok(started);
    }
    let mut transport_failures = 0;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        match wsl_proxyctl::ipc::request(&json!({"command":"environment_job"})) {
            Err(error) => {
                transport_failures += 1;
                if transport_failures >= 30 {
                    return Err(error);
                }
            }
            Ok(reply) => {
                transport_failures = 0;
                if reply.get("job").is_some() {
                    continue;
                }
                if let (Some(code), Some(message)) =
                    (reply["code"].as_str(), reply["message"].as_str())
                {
                    return Err(humanize_code(code, message));
                }
                return Ok(reply);
            }
        }
    }
}

pub(crate) fn worker() -> (Sender<Job>, Receiver<Reply>) {
    let (send, jobs) = mpsc::channel::<Job>();
    let (replies, receive) = mpsc::channel();
    std::thread::spawn(move || {
        for job in jobs {
            let result = if job.kind == Kind::Bootstrap {
                wsl_proxyctl::ipc::ensure_daemon().and_then(|()| {
                    let logs = request(&json!({"command":"runtime_logs","limit":500}))
                        .unwrap_or_else(|_| json!({"logs":[],"total":0,"has_more":false}));
                    Ok(json!({
                        "distributions": request(&json!({"command":"list"}))?,
                        "profile": request(&json!({"command":"profile_get"}))?,
                        "status": request(&json!({"command":"status"}))?,
                        "logs": logs
                    }))
                })
            } else {
                request(&job.request)
            };
            let result = if job.kind.environment_job() {
                result.and_then(wait_environment_job)
            } else {
                result
            };
            // A failed mutation may still have advanced recovery state. Never replay it.
            let status = job
                .kind
                .mutation()
                .then(|| {
                    (!matches!(
                        job.kind,
                        Kind::EnvironmentCreate
                            | Kind::EnvironmentEdit
                            | Kind::EnvironmentBackup
                            | Kind::EnvironmentDelete
                    ))
                    .then(|| request(&json!({"command":"status"})))
                })
                .flatten();
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

#[cfg(test)]
mod tests {
    use super::humanize_error;

    #[test]
    fn translates_environment_errors_for_the_ui() {
        assert_eq!(
            humanize_error("desktop_request_failed · environment_install_dir_exists"),
            "实际环境目录已经存在，请换一个父目录或环境名称。"
        );
        assert_eq!(
            humanize_error("environment_distribution_download_failed:wsl_exit_failed: denied"),
            "下载发行版失败，请检查网络和 WSL 状态后重试。"
        );
    }

    #[test]
    fn asks_for_a_wsl_update_when_install_arguments_are_rejected() {
        assert_eq!(
            humanize_error(
                "desktop_request_failed · environment_wsl_update_required:wsl_exit_failed: 1: Invalid command line argument: --location;environment_import_rolled_back"
            ),
            "当前 WSL 版本不支持按名称和位置安装发行版，请在 Windows 终端运行 wsl --update 后重试。"
        );
    }

    #[test]
    fn explains_blocked_udp_from_ipv4_and_ipv6_flow_errors() {
        let expected = super::UDP_CHAIN_UNAVAILABLE;
        assert_eq!(
            humanize_error(
                "udp_chain_unavailable: chained UDP failed its readiness probe; non-whitelisted UDP is refused until the next start or switch"
            ),
            expected
        );
        assert_eq!(
            humanize_error(
                "IPv6 UDP chain setup failed: udp_chain_unavailable: chained UDP failed its readiness probe"
            ),
            expected
        );
    }

    #[test]
    fn explains_a_full_tcp_connection_table_with_its_actual_limit() {
        let message = humanize_error(
            "tcp_capacity_reached: 512 concurrent TCP connections in use; new connection closed",
        );
        assert!(
            message.starts_with("并发 TCP 连接已满（上限 512 条）"),
            "{message}"
        );
        assert!(humanize_error("tcp_capacity_reached").starts_with("并发 TCP 连接已满，"));
    }

    #[test]
    fn dns_alias_ledger_states_point_to_the_fix() {
        assert!(
            humanize_error("dns_alias_space_exhausted: the durable DNS alias range is used up")
                .contains("重置 DNS 别名")
        );
        assert!(
            humanize_error("dns_alias_session_full: this takeover has used all of its DNS aliases")
                .contains("重新启动")
        );
    }

    #[test]
    fn hides_unrecognized_internal_error_details() {
        assert_eq!(
            humanize_error("transition_commit: os error 5"),
            "操作失败，请检查当前状态后重试。"
        );
    }

    #[test]
    fn explains_recovery_required_readiness_failures_without_raw_details() {
        assert_eq!(
            humanize_error(
                "controller_error:managed_readiness_failed:target_https_probe_failed; forwarding:{\"last_error\":\"secret\"}"
            ),
            "目标 HTTPS 健康探测失败，当前状态需要恢复；请先停止并恢复直连后重试。"
        );
    }
}
