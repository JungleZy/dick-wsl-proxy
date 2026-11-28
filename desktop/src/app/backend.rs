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
    /// 首页事件时间线：读取最新几条运行日志。静默读取，不受日志页筛选影响。
    Events,
    Preflight,
    PrepareKernel,
    /// 在目标里用 apt 装 nftables（决策 41：接管的规则用 nft 写）。
    InstallNftables,
    Save,
    Start,
    Stop,
    Export,
    Probe,
    EnvironmentView,
    /// 读环境里装的图形应用：静默，结果只写进环境详情的应用卡片。
    EnvironmentApps,
    /// 启动环境里的一个应用：静默，不锁界面，结果弹成通知。
    EnvironmentLaunch,
    /// 读被接管环境里的图形应用，列在状态岛上：静默，和环境页的应用列表互不影响。
    IslandApps,
    /// 从状态岛上启动被接管环境里的一个应用：静默，结果显示在岛上。
    IslandLaunch,
    EnvironmentCreate,
    EnvironmentEdit,
    EnvironmentBackup,
    EnvironmentDelete,
    /// 只读检查 WSL 平台（wsl.exe、内核与默认版本）：和读日志一样静默，不占用界面。
    WslPlatform,
    /// 升级 WSL 平台：后台执行 `wsl --update`，请求立刻返回，结果要轮询。
    WslUpdate,
    /// 用已保存的配置检测住宅代理能否直连、能否经宿主 SOCKS5：静默，结果只写进设置页卡片。
    ResidentialProbe,
    ResetDnsAliases,
    Abandon,
    /// 托盘「退出」的最后一步：关闭空闲的后台。不算变更，回复后不再查询状态。
    Shutdown,
}

impl Kind {
    pub(crate) fn mutation(self) -> bool {
        matches!(
            self,
            Self::Save
                | Self::PrepareKernel
                | Self::InstallNftables
                | Self::Start
                | Self::Stop
                | Self::Probe
                | Self::EnvironmentCreate
                | Self::EnvironmentEdit
                | Self::EnvironmentBackup
                | Self::EnvironmentDelete
                | Self::WslUpdate
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
                | Self::WslUpdate
        )
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Bootstrap => "连接后台",
            Self::Status => "刷新状态",
            Self::List => "刷新列表",
            Self::Connections => "读取连接记录",
            Self::Logs => "刷新日志",
            Self::Events => "读取运行事件",
            Self::Preflight => "启动前检查",
            Self::PrepareKernel => "准备内核环境",
            Self::InstallNftables => "安装 nftables",
            Self::Save => "保存修改",
            Self::Start => "启动接管",
            Self::Stop => "停止并恢复",
            Self::Export => "导出诊断",
            Self::Probe => "检测出口",
            Self::EnvironmentView => "查看环境",
            Self::EnvironmentApps => "读取已安装应用",
            Self::EnvironmentLaunch => "启动应用",
            Self::IslandApps => "读取接管环境的应用",
            Self::IslandLaunch => "启动接管环境的应用",
            Self::EnvironmentCreate => "新增环境",
            Self::EnvironmentEdit => "编辑环境",
            Self::EnvironmentBackup => "备份环境",
            Self::EnvironmentDelete => "删除环境",
            Self::WslPlatform => "检查 WSL 平台",
            Self::WslUpdate => "升级 WSL 平台",
            Self::ResidentialProbe => "检测住宅代理",
            Self::ResetDnsAliases => "重置 DNS 别名",
            Self::Abandon => "放弃本次记录",
            Self::Shutdown => "退出程序",
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
    if let Some(text) = policy_field_error(error) {
        return text;
    }
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

/// 保存配置时后台的校验错误以字段名开头、原因是英文（`direct_ips: invalid direct IP CIDR
/// prefix: "10.0.0.1/33"`）。换成页面上的位置和名称，并带上被拒的那一项，用户才知道改哪里。
/// 策略里没有秘密，原值可以显示；住宅凭据的错误本身不带原值。
fn policy_field_error(error: &str) -> Option<String> {
    // (后台字段名, 页面上的位置, 补充说明)
    const FIELDS: &[(&str, &str, &str)] = &[
        ("direct_ips", "规则页「IPv4 / CIDR」", ""),
        ("direct_domains", "规则页「精确域名」", ""),
        ("direct_suffixes", "规则页「域名后缀」", ""),
        (
            "first_hop",
            "设置页「宿主 SOCKS5」",
            "需要是本机回环地址和端口，例如 127.0.0.1:7890。",
        ),
        ("dns_upstream", "设置页「DoH 上游 IPv4:端口」", ""),
        ("dns_tls_name", "设置页受管 DNS 的「TLS 主机名」", ""),
        (
            "direct_dns_upstream",
            "设置页「国内 DoH 上游 IPv4:端口」",
            "需要是公网 IPv4 和端口；留空即关闭。",
        ),
        ("direct_dns_tls_name", "设置页「国内 DoH TLS 主机名」", ""),
        ("health_domain", "设置页「健康检查域名」", ""),
        (
            "max_tcp_connections",
            "设置页「并发 TCP 上限」",
            "范围 16–1024。",
        ),
        (
            "tcp_idle_timeout_seconds",
            "设置页「TCP 空闲断开」",
            "范围 30–86400 秒。",
        ),
        (
            "tcp_half_close_timeout_seconds",
            "设置页「半关闭等待」",
            "范围 5–3600 秒。",
        ),
        ("credential ip", "环境页住宅代理的「服务器 IPv4」", ""),
        (
            "credential endpoint",
            "环境页住宅代理的「服务器 IPv4」或「服务器端口」",
            "",
        ),
        ("credential port", "环境页住宅代理的「服务器端口」", ""),
    ];
    // 后台另有 `controller_error · ` 之类的外层包装时，取里面的原文。
    let detail = error.rsplit(" · ").next().unwrap_or(error).trim();
    let detail = detail
        .strip_prefix("desktop_request_failed:")
        .unwrap_or(detail)
        .trim();
    let (_, place, hint) = FIELDS.iter().find(|(field, _, _)| {
        detail
            .strip_prefix(field)
            .is_some_and(|rest| rest.starts_with(':') || rest.starts_with(' '))
    })?;
    // 被拒的那一项在末尾，带引号。
    let rejected = detail
        .rfind(": \"")
        .map(|at| detail[at + 2..].trim())
        .filter(|value| value.len() > 2 && value.ends_with('"'))
        .map(|value| format!("：{value}"))
        .unwrap_or_default();
    Some(format!("{place}填写有误{rejected}。{hint}"))
}

/// 接管前改时区或重启目标失败：接管没有启动，说清卡在哪一步。
fn timezone_sync_failure(message: &str) -> String {
    let detail = if message.contains("timezone_lookup_domain_is_direct") {
        "my.ippure.com 在直连例外里，经它查到的是本机出口而不是住宅出口；请把它移出直连例外。"
    } else if message.contains("timezone_lookup_failed") {
        "经代理链查询住宅出口的时区失败（查询服务 my.ippure.com），目标没有被改动。请确认住宅代理可用后重试。"
    } else if message.contains("timezone_not_in_target") {
        "目标里没有这个时区的数据（/usr/share/zoneinfo），目标没有被改动。请在目标里安装 tzdata 后重试。"
    } else if message.contains("timezone_apply_failed") {
        "在目标里写入时区失败，目标没有被重启。请确认目标能正常启动后重试。"
    } else if message.contains("target_restart_failed") {
        "时区已经改好，但重启目标失败。请确认目标能正常启动后重试。"
    } else {
        "请查看日志后重试。"
    };
    format!("没能把目标时区改成住宅出口所在时区，接管没有启动：{detail}")
}

fn humanize_code(code: &str, message: &str) -> String {
    match code {
        // 管道只对同一账户开放；这里还被拒绝，就是后台以管理员身份运行、
        // 而这个界面不是（决策 21）。
        "ipc_unavailable" if message.trim() == "Windows error 5" => {
            "后台正以管理员身份运行，当前界面权限较低，连不上它。请同样以管理员身份打开界面；或者在任务管理器里结束 wsl-proxyctl.exe 后台进程，再正常打开。".into()
        }
        // 后台一次只服务一个管道连接。它在处理长操作（例如命令行发起的启动，要一两分钟）时
        // 管道一直忙，`open_pipe` 等满期限：`WaitNamedPipeW` 超时报 ERROR_SEM_TIMEOUT（121），
        // 等待途中被别的客户端抢先、期限用尽时报 `ipc_timeout`。两种都是连不上，请求没有发出。
        "ipc_unavailable" if matches!(message.trim(), "Windows error 121" | "ipc_timeout") => {
            PIPE_BUSY.into()
        }
        "desktop_request_failed" | "controller_error" => humanize_error(message),
        "not_registered" => "找不到指定的 WSL 环境，请刷新列表后重试。".into(),
        "ambiguous_target" => "目标 WSL 名称不唯一，请刷新列表后重试。".into(),
        "not_wsl2" => "该发行版不是 WSL 2，无法执行此操作。".into(),
        "enumeration_failed" => "读取 WSL 环境列表失败，请检查 WSL 服务状态。".into(),
        "probe_failed" => "检查目标 WSL 失败，请确认发行版可以正常启动。".into(),
        "target_already_owned" => "当前已有接管任务，请先停止接管并恢复直连。".into(),
        "timezone_sync_failed" => timezone_sync_failure(message),
        "kernel_prepare_requires_idle" => "请先停止接管并恢复直连，再准备内核环境。".into(),
        "nftables_install_requires_idle" => "请先停止这个环境的接管，再安装 nftables。".into(),
        "nftables_install_requires_apt" => {
            "这个发行版没有 apt，程序装不了 nftables。请在发行版里用它自己的包管理器装上 nftables（提供 nft 命令），再启动接管。".into()
        }
        "nftables_install_failed" => format!(
            "在目标里安装 nftables 失败：{}。请检查发行版的网络和软件源后重试，或在发行版里运行 sudo apt install nftables。",
            // The backend's message repeats the code before the apt output.
            Some(
                message
                    .trim()
                    .strip_prefix("nftables_install_failed:")
                    .unwrap_or(message)
                    .trim()
            )
            .filter(|detail| !detail.is_empty())
            .unwrap_or("apt 没有装上")
        ),
        "kernel_prepare_failed" => {
            "内核环境准备失败，请确认目标发行版能启动，并且带有内核模块。".into()
        }
        "residential_credential_incomplete" => {
            "这个环境的住宅代理不完整，请在环境页填写完整的服务器地址、端口、用户名和密码并保存。".into()
        }
        "environment_requires_idle" => "请先停止接管并恢复直连，再管理 WSL 环境。".into(),
        "wsl_platform_failed" => "检查 WSL 平台失败，请确认 WSL 可以正常运行后重试。".into(),
        "wsl_not_installed" => "没有找到 wsl.exe，请先安装 Windows Subsystem for Linux。".into(),
        "wsl_update_requires_idle" => "请先停止接管并恢复直连，再升级 WSL。".into(),
        "wsl_update_failed" => {
            "升级 WSL 失败，请检查网络和 Windows 更新；也可以在以管理员身份打开的终端里运行 wsl --update，或用 wsl --update --web-download 从 GitHub 下载更新。"
                .into()
        }
        // 后台环境任务会把失败原因包成 desktop_request_failed，只有这里保留命令本身的输出。
        "wsl_update_command_failed" => format!(
            "升级 WSL 失败：{} 请检查网络、Windows 更新和权限；也可以在以管理员身份打开的终端里运行 wsl --update，或用 wsl --update --web-download 从 GitHub 下载更新。",
            message.trim()
        ),
        "stale_environment_revision" => {
            "这个环境的住宅代理已在别处改过，请刷新后重新填写。".into()
        }
        "saved_environment_revision_required" => {
            "这个环境的住宅代理和界面上显示的不一致，请刷新后再启动。".into()
        }
        "ingress_port_in_use" => {
            "这个 Windows 入口端口已分给另一个环境，请换一个，或留空由程序分配。".into()
        }
        "invalid_ingress_port" => "Windows 入口端口需为 1024–65535 的整数。".into(),
        "environment_residential_in_use" => {
            "这个环境正在接管或需要恢复，先停止它再改住宅代理和入口端口。".into()
        }
        "environment_residential_exists" => {
            "这个环境已经有自己的住宅代理；要换成旧的那一份，先清空这个环境的住宅代理并保存。".into()
        }
        "unassigned_residential_missing" => "没有未分配的住宅代理了，请刷新。".into(),
        "environment_name_invalid" => "环境名称只能使用字母、数字、点、下划线和短横线。".into(),
        "environment_hostname_invalid" => {
            "主机名只能用字母、数字、点和短横线，每段以字母或数字开头结尾，最长 63 个字符。".into()
        }
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
        "desktop_store_not_saved" => "设置还没有保存过，请先保存设置。".into(),
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
        "stop_and_restore_before_daemon_shutdown" => {
            "后台仍在接管或需要恢复，不能关闭；请先停止并恢复直连。".into()
        }
        "environment_apps_failed" => "在环境里读取应用列表失败，请确认发行版能正常启动。".into(),
        "environment_app_invalid" => "应用标识无效，请重新读取应用列表。".into(),
        "environment_app_not_found" => {
            "环境里已经没有这个应用的入口（可能已卸载），请重新读取应用列表。".into()
        }
        "environment_app_entry_invalid" => "这个应用的 .desktop 入口没有可用的启动命令。".into(),
        "environment_app_command_missing" => {
            "环境里找不到这个应用的程序（可能已卸载），请重新读取应用列表。".into()
        }
        "environment_app_exited" => format!("应用刚启动就退出了（退出码 {}）。", message.trim()),
        "environment_app_launch_failed" => "没能在环境里启动应用，请确认 WSL 可以正常运行。".into(),
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
        "managed_install_unverified" if message.contains("container_networks_unavailable") => {
            "目标里的 Docker 正在运行，但读不出它的网络，接管没有生效：目标本机的流量已阻断，但目标的容器没有被拦住，可能直连。请先停止并恢复直连，确认 Docker 正常后再启动。".into()
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

/// 这句话也会接在「启动接管失败：」「连接后台失败：」后面，所以只说处处成立的：
/// 请求没有发出，状态轮询会自己恢复，用户发起的操作要自己重试。
const PIPE_BUSY: &str = "后台正在处理另一个操作（例如命令行发起的启动），暂时连不上，这次请求没有发出。等它处理完，状态会自动刷新；需要时再重试刚才的操作。";
const UDP_CHAIN_UNAVAILABLE: &str = "住宅出口没有通过 UDP 探测，UDP（含 QUIC，直连例外也一样）已阻断，不会直连；下次启动或切换目标时重新探测。";
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
    // The digit in "ipv6" keeps this code out of the code table above.
    if lower.contains("ipv6_domain_allowlist_unsupported") {
        return "目标启用了 IPv6，而域名直连规则只支持 IPv4，所以不能启动接管。请到规则页清空「精确域名」和「域名后缀」两列并保存，再启动；IP / CIDR 规则不受影响。".into();
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

/// The preflight blocker for a target WSL kernel older than the one
/// cross-distribution isolation was verified on (decision 01).
pub(crate) const KERNEL_RELEASE_UNVERIFIED: &str = "kernel.release_unverified";

/// What to tell the user when the preflight refused the target's kernel:
/// nothing in the distribution can fix it, only a newer WSL.
pub(crate) fn kernel_release_notice(blockers: &[String]) -> Option<String> {
    blockers
        .iter()
        .any(|blocker| blocker == KERNEL_RELEASE_UNVERIFIED)
        .then(|| {
            "目标的 WSL 内核低于已验证的 6.18.58.1：在更旧的内核上，接管可能波及别的发行版，所以不接管。请在「设置 › WSL 平台」里升级 WSL 后重试。".into()
        })
}

/// Blockers that only loading the target's own modules and empty tables can
/// clear. Used to decide whether a failed preflight should ask the user to
/// prepare the kernel instead of just listing the codes.
pub(crate) fn kernel_gap(blockers: &[String]) -> bool {
    blockers.iter().any(|blocker| {
        blocker.starts_with("capability.kernel.")
            || blocker.starts_with("baseline.ip6tables")
            || blocker.starts_with("baseline.iptables")
    })
}

/// Whether a failed preflight should ask about preparing the kernel. Only a
/// start from idle can do it, and only once per attempt: repeating the
/// question after a failed attempt is noise.
pub(crate) fn offer_kernel_prepare(kind: Option<Kind>, offered: bool, blockers: &[String]) -> bool {
    // An old kernel stays refused whatever is loaded: asking would only lead
    // to a second refusal.
    kind == Some(Kind::Start)
        && !offered
        && kernel_gap(blockers)
        && kernel_release_notice(blockers).is_none()
}

/// The overview notice for one explicit kernel preparation. `true` means the
/// result still needs attention (modules unavailable or remaining blockers).
pub(crate) fn kernel_prepare_notice(value: &Value) -> (String, bool) {
    let preparation = &value["preparation"];
    let count = |key: &str| preparation[key].as_array().map_or(0, Vec::len);
    if preparation["ok"] != true {
        return (humanize_code("kernel_prepare_failed", ""), true);
    }
    let added = count("modules_added");
    let failed = count("modules_failed");
    let tables = ["v4", "v6"]
        .iter()
        .map(|family| {
            preparation["tables"]["added"][family]
                .as_array()
                .map_or(0, Vec::len)
        })
        .sum::<usize>();
    let blockers = value["blockers"].as_array().map_or(0, Vec::len);
    let mut message = if added == 0 && tables == 0 {
        "内核环境已就绪，无需新增模块或空表。".to_owned()
    } else {
        format!("内核环境已准备：新增 {added} 个模块、{tables} 个空表。")
    };
    if failed > 0 {
        message.push_str(&format!("{failed} 个模块不可用，请检查目标内核模块。"));
    }
    let autoload_error = preparation["autoload"]["error"].as_str().is_some()
        || preparation["boot_unit"]["error"].as_str().is_some();
    let autoload_ready = preparation["autoload"]["written"] == true
        && preparation["boot_unit"]["written"] == true
        && preparation["boot_unit"]["enabled"] == true;
    if autoload_ready {
        message.push_str("已设置开机自动加载。");
    } else if autoload_error {
        message.push_str("开机自动加载配置写入失败。");
    }
    let record_error = value["record_error"].as_str().is_some();
    if record_error {
        message.push_str("准备记录写入失败，请检查本机配置目录。");
    }
    if value["inspection_error"].as_str().is_some() {
        message.push_str("无法复核预检结果，请稍后手动预检。");
        return (message, true);
    }
    match blockers {
        0 => message.push_str("可以在总览重新预检并启动接管。"),
        blockers => message.push_str(&format!("仍有 {blockers} 个阻断项，请查看预检结果。")),
    }
    (
        message,
        failed > 0 || blockers > 0 || record_error || autoload_error,
    )
}

/// 设置页 WSL 平台卡片的状态标签：`(文字, 色调)`。色调由视图映射成主题色。
pub(crate) fn wsl_platform_badge(
    report: Option<&Value>,
    checking: bool,
    error: Option<&str>,
) -> (&'static str, &'static str) {
    if checking {
        return ("检查中", "checking");
    }
    if error.is_some() {
        return ("检查失败", "failed");
    }
    let Some(report) = report else {
        return ("尚未检查", "untested");
    };
    let count = |key: &str| report[key].as_array().map_or(0, Vec::len);
    if count("blockers") > 0 {
        ("需要处理", "blocked")
    } else if count("warnings") > 0 {
        ("有提醒", "warning")
    } else {
        ("正常", "ok")
    }
}

/// 环境页住宅代理检测的状态标签：`(文字, 色调)`。`stale` 表示检测之后住宅代理或设置又保存过，
/// 旧结果不再对应当前配置。
pub(crate) fn residential_probe_badge(
    report: Option<&Value>,
    checking: bool,
    error: Option<&str>,
    stale: bool,
) -> (&'static str, &'static str) {
    if checking {
        return ("检测中", "checking");
    }
    if error.is_some() {
        return ("检测失败", "failed");
    }
    let Some(report) = report else {
        return ("尚未检测", "untested");
    };
    if stale {
        return ("设置已改，需重新检测", "untested");
    }
    match report["verdict"].as_str() {
        Some("both") => ("可直连，也可经宿主 SOCKS5", "ok"),
        Some("needs_first_hop") => ("需要宿主 SOCKS5", "ok"),
        Some("direct_only") => ("只能直连", "warning"),
        Some("credential_rejected") => ("登录被拒绝", "failed"),
        _ => ("两条路都不通", "failed"),
    }
}

/// 检测结论的解释。接管始终经宿主 SOCKS5，所以「只能直连」意味着现在启动接管会失败。
pub(crate) fn residential_probe_summary(verdict: &str) -> &'static str {
    match verdict {
        "both" => "住宅代理从 Windows 直接能连上，经宿主 SOCKS5 也能连上。接管照常经宿主 SOCKS5。",
        "needs_first_hop" => {
            "住宅代理从 Windows 直接连不上，经宿主 SOCKS5 能连上，需要宿主 SOCKS5 作为前置代理。"
        }
        "direct_only" => {
            "住宅代理从 Windows 直接能连上，但经宿主 SOCKS5 连不上。接管始终经宿主 SOCKS5，现在启动接管会失败；请检查宿主 SOCKS5 是否在运行、是否放行到住宅服务器的连接。"
        }
        "credential_rejected" => {
            "住宅服务器拒绝了用户名或密码。也可能是服务商只允许白名单里的来源 IP 登录。"
        }
        _ => "直接连接和经宿主 SOCKS5 都没有连上住宅代理，下面是各自停下的位置。",
    }
}

/// 一条路径停在哪一步。阶段码来自后台，措辞留在这里。
pub(crate) fn residential_stage_text(path: &Value) -> String {
    if path["ok"] == true {
        return "能连上，登录和转发都成功".into();
    }
    match path["stage"].as_str() {
        Some("first_hop_unreachable") => "连不上宿主 SOCKS5".into(),
        Some("first_hop_rejected") => "宿主 SOCKS5 拒绝了握手（它需要免认证的 SOCKS5）".into(),
        Some("first_hop_connect_rejected") => "宿主 SOCKS5 没能连到住宅服务器".into(),
        Some("residential_unreachable") => "连不上住宅服务器".into(),
        Some("residential_method_rejected") => {
            "住宅服务器没有按 SOCKS5 用户名密码方式应答；如果服务商给的是 HTTP 代理端口，把协议改成 HTTP".into()
        }
        Some("residential_speaks_http") => {
            "住宅服务器回的是 HTTP 应答，这个端口是 HTTP 代理；把协议改成 HTTP 再试".into()
        }
        Some("residential_speaks_socks5") => {
            "住宅服务器回的是 SOCKS5 应答，这个端口是 SOCKS5 代理；把协议改成 SOCKS5 再试".into()
        }
        Some("residential_not_http") => "住宅服务器没有按 HTTP 代理方式应答".into(),
        Some("residential_auth_rejected") => "住宅服务器拒绝了登录".into(),
        Some("residential_connect_rejected") => "登录成功，但住宅服务器没能连到外部地址".into(),
        Some(other) => format!("检测出错（{other}）"),
        None => "没有结果".into(),
    }
}

/// 一项检查的说明。目标状态由后台的检查代码决定，措辞留在这里。
pub(crate) fn wsl_check_text(code: &str, level: &str, detail: Option<&str>) -> String {
    let failed = level != "ok";
    match (code, failed) {
        ("wsl.executable", true) => {
            "没有找到 wsl.exe；请先安装 Windows Subsystem for Linux。".into()
        }
        ("wsl.executable", false) => "找到 wsl.exe。".into(),
        ("wsl.version_supported", true) => {
            "wsl --version 不可用，可能是旧版 WSL；升级后再检查。".into()
        }
        ("wsl.version_supported", false) => "wsl --version 可用。".into(),
        ("wsl.default_version_2", true) => match detail {
            Some("1") => "默认版本是 WSL 1；新建的发行版不能作为接管目标。".into(),
            _ => "没有读到默认版本；可以先升级 WSL 再检查。".into(),
        },
        ("wsl.default_version_2", false) => "新发行版默认使用 WSL 2。".into(),
        ("wsl.no_wsl1_distribution", true) => match detail {
            Some(names) => format!("{names} 是 WSL 1，不能作为接管目标。"),
            None => "有发行版是 WSL 1，不能作为接管目标。".into(),
        },
        ("wsl.no_wsl1_distribution", false) => "所有发行版都是 WSL 2。".into(),
        (_, true) => "这项检查没有通过。".into(),
        (_, false) => "这项检查已通过。".into(),
    }
}

/// 一次 WSL 升级结果的说明。是否升级按版本前后变化判断，不解析本地化输出。
pub(crate) fn wsl_update_notice(update: &Value) -> String {
    let before = update["before"]["version"].as_str();
    let after = update["after"]["version"].as_str();
    match (before, after) {
        (Some(before), Some(after)) if update["updated"] == true => {
            format!("WSL 已升级：{before} → {after}。")
        }
        (Some(_), Some(after)) => format!("WSL 已是最新（{after}），升级命令执行成功。"),
        _ => "升级命令执行成功，但没有读到版本变化，无法确认是否已升级。".to_owned(),
    }
}

/// 打开命名管道时报「文件不存在」（Windows 错误 2）：当前用户没有后台在运行。
const DAEMON_ABSENT: &str = "ipc_unavailable: Windows error 2";

/// 关闭后台。后台只在空闲且没有环境任务时接受，否则如实返回拒绝原因；
/// 后台本来就不在运行时没有东西要关，同样算关闭成功。
fn shutdown_daemon() -> Result<Value, String> {
    match request(&json!({"command":"shutdown_daemon"})) {
        Err(error) if error == DAEMON_ABSENT => Ok(json!({"shutdown":true,"absent":true})),
        result => result,
    }
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
                    // 读日志失败不影响连接后台，但要把原因带回去，日志页和首页时间线显示读取失败，
                    // 而不是「暂无记录」。
                    let logs = request(&json!({"command":"runtime_logs","limit":500}))
                        .unwrap_or_else(
                            |error| json!({"logs":[],"total":0,"has_more":false,"error":error}),
                        );
                    Ok(json!({
                        "distributions": request(&json!({"command":"list"}))?,
                        "profile": request(&json!({"command":"profile_get"}))?,
                        "status": request(&json!({"command":"status"}))?,
                        "logs": logs
                    }))
                })
            } else if job.kind == Kind::Shutdown {
                shutdown_daemon()
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
        // Dropping the window is not a stop command: the tray exit stops the
        // takeover and shuts the daemon down explicitly before the window closes.
    });
    (send, receive)
}

#[cfg(test)]
mod tests {
    use super::Kind;
    use super::{
        KERNEL_RELEASE_UNVERIFIED, PIPE_BUSY, humanize_error, kernel_gap, kernel_prepare_notice,
        kernel_release_notice, offer_kernel_prepare, residential_probe_badge,
        residential_stage_text, wsl_check_text, wsl_platform_badge, wsl_update_notice,
    };
    use serde_json::json;

    #[test]
    fn offers_kernel_preparation_only_once_for_a_start() {
        // The blockers an actual cold Target produced on 2026-11-24.
        let gap: Vec<String> = [
            "capability.kernel.module.xt_cgroup.unverified",
            "capability.kernel.module.ip6table_nat.unverified",
            "capability.kernel.matches_v4.cgroup.unverified",
            "capability.kernel.matches_v6.cgroup.unverified",
            "capability.kernel.targets_v6.DNAT.unverified",
            "capability.kernel.tables_v6.nat.unverified",
            "baseline.ip6tables_legacy.unavailable",
        ]
        .iter()
        .map(|code| (*code).to_owned())
        .collect();
        assert!(offer_kernel_prepare(Some(Kind::Start), false, &gap));
        assert!(!offer_kernel_prepare(Some(Kind::Start), true, &gap));
        assert!(!offer_kernel_prepare(Some(Kind::Stop), false, &gap));
        assert!(!offer_kernel_prepare(None, false, &gap));
        assert!(!offer_kernel_prepare(
            Some(Kind::Start),
            false,
            &["host_port_unavailable".to_owned()]
        ));
    }

    #[test]
    fn an_old_kernel_gets_its_own_notice_and_no_kernel_preparation() {
        let blockers = vec![KERNEL_RELEASE_UNVERIFIED.to_string()];
        assert!(
            kernel_release_notice(&blockers)
                .unwrap()
                .contains("WSL 平台")
        );
        assert!(!kernel_gap(&blockers));
        let both = vec![
            KERNEL_RELEASE_UNVERIFIED.to_string(),
            "capability.kernel.module.xt_cgroup.unverified".to_string(),
        ];
        assert!(!offer_kernel_prepare(Some(Kind::Start), false, &both));
        assert!(offer_kernel_prepare(Some(Kind::Start), false, &both[1..]));
        assert_eq!(
            kernel_release_notice(&["capability.kernel.module.xt_cgroup.unverified".into()]),
            None
        );
    }

    #[test]
    fn recognizes_kernel_capability_blockers() {
        assert!(kernel_gap(&[
            "capability.kernel.module.xt_cgroup.unverified".into()
        ]));
        assert!(kernel_gap(
            &["baseline.ip6tables_legacy.unavailable".into()]
        ));
        assert!(kernel_gap(&["baseline.iptables_legacy.unavailable".into()]));
        assert!(!kernel_gap(&[
            "identity.pid_namespace_unverified".into(),
            "host_port_unavailable".into()
        ]));
        assert!(!kernel_gap(&[]));
    }

    #[test]
    fn summarizes_kernel_preparation_and_keeps_failures_visible() {
        let ready = json!({
            "preparation": {
                "ok": true,
                "modules_added": ["xt_cgroup"],
                "modules_failed": [],
                "tables": {"added": {"v4": ["filter"], "v6": ["filter", "nat"]}},
                "autoload": {"written": true, "error": null},
                "boot_unit": {"written": true, "enabled": true, "error": null}
            },
            "blockers": [],
            "inspection_error": null
        });
        let (message, error) = kernel_prepare_notice(&ready);
        assert!(message.contains("新增 1 个模块、3 个空表"), "{message}");
        assert!(message.contains("已设置开机自动加载"), "{message}");
        assert!(message.contains("可以"), "{message}");
        assert!(!error);

        let autoload_failed = json!({
            "preparation": {
                "ok": true,
                "modules_added": ["xt_cgroup"],
                "modules_failed": [],
                "tables": {"added": {"v4": [], "v6": []}},
                "autoload": {"written": false, "error": "PermissionError: denied"}
            },
            "blockers": [],
            "inspection_error": null
        });
        let (message, error) = kernel_prepare_notice(&autoload_failed);
        assert!(message.contains("开机自动加载配置写入失败"), "{message}");
        assert!(error);

        let incomplete = json!({
            "preparation": {
                "ok": true,
                "modules_added": [],
                "modules_failed": [{"module": "xt_cgroup", "reason": "not_available"}],
                "tables": {"added": {"v4": [], "v6": []}}
            },
            "blockers": ["capability.kernel.module.xt_cgroup.unverified"],
            "inspection_error": null
        });
        let (message, error) = kernel_prepare_notice(&incomplete);
        assert!(message.contains("1 个模块不可用"), "{message}");
        assert!(message.contains("仍有 1 个阻断项"), "{message}");
        assert!(error);

        let unrecorded = json!({
            "preparation": {
                "ok": true,
                "modules_added": [],
                "modules_failed": [],
                "tables": {"added": {"v4": [], "v6": []}}
            },
            "record_error": "kernel_env_record_rename: denied",
            "blockers": [],
            "inspection_error": null
        });
        let (message, error) = kernel_prepare_notice(&unrecorded);
        assert!(message.contains("准备记录写入失败"), "{message}");
        assert!(error);

        let refused = json!({
            "preparation": {"ok": false, "error": "root_required"},
            "blockers": [],
            "inspection_error": null
        });
        let (message, error) = kernel_prepare_notice(&refused);
        assert_eq!(
            message,
            "内核环境准备失败，请确认目标发行版能启动，并且带有内核模块。"
        );
        assert!(error);
    }

    #[test]
    fn translates_kernel_preparation_errors_for_the_ui() {
        assert_eq!(
            humanize_error("kernel_prepare_requires_idle"),
            "请先停止接管并恢复直连，再准备内核环境。"
        );
        assert_eq!(
            humanize_error("kernel_prepare_failed: Target"),
            "内核环境准备失败，请确认目标发行版能启动，并且带有内核模块。"
        );
    }

    #[test]
    fn translates_nftables_install_errors_for_the_ui() {
        assert!(humanize_error("nftables_install_requires_apt").contains("没有 apt"));
        let failed =
            humanize_error("nftables_install_failed: E: Unable to locate package nftables");
        assert!(
            failed.contains("E: Unable to locate package nftables"),
            "{failed}"
        );
        assert!(failed.contains("sudo apt install nftables"), "{failed}");
        assert!(humanize_error("nftables_install_requires_idle").contains("先停止这个环境的接管"));
    }

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
                "udp_chain_unavailable: chained UDP failed its readiness probe; application UDP, whitelisted or not, is refused until the next start or switch"
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
    fn an_ipv6_target_with_domain_rules_points_to_the_rules_page() {
        assert!(
            humanize_error("controller_error · ipv6_domain_allowlist_unsupported")
                .contains("规则页清空")
        );
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
    fn explains_why_the_daemon_refused_to_shut_down() {
        assert_eq!(
            humanize_error("desktop_request_failed · stop_and_restore_before_daemon_shutdown"),
            "后台仍在接管或需要恢复，不能关闭；请先停止并恢复直连。"
        );
        assert_eq!(
            humanize_error("environment_job_running · environment_create is still running for Dev"),
            "后台正在执行环境操作，请等它完成后再试。"
        );
    }

    #[test]
    fn translates_app_launch_failures_for_the_ui() {
        assert_eq!(
            humanize_error("desktop_request_failed · environment_app_exited:3"),
            "应用刚启动就退出了（退出码 3）。"
        );
        assert_eq!(
            humanize_error("desktop_request_failed · environment_app_command_missing"),
            "环境里找不到这个应用的程序（可能已卸载），请重新读取应用列表。"
        );
        assert_eq!(
            humanize_error(
                "desktop_request_failed · environment_apps_failed:wsl_exit_failed: exit code: 1: boom"
            ),
            "在环境里读取应用列表失败，请确认发行版能正常启动。"
        );
    }

    #[test]
    fn names_the_page_field_and_entry_a_saved_policy_was_refused_for() {
        assert_eq!(
            humanize_error(
                "desktop_request_failed · direct_ips: invalid direct IP CIDR prefix: \"10.0.0.1/33\""
            ),
            "规则页「IPv4 / CIDR」填写有误：\"10.0.0.1/33\"。"
        );
        assert_eq!(
            humanize_error(
                "direct_suffixes: policy domain must be an ASCII DNS hostname: \"bad name\""
            ),
            "规则页「域名后缀」填写有误：\"bad name\"。"
        );
        assert_eq!(
            humanize_error(
                "desktop_request_failed · direct_dns_upstream must be a literal public IPv4:port or null"
            ),
            "设置页「国内 DoH 上游 IPv4:端口」填写有误。需要是公网 IPv4 和端口；留空即关闭。"
        );
        assert_eq!(
            humanize_error("dns_upstream must be a literal unicast IPv4:port"),
            "设置页「DoH 上游 IPv4:端口」填写有误。"
        );
        assert_eq!(
            humanize_error("credential ip must be literal IPv4"),
            "环境页住宅代理的「服务器 IPv4」填写有误。"
        );
        // A code that merely starts with a field name is not a field error.
        assert!(!humanize_error("first_hop_unreachable").contains("填写有误"));
    }

    #[test]
    fn explains_a_start_that_could_not_read_the_targets_docker_networks() {
        assert!(
            humanize_error(
                "controller_error · managed_install_unverified:container_networks_unavailable:docker_networks_unavailable; ingress_stop:None"
            )
            .starts_with("目标里的 Docker 正在运行，但读不出它的网络")
        );
        assert!(
            humanize_error(
                "managed_install_unverified:container_networks_unavailable:docker_networks_unavailable"
            )
            .contains("目标的容器没有被拦住，可能直连")
        );
        assert!(
            humanize_error("managed_install_unverified:install:wsl_exit_failed")
                .starts_with("接管规则安装结果未确认")
        );
    }

    #[test]
    fn explains_an_elevated_controller_the_window_cannot_reach() {
        assert!(
            humanize_error("ipc_unavailable: Windows error 5")
                .starts_with("后台正以管理员身份运行")
        );
        // A missing controller is still told apart (`DAEMON_ABSENT`).
        assert!(!humanize_error("ipc_unavailable: Windows error 2").contains("管理员"));
    }

    #[test]
    fn explains_a_controller_busy_with_another_request() {
        // `report()` formats `WaitNamedPipeW`'s ERROR_SEM_TIMEOUT and `open_pipe`'s own
        // deadline error like this.
        for error in [
            "ipc_unavailable: Windows error 121",
            "ipc_unavailable: ipc_timeout",
        ] {
            assert_eq!(humanize_error(error), PIPE_BUSY, "{error}");
        }
        assert!(PIPE_BUSY.starts_with("后台正在处理另一个操作"));
        // The other pipe errors keep their own explanations.
        for error in [
            "ipc_unavailable: Windows error 2",
            "ipc_unavailable: Windows error 5",
            "ipc_untrusted_server: Windows error 121",
        ] {
            assert_ne!(humanize_error(error), PIPE_BUSY, "{error}");
        }
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

    #[test]
    fn residential_probe_badge_follows_the_latest_result_and_saved_settings() {
        assert_eq!(
            residential_probe_badge(None, false, None, false).0,
            "尚未检测"
        );
        assert_eq!(residential_probe_badge(None, true, None, false).0, "检测中");
        assert_eq!(
            residential_probe_badge(None, false, Some("后台离线"), false).0,
            "检测失败"
        );
        let report = |verdict: &str| json!({"verdict": verdict});
        assert_eq!(
            residential_probe_badge(Some(&report("needs_first_hop")), false, None, false),
            ("需要宿主 SOCKS5", "ok")
        );
        assert_eq!(
            residential_probe_badge(Some(&report("direct_only")), false, None, false).1,
            "warning"
        );
        assert_eq!(
            residential_probe_badge(Some(&report("credential_rejected")), false, None, false).1,
            "failed"
        );
        // 检测之后又保存过设置，旧结论不能再当成当前配置的结果。
        assert_eq!(
            residential_probe_badge(Some(&report("both")), false, None, true).0,
            "设置已改，需重新检测"
        );
        assert_eq!(
            residential_stage_text(&json!({"ok": false, "stage": "first_hop_unreachable"})),
            "连不上宿主 SOCKS5"
        );
        assert_eq!(
            residential_stage_text(&json!({"ok": true})),
            "能连上，登录和转发都成功"
        );
    }

    #[test]
    fn wsl_platform_badge_follows_the_latest_check() {
        assert_eq!(wsl_platform_badge(None, false, None).0, "尚未检查");
        assert_eq!(wsl_platform_badge(None, true, None).0, "检查中");
        assert_eq!(
            wsl_platform_badge(None, false, Some("后台离线")).0,
            "检查失败"
        );
        let blocked = json!({"blockers": ["wsl.executable"], "warnings": []});
        assert_eq!(
            wsl_platform_badge(Some(&blocked), false, None).0,
            "需要处理"
        );
        let warned = json!({"blockers": [], "warnings": ["wsl.default_version_2"]});
        assert_eq!(wsl_platform_badge(Some(&warned), false, None).0, "有提醒");
        let ready = json!({"blockers": [], "warnings": []});
        assert_eq!(wsl_platform_badge(Some(&ready), false, None).0, "正常");
    }

    #[test]
    fn wsl_check_text_matches_each_reported_state() {
        assert!(wsl_check_text("wsl.version_supported", "blocker", None).contains("旧版 WSL"));
        assert!(wsl_check_text("wsl.version_supported", "ok", None).contains("可用"));
        assert!(wsl_check_text("wsl.default_version_2", "warning", Some("1")).contains("WSL 1"));
        assert!(wsl_check_text("wsl.default_version_2", "warning", None).contains("没有读到"));
        assert!(
            wsl_check_text("wsl.no_wsl1_distribution", "warning", Some("Legacy"))
                .contains("Legacy")
        );
        assert!(wsl_check_text("wsl.no_wsl1_distribution", "ok", None).contains("都是 WSL 2"));
        assert_eq!(
            wsl_check_text("wsl.unknown", "blocker", None),
            "这项检查没有通过。"
        );
    }

    #[test]
    fn wsl_update_notice_reports_only_measured_changes() {
        let upgraded =
            json!({"before":{"version":"3.0.5.0"},"after":{"version":"3.0.6.0"},"updated":true});
        assert!(wsl_update_notice(&upgraded).contains("3.0.5.0 → 3.0.6.0"));
        let current =
            json!({"before":{"version":"3.0.5.0"},"after":{"version":"3.0.5.0"},"updated":false});
        assert!(wsl_update_notice(&current).contains("已是最新"));
        let unread = json!({"before":{"version":null},"after":{"version":null},"updated":false});
        assert!(wsl_update_notice(&unread).contains("无法确认"));
    }

    #[test]
    fn keeps_the_wsl_update_command_output_and_adds_the_fix() {
        let message = humanize_error(
            "desktop_request_failed · wsl_update_command_failed: wsl_exit_failed: exit code: 0xffffffff: 正在检查更新。已禁止(403)。",
        );
        assert!(message.starts_with("升级 WSL 失败："), "{message}");
        assert!(message.contains("已禁止(403)"), "{message}");
        assert!(message.contains("管理员"), "{message}");
        assert!(message.contains("--web-download"), "{message}");
    }
}
