//! WSL 平台（`wsl.exe` 与共享的 WSL2 内核）的只读检查和显式升级。
//!
//! 检查只运行 `wsl.exe` 的只读子命令并读注册表，不启动发行版、不写引流规则、
//! 不改任何配置。升级执行 `wsl --update`：它替换 WSL 包并可能重启 WSL，因此
//! 只在空闲时可用、必须显式确认；是否升级成功按版本前后的实际变化判断，
//! 不解析本地化的命令输出。

use crate::host;
use serde_json::{Value, json};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const VERSION_DEADLINE: Duration = Duration::from_secs(20);
const STATUS_DEADLINE: Duration = Duration::from_secs(20);
const UPDATE_DEADLINE: Duration = Duration::from_secs(30 * 60);
/// 命令输出只保留末尾一段：足够说明结果，又不把整段下载进度写进回复和日志。
const OUTPUT_LIMIT: usize = 2000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Versions {
    wsl: Option<String>,
    kernel: Option<String>,
    windows: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Defaults {
    distribution: Option<String>,
    version: Option<u32>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// 一行 `标签: 值` 里的值。`wsl.exe` 的标签随系统语言变化，值不随。
fn value_after_colon(line: &str) -> Option<&str> {
    let (_, value) = line.split_once(':')?;
    let value = value.trim();
    (!value.is_empty() && value.len() <= 64).then_some(value)
}

/// 仅由数字和点组成、至少两段的版本号。
fn dotted_version(value: &str) -> bool {
    value.contains('.')
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

/// 形如 `6.18.58.1-1` 或 `5.15.153.1-microsoft-standard-WSL2` 的内核版本。
fn kernel_version(value: &str) -> bool {
    let Some((prefix, suffix)) = value.split_once('-') else {
        return false;
    };
    dotted_version(prefix)
        && !suffix.is_empty()
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn windows_version(value: &str) -> bool {
    value.starts_with("10.0.") && dotted_version(value)
}

/// `wsl --version` 每个组件一行，顺序固定：WSL、内核、WSLg、MSRDC、Direct3D、
/// DXCore、Windows。标签是本地化的，所以只按行的位置和值的形状识别：第一行
/// 是 WSL 版本，第二行是内核版本，`10.0.` 开头的是 Windows 版本。Direct3D
/// 的版本也带 `-` 后缀，位置是唯一能把它和内核区分开的信号，因此内核只认
/// 第二行（缺失时为 `None`，不拿别的行顶替）。
fn parse_version(output: &str) -> Versions {
    let values: Vec<&str> = output.lines().filter_map(value_after_colon).collect();
    Versions {
        wsl: values
            .first()
            .filter(|value| dotted_version(value))
            .map(|value| (*value).to_owned()),
        kernel: values
            .get(1)
            .filter(|value| kernel_version(value))
            .map(|value| (*value).to_owned()),
        windows: values
            .iter()
            .find(|value| windows_version(value))
            .map(|value| (*value).to_owned()),
    }
}

/// `wsl --status` 的前两行是默认发行版和默认版本，标签同样是本地化的。
/// 值分别匹配已注册的发行版名和数字 1/2，读不到就留空。
fn parse_status(output: &str, names: &[String]) -> Defaults {
    let mut defaults = Defaults::default();
    for value in output.lines().filter_map(value_after_colon) {
        if defaults.version.is_none() && matches!(value, "1" | "2") {
            defaults.version = value.parse().ok();
        } else if defaults.distribution.is_none()
            && let Some(name) = names.iter().find(|name| name.eq_ignore_ascii_case(value))
        {
            defaults.distribution = Some(name.clone());
        }
    }
    defaults
}

/// 命令输出的末尾一段，按行整理：去掉进度用的回车和空行，超出上限只留尾部。
fn command_tail(output: &str) -> String {
    let normalized = output.replace("\r\n", "\n").replace('\r', "\n");
    let mut tail = normalized
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let excess = tail.chars().count().saturating_sub(OUTPUT_LIMIT);
    if excess > 0 {
        tail = tail.chars().skip(excess).collect();
        tail.insert_str(0, "…\n");
    }
    tail
}

struct Check {
    code: &'static str,
    level: &'static str,
    detail: Option<String>,
}

impl Check {
    fn new(code: &'static str, ok: bool, level_if_failed: &'static str) -> Self {
        Self {
            code,
            level: if ok { "ok" } else { level_if_failed },
            detail: None,
        }
    }

    fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    fn value(&self) -> Value {
        json!({"code": self.code, "level": self.level, "detail": self.detail})
    }
}

/// 只读报告。`Err` 只表示连报告都构造不出来（例如读注册表失败）；WSL 未安装、
/// 版本读不到都写在报告里，由调用方决定如何显示。
pub(crate) fn inspect() -> Result<Value, String> {
    let executable = host::wsl_executable()?;
    let installed = executable.is_file();
    let mut versions = Versions::default();
    let mut version_supported = false;
    let mut version_error = None;
    if installed {
        match host::wsl_command(&["--version".into()], None, VERSION_DEADLINE) {
            Ok(output) => {
                versions = parse_version(&output);
                version_supported = versions.wsl.is_some();
            }
            Err(error) => version_error = Some(error),
        }
    }
    let distributions = if installed {
        host::distributions()?
    } else {
        Vec::new()
    };
    let names: Vec<String> = distributions
        .iter()
        .map(|distro| distro.name.clone())
        .collect();
    let mut defaults = Defaults::default();
    let mut status_error = None;
    if installed && version_supported {
        match host::wsl_command(&["--status".into()], None, STATUS_DEADLINE) {
            Ok(output) => defaults = parse_status(&output, &names),
            Err(error) => status_error = Some(error),
        }
    }
    let wsl1: Vec<&str> = distributions
        .iter()
        .filter(|distro| distro.version != 2)
        .map(|distro| distro.name.as_str())
        .collect();
    let checks = [
        Check::new("wsl.executable", installed, "blocker"),
        Check::new("wsl.version_supported", version_supported, "blocker"),
        match defaults.version {
            Some(1) => Check::new("wsl.default_version_2", false, "warning").detail("1"),
            Some(2) => Check::new("wsl.default_version_2", true, "warning"),
            _ => Check::new("wsl.default_version_2", false, "warning"),
        },
        match wsl1.is_empty() {
            true => Check::new("wsl.no_wsl1_distribution", true, "warning"),
            false => {
                Check::new("wsl.no_wsl1_distribution", false, "warning").detail(wsl1.join(", "))
            }
        },
    ];
    let level = |wanted: &str| -> Vec<&'static str> {
        checks
            .iter()
            .filter(|check| check.level == wanted)
            .map(|check| check.code)
            .collect()
    };
    let elevated = host::elevated();
    Ok(json!({
        "schema_version": 1,
        "wsl": {
            "executable": executable.to_string_lossy(),
            "installed": installed,
            "version_supported": version_supported,
            "version": versions.wsl,
            "kernel_version": versions.kernel,
            "windows_version": versions.windows,
            "version_error": version_error,
        },
        "defaults": {
            "version": defaults.version,
            "distribution": defaults.distribution,
            "status_error": status_error,
        },
        "distributions": distributions
            .iter()
            .map(|distro| json!({"name": distro.name, "version": distro.version}))
            .collect::<Vec<_>>(),
        "wsl1": wsl1,
        "elevated": elevated,
        "blockers": level("blocker"),
        "warnings": level("warning"),
        "checks": checks.iter().map(Check::value).collect::<Vec<_>>(),
        "checked_at_unix_seconds": now(),
    }))
}

/// 当前 WSL 版本与内核版本；读不到时留空，不影响升级本身。
fn current_versions() -> Versions {
    host::wsl_command(&["--version".into()], None, VERSION_DEADLINE)
        .map(|output| parse_version(&output))
        .unwrap_or_default()
}

/// `wsl --update`。调用方负责先确认并在空闲时调用：它会重启 WSL，接管中的
/// 规则会随之消失。
pub(crate) fn update() -> Result<Value, String> {
    let executable = host::wsl_executable()?;
    if !executable.is_file() {
        return Err("wsl_not_installed".into());
    }
    let before = current_versions();
    let output = host::wsl_command(&["--update".into()], None, UPDATE_DEADLINE)
        .map_err(|error| format!("wsl_update_command_failed: {error}"))?;
    let after = current_versions();
    let updated = before.wsl != after.wsl || before.kernel != after.kernel;
    Ok(json!({
        "schema_version": 1,
        "before": {"version": before.wsl, "kernel_version": before.kernel},
        "after": {"version": after.wsl, "kernel_version": after.kernel},
        "updated": updated,
        "elevated": host::elevated(),
        "output": command_tail(&output),
        "checked_at_unix_seconds": now(),
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        Defaults, Versions, command_tail, dotted_version, kernel_version, parse_status,
        parse_version,
    };

    const CHINESE_VERSION: &str = "WSL 版本: 3.0.5.0\r\n\
        内核版本: 6.18.58.1-1\r\n\
        WSLg 版本: 1.0.79\r\n\
        MSRDC 版本: 1.2.7391\r\n\
        Direct3D 版本: 1.611.1-81528511\r\n\
        DXCore 版本: 10.0.26100.1-240331-1435.ge-release\r\n\
        Windows 版本: 10.0.26300.9974\r\n";

    const ENGLISH_VERSION: &str = "WSL version: 2.5.9.0\n\
        Kernel version: 6.6.87.2-1\n\
        WSLg version: 1.0.66\n\
        MSRDC version: 1.2.6074\n\
        Direct3D version: 1.611.1-81528511\n\
        DXCore version: 10.0.26100.1-240331-1435.ge-release\n\
        Windows version: 10.0.26100.3915\n";

    fn names() -> Vec<String> {
        vec!["Ubuntu-24.04".to_owned(), "Target".to_owned()]
    }

    #[test]
    fn reads_versions_from_the_fixed_line_order_in_any_language() {
        assert_eq!(
            parse_version(CHINESE_VERSION),
            Versions {
                wsl: Some("3.0.5.0".into()),
                kernel: Some("6.18.58.1-1".into()),
                windows: Some("10.0.26300.9974".into()),
            }
        );
        assert_eq!(
            parse_version(ENGLISH_VERSION),
            Versions {
                wsl: Some("2.5.9.0".into()),
                kernel: Some("6.6.87.2-1".into()),
                windows: Some("10.0.26100.3915".into()),
            }
        );
    }

    #[test]
    fn missing_kernel_line_is_reported_as_unknown_instead_of_guessed() {
        // 第二行缺失时 Direct3D 的 `1.611.1-81528511` 也长得像内核版本，
        // 但它是第四行之后的内容，不能被当成内核。
        let output = "WSL 版本: 3.0.5.0\r\n\
            WSLg 版本: 1.0.79\r\n\
            Direct3D 版本: 1.611.1-81528511\r\n";
        assert_eq!(parse_version(output).kernel, None);
    }

    #[test]
    fn version_output_without_any_value_is_empty() {
        for output in ["", "wsl: 无效的命令行选项 --version", "no colons here"] {
            assert_eq!(parse_version(output), Versions::default());
        }
    }

    #[test]
    fn recognizes_kernel_shapes_only() {
        assert!(kernel_version("6.18.58.1-1"));
        assert!(kernel_version("5.15.153.1-microsoft-standard-WSL2"));
        assert!(!kernel_version("1.0.79"));
        assert!(!kernel_version("6.18.58.1-"));
        assert!(!kernel_version("-1"));
        assert!(dotted_version("3.0.5.0"));
        assert!(!dotted_version("3.0.5."));
        assert!(!dotted_version("3.0.5-beta"));
    }

    #[test]
    fn reads_defaults_from_status_values_without_localized_labels() {
        let chinese = "默认分发: Ubuntu-24.04\r\n默认版本: 2\r\n当前计算机配置不支持 WSL1。\r\n";
        assert_eq!(
            parse_status(chinese, &names()),
            Defaults {
                distribution: Some("Ubuntu-24.04".into()),
                version: Some(2),
            }
        );
        let english = "Default Distribution: Target\nDefault Version: 1\n";
        assert_eq!(
            parse_status(english, &names()),
            Defaults {
                distribution: Some("Target".into()),
                version: Some(1),
            }
        );
        // 读不到的值留空，不拿不相干的数字或名字顶替。
        assert_eq!(
            parse_status("Default Distribution: Something\n", &names()),
            Defaults::default()
        );
    }

    #[test]
    fn keeps_only_the_tail_of_the_command_output() {
        assert_eq!(command_tail("a\r\n\r\nb\rc\r\n"), "a\nb\nc");
        assert_eq!(command_tail(""), "");
        let long = "x".repeat(4_000);
        let tail = command_tail(&long);
        assert!(tail.starts_with("…\n"));
        assert_eq!(tail.chars().count(), 2_002);
    }
}
