//! 把环境检查读到的事实整理成环境详情页的显示内容。
//!
//! 只整理、不下结论：能不能接管由预检判断，这里只说组件在不在、齐不齐。
//! 后台没给某个字段（比如旧版后台）时显示「未读取」，不当成「未安装」。

use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ComponentState {
    /// 当前版本安装脚本装的东西都在。
    Ready,
    /// 装过但缺东西，通常是旧版本建的环境；「编辑 → 保存设置」会按当前脚本补齐。
    Incomplete,
    /// 程序在，但本工具写的文件（输入法启动脚本、chrome 启动器）不在，多半是自己装的。
    /// 只列出缺什么，不提示「编辑 → 保存设置」：那会跑 apt、把系统语言改成中文并重启发行版。
    Foreign,
    Missing,
    /// 后台没返回判断所需的字段。
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Component {
    pub(crate) state: ComponentState,
    /// 需要补齐或手动安装时缺了什么，按显示顺序。
    pub(crate) gaps: Vec<&'static str>,
}

impl Component {
    fn of(state: ComponentState) -> Self {
        Self {
            state,
            gaps: Vec::new(),
        }
    }

    fn from_gaps(foreign: bool, gaps: Vec<&'static str>) -> Self {
        let state = if foreign {
            ComponentState::Foreign
        } else if gaps.is_empty() {
            ComponentState::Ready
        } else {
            ComponentState::Incomplete
        };
        Self { state, gaps }
    }
}

fn flag(features: &Value, key: &str) -> Option<bool> {
    features.get(key)?.as_bool()
}

fn word<'a>(features: &'a Value, key: &str) -> Option<&'a str> {
    features.get(key)?.as_str()
}

pub(crate) fn zsh(features: &Value) -> Component {
    match flag(features, "zsh") {
        Some(true) => Component::of(ComponentState::Ready),
        Some(false) => Component::of(ComponentState::Missing),
        None => Component::of(ComponentState::Unknown),
    }
}

/// Chrome 要浏览器本体和 `chrome` 启动器（带关闭 QUIC 等启动参数）。装了中文输入法时，
/// 启动器还得是导出输入法变量的新版，否则从 Windows 打开的 Chrome 打不了中文。
pub(crate) fn chrome(features: &Value) -> Component {
    let (Some(browser), Some(launcher)) =
        (flag(features, "chrome"), word(features, "chrome_launcher"))
    else {
        return Component::of(ComponentState::Unknown);
    };
    if !browser && launcher == "missing" {
        return Component::of(ComponentState::Missing);
    }
    let mut gaps = Vec::new();
    if !browser {
        gaps.push("缺 Chrome 浏览器");
    }
    match launcher {
        "missing" => gaps.push("缺 chrome 启动器"),
        "outdated" if flag(features, "chinese") == Some(true) => {
            gaps.push("chrome 启动器是旧版，不带输入法设置")
        }
        _ => {}
    }
    Component::from_gaps(browser && launcher == "missing", gaps)
}

/// 中文环境和输入法：zh_CN.UTF-8、fcitx5、GTK 输入法模块（Chrome 靠它接输入法）和
/// 带 `--disable=wayland` 的启动脚本。只生成了中文 locale 不算装过：装 Chrome 也会生成它。
pub(crate) fn chinese(features: &Value) -> Component {
    let (Some(fcitx5), Some(locale), Some(gtk), Some(profile)) = (
        flag(features, "chinese"),
        flag(features, "zh_locale"),
        flag(features, "fcitx5_gtk"),
        word(features, "input_profile"),
    ) else {
        return Component::of(ComponentState::Unknown);
    };
    if !fcitx5 && profile == "missing" {
        return Component::of(ComponentState::Missing);
    }
    let mut gaps = Vec::new();
    if !locale {
        gaps.push("缺 zh_CN.UTF-8 语言环境");
    }
    if !fcitx5 {
        gaps.push("缺 fcitx5");
    }
    if !gtk {
        gaps.push("缺 GTK 输入法模块");
    }
    match profile {
        "missing" => gaps.push("缺输入法启动脚本"),
        "outdated" => gaps.push("输入法启动脚本是旧版"),
        _ => {}
    }
    Component::from_gaps(fcitx5 && profile == "missing", gaps)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Systemd {
    Running,
    /// wsl.conf 开了，但 PID 1 不是 systemd：还没重启，或者没装 systemd。
    ConfiguredNotRunning,
    Off,
    Unknown,
}

pub(crate) fn systemd(features: &Value) -> Systemd {
    if word(features, "pid1") == Some("systemd") {
        return Systemd::Running;
    }
    match flag(features, "systemd_configured") {
        Some(true) => Systemd::ConfiguredNotRunning,
        Some(false) => Systemd::Off,
        None => Systemd::Unknown,
    }
}

/// 图形界面一栏的文字。Chrome 和输入法都走 WSLg 的 X11（XWayland）。
pub(crate) fn graphics(features: &Value) -> &'static str {
    match (flag(features, "wslg"), flag(features, "x11_socket")) {
        (None, _) => "未读取",
        (Some(false), _) => "WSLg 不可用",
        (Some(true), Some(false)) => "WSLg 缺 X11 套接字",
        (Some(true), _) => "WSLg 可用",
    }
}

pub(crate) fn default_user(features: &Value) -> String {
    match word(features, "default_user") {
        None => "未读取".into(),
        Some("") => "wsl.conf 未指定".into(),
        Some(user) => user.into(),
    }
}

fn kilobytes(features: &Value, key: &str) -> Option<u64> {
    word(features, key)?.parse().ok()
}

fn size(kilobytes: u64) -> String {
    let gigabytes = kilobytes as f64 / (1024. * 1024.);
    if gigabytes >= 1. {
        format!("{gigabytes:.1} GB")
    } else {
        format!("{} MB", kilobytes / 1024)
    }
}

/// 「已用 / 上限」。虚拟磁盘按需增长，发行版里看到的总量是上限，不是 Windows 盘上占的空间。
pub(crate) fn disk(features: &Value) -> String {
    match (
        kilobytes(features, "disk_used_kb"),
        kilobytes(features, "disk_total_kb"),
    ) {
        (Some(used), Some(total)) if total > 0 => {
            format!("{} / {}", size(used), size(total))
        }
        _ => "未读取".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn current() -> Value {
        json!({
            "zsh": true,
            "chrome": true,
            "chinese": true,
            "input_method": true,
            "zh_locale": true,
            "fcitx5_gtk": true,
            "input_profile": "current",
            "chrome_launcher": "current",
            "systemd_configured": true,
            "pid1": "systemd",
            "default_user": "builder",
            "wslg": true,
            "x11_socket": true,
            "disk_total_kb": "1055762868",
            "disk_used_kb": "93573908"
        })
    }

    #[test]
    fn an_environment_set_up_by_the_current_script_is_ready() {
        let facts = current();
        assert_eq!(zsh(&facts).state, ComponentState::Ready);
        assert_eq!(chrome(&facts).state, ComponentState::Ready);
        assert_eq!(chinese(&facts).state, ComponentState::Ready);
        assert_eq!(systemd(&facts), Systemd::Running);
        assert_eq!(graphics(&facts), "WSLg 可用");
        assert_eq!(default_user(&facts), "builder");
        assert_eq!(disk(&facts), "89.2 GB / 1006.9 GB");
    }

    #[test]
    fn an_input_method_from_an_older_version_needs_completing() {
        let mut facts = current();
        facts["fcitx5_gtk"] = json!(false);
        facts["input_profile"] = json!("outdated");
        facts["chrome_launcher"] = json!("outdated");
        let input = chinese(&facts);
        assert_eq!(input.state, ComponentState::Incomplete);
        assert_eq!(input.gaps, ["缺 GTK 输入法模块", "输入法启动脚本是旧版"]);
        let browser = chrome(&facts);
        assert_eq!(browser.state, ComponentState::Incomplete);
        assert_eq!(browser.gaps, ["chrome 启动器是旧版，不带输入法设置"]);
    }

    #[test]
    fn an_old_launcher_is_fine_without_the_input_method() {
        let mut facts = current();
        facts["chinese"] = json!(false);
        facts["input_profile"] = json!("missing");
        facts["chrome_launcher"] = json!("outdated");
        assert_eq!(chrome(&facts).state, ComponentState::Ready);
        assert_eq!(chinese(&facts).state, ComponentState::Missing);
    }

    #[test]
    fn a_chinese_locale_alone_is_not_an_installed_input_method() {
        let mut facts = current();
        facts["chinese"] = json!(false);
        facts["fcitx5_gtk"] = json!(false);
        facts["input_profile"] = json!("missing");
        assert_eq!(chinese(&facts).state, ComponentState::Missing);
    }

    #[test]
    fn components_installed_by_hand_are_not_sent_to_the_repair_path() {
        let mut facts = current();
        facts["chrome_launcher"] = json!("missing");
        let browser = chrome(&facts);
        assert_eq!(browser.state, ComponentState::Foreign);
        assert_eq!(browser.gaps, ["缺 chrome 启动器"]);

        // fcitx5 装了、GTK 模块也有，但没有本工具的启动脚本和中文 locale。
        facts["zh_locale"] = json!(false);
        facts["input_profile"] = json!("missing");
        let input = chinese(&facts);
        assert_eq!(input.state, ComponentState::Foreign);
        assert_eq!(input.gaps, ["缺 zh_CN.UTF-8 语言环境", "缺输入法启动脚本"]);
    }

    #[test]
    fn a_tool_launcher_without_the_browser_needs_completing() {
        let mut facts = current();
        facts["chrome"] = json!(false);
        let browser = chrome(&facts);
        assert_eq!(browser.state, ComponentState::Incomplete);
        assert_eq!(browser.gaps, ["缺 Chrome 浏览器"]);
    }

    #[test]
    fn facts_an_older_controller_did_not_send_read_as_unknown() {
        let facts = json!({"zsh": false, "chrome": true, "chinese": true, "input_method": true});
        assert_eq!(zsh(&facts).state, ComponentState::Missing);
        assert_eq!(chrome(&facts).state, ComponentState::Unknown);
        assert_eq!(chinese(&facts).state, ComponentState::Unknown);
        assert_eq!(systemd(&facts), Systemd::Unknown);
        assert_eq!(graphics(&facts), "未读取");
        assert_eq!(default_user(&facts), "未读取");
        assert_eq!(disk(&facts), "未读取");
    }

    #[test]
    fn systemd_switched_on_but_not_pid_1_waits_for_a_restart() {
        let mut facts = current();
        facts["pid1"] = json!("init");
        assert_eq!(systemd(&facts), Systemd::ConfiguredNotRunning);
        facts["systemd_configured"] = json!(false);
        assert_eq!(systemd(&facts), Systemd::Off);
    }

    #[test]
    fn graphics_and_disk_report_what_is_missing() {
        let mut facts = current();
        facts["x11_socket"] = json!(false);
        assert_eq!(graphics(&facts), "WSLg 缺 X11 套接字");
        facts["wslg"] = json!(false);
        assert_eq!(graphics(&facts), "WSLg 不可用");
        facts["default_user"] = json!("");
        assert_eq!(default_user(&facts), "wsl.conf 未指定");
        facts["disk_used_kb"] = json!("524288");
        facts["disk_total_kb"] = json!("");
        assert_eq!(disk(&facts), "未读取");
        facts["disk_total_kb"] = json!("2097152");
        assert_eq!(disk(&facts), "512 MB / 2.0 GB");
    }
}
