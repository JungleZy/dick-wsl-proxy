//! 检查更新与一键升级（决策 31）。
//!
//! 查 GitHub 上的新版本、下载并核对安装包，都在桌面这个普通权限的进程里做，不经后台。
//! 替换程序文件交给新包里的 `install.ps1`：桌面先拉起一个独立的 PowerShell 进程再退出，
//! 那个进程等桌面退出后解压、运行安装器、把结果写进文件，再重新打开桌面；新打开的桌面
//! 读到结果后显示一次。安装器自己的检查、事务、回滚和 `-Recover` 全部原样沿用。

use std::fs;
use std::io::Read as _;
use std::net::SocketAddrV4;
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use gpui_kit::component::{
    Disableable as _, WindowExt as _,
    button::{Button, ButtonVariants as _},
    dialog::DialogButtonProps,
};
use gpui_kit::{prelude::*, *};
use serde_json::Value;
use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows_sys::Win32::System::Threading::{CREATE_BREAKAWAY_FROM_JOB, CREATE_NO_WINDOW};
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;
use wsl_proxyctl::update::{self, Downloaded, RELEASES_PAGE, Release, UpdateError, Version};

use super::components::{badge, design_icon};
use super::state::{Desktop, Reminder};
use super::theme::{
    ACCENT, AMBER, INK, MONO_FONT, MUTED, RUST, SUCCESS_BG, SURFACE, SURFACE_SOFT, TEAL,
    WARNING_BG, app_rgb as rgb,
};

/// 和主题设置同一个注册表键（见 `theme.rs`）。
const PREFERENCES_KEY: &str = "Software\\WSLProxyLab";
/// 「自动检查更新」：DWORD，0 表示关闭；没有这一项时开启。
const AUTO_CHECK_VALUE: &str = "UpdateCheck";
/// 打开窗口后等这么久再自动检查，先让后台连接、读配置跑完。
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(15);
/// 配置一直没读到时，最多等这么久，之后只直连检查。
const PROFILE_WAIT: Duration = Duration::from_secs(60);
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const POLICY_TIMEOUT: Duration = Duration::from_secs(30);
const OUTCOME_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// 下载进度至少隔这么多字节才报一次，免得每 64 KB 刷新一次界面。
const PROGRESS_STEP: u64 = 512 * 1024;
/// 安装器写在安装目录里的安装记录（`packaging/windows/common.ps1`）。
const MARKER_NAME: &str = ".wsl-proxy-install.json";
const RESULT_NAME: &str = "result.json";
/// 结果框里最多显示安装器输出的最后几行。
const OUTPUT_LINES: usize = 12;

pub(crate) struct Updater {
    pub(crate) auto: bool,
    pub(crate) checking: bool,
    pub(crate) checked_at: Option<Instant>,
    /// 最近一次检查找到的新版本；之后检查失败时保留，检查到已是最新时清掉。
    pub(crate) release: Option<Release>,
    pub(crate) error: Option<String>,
    /// 正在读 PowerShell 执行策略。
    pub(crate) preparing: bool,
    /// 下载进度：已写字节、总字节。
    pub(crate) downloading: Option<(u64, u64)>,
    /// 读执行策略期间要升级的安装目录。
    pending: Option<PathBuf>,
    /// 执行策略允许运行安装脚本，等着弹确认框的安装目录。
    confirm: Option<PathBuf>,
    /// 下载完成后要交给安装器的安装目录。
    installing: Option<PathBuf>,
    /// 打开程序时这个副本能不能一键升级：能就是安装目录，不能就是原因。点「升级」时会再查一次。
    installable: Result<PathBuf, String>,
    /// 上一次升级的结果，窗口打开后显示一次。
    outcome: Option<Outcome>,
    /// 上次看结果文件的时刻。升级期间用户自己打开了程序时，安装器会拒绝，助手写下结果后
    /// 只能唤醒这个已经打开的窗口，所以运行中也隔一会儿看一次，不只在启动时读。
    outcome_polled: Instant,
    started: Instant,
    last_auto: Option<Instant>,
    /// 已经提醒过的新版本：同一个版本只自动提醒一次。
    notified: Option<Version>,
    sender: Sender<Event>,
    events: Receiver<Event>,
}

enum Event {
    Checked {
        manual: bool,
        result: Result<Option<Release>, UpdateError>,
    },
    Policy(Result<String, String>),
    Progress(u64, u64),
    Downloaded(Result<Downloaded, UpdateError>),
}

impl Updater {
    pub(crate) fn new() -> Self {
        let (sender, events) = mpsc::channel();
        Self {
            auto: load_auto(),
            checking: false,
            checked_at: None,
            release: None,
            error: None,
            preparing: false,
            downloading: None,
            pending: None,
            confirm: None,
            installing: None,
            installable: installed_dir(),
            outcome: take_outcome(),
            outcome_polled: Instant::now(),
            started: Instant::now(),
            last_auto: None,
            notified: None,
            sender,
            events,
        }
    }

    fn busy(&self) -> bool {
        self.checking
            || self.preparing
            || self.downloading.is_some()
            || self.confirm.is_some()
            || self.installing.is_some()
    }
}

/// 上一次升级时安装器助手写下的结果。
#[derive(Debug, PartialEq)]
pub(crate) struct Outcome {
    ok: bool,
    /// `installed`、`refused`（安装器拒绝，文件没动）、`interrupted`（文件替换中断，
    /// 要 `-Recover`）或 `failed`（没走到安装器）。
    stage: String,
    version: String,
    from: String,
    install_dir: String,
    package: String,
    output: String,
}

impl Outcome {
    fn parse(text: &str) -> Option<Self> {
        let value: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
        let field = |key: &str| value[key].as_str().unwrap_or_default().to_owned();
        (value["schema_version"] == 1).then(|| Self {
            ok: value["ok"] == true,
            stage: field("stage"),
            version: field("version"),
            from: field("from"),
            install_dir: field("install_dir"),
            package: field("package"),
            output: field("output"),
        })
    }
}

impl Desktop {
    /// 每次界面刷新调用：收后台线程发回的结果，到点自动检查，弹出待弹的确认框和结果框。
    pub(crate) fn update_tick(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let mut changed = false;
        while let Ok(event) = self.updater.events.try_recv() {
            self.accept_update_event(event, cx);
            changed = true;
        }
        if self.auto_check_due() {
            self.check_update(false, cx);
        }
        if self.updater.outcome.is_none()
            && !self.exiting
            && self.updater.outcome_polled.elapsed() >= OUTCOME_POLL_INTERVAL
        {
            self.updater.outcome_polled = Instant::now();
            self.updater.outcome = take_outcome();
        }
        if changed {
            cx.notify();
        }
        // 不和加载框、确认框或别的对话框叠在一起。
        if self.loading_dialog_open || self.confirmation.is_some() || window.has_active_dialog(cx) {
            return;
        }
        if let Some(install_dir) = self.updater.confirm.take() {
            self.open_upgrade_dialog(install_dir, window, cx);
        } else if let Some(outcome) = self.updater.outcome.take() {
            self.show_outcome(outcome, window, cx);
        }
    }

    fn auto_check_due(&self) -> bool {
        let updater = &self.updater;
        if !updater.auto || updater.busy() || self.exiting {
            return false;
        }
        match updater.last_auto {
            Some(at) => at.elapsed() >= CHECK_INTERVAL,
            None => {
                let waited = updater.started.elapsed();
                waited >= FIRST_CHECK_DELAY && (!self.profile.is_null() || waited >= PROFILE_WAIT)
            }
        }
    }

    /// 查 GitHub 上有没有更新的版本。`manual` 是用户点的「检查更新」：已是最新时也提示一声。
    pub(crate) fn check_update(&mut self, manual: bool, cx: &mut Context<Self>) {
        if self.updater.busy() {
            return;
        }
        if !manual {
            self.updater.last_auto = Some(Instant::now());
        }
        self.updater.checking = true;
        let routes = update::routes(self.saved_first_hop());
        let sender = self.updater.sender.clone();
        std::thread::spawn(move || {
            let result = update::check(&routes, Version::current());
            let _ = sender.send(Event::Checked { manual, result });
        });
        cx.notify();
    }

    /// 已保存的宿主 SOCKS5。输入框里没保存的值不用。
    fn saved_first_hop(&self) -> Option<SocketAddrV4> {
        self.profile["first_hop"].as_str()?.parse().ok()
    }

    pub(crate) fn set_auto_update(&mut self, enabled: bool, cx: &mut Context<Self>) {
        match persist_auto(enabled) {
            Ok(()) => {
                self.updater.auto = enabled;
                // 这次运行还没自动查过：从打开开关起 15 秒后查；查过的仍按上次的时间隔一天。
                if enabled && self.updater.last_auto.is_none() {
                    self.updater.started = Instant::now();
                }
            }
            Err(error) => self.fail(format!("没能保存「自动检查更新」：{error}"), cx),
        }
        cx.notify();
    }

    fn accept_update_event(&mut self, event: Event, cx: &mut Context<Self>) {
        match event {
            Event::Checked { manual, result } => {
                self.updater.checking = false;
                self.updater.checked_at = Some(Instant::now());
                match result {
                    Ok(Some(release)) => {
                        if self.updater.notified != Some(release.version) {
                            self.updater.notified = Some(release.version);
                            if !manual {
                                self.reminder = Some(Reminder {
                                    message: format!(
                                        "发现新版本 v{}，可以在「设置 › 关于」升级。",
                                        release.version
                                    ),
                                    warning: false,
                                });
                            }
                        }
                        self.updater.error = None;
                        self.updater.release = Some(release);
                    }
                    Ok(None) => {
                        self.updater.error = None;
                        self.updater.release = None;
                        if manual {
                            self.reminder = Some(Reminder {
                                message: format!("已是最新版本（v{}）。", Version::current()),
                                warning: false,
                            });
                        }
                    }
                    Err(error) => self.updater.error = Some(describe(&error)),
                }
            }
            Event::Policy(result) => {
                self.updater.preparing = false;
                let Some(install_dir) = self.updater.pending.take() else {
                    return;
                };
                match result {
                    Ok(policy) if policy_allows(&policy) => self.updater.confirm = Some(install_dir),
                    Ok(policy) => self.fail(
                        format!(
                            "本机 PowerShell 的执行策略是 {policy}，不允许运行安装脚本，所以不能一键升级。请在「设置 › 关于」打开发布页手动下载，按 README「升级与卸载」安装；不要为此修改执行策略。"
                        ),
                        cx,
                    ),
                    Err(error) => self.fail(
                        format!("读不到 PowerShell 的执行策略（{error}），不能一键升级，请从发布页手动下载升级。"),
                        cx,
                    ),
                }
            }
            Event::Progress(done, total) => self.updater.downloading = Some((done, total)),
            Event::Downloaded(result) => {
                self.updater.downloading = None;
                let install_dir = self.updater.installing.take();
                match (result, install_dir) {
                    (Ok(downloaded), Some(install_dir)) => {
                        self.hand_off(downloaded, install_dir, cx);
                    }
                    (Ok(_), None) => {}
                    (Err(error), _) => {
                        let message = describe(&error);
                        self.updater.error = Some(message.clone());
                        self.fail(format!("下载安装包失败，没有安装：{message}"), cx);
                    }
                }
            }
        }
    }

    /// 「升级」按钮：先在本地确认能升级、读执行策略，通过后再弹确认框。
    pub(crate) fn prompt_upgrade(&mut self, cx: &mut Context<Self>) {
        if self.updater.release.is_none() || self.updater.busy() {
            return;
        }
        if let Some(reason) = self.upgrade_blocker() {
            self.fail(reason, cx);
            return;
        }
        let install_dir = match installed_dir() {
            Ok(install_dir) => install_dir,
            Err(reason) => {
                self.fail(reason, cx);
                return;
            }
        };
        self.updater.preparing = true;
        self.updater.pending = Some(install_dir);
        let sender = self.updater.sender.clone();
        std::thread::spawn(move || {
            let _ = sender.send(Event::Policy(execution_policy()));
        });
        cx.notify();
    }

    /// 现在不能升级的原因。安装器自己也会拒绝这些情况，这里先说清楚，免得关了窗口才失败。
    fn upgrade_blocker(&self) -> Option<&'static str> {
        upgrade_blocker(self.status_valid, &self.sessions, self.locked())
    }

    fn open_upgrade_dialog(
        &mut self,
        install_dir: PathBuf,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(release) = self.updater.release.clone() else {
            return;
        };
        let route = match self.saved_first_hop() {
            Some(proxy) => format!("经宿主 SOCKS5（{proxy}）访问 GitHub，连不上再直连"),
            None => "直连 GitHub".to_owned(),
        };
        let message = format!(
            "将下载安装包 {name}（{size}，{route}），核对发布页公布的 SHA-256 后关闭本窗口，运行新包里的 install.ps1 升级 {dir}，装好后自动重新打开。窗口关闭后通常要一两分钟才会重新打开，期间看不到进度；请不要自己打开程序，否则安装器会拒绝这次升级。\n\n后台必须空闲：安装器会请它退出，任何一个环境在接管中或需要恢复都会拒绝。升级只替换程序文件，配置库 desktop.sqlite、开机自启和恢复记录都保留。\n\n安装包没有签名：SHA-256 只能发现下载损坏，证明不了发布者是谁；这和手动从发布页下载是同一个信任前提。",
            name = release.package.name,
            size = megabytes(release.package.size),
            dir = install_dir.display(),
        );
        let title = format!("升级到 v{}", release.version);
        let view = cx.entity().clone();
        window.open_alert_dialog(cx, move |dialog, _, _| {
            let ok_view = view.clone();
            let install_dir = install_dir.clone();
            dialog
                .confirm()
                .title(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::NORMAL)
                        .child(title.clone()),
                )
                .button_props(
                    DialogButtonProps::default()
                        .ok_text("下载并升级")
                        .cancel_text("取消"),
                )
                .description(div().text_sm().child(message.clone()))
                .on_ok(move |_, _, cx| {
                    let install_dir = install_dir.clone();
                    ok_view.update(cx, |this, cx| this.start_download(install_dir, cx));
                    true
                })
                .on_cancel(|_, _, _| true)
        });
    }

    fn start_download(&mut self, install_dir: PathBuf, cx: &mut Context<Self>) {
        let Some(release) = self.updater.release.clone() else {
            return;
        };
        let staging = match updates_dir() {
            Ok(updates) => updates.join(release.version.to_string()),
            Err(error) => {
                self.fail(format!("找不到存放安装包的目录：{error}"), cx);
                return;
            }
        };
        self.updater.error = None;
        self.updater.installing = Some(install_dir);
        self.updater.downloading = Some((0, release.package.size));
        let routes = update::routes(self.saved_first_hop());
        let sender = self.updater.sender.clone();
        std::thread::spawn(move || {
            let mut reported = 0;
            let result = update::download(&release, &routes, &staging, &mut |done, total| {
                if done == total || done < reported || done - reported >= PROGRESS_STEP {
                    reported = done;
                    let _ = sender.send(Event::Progress(done, total));
                }
            });
            let _ = sender.send(Event::Downloaded(result));
        });
        cx.notify();
    }

    /// 下载并核对完成：再确认一次能升级，拉起安装器助手，然后退出程序。
    fn hand_off(&mut self, downloaded: Downloaded, install_dir: PathBuf, cx: &mut Context<Self>) {
        let Some(release) = self.updater.release.clone() else {
            return;
        };
        let kept = format!(
            "安装包已下载并核对（{}），下次点升级不会重新下载。",
            downloaded.path.display()
        );
        if let Some(reason) = self.upgrade_blocker() {
            self.fail(format!("{reason}{kept}"), cx);
            return;
        }
        let handoff = (|| -> Result<(), String> {
            let staging = downloaded
                .path
                .parent()
                .ok_or("安装包没有所在目录")?
                .to_path_buf();
            let updates = updates_dir()?;
            if overlaps(&staging, &install_dir) {
                return Err("存放安装包的目录和安装目录重叠，安装器会拒绝".into());
            }
            let powershell = powershell()?;
            let script = helper_script(&Handoff {
                zip: &downloaded.path,
                sha256: &downloaded.sha256,
                package: &staging.join("package"),
                staging: &staging,
                install_dir: &install_dir,
                result: &updates.join(RESULT_NAME),
                powershell: &powershell,
                desktop_pid: std::process::id(),
                version: release.version,
                from: Version::current(),
            });
            spawn_helper(&powershell, &script, &updates)
        })();
        match handoff {
            Ok(()) => {
                self.exiting = true;
                self.notice = format!(
                    "正在升级到 v{}：程序即将关闭，装好后会自动重新打开。",
                    release.version
                );
                self.error = false;
                if !super::tray::quit_application() {
                    cx.quit();
                }
            }
            Err(error) => self.fail(format!("没能启动安装器：{error}。{kept}"), cx),
        }
    }

    fn show_outcome(&mut self, outcome: Outcome, window: &mut Window, cx: &mut Context<Self>) {
        let current = Version::current().to_string();
        if outcome.ok && outcome.version == current {
            self.reminder = Some(Reminder {
                message: format!("已从 v{} 升级到 v{current}。", outcome.from),
                warning: false,
            });
            // 装好了就不再需要留着的安装包。
            if let Ok(updates) = updates_dir() {
                let _ = fs::remove_dir_all(updates);
            }
            cx.notify();
            return;
        }
        let (title, description) = outcome_text(&outcome, &current);
        window.open_alert_dialog(cx, move |dialog, _, _| {
            dialog
                .title(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::NORMAL)
                        .child(title.clone()),
                )
                .button_props(DialogButtonProps::default().ok_text("知道了"))
                .description(div().flex().flex_col().gap_2().text_sm().children(
                    description.iter().map(|(text, mono)| {
                        let line = div().child(text.clone());
                        if *mono {
                            line.font_family(MONO_FONT).text_color(rgb(MUTED))
                        } else {
                            line
                        }
                    }),
                ))
                .on_ok(|_, _, _| true)
        });
    }

    /// 设置页「关于」里「更新」一组的内容。
    pub(crate) fn update_panel(&self, cx: &Context<Self>) -> Div {
        let updater = &self.updater;
        let current = Version::current();
        let (label, color, background) = if updater.checking {
            ("检查中", MUTED, SURFACE_SOFT)
        } else if updater.downloading.is_some() {
            ("下载中", AMBER, WARNING_BG)
        } else if updater.release.is_some() {
            ("有新版本", AMBER, WARNING_BG)
        } else if updater.error.is_some() {
            ("检查失败", RUST, SURFACE_SOFT)
        } else if updater.checked_at.is_some() {
            ("已是最新", TEAL, SUCCESS_BG)
        } else {
            ("尚未检查", MUTED, SURFACE_SOFT)
        };
        let checked = updater
            .checked_at
            .map(|at| super::views::elapsed_label(at, "检查"));
        let upgrade_label: SharedString = updater
            .release
            .as_ref()
            .map_or_else(
                || "升级".into(),
                |release| format!("升级到 v{}", release.version),
            )
            .into();
        let blocker =
            self.upgrade_blocker()
                .or(updater.installable.as_ref().err().map(String::as_str));
        let upgrade_disabled = updater.release.is_none() || updater.busy() || blocker.is_some();
        let page = updater
            .release
            .as_ref()
            .map_or_else(|| RELEASES_PAGE.to_owned(), |release| release.page.clone());
        let buttons = div()
            .flex()
            .items_center()
            .gap_2()
            .child(
                Button::new("settings-update-check")
                    .label("检查更新")
                    .icon(design_icon("refresh", 15., MUTED))
                    .disabled(updater.busy())
                    .on_click(cx.listener(|this, _, _, cx| this.check_update(true, cx))),
            )
            .child(
                Button::new("settings-update-page")
                    .label("发布页")
                    .on_click(move |_, _, cx: &mut App| cx.open_url(&page)),
            )
            .child(
                Button::new("settings-update-upgrade")
                    .label(upgrade_label)
                    .primary()
                    .icon(design_icon("play", 15., SURFACE))
                    .disabled(upgrade_disabled)
                    .on_click(cx.listener(|this, _, _, cx| this.prompt_upgrade(cx))),
            );
        let mut facts = vec![format!("当前版本 v{current}")];
        if let Some(release) = &updater.release {
            let date = release.published_at.get(..10).unwrap_or_default();
            facts.push(format!(
                "新版本 v{}{}，安装包 {}",
                release.version,
                if date.is_empty() {
                    String::new()
                } else {
                    format!("（{date} 发布）")
                },
                megabytes(release.package.size)
            ));
        }
        // 有新版本却点不了「升级」时，在这里说明原因。
        let status = if updater.preparing {
            Some("正在读取 PowerShell 执行策略……".to_owned())
        } else {
            updater
                .release
                .as_ref()
                .and(blocker)
                .filter(|_| !updater.busy())
                .map(str::to_owned)
        };
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(badge(label, color, background))
                            .when_some(checked, |body, checked| {
                                body.child(div().text_sm().text_color(rgb(MUTED)).child(checked))
                            }),
                    )
                    .child(buttons),
            )
            .children(facts.into_iter().map(|fact| div().text_sm().text_color(rgb(INK)).child(fact)))
            .when_some(updater.downloading, |body, (done, total)| {
                let fraction = if total == 0 { 0. } else { done as f32 / total as f32 };
                body.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            div()
                                .h(px(8.))
                                .w_full()
                                .bg(rgb(SURFACE_SOFT))
                                .rounded_full()
                                .child(
                                    div()
                                        .h(px(8.))
                                        .w(relative(fraction.clamp(0., 1.)))
                                        .bg(rgb(ACCENT))
                                        .rounded_full(),
                                ),
                        )
                        .child(div().text_sm().text_color(rgb(MUTED)).child(format!(
                            "已下载 {} / {}",
                            megabytes(done),
                            megabytes(total)
                        ))),
                )
            })
            .when_some(status, |body, status| {
                body.child(div().text_sm().text_color(rgb(MUTED)).child(status))
            })
            .when_some(updater.error.clone(), |body, error| {
                body.child(div().text_sm().text_color(rgb(RUST)).child(error))
            })
            .child(div().text_sm().text_color(rgb(MUTED)).child(
                "升级会下载安装包、核对 SHA-256，然后关闭窗口、运行新包里的安装器，装好后自动重新打开；只在所有环境都没有接管时可用。安装包没有签名：核对只能发现下载损坏，证明不了发布者是谁。",
            ))
    }

    /// 底部状态栏版本号旁边的「有新版本」：点了去设置页。
    pub(crate) fn update_chip(&self, cx: &Context<Self>) -> Option<AnyElement> {
        let release = self.updater.release.as_ref()?;
        let label = format!("有新版本 v{}", release.version);
        Some(
            Button::new("status-update")
                .label(label.clone())
                .ghost()
                .compact()
                .tooltip(format!("{label}：到「设置 › 关于」升级"))
                .on_click(cx.listener(|this, _, _, cx| {
                    this.page = super::model::Page::Settings;
                    cx.notify();
                }))
                .into_any_element(),
        )
    }
}

/// 现在不能升级的原因：后台状态没确认、任何一个环境有接管或待恢复、有操作在进行。
/// `sessions` 是后台每个环境一项的会话状态。
fn upgrade_blocker(status_valid: bool, sessions: &[Value], locked: bool) -> Option<&'static str> {
    let owned = |session: &Value| {
        session["phase"].as_str() != Some("idle") || !session["active_target"].is_null()
    };
    if !status_valid {
        Some("后台状态未确认，暂时不能升级；请先点底部状态栏的后台图标重新连接。")
    } else if sessions.iter().any(owned) {
        Some(
            "有环境在接管中或需要恢复，不能升级，安装器会拒绝。请先停止全部接管、恢复直连，再升级。",
        )
    } else if locked {
        Some("有操作正在进行，等它结束后再升级。")
    } else {
        None
    }
}

fn describe(error: &UpdateError) -> String {
    match error {
        UpdateError::Network(detail) => format!("连不上 GitHub（{detail}）。"),
        UpdateError::RateLimited => {
            "GitHub 暂时限制了这个出口 IP 的查询（未登录每小时 60 次），稍后再试。".into()
        }
        UpdateError::Response(detail) => format!("GitHub 返回的内容不对（{detail}）。"),
        UpdateError::Checksum => {
            "下载的安装包和发布页公布的 SHA-256 对不上，已删除。可能是下载损坏或被改动，稍后重试。"
                .into()
        }
        UpdateError::Storage(detail) => format!("安装包读写失败（{detail}）。"),
    }
}

/// 允许运行本机未签名脚本的执行策略。下载由本程序自己写盘，没有「来自网络」标记，
/// 所以 RemoteSigned 也放行。
fn policy_allows(policy: &str) -> bool {
    ["RemoteSigned", "Unrestricted", "Bypass"]
        .iter()
        .any(|allowed| policy.trim().eq_ignore_ascii_case(allowed))
}

fn megabytes(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1024. / 1024.)
}

/// 结果框的标题和内容；内容每一项是一段文字和它是否用等宽字体（命令、输出）。
fn outcome_text(outcome: &Outcome, current: &str) -> (String, Vec<(String, bool)>) {
    let quote = |text: &str| format!("'{}'", text.replace('\'', "''"));
    let installer = Path::new(&outcome.package).join("install.ps1");
    let installer = quote(&installer.display().to_string());
    let target = quote(&outcome.install_dir);
    let mut lines = Vec::new();
    let title;
    if outcome.ok {
        title = "升级结果和当前版本不一致".to_owned();
        lines.push((
            format!(
                "安装器报告已装好 v{}，但现在运行的是 v{current}。请到安装目录核对 wsl-proxy-desktop.exe 的版本。",
                outcome.version
            ),
            false,
        ));
    } else if outcome.stage == "interrupted" {
        title = "升级没有完成：文件替换中断".to_owned();
        lines.push((
            format!(
                "升级到 v{} 时文件替换中途中断，安装器保留了事务记录。请先关闭本程序，不要做别的操作，在 PowerShell 里运行下面的命令恢复：",
                outcome.version
            ),
            false,
        ));
        lines.push((format!("& {installer} -InstallDir {target} -Recover"), true));
    } else {
        title = "升级没有完成".to_owned();
        let reason = if outcome.stage == "refused" {
            "安装器拒绝了这次升级，程序文件没有改动。"
        } else {
            "升级在运行安装器之前就停下了，程序文件没有改动。"
        };
        lines.push((
            format!("{reason}现在运行的是 v{current}。原因见下面的输出。"),
            false,
        ));
        if Path::new(&outcome.package).join("install.ps1").is_file() {
            lines.push((
                "处理好之后可以在「设置 › 关于」重新升级，或关闭本程序后在 PowerShell 里手动运行："
                    .into(),
                false,
            ));
            lines.push((format!("& {installer} -InstallDir {target}"), true));
        }
    }
    let output: Vec<&str> = outcome
        .output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let tail = &output[output.len().saturating_sub(OUTPUT_LINES)..];
    if !tail.is_empty() {
        lines.push((tail.join("\n"), true));
    }
    (title, lines)
}

fn load_auto() -> bool {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(PREFERENCES_KEY)
        .and_then(|key| key.get_value::<u32, _>(AUTO_CHECK_VALUE))
        .map_or(true, |value| value != 0)
}

fn persist_auto(enabled: bool) -> Result<(), String> {
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(PREFERENCES_KEY)
        .map_err(|error| error.to_string())?;
    key.set_value(AUTO_CHECK_VALUE, &u32::from(enabled))
        .map_err(|error| error.to_string())
}

/// `%LocalAppData%\WSLProxyLab\updates`：下载的安装包、解压出的新包和升级结果。
fn updates_dir() -> Result<PathBuf, String> {
    Ok(wsl_proxyctl::paths::state_dir()?.join("updates"))
}

/// 读出并删掉上一次升级的结果；没有或读不懂时返回 `None`。
fn take_outcome() -> Option<Outcome> {
    let path = updates_dir().ok()?.join(RESULT_NAME);
    let text = fs::read_to_string(&path).ok()?;
    let _ = fs::remove_file(&path);
    Outcome::parse(&text)
}

/// 当前程序是安装器装的副本时返回安装目录：EXE 旁边有安装记录、记录的目录就是这里，
/// 且没有没完成的安装事务。直接解压运行或自己编译的副本只提醒、不一键升级。
fn installed_dir() -> Result<PathBuf, String> {
    let directory = wsl_proxyctl::paths::data_dir()?;
    let marker = fs::read_to_string(directory.join(MARKER_NAME)).map_err(|_| {
        "当前程序不是用安装器装的（旁边没有安装记录），不能一键升级。请从发布页下载新包，按 README「安装」运行 install.ps1。".to_owned()
    })?;
    let marker: Value = serde_json::from_str(marker.trim_start_matches('\u{feff}'))
        .map_err(|_| "安装记录读不懂，不能一键升级，请从发布页下载新包手动升级。".to_owned())?;
    let recorded = marker["install_dir"].as_str().unwrap_or_default();
    if marker["product"] != "wsl-proxy" || !same_path(Path::new(recorded), &directory) {
        return Err(format!(
            "安装记录里的目录（{recorded}）不是当前程序所在的目录（{}），不能一键升级，请从发布页下载新包手动升级。",
            directory.display()
        ));
    }
    let transaction = PathBuf::from(format!("{recorded}.wsl-proxy-transaction.json"));
    if transaction.exists() {
        return Err(format!(
            "上一次安装没有完成（有事务记录 {}），先按 README「升级与卸载」用 -Recover 恢复，再升级。",
            transaction.display()
        ));
    }
    Ok(PathBuf::from(recorded))
}

fn same_path(left: &Path, right: &Path) -> bool {
    let normal = |path: &Path| {
        path.display()
            .to_string()
            .trim_end_matches(['\\', '/'])
            .to_lowercase()
    };
    normal(left) == normal(right)
}

/// 一个目录是不是另一个本身或在它里面（不区分大小写）。
fn overlaps(left: &Path, right: &Path) -> bool {
    let normal = |path: &Path| {
        let mut text = path.display().to_string().replace('/', "\\").to_lowercase();
        if !text.ends_with('\\') {
            text.push('\\');
        }
        text
    };
    let (left, right) = (normal(left), normal(right));
    left.starts_with(&right) || right.starts_with(&left)
}

/// 系统目录里的 Windows PowerShell 5.1；不靠 PATH，免得找到别的同名程序。
fn powershell() -> Result<PathBuf, String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt as _;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buffer = vec![0u16; 260];
    loop {
        // SAFETY: the buffer is writable for the length passed.
        let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 {
            return Err(format!(
                "读不到系统目录：{}",
                std::io::Error::last_os_error()
            ));
        }
        if (length as usize) < buffer.len() {
            let system = PathBuf::from(OsString::from_wide(&buffer[..length as usize]));
            return Ok(system.join("WindowsPowerShell\\v1.0\\powershell.exe"));
        }
        if length > 32768 {
            return Err("系统目录的长度不对".into());
        }
        buffer.resize(length as usize + 1, 0);
    }
}

/// 当前生效的 PowerShell 执行策略（含组策略），例如 `RemoteSigned`。
fn execution_policy() -> Result<String, String> {
    let mut child = Command::new(powershell()?)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[string](Get-ExecutionPolicy)",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("启动 PowerShell 失败：{error}"))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(status)) => return Err(format!("PowerShell 退出码 {status}")),
            Ok(None) if started.elapsed() >= POLICY_TIMEOUT => {
                let _ = child.kill();
                return Err("PowerShell 30 秒没有回答".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => return Err(error.to_string()),
        }
    }
    let mut output = String::new();
    child
        .stdout
        .take()
        .ok_or("没有拿到 PowerShell 的输出")?
        .read_to_string(&mut output)
        .map_err(|error| error.to_string())?;
    let policy = output.trim();
    if policy.is_empty() || !policy.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(format!("看不懂 PowerShell 的回答：{policy}"));
    }
    Ok(policy.to_owned())
}

/// 交给安装器助手的全部参数。
struct Handoff<'a> {
    zip: &'a Path,
    sha256: &'a str,
    /// 新包解压到这里，必须在安装目录以外。
    package: &'a Path,
    /// 这个版本的下载目录；装好后整个删掉。
    staging: &'a Path,
    install_dir: &'a Path,
    result: &'a Path,
    powershell: &'a Path,
    desktop_pid: u32,
    version: Version,
    from: Version,
}

/// 安装器助手：等桌面退出，再核对一次安装包，解压，运行新包的 install.ps1，写下结果，
/// 然后重新打开桌面。文件替换中断时不重新打开（安装器要求先 `-Recover`），改为弹窗说明。
fn helper_script(handoff: &Handoff<'_>) -> String {
    let quote = |path: &Path| format!("'{}'", path.display().to_string().replace('\'', "''"));
    format!(
        r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$zip = {zip}
$sha = '{sha}'
$package = {package}
$staging = {staging}
$target = {target}
$resultPath = {result}
$shell = {shell}
$desktopPid = {pid}
$version = '{version}'
$from = '{from}'
function Save-Result([bool] $ok, [string] $stage, [string] $output) {{
    $value = [ordered]@{{ schema_version = 1; ok = $ok; stage = $stage; version = $version; from = $from; install_dir = $target; package = $package; output = $output; finished_at = [DateTime]::UtcNow.ToString('o') }}
    $temporary = $resultPath + '.tmp'
    [IO.File]::WriteAllText($temporary, (ConvertTo-Json -InputObject $value -Compress), (New-Object Text.UTF8Encoding $false))
    Move-Item -LiteralPath $temporary -Destination $resultPath -Force
}}
$relaunch = $true
try {{
    $process = Get-Process -Id $desktopPid -ErrorAction SilentlyContinue
    if ($null -ne $process -and -not $process.WaitForExit(120000)) {{ throw 'The desktop window did not close within 2 minutes. Nothing was installed.' }}
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant() -cne $sha) {{ throw 'The downloaded package changed after it was checked. Nothing was installed.' }}
    if (Test-Path -LiteralPath $package) {{ Remove-Item -LiteralPath $package -Recurse -Force }}
    Expand-Archive -LiteralPath $zip -DestinationPath $package
    $manifest = Get-Content -LiteralPath (Join-Path $package 'release.json') -Raw | ConvertFrom-Json
    if ($manifest.version -cne $version) {{ throw "The package is version $($manifest.version), not $version. Nothing was installed." }}
    $ErrorActionPreference = 'Continue'
    $lines = @(& $shell -NoProfile -NonInteractive -File (Join-Path $package 'install.ps1') -InstallDir $target 2>&1 | ForEach-Object {{ "$_" }})
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    $output = ($lines | Select-Object -Last 40) -join "`n"
    if ($code -eq 0) {{
        Save-Result $true 'installed' $output
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }} elseif (Test-Path -LiteralPath ($target + '.wsl-proxy-transaction.json')) {{
        $relaunch = $false
        Save-Result $false 'interrupted' $output
    }} else {{
        Save-Result $false 'refused' $output
    }}
}} catch {{
    $message = "$($_.Exception.Message)"
    try {{ Save-Result $false 'failed' $message }} catch {{ }}
}}
if ($relaunch) {{
    $desktop = Join-Path $target 'wsl-proxy-desktop.exe'
    if (Test-Path -LiteralPath $desktop) {{ Start-Process -FilePath $desktop -WorkingDirectory $target }}
}} else {{
    $recover = "& '" + (Join-Path $package 'install.ps1').Replace("'", "''") + "' -InstallDir '" + $target.Replace("'", "''") + "' -Recover"
    Add-Type -AssemblyName System.Windows.Forms
    [void][System.Windows.Forms.MessageBox]::Show("升级到 $version 时文件替换中途中断，安装器保留了事务记录。请先不要打开 WSL Proxy，在 PowerShell 里运行下面的命令恢复：`n`n$recover", 'WSL Proxy 升级没有完成', 'OK', 'Warning')
}}
"#,
        zip = quote(handoff.zip),
        sha = handoff.sha256,
        package = quote(handoff.package),
        staging = quote(handoff.staging),
        target = quote(handoff.install_dir),
        result = quote(handoff.result),
        shell = quote(handoff.powershell),
        pid = handoff.desktop_pid,
        version = handoff.version,
        from = handoff.from,
    )
}

/// 拉起安装器助手。它要活过桌面退出，所以尽量脱离桌面所在的作业；工作目录放在
/// 安装目录以外，免得挡住安装器移动安装目录。
fn spawn_helper(powershell: &Path, script: &str, directory: &Path) -> Result<(), String> {
    fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    let encoded = encode_command(script);
    let mut command = Command::new(powershell);
    command
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB);
    // 不允许脱离的作业会拒绝这个标志；那就留在作业里。
    match command.spawn() {
        Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => command
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map(drop)
            .map_err(|error| error.to_string()),
        result => result.map(drop).map_err(|error| error.to_string()),
    }
}

/// `-EncodedCommand` 要的格式：UTF-16LE 再 Base64。
fn encode_command(script: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = chunk.iter().enumerate().fold(0u32, |value, (index, byte)| {
            value | (u32::from(*byte) << (16 - 8 * index))
        });
        for index in 0..4 {
            if index <= chunk.len() {
                encoded.push(char::from(
                    TABLE[((value >> (18 - 6 * index)) & 63) as usize],
                ));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

#[cfg(test)]
mod tests;
