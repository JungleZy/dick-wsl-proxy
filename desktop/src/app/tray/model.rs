//! 托盘显示什么、菜单有哪些项。界面线程按后台状态算出 [`Snapshot`]，托盘线程只照着画；
//! 这里只有数据和规则，不碰 Win32。

/// 托盘图标的样子，对应首页保护状态的几种情况。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Look {
    /// 后台没连上，或者状态没确认。接管可能仍在生效，所以不能画成「未接管」。
    #[default]
    Unknown,
    Idle,
    Managed,
    Scoped,
    Recovery,
}

impl Look {
    pub(crate) const ALL: [Self; 5] = [
        Self::Unknown,
        Self::Idle,
        Self::Managed,
        Self::Scoped,
        Self::Recovery,
    ];

    /// `phase` 是后台状态里的阶段；状态无效时一律算未确认，和首页一致。
    pub(crate) fn from_status(status_valid: bool, phase: &str) -> Self {
        if !status_valid {
            return Self::Unknown;
        }
        match phase {
            "idle" => Self::Idle,
            "forwarding_managed" => Self::Managed,
            "forwarding_scoped" => Self::Scoped,
            "recovery_required" => Self::Recovery,
            _ => Self::Unknown,
        }
    }

    /// 只有接管中才动：动效只表达「正在接管」这一件事。
    pub(crate) fn animated(self) -> bool {
        self == Self::Managed
    }

    /// 和主窗口状态栏、首页保护状态的用词一致。
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Unknown => "后台状态未确认",
            Self::Idle => "未接管",
            Self::Managed => "接管中",
            Self::Scoped => "诊断转发中",
            Self::Recovery => "需要恢复",
        }
    }
}

/// 菜单里的主操作，和首页的主按钮跟着同一套状态走。启动接管在各环境的页面上
/// （决策 40），托盘只负责停止全部接管和带用户去对应的页面。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Primary {
    #[default]
    Reconnect,
    /// 空闲：去环境页选一个环境启动接管。
    Environments,
    /// 需要恢复：去那个环境的页面恢复或放弃。
    Recover,
    Stop,
    /// 需要恢复、但那个发行版已经不在 WSL 里：没有页面可去，直接放弃记录。
    Abandon,
}

impl Primary {
    pub(crate) fn command(self) -> Command {
        match self {
            Self::Reconnect => Command::Reconnect,
            Self::Environments => Command::Environments,
            Self::Recover => Command::Recover,
            Self::Stop => Command::Stop,
            Self::Abandon => Command::Abandon,
        }
    }

    /// 只是带用户去某一页，不发请求，界面忙的时候也能点。
    pub(crate) fn navigates(self) -> bool {
        matches!(self, Self::Environments | Self::Recover)
    }
}

/// 界面线程交给托盘线程的全部信息。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) look: Look,
    /// 正在接管或需要恢复的发行版；空闲和状态未确认时为空。
    pub(crate) target: Option<String>,
    pub(crate) primary: Primary,
    /// 界面有操作在进行或在等确认时的说明，例如「正在启动接管…」。
    /// 这时会发请求的菜单项置灰：点了界面也会拒绝。
    pub(crate) busy: Option<String>,
    pub(crate) autostart: bool,
    /// 屏幕顶部状态岛是否打开。
    pub(crate) island: bool,
}

impl Snapshot {
    /// 界面还没发布过状态时的样子。
    pub(crate) const INITIAL: Self = Self {
        look: Look::Unknown,
        target: None,
        primary: Primary::Reconnect,
        busy: None,
        autostart: false,
        island: true,
    };

    /// 一行状态，例如「接管中 · Ubuntu-24.04」。
    pub(crate) fn status_line(&self) -> String {
        match &self.target {
            Some(target) => format!("{} · {target}", self.look.label()),
            None => self.look.label().to_owned(),
        }
    }

    /// 悬停提示：第一行是程序名，下面是状态和正在进行的操作。
    pub(crate) fn tooltip(&self) -> String {
        let mut tip = format!("WSL Proxy\n{}", self.status_line());
        if let Some(busy) = &self.busy {
            tip.push('\n');
            tip.push_str(busy);
        }
        tip
    }
}

/// 菜单命令。编号从 1 开始，`TrackPopupMenu` 用 0 表示没有选任何一项。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Open,
    Reconnect,
    Environments,
    Recover,
    Stop,
    Abandon,
    Probe,
    Connections,
    Logs,
    Autostart,
    Island,
    Exit,
}

impl Command {
    const ALL: [Self; 12] = [
        Self::Open,
        Self::Reconnect,
        Self::Environments,
        Self::Recover,
        Self::Stop,
        Self::Abandon,
        Self::Probe,
        Self::Connections,
        Self::Logs,
        Self::Autostart,
        Self::Island,
        Self::Exit,
    ];

    pub(crate) fn id(self) -> usize {
        Self::ALL
            .iter()
            .position(|command| *command == self)
            .map_or(0, |index| index + 1)
    }

    pub(crate) fn from_id(id: usize) -> Option<Self> {
        id.checked_sub(1)
            .and_then(|index| Self::ALL.get(index))
            .copied()
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Open => "打开 WSL Proxy",
            Self::Reconnect => "重新连接后台",
            Self::Environments => "打开环境页",
            Self::Recover => "去恢复接管",
            Self::Stop => "停止全部接管",
            Self::Abandon => "放弃本次记录",
            Self::Probe => "检测公网出口",
            Self::Connections => "查看连接记录",
            Self::Logs => "查看运行日志",
            Self::Autostart => "开机自动启动",
            Self::Island => "显示顶部状态岛",
            Self::Exit => "退出",
        }
    }
}

/// 菜单的一行。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    /// 只显示、不能点的说明文字。
    Text(String),
    Separator,
    Item {
        command: Command,
        label: &'static str,
        enabled: bool,
        checked: bool,
        /// 加粗显示，等同于单击、双击图标。
        default: bool,
    },
}

fn item(command: Command, enabled: bool) -> Entry {
    Entry::Item {
        command,
        label: command.label(),
        enabled,
        checked: false,
        default: false,
    }
}

/// 右键菜单。各项位置固定，只换主操作的文字和置灰状态，免得用户每次都要重新找。
pub(crate) fn menu(snapshot: &Snapshot) -> Vec<Entry> {
    let idle_ui = snapshot.busy.is_none();
    let mut entries = vec![Entry::Text(snapshot.status_line())];
    entries.extend(snapshot.busy.clone().map(Entry::Text));
    entries.extend([
        Entry::Separator,
        Entry::Item {
            command: Command::Open,
            label: Command::Open.label(),
            enabled: true,
            checked: false,
            default: true,
        },
        Entry::Separator,
        item(
            snapshot.primary.command(),
            idle_ui || snapshot.primary.navigates(),
        ),
        item(Command::Probe, idle_ui && snapshot.look == Look::Managed),
        Entry::Separator,
        item(Command::Connections, true),
        item(Command::Logs, true),
        Entry::Separator,
        Entry::Item {
            command: Command::Autostart,
            label: Command::Autostart.label(),
            enabled: true,
            checked: snapshot.autostart,
            default: false,
        },
        Entry::Item {
            command: Command::Island,
            label: Command::Island.label(),
            enabled: true,
            checked: snapshot.island,
            default: false,
        },
        Entry::Separator,
        // 忙的时候也能点：界面会说明为什么现在不能退出，比置灰更清楚。
        item(Command::Exit, true),
    ]);
    entries
}

/// 按 UTF-16 写进 `buffer`，放不下就截断，最后一格一定是 NUL。
pub(crate) fn fill_wide(buffer: &mut [u16], text: &str) {
    let Some(last) = buffer.len().checked_sub(1) else {
        return;
    };
    let mut length = 0;
    for unit in text.encode_utf16().take(last) {
        buffer[length] = unit;
        length += 1;
    }
    // 不把代理对劈成两半：截断落在高位代理上就把它也去掉。
    if length == last && length > 0 && (0xD800..0xDC00).contains(&buffer[length - 1]) {
        length -= 1;
    }
    buffer[length..].fill(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(look: Look, primary: Primary) -> Snapshot {
        Snapshot {
            look,
            primary,
            ..Snapshot::INITIAL
        }
    }

    fn enabled(entries: &[Entry], wanted: Command) -> Option<bool> {
        entries.iter().find_map(|entry| match entry {
            Entry::Item {
                command, enabled, ..
            } if *command == wanted => Some(*enabled),
            _ => None,
        })
    }

    #[test]
    fn only_a_managed_takeover_animates() {
        for look in Look::ALL {
            assert_eq!(look.animated(), look == Look::Managed, "{look:?}");
        }
    }

    #[test]
    fn an_unconfirmed_status_never_looks_idle() {
        assert_eq!(Look::from_status(false, "idle"), Look::Unknown);
        assert_eq!(
            Look::from_status(false, "forwarding_managed"),
            Look::Unknown
        );
        assert_eq!(Look::from_status(true, "something_new"), Look::Unknown);
        assert_eq!(Look::from_status(true, "idle"), Look::Idle);
        assert_eq!(Look::from_status(true, "forwarding_managed"), Look::Managed);
        assert_eq!(Look::from_status(true, "forwarding_scoped"), Look::Scoped);
        assert_eq!(Look::from_status(true, "recovery_required"), Look::Recovery);
    }

    #[test]
    fn command_ids_round_trip_and_zero_is_no_choice() {
        assert_eq!(Command::from_id(0), None);
        for command in Command::ALL {
            assert_ne!(command.id(), 0);
            assert_eq!(Command::from_id(command.id()), Some(command));
        }
        assert_eq!(Command::from_id(Command::ALL.len() + 1), None);
    }

    #[test]
    fn the_menu_offers_exactly_one_primary_action() {
        let primaries = [
            Command::Reconnect,
            Command::Environments,
            Command::Recover,
            Command::Stop,
            Command::Abandon,
        ];
        for (primary, expected) in [
            (Primary::Reconnect, Command::Reconnect),
            (Primary::Environments, Command::Environments),
            (Primary::Recover, Command::Recover),
            (Primary::Stop, Command::Stop),
            (Primary::Abandon, Command::Abandon),
        ] {
            let entries = menu(&snapshot(Look::Idle, primary));
            let offered: Vec<_> = primaries
                .iter()
                .filter(|command| enabled(&entries, **command).is_some())
                .collect();
            assert_eq!(offered, [&expected]);
        }
    }

    #[test]
    fn the_exit_probe_is_only_offered_during_a_managed_takeover() {
        for look in Look::ALL {
            let entries = menu(&snapshot(look, Primary::Stop));
            assert_eq!(
                enabled(&entries, Command::Probe),
                Some(look == Look::Managed),
                "{look:?}"
            );
        }
    }

    #[test]
    fn a_busy_interface_greys_out_requests_but_not_navigation_or_exit() {
        let busy = |primary| Snapshot {
            busy: Some("正在启动接管…".into()),
            ..snapshot(Look::Managed, primary)
        };
        let entries = menu(&busy(Primary::Stop));
        assert_eq!(enabled(&entries, Command::Stop), Some(false));
        assert_eq!(enabled(&entries, Command::Probe), Some(false));
        assert_eq!(enabled(&entries, Command::Open), Some(true));
        assert_eq!(enabled(&entries, Command::Logs), Some(true));
        assert_eq!(enabled(&entries, Command::Exit), Some(true));
        assert_eq!(entries[1], Entry::Text("正在启动接管…".into()));
        for primary in [Primary::Environments, Primary::Recover] {
            let entries = menu(&busy(primary));
            assert_eq!(enabled(&entries, primary.command()), Some(true));
        }
    }

    #[test]
    fn the_autostart_and_island_items_show_the_current_settings() {
        let checked = |snapshot: Snapshot, wanted: Command| {
            menu(&snapshot).into_iter().find_map(|entry| match entry {
                Entry::Item {
                    command, checked, ..
                } if command == wanted => Some(checked),
                _ => None,
            })
        };
        for on in [true, false] {
            let autostart = Snapshot {
                autostart: on,
                ..Snapshot::INITIAL
            };
            assert_eq!(checked(autostart, Command::Autostart), Some(on));
            let island = Snapshot {
                island: on,
                ..Snapshot::INITIAL
            };
            assert_eq!(checked(island, Command::Island), Some(on));
        }
    }

    #[test]
    fn the_tooltip_names_the_state_target_and_running_operation() {
        let mut snapshot = Snapshot {
            target: Some("Test-Target".into()),
            ..snapshot(Look::Managed, Primary::Stop)
        };
        assert_eq!(snapshot.tooltip(), "WSL Proxy\n接管中 · Test-Target");
        snapshot.busy = Some("正在检测出口…".into());
        assert_eq!(
            snapshot.tooltip(),
            "WSL Proxy\n接管中 · Test-Target\n正在检测出口…"
        );
        assert_eq!(Snapshot::INITIAL.tooltip(), "WSL Proxy\n后台状态未确认");
    }

    #[test]
    fn wide_text_is_cut_to_fit_and_always_ends_with_nul() {
        let mut buffer = [0xFFFF_u16; 6];
        fill_wide(&mut buffer, "WSL");
        assert_eq!(buffer, [87, 83, 76, 0, 0, 0]);
        fill_wide(&mut buffer, "WSL Proxy");
        assert_eq!(buffer, [87, 83, 76, 32, 80, 0]);
        // 「😀」是一对代理；第二半放不下时整个字符都不写。
        fill_wide(&mut buffer, "WSL 😀");
        assert_eq!(buffer, [87, 83, 76, 32, 0, 0]);
        fill_wide(&mut [], "WSL");
    }
}
