//! 顶部状态岛显示什么、什么时候展开。这里只有数据和规则，不碰窗口；
//! 状态和操作都来自托盘的 [`Snapshot`]，岛不另做状态判断。

use std::time::{Duration, Instant};

use crate::app::tray::{Command, Look, Snapshot};

/// 收起时的药丸大小（逻辑像素，不含顶部两侧的肩）。中间留空，内容只放左右两端，
/// 和 Apple 灵动岛一样。
pub(crate) const PILL: (f32, f32) = (184., 32.);
/// 展开时的卡片大小（逻辑像素，不含肩）。按内容排紧：16 边距、两行标题区、36 高按钮。
pub(crate) const CARD: (f32, f32) = (356., 132.);
/// 接管中展开时多出一行出口和一排三格环境信息，卡片更高。
pub(crate) const CARD_DETAILED: (f32, f32) = (356., 214.);
/// 展开时底部两个角的圆角。收起时等于高度的一半。
pub(crate) const CARD_RADIUS: f32 = 30.;
/// 岛贴着屏幕顶边，左右上角各有一段向内凹的圆弧（「肩」），和屏幕边缘平滑接上。
/// 这是圆弧的半径：肩在顶边处向外伸出这么宽，往下这么高收拢到竖直侧边。
pub(crate) const FILLET: f32 = 12.;
/// 窗口始终是这么大：卡片加两侧的肩，再留一圈余量，形变动画冲过头时不被裁掉。
/// 能点到的范围由窗口区域裁成当前形状，其余部分不挡下面窗口的点击。
pub(crate) const WINDOW: (f32, f32) = (CARD.0 + 2. * FILLET + 32., CARD_DETAILED.1 + 16.);

/// 在按钮上按住多久算长按、开始拖动；在岛的其他地方按下后一移动就开始拖。
pub(crate) const LONG_PRESS: Duration = Duration::from_millis(400);
/// 按下后光标移动超过这么多（逻辑像素）算开始拖；在按钮上则算放弃这次按下。
pub(crate) const PRESS_SLOP: f32 = 6.;

/// 岛只能沿屏幕顶边左右拖动，位置记成窗口中心在主显示器宽度上的比例，0.5 是正中。
/// 换分辨率或缩放后按比例摆回，不会跑出屏幕。
pub(crate) fn window_left(
    screen_left: i32,
    screen_width: i32,
    window_width: i32,
    ratio: f32,
) -> i32 {
    let center = screen_left as f32 + ratio.clamp(0., 1.) * screen_width as f32;
    let left = (center - window_width as f32 / 2.).round() as i32;
    left.clamp(
        screen_left,
        screen_left + (screen_width - window_width).max(0),
    )
}

/// [`window_left`] 的反过来：窗口左边在哪，对应的比例是多少。
pub(crate) fn ratio_of(
    screen_left: i32,
    screen_width: i32,
    window_left: i32,
    window_width: i32,
) -> f32 {
    if screen_width <= 0 {
        return 0.5;
    }
    let center = (window_left - screen_left) as f32 + window_width as f32 / 2.;
    (center / screen_width as f32).clamp(0., 1.)
}

/// 接管中的环境信息，由主界面从后台状态里摘出来。
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Details {
    /// 最近一次检测到的公网出口 IP 和国家；没检测过为空。
    pub(crate) exit_ip: Option<String>,
    pub(crate) exit_country: Option<String>,
    /// 出口和住宅地址是否一致；没比对为空。
    pub(crate) exit_matches: Option<bool>,
    /// 系统 DNS 是否由接管接手，以及启动时测到的延迟。
    pub(crate) dns_managed: bool,
    pub(crate) dns_latency_ms: Option<f64>,
    /// UDP 走向，用主界面的说法：「经代理链」「已阻断」「未确认」。
    pub(crate) udp: &'static str,
    /// 正在转发的 TCP 连接数。
    pub(crate) active_tcp: Option<u64>,
}

/// 卡片上的一格信息：小字标签、数值和颜色档。
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Fact {
    pub(crate) label: &'static str,
    pub(crate) value: String,
    pub(crate) tone: Tone,
}

/// 公网出口那一行：IP、国家和核对结果。不一致是要留意的情况，用待处理色。
pub(crate) fn exit_fact(details: &Details) -> Fact {
    let Some(ip) = &details.exit_ip else {
        return Fact {
            label: "公网出口",
            value: "未检测".to_owned(),
            tone: Tone::Off,
        };
    };
    let mut value = ip.clone();
    if let Some(country) = &details.exit_country {
        value.push_str(" · ");
        value.push_str(country);
    }
    let (verdict, tone) = match details.exit_matches {
        Some(true) => ("与住宅地址一致", Tone::Ok),
        Some(false) => ("与住宅地址不一致", Tone::Warn),
        None => ("未比对", Tone::Off),
    };
    value.push_str(" · ");
    value.push_str(verdict);
    Fact {
        label: "公网出口",
        value,
        tone,
    }
}

/// 出口下面的三格：DNS、UDP、连接数。
pub(crate) fn cells(details: &Details) -> [Fact; 3] {
    let dns = if details.dns_managed {
        Fact {
            label: "DNS",
            value: details.dns_latency_ms.map_or_else(
                || "已接管".to_owned(),
                |ms| format!("{} ms", ms.round() as u64),
            ),
            tone: Tone::Ok,
        }
    } else {
        Fact {
            label: "DNS",
            value: "未接管".to_owned(),
            tone: Tone::Warn,
        }
    };
    let udp = Fact {
        label: "UDP",
        value: details.udp.to_owned(),
        tone: match details.udp {
            "经代理链" => Tone::Ok,
            "已阻断" => Tone::Warn,
            _ => Tone::Off,
        },
    };
    let connections = Fact {
        label: "连接",
        value: details
            .active_tcp
            .map_or_else(|| "—".to_owned(), |count| format!("{count} 条")),
        tone: Tone::Off,
    };
    [dns, udp, connections]
}

/// 展开时的卡片大小：有环境信息就用高的那种。
pub(crate) fn card_size(details: Option<&Details>) -> (f32, f32) {
    if details.is_some() {
        CARD_DETAILED
    } else {
        CARD
    }
}

/// 普通变化和提醒自动展开多久。
const NOTICE: Duration = Duration::from_secs(5);
/// 需要用户留意的变化（需要恢复、状态未确认、警告类提醒）展开多久。
const WARNING_NOTICE: Duration = Duration::from_secs(10);
/// 鼠标移开后等多久收回：一晃而过不会让卡片闪一下就没了。
const LEAVE_GRACE: Duration = Duration::from_millis(400);

/// 状态圆点和主体文字的颜色档。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tone {
    Ok,
    Warn,
    Error,
    Off,
}

impl Tone {
    pub(crate) fn of(snapshot: &Snapshot) -> Self {
        if snapshot.busy.is_some() {
            return Self::Warn;
        }
        match snapshot.look {
            Look::Managed => Self::Ok,
            Look::Scoped | Look::Unknown => Self::Warn,
            Look::Recovery => Self::Error,
            Look::Idle => Self::Off,
        }
    }
}

/// 卡片上的一颗按钮。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Action {
    pub(crate) command: Command,
    pub(crate) label: &'static str,
    pub(crate) enabled: bool,
    /// 主操作：用强调色画，其余是灰色胶囊。
    pub(crate) primary: bool,
}

/// 岛上按钮的文字。卡片里最多三颗等宽按钮，托盘菜单的长说法放不下，换成短的。
fn short_label(command: Command) -> &'static str {
    match command {
        Command::Stop => "停止接管",
        Command::Abandon => "放弃记录",
        Command::Probe => "检测出口",
        Command::ChooseTarget => "选择目标",
        Command::Reconnect => "重新连接",
        Command::Open => "打开主窗口",
        other => other.label(),
    }
}

/// 卡片按钮，与托盘菜单的启用规则一致：界面忙时只留不发请求的按钮。
pub(crate) fn actions(snapshot: &Snapshot) -> Vec<Action> {
    let idle_ui = snapshot.busy.is_none();
    let primary = snapshot.primary.command();
    let mut actions = vec![Action {
        command: primary,
        label: short_label(primary),
        enabled: idle_ui || snapshot.primary.navigates(),
        primary: true,
    }];
    if snapshot.look == Look::Managed {
        actions.push(Action {
            command: Command::Probe,
            label: short_label(Command::Probe),
            enabled: idle_ui,
            primary: false,
        });
    }
    actions.push(Action {
        command: Command::Open,
        label: short_label(Command::Open),
        enabled: true,
        primary: false,
    });
    actions
}

/// 接管中的实时速率（字节每秒）。
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Rates {
    pub(crate) up: f32,
    pub(crate) down: f32,
}

/// 收起时右端的一小段字：接管中显示下行速率，其余显示状态的简称。
pub(crate) fn trailing(snapshot: &Snapshot, rates: Option<Rates>) -> String {
    if snapshot.busy.is_some() {
        return "处理中".to_owned();
    }
    match snapshot.look {
        Look::Managed => rates.map_or_else(
            || "接管中".to_owned(),
            |r| format!("↓ {}", short_rate(r.down)),
        ),
        Look::Scoped => "诊断中".to_owned(),
        Look::Recovery => "需恢复".to_owned(),
        Look::Unknown => "未连接".to_owned(),
        Look::Idle => "直连".to_owned(),
    }
}

/// 窄地方用的速率：最多四位有效字符，例如 `0 B/s`、`812K/s`、`1.2M/s`。
pub(crate) fn short_rate(bytes_per_second: f32) -> String {
    let value = bytes_per_second.max(0.);
    let (scaled, unit) = if value >= 1024. * 1024. * 1024. {
        (value / (1024. * 1024. * 1024.), "G")
    } else if value >= 1024. * 1024. {
        (value / (1024. * 1024.), "M")
    } else if value >= 1024. {
        (value / 1024., "K")
    } else {
        return format!("{} B/s", value.round() as u32);
    };
    if scaled < 10. {
        format!("{scaled:.1}{unit}/s")
    } else {
        format!("{}{unit}/s", scaled.round() as u32)
    }
}

/// 岛在某一刻的外形（逻辑像素）。
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Shape {
    pub(crate) width: f32,
    pub(crate) height: f32,
    pub(crate) radius: f32,
}

/// `m` 为 0 是药丸，为 1 是卡片；动画回弹时会略超出 0 到 1。
pub(crate) fn shape(m: f32, card: (f32, f32)) -> Shape {
    let lerp = |a: f32, b: f32| a + (b - a) * m;
    let height = lerp(PILL.1, card.1).clamp(PILL.1 * 0.7, WINDOW.1);
    Shape {
        width: lerp(PILL.0, card.0).clamp(PILL.0 * 0.9, WINDOW.0 - 2. * FILLET - 4.),
        height,
        radius: (PILL.1 / 2. + (CARD_RADIUS - PILL.1 / 2.) * m.clamp(0., 1.)).min(height / 2.),
    }
}

/// 刘海轮廓：顶边贴着窗口顶，两肩是向内凹的四分之一圆弧，竖直侧边，底部两个圆角。
/// `left` 是主体左边，`grow` 把轮廓整体向外扩（裁窗口区域时给边缘的抗锯齿留位置）。
/// 点按顺时针排列：右侧自上而下，再左侧自下而上。
pub(crate) fn outline(shape: Shape, left: f32, grow: f32) -> Vec<(f32, f32)> {
    use std::f32::consts::FRAC_PI_2;
    const STEPS: usize = 16;
    let (x0, x1) = (left - grow, left + shape.width + grow);
    let bottom = shape.height + grow;
    let radius = (shape.radius + grow)
        .min(bottom / 2.)
        .min((x1 - x0) / 2.)
        .max(0.);
    let fillet = (FILLET + grow).min(bottom - radius).max(0.);
    // (y, 左 x, 右 x)，自上而下。
    let mut rows = Vec::with_capacity(2 * STEPS + 4);
    for i in 0..=STEPS {
        // 肩：圆心在主体外侧 (x1 + fillet, fillet)，从顶边那一点转到侧边那一点。
        let a = i as f32 / STEPS as f32 * FRAC_PI_2;
        let wing = fillet * (1. - a.sin());
        rows.push((fillet * (1. - a.cos()), x0 - wing, x1 + wing));
    }
    if bottom - radius > fillet {
        rows.push((bottom - radius, x0, x1));
    }
    for i in 1..=STEPS {
        let a = i as f32 / STEPS as f32 * FRAC_PI_2;
        rows.push((
            bottom - radius + radius * a.sin(),
            x0 + radius - radius * a.cos(),
            x1 - radius + radius * a.cos(),
        ));
    }
    rows.iter()
        .map(|&(y, _, right)| (right, y))
        .chain(rows.iter().rev().map(|&(y, l, _)| (l, y)))
        .collect()
}

/// 一段临界阻尼弹簧：平滑减速，正好停在终点，不冲过头、不来回晃。`omega` 越大越快。
#[derive(Clone, Copy, Debug, PartialEq)]
struct Spring {
    omega: f32,
}

/// 展开：约 0.35 秒基本到位。
const EXPAND: Spring = Spring { omega: 17. };
/// 收回：更利落一些。
const COLLAPSE: Spring = Spring { omega: 21. };
/// 弹簧到这个时候已停稳（误差远小于一个像素），之后直接取终点。
const SETTLE: Duration = Duration::from_millis(900);

impl Spring {
    /// 从 0 出发、终点为 1 的阶跃响应，全程单调上升。
    fn at(self, t: f32) -> f32 {
        let wt = self.omega * t;
        1. - (-wt).exp() * (1. + wt)
    }
}

/// 展开程度随时间的变化：按临界阻尼弹簧运动，起步快、收尾慢，停下时没有抖动。
#[derive(Clone, Copy, Debug)]
pub(crate) struct Morph {
    from: f32,
    to: f32,
    start: Option<Instant>,
}

impl Default for Morph {
    fn default() -> Self {
        Self {
            from: 0.,
            to: 0.,
            start: None,
        }
    }
}

impl Morph {
    /// 开始往展开或收起走；已经在往那边走就不重新开始。中途反向时从当前位置出发。
    pub(crate) fn aim(&mut self, expanded: bool, now: Instant) {
        let to = if expanded { 1. } else { 0. };
        if to == self.to {
            return;
        }
        self.from = self.value(now);
        self.to = to;
        self.start = Some(now);
    }

    /// 不要动画（系统设置了减少动态效果）：直接到终点。
    pub(crate) fn jump(&mut self, expanded: bool) {
        self.to = if expanded { 1. } else { 0. };
        self.from = self.to;
        self.start = None;
    }

    pub(crate) fn value(&self, now: Instant) -> f32 {
        let Some(start) = self.start else {
            return self.to;
        };
        let elapsed = now.duration_since(start);
        if elapsed >= SETTLE {
            return self.to;
        }
        let spring = if self.to > self.from {
            EXPAND
        } else {
            COLLAPSE
        };
        self.from + (self.to - self.from) * spring.at(elapsed.as_secs_f32())
    }

    pub(crate) fn settled(&self, now: Instant) -> bool {
        self.start
            .is_none_or(|start| now.duration_since(start) >= SETTLE)
    }
}

/// 卡片主体下面的灰字：提醒优先，其次是进行中的操作，最后是目标发行版。
pub(crate) fn caption(snapshot: &Snapshot, notice: Option<&str>) -> String {
    if let Some(notice) = notice {
        return notice.to_owned();
    }
    if let Some(busy) = &snapshot.busy {
        return busy.clone();
    }
    match (&snapshot.target, snapshot.look) {
        (Some(target), _) => target.clone(),
        (None, Look::Idle) => "流量照常直连".to_owned(),
        (None, _) => "打开主窗口查看详情".to_owned(),
    }
}

struct Notice {
    /// 有文字时卡片显示它；状态变化引起的展开没有文字，显示状态本身。
    message: Option<String>,
    until: Instant,
}

/// 岛的展开状态。岛每次看光标时调用 [`Presence::update`]，提醒到来时调用 [`Presence::notify`]。
#[derive(Default)]
pub(crate) struct Presence {
    /// 上次看到的状态；还没确认过一次后台状态时为空，那时的变化不算。
    last_look: Option<Look>,
    notice: Option<Notice>,
    hovered: bool,
    left_at: Option<Instant>,
}

impl Presence {
    /// 主界面弹出的提醒也在岛上展开显示。
    pub(crate) fn notify(&mut self, message: String, warning: bool, now: Instant) {
        let length = if warning { WARNING_NOTICE } else { NOTICE };
        self.notice = Some(Notice {
            message: Some(message),
            until: now + length,
        });
    }

    /// 正在显示的提醒文字。
    pub(crate) fn notice(&self) -> Option<&str> {
        self.notice
            .as_ref()
            .and_then(|notice| notice.message.as_deref())
    }

    /// 返回这一刻是否展开。`cursor_inside` 是光标是否在岛上。
    pub(crate) fn update(
        &mut self,
        snapshot: &Snapshot,
        cursor_inside: bool,
        now: Instant,
    ) -> bool {
        self.track_look(snapshot.look, now);
        if self
            .notice
            .as_ref()
            .is_some_and(|notice| now >= notice.until)
        {
            self.notice = None;
        }
        if cursor_inside {
            self.hovered = true;
            self.left_at = None;
        } else if self.hovered {
            let left_at = *self.left_at.get_or_insert(now);
            if now.duration_since(left_at) >= LEAVE_GRACE {
                self.hovered = false;
                self.left_at = None;
            }
        }
        self.hovered || self.notice.is_some()
    }

    fn track_look(&mut self, look: Look, now: Instant) {
        let previous = self.last_look;
        // 刚启动时状态从「未确认」变成第一次确认的结果，不算变化。
        if previous.is_none() && look == Look::Unknown {
            return;
        }
        self.last_look = Some(look);
        let Some(previous) = previous else {
            return;
        };
        if previous == look {
            return;
        }
        let length = if matches!(look, Look::Recovery | Look::Unknown) {
            WARNING_NOTICE
        } else {
            NOTICE
        };
        // 已有更晚结束的提醒时不缩短它，只保留它的文字。
        let until = now + length;
        match &mut self.notice {
            Some(notice) => notice.until = notice.until.max(until),
            None => {
                self.notice = Some(Notice {
                    message: None,
                    until,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tray::Primary;

    fn snapshot(look: Look) -> Snapshot {
        Snapshot {
            look,
            ..Snapshot::INITIAL
        }
    }

    #[test]
    fn startup_does_not_expand() {
        let mut presence = Presence::default();
        let now = Instant::now();
        assert!(!presence.update(&snapshot(Look::Unknown), false, now));
        assert!(!presence.update(&snapshot(Look::Idle), false, now));
        assert!(!presence.update(&snapshot(Look::Idle), false, now + NOTICE));
    }

    #[test]
    fn a_state_change_expands_for_a_while() {
        let mut presence = Presence::default();
        let now = Instant::now();
        presence.update(&snapshot(Look::Idle), false, now);
        assert!(presence.update(&snapshot(Look::Managed), false, now));
        assert!(presence.update(&snapshot(Look::Managed), false, now + NOTICE / 2));
        assert!(!presence.update(&snapshot(Look::Managed), false, now + NOTICE));
    }

    #[test]
    fn losing_the_backend_stays_open_longer() {
        let mut presence = Presence::default();
        let now = Instant::now();
        presence.update(&snapshot(Look::Managed), false, now);
        assert!(presence.update(&snapshot(Look::Unknown), false, now));
        assert!(presence.update(&snapshot(Look::Unknown), false, now + NOTICE));
        assert!(!presence.update(&snapshot(Look::Unknown), false, now + WARNING_NOTICE));
    }

    #[test]
    fn hover_keeps_it_open_and_leaving_waits_a_moment() {
        let mut presence = Presence::default();
        let now = Instant::now();
        let idle = snapshot(Look::Idle);
        presence.update(&idle, false, now);
        assert!(presence.update(&idle, true, now));
        assert!(presence.update(&idle, false, now + Duration::from_millis(100)));
        assert!(presence.update(&idle, false, now + Duration::from_millis(300)));
        assert!(!presence.update(&idle, false, now + Duration::from_millis(600)));
    }

    #[test]
    fn reminders_show_their_text_until_they_expire() {
        let mut presence = Presence::default();
        let now = Instant::now();
        let idle = snapshot(Look::Idle);
        presence.update(&idle, false, now);
        presence.notify("UDP 已阻断".into(), true, now);
        assert!(presence.update(&idle, false, now + NOTICE));
        assert_eq!(presence.notice(), Some("UDP 已阻断"));
        assert!(!presence.update(&idle, false, now + WARNING_NOTICE));
        assert_eq!(presence.notice(), None);
    }

    #[test]
    fn a_state_change_does_not_cut_a_warning_short() {
        let mut presence = Presence::default();
        let now = Instant::now();
        presence.update(&snapshot(Look::Idle), false, now);
        presence.notify("警告".into(), true, now);
        presence.update(&snapshot(Look::Managed), false, now);
        assert!(presence.update(&snapshot(Look::Managed), false, now + NOTICE));
        assert_eq!(presence.notice(), Some("警告"));
    }

    #[test]
    fn buttons_follow_the_tray_menu_rules() {
        let mut busy = Snapshot {
            look: Look::Managed,
            primary: Primary::Stop,
            busy: Some("正在停止接管…".into()),
            ..Snapshot::INITIAL
        };
        let found = actions(&busy);
        assert_eq!(
            found
                .iter()
                .map(|a| (a.command, a.enabled))
                .collect::<Vec<_>>(),
            [
                (Command::Stop, false),
                (Command::Probe, false),
                (Command::Open, true)
            ]
        );
        busy.busy = None;
        assert!(actions(&busy).iter().all(|a| a.enabled));
        let idle = Snapshot {
            look: Look::Idle,
            primary: Primary::ChooseTarget,
            busy: Some("等待在主窗口确认".into()),
            ..Snapshot::INITIAL
        };
        let found = actions(&idle);
        assert_eq!(found.len(), 2, "只有接管中才有检测出口");
        assert!(found[0].enabled, "只是跳页的主操作忙时也能点");
        assert!(found[0].primary);
    }

    #[test]
    fn button_labels_fit_three_in_a_row() {
        let managed = Snapshot {
            look: Look::Managed,
            primary: Primary::Stop,
            ..Snapshot::INITIAL
        };
        let labels: Vec<_> = actions(&managed).iter().map(|a| a.label).collect();
        assert_eq!(labels, ["停止接管", "检测出口", "打开主窗口"]);
        for primary in [
            Primary::Reconnect,
            Primary::ChooseTarget,
            Primary::GoSave,
            Primary::Start,
            Primary::Stop,
            Primary::Abandon,
        ] {
            let snapshot = Snapshot {
                primary,
                ..Snapshot::INITIAL
            };
            for action in actions(&snapshot) {
                assert!(action.label.chars().count() <= 5, "{}", action.label);
            }
        }
    }

    #[test]
    fn texts_prefer_what_is_happening_now() {
        let managed = Snapshot {
            look: Look::Managed,
            target: Some("Ubuntu-24.04".into()),
            ..Snapshot::INITIAL
        };
        assert_eq!(trailing(&managed, None), "接管中");
        assert_eq!(
            trailing(
                &managed,
                Some(Rates {
                    up: 0.,
                    down: 1.5 * 1024. * 1024.
                })
            ),
            "↓ 1.5M/s"
        );
        assert_eq!(caption(&managed, None), "Ubuntu-24.04");
        assert_eq!(caption(&managed, Some("提醒")), "提醒");
        let busy = Snapshot {
            busy: Some("正在启动接管…".into()),
            ..managed
        };
        assert_eq!(trailing(&busy, None), "处理中");
        assert_eq!(Tone::of(&busy), Tone::Warn);
        assert_eq!(caption(&snapshot(Look::Idle), None), "流量照常直连");
    }

    #[test]
    fn short_rates_stay_short() {
        assert_eq!(short_rate(0.), "0 B/s");
        assert_eq!(short_rate(-3.), "0 B/s");
        assert_eq!(short_rate(812. * 1024.), "812K/s");
        assert_eq!(short_rate(1.24 * 1024. * 1024.), "1.2M/s");
        assert_eq!(short_rate(3. * 1024. * 1024. * 1024.), "3.0G/s");
    }

    #[test]
    fn the_morph_never_overshoots_and_lands_exactly() {
        let now = Instant::now();
        let mut morph = Morph::default();
        assert_eq!(morph.value(now), 0.);
        morph.aim(true, now);
        // 全程单调上升、不超过终点：停下时不会有回弹的抖动。
        let mut last = 0f32;
        for i in 1..=100 {
            let value = morph.value(now + SETTLE * i / 100);
            assert!(value >= last - 1e-6 && value <= 1., "第 {i} 帧 {value}");
            last = value;
        }
        assert!(
            morph.value(now + Duration::from_millis(350)) > 0.97,
            "0.35 秒基本到位"
        );
        // 到停稳前最后一刻已和终点相差不到千分之一，取终点时不会跳。
        let before = morph.value(now + SETTLE - Duration::from_millis(1));
        assert!((before - 1.).abs() < 1e-3, "{before}");
        assert!(!morph.settled(now + SETTLE / 2));
        assert_eq!(morph.value(now + SETTLE), 1.);
        assert!(morph.settled(now + SETTLE));
        // 收回同样不低于终点。
        let mut closing = Morph::default();
        closing.jump(true);
        closing.aim(false, now);
        for i in 1..=100 {
            assert!(closing.value(now + SETTLE * i / 100) >= 0.);
        }
        // 中途反向：从当前位置开始收回，不跳回终点。
        let half = now + Duration::from_millis(150);
        let mut reversed = Morph::default();
        reversed.aim(true, now);
        let at = reversed.value(half);
        reversed.aim(false, half);
        assert!((reversed.value(half) - at).abs() < 1e-6);
        assert_eq!(reversed.value(half + SETTLE), 0.);
    }

    #[test]
    fn the_outline_hugs_the_top_edge_and_stays_in_the_window() {
        for m in [0., 0.5, 1.] {
            let shape = shape(m, CARD);
            let left = (WINDOW.0 - shape.width) / 2.;
            let points = outline(shape, left, 1.);
            let (first, last) = (points[0], points[points.len() - 1]);
            // 两端都在顶边上，伸出主体一个肩宽。
            assert_eq!(first.1, 0.);
            assert_eq!(last.1, 0.);
            assert!((first.0 - (left + shape.width + 1. + FILLET + 1.)).abs() < 1e-3);
            assert!((last.0 - (left - 1. - FILLET - 1.)).abs() < 1e-3);
            for (x, y) in points {
                assert!(x >= 0. && x <= WINDOW.0, "{m}: x={x}");
                assert!(y >= 0. && y <= WINDOW.1, "{m}: y={y}");
            }
        }
    }

    #[test]
    fn dragged_positions_stay_on_screen_and_round_trip() {
        // 2560 宽的屏幕，窗口 400 宽。
        assert_eq!(window_left(0, 2560, 400, 0.5), 1080);
        assert_eq!(window_left(0, 2560, 400, 0.), 0, "拖到最左也不出屏幕");
        assert_eq!(window_left(0, 2560, 400, 1.), 2160, "拖到最右也不出屏幕");
        assert_eq!(
            window_left(-1920, 1920, 400, 0.5),
            -1160,
            "主显示器左边可以是负坐标"
        );
        for left in [0, 333, 1080, 2160] {
            let ratio = ratio_of(0, 2560, left, 400);
            assert_eq!(window_left(0, 2560, 400, ratio), left);
        }
        assert_eq!(ratio_of(0, 0, 10, 400), 0.5);
    }

    #[test]
    fn environment_facts_read_like_the_main_window() {
        let details = Details {
            exit_ip: Some("203.0.113.7".into()),
            exit_country: Some("US".into()),
            exit_matches: Some(true),
            dns_managed: true,
            dns_latency_ms: Some(23.4),
            udp: "经代理链",
            active_tcp: Some(12),
        };
        let exit = exit_fact(&details);
        assert_eq!(exit.value, "203.0.113.7 · US · 与住宅地址一致");
        assert_eq!(exit.tone, Tone::Ok);
        let [dns, udp, connections] = cells(&details);
        assert_eq!((dns.value.as_str(), dns.tone), ("23 ms", Tone::Ok));
        assert_eq!((udp.value.as_str(), udp.tone), ("经代理链", Tone::Ok));
        assert_eq!(connections.value, "12 条");

        let worse = Details {
            exit_matches: Some(false),
            dns_managed: false,
            udp: "已阻断",
            active_tcp: None,
            ..details
        };
        assert_eq!(exit_fact(&worse).tone, Tone::Warn);
        let [dns, udp, connections] = cells(&worse);
        assert_eq!((dns.value.as_str(), dns.tone), ("未接管", Tone::Warn));
        assert_eq!(udp.tone, Tone::Warn);
        assert_eq!(connections.value, "—");
        assert_eq!(exit_fact(&Details::default()).value, "未检测");
        assert_eq!(card_size(Some(&worse)), CARD_DETAILED);
        assert_eq!(card_size(None), CARD);
    }

    #[test]
    fn every_shape_fits_the_window() {
        for i in -20..=120 {
            let shape = shape(i as f32 / 100., CARD);
            assert!(shape.width + 2. * FILLET <= WINDOW.0 && shape.height <= WINDOW.1);
            assert!(shape.radius <= shape.height / 2. + 1e-3);
        }
        assert_eq!(shape(0., CARD).width, PILL.0);
        assert_eq!(shape(1., CARD).height, CARD.1);
        assert_eq!(shape(1., CARD).radius, CARD_RADIUS);
    }
}
