//! 顶部状态岛显示什么、什么时候展开。这里只有数据和规则，不碰窗口；
//! 状态和操作都来自托盘的 [`Snapshot`]，岛不另做状态判断。

use std::time::{Duration, Instant};

pub(crate) use crate::app::launcher::AppTile;
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
/// 接管中展开时，卡片右边另起一条竖着的胶囊，列出被接管环境里的图形应用，
/// 和 Apple 灵动岛旁边的小岛一样不和卡片连在一起。这是它的宽度、离卡片的间距
/// 和离屏幕顶边的距离。
pub(crate) const STRIP_WIDTH: f32 = 48.;
pub(crate) const STRIP_GAP: f32 = 8.;
pub(crate) const STRIP_TOP: f32 = 6.;
/// 应用胶囊里一格的边长和格间距，图标比格子小一圈。
pub(crate) const STRIP_SLOT: f32 = 38.;
pub(crate) const STRIP_ICON: f32 = 28.;
/// 卡片最宽能到多少：形变动画冲过头时也不超过它。
const MAX_WIDTH: f32 = CARD.0 + 28.;
/// 窗口始终是这么大：卡片两侧各留出应用胶囊和一圈余量（卡片始终居中，所以左边也留），
/// 形变动画冲过头时不被裁掉。能点到的范围由窗口区域裁成当前形状，其余部分不挡下面
/// 窗口的点击。
pub(crate) const WINDOW: (f32, f32) = (
    MAX_WIDTH + 2. * (STRIP_GAP + STRIP_WIDTH + 8.),
    CARD_DETAILED.1 + 16.,
);

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
    /// 被接管环境里的图形应用，列在卡片旁边的胶囊里。
    pub(crate) apps: Apps,
    /// 正在从岛上启动的应用（桌面文件 ID）；同一时间只启动一个。
    pub(crate) launching: Option<String>,
    /// 同时接管多个环境时每个环境一行（决策 40），转发中的在前。只有一个环境时为空，
    /// 卡片照上面那些字段画；有两行以上时卡片改成按环境列出，上面那些字段不再显示。
    pub(crate) environments: Vec<Environment>,
}

/// 多个环境时卡片上的一行：哪个环境、走哪个出口、各自的速率。
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Environment {
    pub(crate) name: String,
    pub(crate) exit_ip: Option<String>,
    pub(crate) exit_country: Option<String>,
    pub(crate) exit_matches: Option<bool>,
    /// 这个环境需要恢复：转发观测可能还在，但不算正常接管，不显示出口和速率。
    pub(crate) recovering: bool,
    /// 这个环境的实时速率；没有转发观测时为空。
    pub(crate) rates: Option<Rates>,
}

/// 卡片最多列几行环境：再多就把最后一行换成「另外 N 个环境」，卡片不加高。
pub(crate) const ENVIRONMENT_ROWS: usize = 3;
/// 一行环境的高度和行间距。
pub(crate) const ENVIRONMENT_ROW_HEIGHT: f32 = 26.;
pub(crate) const ENVIRONMENT_ROW_GAP: f32 = 4.;

/// 卡片按环境列出还是只画一个环境的详情。
pub(crate) fn lists_environments(details: Option<&Details>) -> bool {
    details.is_some_and(|details| details.environments.len() > 1)
}

/// 卡片上列出的一行。
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Line {
    /// 一个环境：名字、出口（含颜色档）、速率（`↓ … ↑ …`，没有时为空）。
    Environment {
        name: String,
        exit: Fact,
        rates: Option<String>,
    },
    /// 放不下的环境数。
    More(usize),
}

/// 多个环境时要列出的行：放得下就全列，放不下最后一行写还有几个。
pub(crate) fn environment_lines(details: &Details) -> Vec<Line> {
    let all = &details.environments;
    let shown = if all.len() > ENVIRONMENT_ROWS {
        ENVIRONMENT_ROWS - 1
    } else {
        all.len()
    };
    let mut lines: Vec<Line> = all[..shown]
        .iter()
        .map(|environment| Line::Environment {
            name: environment.name.clone(),
            exit: environment_exit(environment),
            rates: environment
                .rates
                .filter(|_| !environment.recovering)
                .map(|r| format!("↓ {} ↑ {}", short_rate(r.down), short_rate(r.up))),
        })
        .collect();
    if shown < all.len() {
        lines.push(Line::More(all.len() - shown));
    }
    lines
}

/// 一行里的出口：位置窄，只写 IP 和国家，核对结果用颜色表示；需要恢复的写需要恢复。
fn environment_exit(environment: &Environment) -> Fact {
    let fact = |value: String, tone| Fact {
        label: "出口",
        value,
        tone,
    };
    if environment.recovering {
        return fact("需要恢复".to_owned(), Tone::Error);
    }
    let Some(ip) = &environment.exit_ip else {
        return fact("未检测".to_owned(), Tone::Off);
    };
    let value = match &environment.exit_country {
        Some(country) => format!("{ip} · {country}"),
        None => ip.clone(),
    };
    let tone = match environment.exit_matches {
        Some(true) => Tone::Ok,
        Some(false) => Tone::Warn,
        None => Tone::Off,
    };
    fact(value, tone)
}

/// 汇总行（收起时的药丸、展开时的右上角）用的速率：多个环境时是在转发的各环境之和，
/// 需要恢复的不算；只有一个环境时就是传进来的那份。
pub(crate) fn summary_rates(rates: Option<Rates>, details: Option<&Details>) -> Option<Rates> {
    let Some(details) = details.filter(|details| details.environments.len() > 1) else {
        return rates;
    };
    details
        .environments
        .iter()
        .filter(|environment| !environment.recovering)
        .filter_map(|environment| environment.rates)
        .reduce(|total, rates| Rates {
            up: total.up + rates.up,
            down: total.down + rates.down,
        })
}

/// 被接管环境的应用列表读到哪一步了。
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) enum Apps {
    /// 还在读：胶囊里转圈。
    #[default]
    Loading,
    /// 读失败了：胶囊里放一颗重试按钮，原因悬停时显示。
    Failed(String),
    /// 读到了；一个都没有时不显示胶囊。
    Listed(Vec<AppTile>),
}

/// 应用胶囊上下各留的空和格与格的间距。
pub(crate) const STRIP_PADDING: f32 = 5.;
pub(crate) const STRIP_SPACING: f32 = 4.;

/// 应用胶囊的高度：刚好放下 `slots` 格，最高 `limit`（和卡片齐平），再多就在里面滚动；
/// 最矮是个圆。
pub(crate) fn strip_height(slots: usize, limit: f32) -> f32 {
    let slots = slots.max(1) as f32;
    let content = 2. * STRIP_PADDING + slots * STRIP_SLOT + (slots - 1.) * STRIP_SPACING;
    content.min(limit).max(STRIP_WIDTH)
}

/// 应用胶囊显不显示：读到了空列表就不占地方，其余（读取中、失败、有应用）都显示。
pub(crate) fn shows_strip(details: Option<&Details>) -> bool {
    details.is_some_and(|details| !matches!(&details.apps, Apps::Listed(apps) if apps.is_empty()))
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

/// 展开时的卡片大小：有环境信息就用高的那种。按环境列出时也用它：
/// 最多 [`ENVIRONMENT_ROWS`] 行，和出口一行加三格一样高，窗口不用变大。
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
        Command::Environments => "去环境页",
        Command::Recover => "去恢复",
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
        width: lerp(PILL.0, card.0).clamp(PILL.0 * 0.9, MAX_WIDTH),
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

/// 接管中的静止描边宽度。取整像素：边框会被对齐到像素，肩的细圆环不会，
/// 宽度带小数时两者对不齐，接缝处出一个折角。
pub(crate) const OUTLINE: f32 = 1.;

/// 流动光走的线：静止描边的中线。和描边用同一套几何：两侧是主体的竖直边往里
/// 半个描边宽，底部圆角半径少半个描边宽，肩是同一个圆心、半径多半个描边宽的凹弧。
/// 从右肩在顶边上的那一点开始，沿右侧、底边绕到左肩在顶边上的那一点。
pub(crate) fn light_path(shape: Shape, left: f32) -> Vec<(f32, f32)> {
    use std::f32::consts::FRAC_PI_2;
    const STEPS: usize = 16;
    let d = OUTLINE / 2.;
    let (xl, xr) = (left, left + shape.width);
    let f = FILLET;
    let shoulder = f + d;
    // 肩的圆和顶边（y = 0）相交处的角度：从水平方向往上量。
    let top = (f / shoulder).clamp(-1., 1.).asin();
    let r = shape.radius.max(d);
    let corner_y = (shape.height - r).max(f);
    let mut points = Vec::with_capacity(4 * STEPS + 4);
    // 右肩：圆心 (xr + f, f)，从顶边那一点转到侧边那一点 (xr - d, f)。
    for i in 0..=STEPS {
        let a = top * (1. - i as f32 / STEPS as f32);
        points.push((xr + f - shoulder * a.cos(), f - shoulder * a.sin()));
    }
    // 右下角、底边、左下角：圆心 (xr - r, corner_y) 和 (xl + r, corner_y)，半径 r - d。
    for i in 0..=STEPS {
        let a = FRAC_PI_2 * i as f32 / STEPS as f32;
        points.push((xr - r + (r - d) * a.cos(), corner_y + (r - d) * a.sin()));
    }
    for i in 0..=STEPS {
        let a = FRAC_PI_2 * (1. + i as f32 / STEPS as f32);
        points.push((xl + r + (r - d) * a.cos(), corner_y + (r - d) * a.sin()));
    }
    // 左肩：圆心 (xl - f, f)，从侧边那一点 (xl + d, f) 转到顶边那一点。
    for i in 0..=STEPS {
        let a = top * i as f32 / STEPS as f32;
        points.push((xl - f + shoulder * a.cos(), f - shoulder * a.sin()));
    }
    points
}

/// 接管中沿岛边缘流动的光：一圈多长时间。
pub(crate) const FLOW_PERIOD: Duration = Duration::from_millis(3200);
/// 一道光（含渐隐的尾巴）占轮廓全长的比例。
const FLOW_LENGTH: f32 = 0.3;
/// 一道光切成几段，从尾到头逐段变亮。
const FLOW_PIECES: usize = 12;

/// 折线上从起点量起 `from` 到 `to` 这一段（按长度），两端落在线段中间时插值。
/// `cumulative[i]` 是第 `i` 个点离起点的长度。
fn slice(points: &[(f32, f32)], cumulative: &[f32], from: f32, to: f32) -> Vec<(f32, f32)> {
    let at = |length: f32| {
        let i = cumulative
            .partition_point(|&c| c < length)
            .clamp(1, points.len() - 1);
        let (a, b) = (points[i - 1], points[i]);
        let span = cumulative[i] - cumulative[i - 1];
        let t = if span > 0. {
            ((length - cumulative[i - 1]) / span).clamp(0., 1.)
        } else {
            0.
        };
        (a.0 + (b.0 - a.0) * t, a.1 + (b.1 - a.1) * t)
    };
    let mut piece = vec![at(from)];
    piece.extend(
        points
            .iter()
            .zip(cumulative)
            .filter(|&(_, &c)| c > from && c < to)
            .map(|(&point, _)| point),
    );
    piece.push(at(to));
    piece
}

/// 流动光这一刻要画的几段折线和各自的亮度（0 到 1，越靠光头越亮）。
///
/// `points` 是岛的轮廓（不含顶边，从右肩沿右侧、底边绕到左肩），`phase` 是一圈里走到
/// 哪了（0 到 1）。两道光相隔半圈，从右肩进来、绕过底边、从左肩出去；光头出了轮廓，
/// 尾巴还会接着走完，所以任何时候边上都有光。
pub(crate) fn flow(points: &[(f32, f32)], phase: f32) -> Vec<(Vec<(f32, f32)>, f32)> {
    if points.len() < 2 {
        return Vec::new();
    }
    let mut cumulative = Vec::with_capacity(points.len());
    let mut total = 0.;
    cumulative.push(0.);
    for pair in points.windows(2) {
        total += (pair[1].0 - pair[0].0).hypot(pair[1].1 - pair[0].1);
        cumulative.push(total);
    }
    if total <= 0. {
        return Vec::new();
    }
    let tail = total * FLOW_LENGTH;
    let step = tail / FLOW_PIECES as f32;
    let mut pieces = Vec::new();
    for offset in [0., 0.5] {
        // 光头从起点前一个光长走到终点，走完正好一圈，接上下一圈不跳。
        let head = (phase + offset).fract() * (total + tail);
        for k in 0..FLOW_PIECES {
            let from = head - tail + k as f32 * step;
            let to = from + step;
            let (from, to) = (from.max(0.), to.min(total));
            if to - from < 0.5 {
                continue;
            }
            let brightness = (k + 1) as f32 / FLOW_PIECES as f32;
            pieces.push((
                slice(points, &cumulative, from, to),
                brightness * brightness,
            ));
        }
    }
    pieces
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
            primary: Primary::Environments,
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
            Primary::Environments,
            Primary::Recover,
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
            ..Details::default()
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

    fn environment(name: &str, down: f32) -> Environment {
        Environment {
            name: name.into(),
            rates: Some(Rates { up: 1024., down }),
            ..Environment::default()
        }
    }

    #[test]
    fn several_environments_add_up_their_rates() {
        let single = Some(Rates { up: 1., down: 2. });
        assert_eq!(summary_rates(single, None), single);
        // 只有一个环境：用传进来的速率，不看行。
        let one = Details {
            environments: vec![environment("Test-Alpha", 9.)],
            ..Details::default()
        };
        assert_eq!(summary_rates(single, Some(&one)), single);
        assert!(!lists_environments(Some(&one)));
        let mut stuck = environment("Test-Gamma", 1e6);
        stuck.recovering = true;
        let many = Details {
            environments: vec![
                environment("Test-Alpha", 1024.),
                environment("Test-Beta", 2048.),
                stuck,
            ],
            ..Details::default()
        };
        assert!(lists_environments(Some(&many)));
        assert_eq!(
            summary_rates(single, Some(&many)),
            Some(Rates {
                up: 2048.,
                down: 3072.
            }),
            "需要恢复的环境不计入合计"
        );
        let quiet = Details {
            environments: vec![Environment::default(), Environment::default()],
            ..Details::default()
        };
        assert_eq!(summary_rates(single, Some(&quiet)), None);
        assert_eq!(card_size(Some(&many)), CARD_DETAILED);
    }

    #[test]
    fn each_environment_line_names_its_exit_and_rates() {
        let mut checked = environment("Test-Alpha", 1.5 * 1024. * 1024.);
        checked.exit_ip = Some("203.0.113.7".into());
        checked.exit_country = Some("US".into());
        checked.exit_matches = Some(false);
        let mut stuck = environment("Test-Gamma", 1024.);
        stuck.recovering = true;
        let details = Details {
            environments: vec![checked, environment("Test-Beta", 0.), stuck],
            ..Details::default()
        };
        let lines = environment_lines(&details);
        let Line::Environment { name, exit, rates } = &lines[0] else {
            panic!("{lines:?}");
        };
        assert_eq!(name, "Test-Alpha");
        assert_eq!(
            (exit.value.as_str(), exit.tone),
            ("203.0.113.7 · US", Tone::Warn)
        );
        assert_eq!(rates.as_deref(), Some("↓ 1.5M/s ↑ 1.0K/s"));
        let Line::Environment { exit, rates, .. } = &lines[1] else {
            panic!("{lines:?}");
        };
        assert_eq!((exit.value.as_str(), exit.tone), ("未检测", Tone::Off));
        assert_eq!(rates.as_deref(), Some("↓ 0 B/s ↑ 1.0K/s"));
        let Line::Environment { exit, rates, .. } = &lines[2] else {
            panic!("{lines:?}");
        };
        assert_eq!((exit.value.as_str(), exit.tone), ("需要恢复", Tone::Error));
        assert_eq!(rates, &None);
    }

    #[test]
    fn environments_that_do_not_fit_fold_into_one_line() {
        let details = |count: usize| Details {
            environments: (0..count)
                .map(|i| environment(&format!("Test-{i}"), 0.))
                .collect(),
            ..Details::default()
        };
        assert_eq!(
            environment_lines(&details(ENVIRONMENT_ROWS)).len(),
            ENVIRONMENT_ROWS
        );
        let lines = environment_lines(&details(5));
        assert_eq!(lines.len(), ENVIRONMENT_ROWS);
        assert_eq!(
            lines[ENVIRONMENT_ROWS - 1],
            Line::More(5 - (ENVIRONMENT_ROWS - 1))
        );
        // 列出的几行和出口一行加三格一样高，放得进详情卡片：
        // 14 上边距 + 38 标题 + 8 + 行 + 8 + 8 + 36 按钮 + 14 下边距。
        let rows = ENVIRONMENT_ROWS as f32;
        let list = rows * ENVIRONMENT_ROW_HEIGHT + (rows - 1.) * ENVIRONMENT_ROW_GAP;
        assert!(14. + 38. + 8. + list + 8. + 8. + 36. + 14. <= CARD_DETAILED.1);
    }

    #[test]
    fn the_app_strip_hides_only_for_an_empty_list() {
        assert!(!shows_strip(None));
        let mut details = Details::default();
        assert!(shows_strip(Some(&details)), "读取中也占位，读到后卡片不跳");
        details.apps = Apps::Failed("读不到".into());
        assert!(shows_strip(Some(&details)));
        details.apps = Apps::Listed(Vec::new());
        assert!(!shows_strip(Some(&details)));
        // 高度跟着格数走，到卡片高度为止。
        assert_eq!(strip_height(1, 200.), STRIP_WIDTH);
        assert_eq!(strip_height(3, 200.), 10. + 3. * STRIP_SLOT + 8.);
        assert_eq!(strip_height(40, 200.), 200.);
        // 展开的卡片加上胶囊仍在窗口里。
        let right = (WINDOW.0 + CARD_DETAILED.0) / 2. + STRIP_GAP + STRIP_WIDTH;
        assert!(right <= WINDOW.0);
    }

    #[test]
    fn the_flowing_light_stays_on_the_outline_and_brightens_toward_its_head() {
        let shape = shape(1., CARD_DETAILED);
        let left = (WINDOW.0 - shape.width) / 2.;
        let points = light_path(shape, left);
        // 两端在顶边上，左右对称，侧边在主体里半个描边宽。
        let (first, last) = (points[0], points[points.len() - 1]);
        assert!(first.1.abs() < 1e-3 && last.1.abs() < 1e-3);
        assert!(((first.0 - left - shape.width) - (left - last.0)).abs() < 1e-3);
        assert!(points.iter().any(|&(x, y)| {
            (x - (left + shape.width - OUTLINE / 2.)).abs() < 1e-3 && (y - FILLET).abs() < 1e-3
        }));
        for i in 0..=40 {
            let pieces = flow(&points, i as f32 / 40.);
            assert!(!pieces.is_empty(), "phase {i}/40 时边上没有光");
            for (piece, brightness) in &pieces {
                assert!(piece.len() >= 2);
                assert!(*brightness > 0. && *brightness <= 1.);
                for &(x, y) in piece {
                    assert!(x >= 0. && x <= WINDOW.0 && y >= 0. && y <= WINDOW.1);
                }
            }
        }
        // 每道光从尾到头逐段变亮。
        let pieces = flow(&points, 0.3);
        assert!(pieces.windows(2).any(|pair| pair[1].1 > pair[0].1));
        // 一圈首尾相接：phase 0 和 1 画的一样。
        assert_eq!(flow(&points, 0.), flow(&points, 1.));
        assert!(flow(&points[..1], 0.5).is_empty());
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
