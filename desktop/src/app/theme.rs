//! 全局视觉令牌：颜色、主题字体和窗口标题只在这里定义。

use std::sync::atomic::{AtomicBool, Ordering};

use gpui_kit::component::{Theme, ThemeMode};
use gpui_kit::{App, Rgba, px};
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

// 白天主题取「雾绿 + 森林绿」，黑夜主题取「黑 + 透白」，两套共用亮绿 #47C86D。
// 下面的常量是白天的值，`resolve_color` 把它们换成黑夜的值，所以白天的常量之间不能重值。
pub(crate) const INK: u32 = 0x13261b;
pub(crate) const PAPER: u32 = 0xf2f6f3;
pub(crate) const SURFACE: u32 = 0xffffff;
pub(crate) const SURFACE_SOFT: u32 = 0xe8efea;
pub(crate) const SIDEBAR_BG: u32 = 0xdde7df;
/// 未选中导航项、普通环境行的悬停底色。
pub(crate) const HOVER: u32 = 0xd3dfd6;
/// 强调色：选中项文字和图标、焦点、主按钮悬停。
pub(crate) const ACCENT: u32 = 0x24573c;
/// 主按钮底色（森林绿）。
pub(crate) const PRIMARY: u32 = 0x1b412d;
/// 强调色的浅底：导航选中、当前目标。
pub(crate) const ACCENT_SOFT: u32 = 0xc9ebd3;
pub(crate) const SELECTED_BG: u32 = 0xb5e3c3;
pub(crate) const TEAL: u32 = 0x1e7b45;
pub(crate) const AMBER: u32 = 0x9a6412;
pub(crate) const RUST: u32 = 0xc0161e;
pub(crate) const RULE: u32 = 0xcfdbd2;
pub(crate) const INPUT_BORDER: u32 = 0x9db2a3;
pub(crate) const MUTED: u32 = 0x5b6e62;
pub(crate) const HEADER_MUTED: u32 = 0x5b6e62;
pub(crate) const TARGET_BG: u32 = 0xc9ebd3;
pub(crate) const SUCCESS_BG: u32 = 0xdcf3e3;
pub(crate) const WARNING_BG: u32 = 0xfbf0da;
pub(crate) const DANGER_BG: u32 = 0xfce6e5;
/// 状态栏图标的状态色：比正文的状态色更鲜明，正常、待处理、故障三种一眼能分开；
/// 未启用用浅灰，让「没在工作」的图标退到后面。
pub(crate) const STATUS_OK: u32 = 0x1f9d50;
pub(crate) const STATUS_WARN: u32 = 0xd97706;
pub(crate) const STATUS_ERROR: u32 = 0xd71019;
pub(crate) const STATUS_OFF: u32 = 0xa3b0a7;
/// 托盘图标「未接管」的盾牌色。托盘不跟随界面主题、不经过 `resolve_color`，
/// 任务栏可能浅也可能深，所以比 `STATUS_OFF` 深一档，浅色任务栏上也看得清。
/// 其余状态直接用 `STATUS_OK`、`STATUS_WARN`、`STATUS_ERROR` 的白天值。
pub(crate) const TRAY_IDLE: u32 = 0x86938b;
/// 首页流量图的上行（亮绿）；下行用正文色 `INK`，两条线靠明暗分开。
pub(crate) const CHART_UP: u32 = 0x2fa85a;
/// 「直连」路由：没走代理链，用中性的石板蓝，免得和强调色、「双跳」的绿色混在一起。
pub(crate) const ROUTE_DIRECT: u32 = 0x4a6a8c;
pub(crate) const ROUTE_DIRECT_BG: u32 = 0xe3eaf2;
pub(crate) const UI_FONT: &str = "Inter";
pub(crate) const MONO_FONT: &str = "IBM Plex Mono";
pub(crate) const TITLE: &str = "WSL Proxy";
/// 界面统一字号（px）。
const TEXT_SIZE: f32 = 12.;

const PRIMARY_PRESSED: u32 = 0x12301f;
const SECONDARY: u32 = 0x234a34;
const SECONDARY_HOVER: u32 = 0x2c5a40;
const DANGER_HOVER: u32 = 0x9e1219;
const DARK_INK: u32 = 0xdadadb;
const DARK_PAPER: u32 = 0x080808;
const DARK_SURFACE: u32 = 0x141415;
const DARK_SURFACE_SOFT: u32 = 0x1d1d1f;
const DARK_SIDEBAR_BG: u32 = 0x0e0e0f;
const DARK_HOVER: u32 = 0x242426;
const DARK_ACCENT: u32 = 0x5ed482;
const DARK_PRIMARY: u32 = 0x47c86d;
const DARK_ACCENT_SOFT: u32 = 0x15301f;
const DARK_TEAL: u32 = 0x47c86d;
const DARK_AMBER: u32 = 0xe8b04b;
const DARK_RUST: u32 = 0xff6b63;
const DARK_RULE: u32 = 0x2a2a2d;
const DARK_INPUT_BORDER: u32 = 0x56565c;
const DARK_MUTED: u32 = 0x8e8e93;
const DARK_SUCCESS_BG: u32 = 0x12301c;
const DARK_WARNING_BG: u32 = 0x332710;
const DARK_DANGER_BG: u32 = 0x3a1614;
const DARK_PRIMARY_PRESSED: u32 = 0x3aae5c;
const DARK_SECONDARY: u32 = 0x1f2a23;
const DARK_SECONDARY_HOVER: u32 = 0x2a3a30;
const DARK_DANGER_HOVER: u32 = 0xff8a84;
const DARK_STATUS_OK: u32 = 0x47c86d;
const DARK_STATUS_WARN: u32 = 0xf5b841;
const DARK_STATUS_ERROR: u32 = 0xff5a52;
const DARK_STATUS_OFF: u32 = 0x55555a;
const DARK_SELECTION: u32 = 0x1c3f28;
const DARK_CHART_UP: u32 = 0x47c86d;
const DARK_ROUTE_DIRECT: u32 = 0x9db6d3;
const DARK_ROUTE_DIRECT_BG: u32 = 0x1c2430;
pub(crate) const PREFERENCES_KEY: &str = "Software\\WSLProxyLab";
const THEME_VALUE: &str = "DesktopTheme";

static DARK_MODE: AtomicBool = AtomicBool::new(false);

pub(crate) fn is_dark() -> bool {
    DARK_MODE.load(Ordering::Relaxed)
}

pub(crate) fn load_mode() -> ThemeMode {
    let current_user = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(preferences) = current_user.open_subkey(PREFERENCES_KEY) else {
        return ThemeMode::Light;
    };
    match preferences.get_value::<String, _>(THEME_VALUE) {
        Ok(value) if value.eq_ignore_ascii_case(ThemeMode::Dark.name()) => ThemeMode::Dark,
        _ => ThemeMode::Light,
    }
}

fn persist_mode(mode: ThemeMode) -> Result<(), String> {
    let current_user = RegKey::predef(HKEY_CURRENT_USER);
    let (preferences, _) = current_user
        .create_subkey(PREFERENCES_KEY)
        .map_err(|error| format!("theme_preference_open_failed:{error}"))?;
    let value = mode.name().to_owned();
    preferences
        .set_value(THEME_VALUE, &value)
        .map_err(|error| format!("theme_preference_write_failed:{error}"))
}

fn resolve_color(value: u32) -> u32 {
    if !is_dark() {
        return value;
    }

    match value {
        INK => DARK_INK,
        PAPER => DARK_PAPER,
        SURFACE => DARK_SURFACE,
        SURFACE_SOFT => DARK_SURFACE_SOFT,
        SIDEBAR_BG => DARK_SIDEBAR_BG,
        ACCENT => DARK_ACCENT,
        PRIMARY => DARK_PRIMARY,
        ACCENT_SOFT => DARK_ACCENT_SOFT,
        TEAL => DARK_TEAL,
        AMBER => DARK_AMBER,
        RUST => DARK_RUST,
        RULE => DARK_RULE,
        INPUT_BORDER => DARK_INPUT_BORDER,
        MUTED => DARK_MUTED,
        SUCCESS_BG => DARK_SUCCESS_BG,
        WARNING_BG => DARK_WARNING_BG,
        DANGER_BG => DARK_DANGER_BG,
        PRIMARY_PRESSED => DARK_PRIMARY_PRESSED,
        SECONDARY => DARK_SECONDARY,
        SECONDARY_HOVER => DARK_SECONDARY_HOVER,
        DANGER_HOVER => DARK_DANGER_HOVER,
        SELECTED_BG => DARK_SELECTION,
        STATUS_OK => DARK_STATUS_OK,
        STATUS_WARN => DARK_STATUS_WARN,
        STATUS_ERROR => DARK_STATUS_ERROR,
        STATUS_OFF => DARK_STATUS_OFF,
        HOVER => DARK_HOVER,
        CHART_UP => DARK_CHART_UP,
        ROUTE_DIRECT => DARK_ROUTE_DIRECT,
        ROUTE_DIRECT_BG => DARK_ROUTE_DIRECT_BG,
        value => value,
    }
}

pub(crate) fn app_rgb(value: u32) -> Rgba {
    gpui_kit::rgb(resolve_color(value))
}

pub(crate) fn apply(mode: ThemeMode, cx: &mut App) {
    DARK_MODE.store(mode.is_dark(), Ordering::Relaxed);
    Theme::change(mode, None, cx);
    Theme::update(cx, |theme| {
        theme.font_family = UI_FONT.into();
        // 全部文字统一 12px。gpui-kit 的按钮、输入框、下拉框正文按 0.875rem（text_sm）
        // 排版，页面文字也统一用 text_sm；把主题字号（即 rem）设成 12/0.875，两者都正好 12px。
        theme.font_size = px(TEXT_SIZE / 0.875);
        theme.mono_font_family = MONO_FONT.into();
        theme.background = app_rgb(PAPER).into();
        theme.foreground = app_rgb(INK).into();
        theme.primary = app_rgb(PRIMARY).into();
        theme.primary_hover = app_rgb(ACCENT).into();
        theme.primary_active = app_rgb(PRIMARY_PRESSED).into();
        theme.primary_foreground = app_rgb(SURFACE).into();
        // gpui-kit 0.10 的主按钮读 `button_primary*`，它在加载默认主题时就取了默认主色（近黑），
        // 之后改 `primary` 不会同步过去，所以这里要一起设。
        theme.button_primary = app_rgb(PRIMARY).into();
        theme.button_primary_hover = app_rgb(ACCENT).into();
        theme.button_primary_active = app_rgb(PRIMARY_PRESSED).into();
        theme.button_primary_foreground = app_rgb(SURFACE).into();
        theme.secondary = app_rgb(SECONDARY).into();
        theme.secondary_hover = app_rgb(SECONDARY_HOVER).into();
        theme.secondary_active = app_rgb(PRIMARY).into();
        theme.secondary_foreground = app_rgb(HEADER_MUTED).into();
        theme.border = app_rgb(RULE).into();
        theme.input = app_rgb(INPUT_BORDER).into();
        theme.ring = app_rgb(ACCENT).into();
        theme.caret = app_rgb(ACCENT).into();
        theme.danger = app_rgb(RUST).into();
        theme.danger_hover = app_rgb(DANGER_HOVER).into();
        theme.danger_foreground = app_rgb(SURFACE).into();
        theme.selection = app_rgb(SELECTED_BG).into();
        theme.sidebar = app_rgb(SIDEBAR_BG).into();
        theme.sidebar_foreground = app_rgb(INK).into();
        theme.sidebar_border = app_rgb(RULE).into();
        theme.sidebar_accent = app_rgb(ACCENT_SOFT).into();
        theme.sidebar_accent_foreground = app_rgb(ACCENT).into();
        theme.title_bar = app_rgb(SURFACE).into();
        theme.title_bar_border = app_rgb(RULE).into();
        theme.status_bar = app_rgb(SURFACE).into();
        theme.status_bar_border = app_rgb(RULE).into();
        theme.popover = app_rgb(SURFACE).into();
        theme.popover_foreground = app_rgb(INK).into();
        theme.muted = app_rgb(SURFACE_SOFT).into();
        theme.muted_foreground = app_rgb(MUTED).into();
        // 设置页的分组框（gpui-kit Settings 用的 GroupBox）：文字用正文墨色，填充样式用浅底。
        theme.group_box = app_rgb(SURFACE_SOFT).into();
        theme.group_box_foreground = app_rgb(INK).into();
        theme.success = app_rgb(SUCCESS_BG).into();
        theme.success_foreground = app_rgb(TEAL).into();
        theme.warning = app_rgb(WARNING_BG).into();
        theme.warning_foreground = app_rgb(AMBER).into();
        theme.danger_active = app_rgb(RUST).into();
        theme.radius = px(10.);
        theme.radius_lg = px(10.);
        theme.shadow = !mode.is_dark();
    });
}

pub(crate) fn toggle(cx: &mut App) {
    let mode = if is_dark() {
        ThemeMode::Light
    } else {
        ThemeMode::Dark
    };
    if let Err(error) = persist_mode(mode) {
        eprintln!("{error}");
    }
    apply(mode, cx);
}
