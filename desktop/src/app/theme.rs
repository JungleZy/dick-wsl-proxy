//! 全局视觉令牌：颜色、主题字体和窗口标题只在这里定义。

use std::sync::atomic::{AtomicBool, Ordering};

use gpui_kit::component::{Theme, ThemeMode};
use gpui_kit::{App, Rgba, px};
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

pub(crate) const INK: u32 = 0x1b2732;
pub(crate) const PAPER: u32 = 0xf8f8f7;
pub(crate) const SURFACE: u32 = 0xffffff;
pub(crate) const SURFACE_SOFT: u32 = 0xf0f1f2;
pub(crate) const SIDEBAR_BG: u32 = 0xeef0f2;
pub(crate) const BLUE: u32 = 0x3658c8;
pub(crate) const BLUE_ACTIVE: u32 = 0x314d91;
pub(crate) const BLUE_SOFT: u32 = 0xe7edff;
pub(crate) const TEAL: u32 = 0x287b61;
pub(crate) const AMBER: u32 = 0xa66a1d;
pub(crate) const RUST: u32 = 0xb34f42;
pub(crate) const RULE: u32 = 0xd6d9de;
pub(crate) const INPUT_BORDER: u32 = 0xaab5c0;
pub(crate) const MUTED: u32 = 0x6f7b84;
pub(crate) const HEADER_MUTED: u32 = 0x6f7b84;
pub(crate) const TARGET_BG: u32 = 0xe7edff;
pub(crate) const SUCCESS_BG: u32 = 0xe7f1ed;
pub(crate) const WARNING_BG: u32 = 0xfaf0de;
pub(crate) const DANGER_BG: u32 = 0xfbe9e3;
pub(crate) const UI_FONT: &str = "Inter";
pub(crate) const MONO_FONT: &str = "IBM Plex Mono";
pub(crate) const TITLE: &str = "WSL Proxy";

const PRIMARY_ACTIVE: u32 = 0x263d73;
const SECONDARY: u32 = 0x18344c;
const SECONDARY_HOVER: u32 = 0x234b67;
const DANGER_HOVER: u32 = 0x9b3e1f;
const SELECTION: u32 = 0xdbeafe;
const DARK_INK: u32 = 0xe5e7eb;
const DARK_PAPER: u32 = 0x111827;
const DARK_SURFACE: u32 = 0x1f2937;
const DARK_SURFACE_SOFT: u32 = 0x273449;
const DARK_SIDEBAR_BG: u32 = 0x172033;
const DARK_BLUE: u32 = 0x8aa9ff;
const DARK_BLUE_ACTIVE: u32 = 0xa8bdff;
const DARK_BLUE_SOFT: u32 = 0x2d416f;
const DARK_TEAL: u32 = 0x63d0a6;
const DARK_AMBER: u32 = 0xf0c36c;
const DARK_RUST: u32 = 0xff9182;
const DARK_RULE: u32 = 0x3a4658;
const DARK_INPUT_BORDER: u32 = 0x5b6a80;
const DARK_MUTED: u32 = 0xa3adbb;
const DARK_SUCCESS_BG: u32 = 0x1b3b31;
const DARK_WARNING_BG: u32 = 0x4a391f;
const DARK_DANGER_BG: u32 = 0x4a2927;
const DARK_PRIMARY_ACTIVE: u32 = 0xb7c8ff;
const DARK_SECONDARY: u32 = 0x253650;
const DARK_SECONDARY_HOVER: u32 = 0x36527a;
const DARK_DANGER_HOVER: u32 = 0xffaa9d;
const DARK_SELECTION: u32 = 0x2d416f;
const PREFERENCES_KEY: &str = "Software\\WSLProxyLab";
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
        BLUE => DARK_BLUE,
        BLUE_ACTIVE => DARK_BLUE_ACTIVE,
        BLUE_SOFT => DARK_BLUE_SOFT,
        TEAL => DARK_TEAL,
        AMBER => DARK_AMBER,
        RUST => DARK_RUST,
        RULE => DARK_RULE,
        INPUT_BORDER => DARK_INPUT_BORDER,
        MUTED => DARK_MUTED,
        SUCCESS_BG => DARK_SUCCESS_BG,
        WARNING_BG => DARK_WARNING_BG,
        DANGER_BG => DARK_DANGER_BG,
        PRIMARY_ACTIVE => DARK_PRIMARY_ACTIVE,
        SECONDARY => DARK_SECONDARY,
        SECONDARY_HOVER => DARK_SECONDARY_HOVER,
        DANGER_HOVER => DARK_DANGER_HOVER,
        SELECTION => DARK_SELECTION,
        0xe3e8ed => DARK_SURFACE_SOFT,
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
        theme.font_size = px(14.);
        theme.mono_font_family = MONO_FONT.into();
        theme.background = app_rgb(PAPER).into();
        theme.foreground = app_rgb(INK).into();
        theme.primary = app_rgb(BLUE_ACTIVE).into();
        theme.primary_hover = app_rgb(BLUE).into();
        theme.primary_active = app_rgb(PRIMARY_ACTIVE).into();
        theme.primary_foreground = app_rgb(SURFACE).into();
        theme.secondary = app_rgb(SECONDARY).into();
        theme.secondary_hover = app_rgb(SECONDARY_HOVER).into();
        theme.secondary_active = app_rgb(BLUE_ACTIVE).into();
        theme.secondary_foreground = app_rgb(HEADER_MUTED).into();
        theme.border = app_rgb(RULE).into();
        theme.input = app_rgb(INPUT_BORDER).into();
        theme.ring = app_rgb(BLUE).into();
        theme.caret = app_rgb(BLUE).into();
        theme.danger = app_rgb(RUST).into();
        theme.danger_hover = app_rgb(DANGER_HOVER).into();
        theme.danger_foreground = app_rgb(SURFACE).into();
        theme.selection = app_rgb(SELECTION).into();
        theme.sidebar = app_rgb(SIDEBAR_BG).into();
        theme.sidebar_foreground = app_rgb(INK).into();
        theme.sidebar_border = app_rgb(RULE).into();
        theme.sidebar_accent = app_rgb(BLUE_SOFT).into();
        theme.sidebar_accent_foreground = app_rgb(BLUE).into();
        theme.title_bar = app_rgb(SURFACE).into();
        theme.title_bar_border = app_rgb(RULE).into();
        theme.status_bar = app_rgb(SURFACE).into();
        theme.status_bar_border = app_rgb(RULE).into();
        theme.popover = app_rgb(SURFACE).into();
        theme.popover_foreground = app_rgb(INK).into();
        theme.muted = app_rgb(SURFACE_SOFT).into();
        theme.muted_foreground = app_rgb(MUTED).into();
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
