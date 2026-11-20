//! `main.rs` 只做平台入口分发；此模块承载 Windows 专属 GPUI 实现，因此不合并。
use gpui_kit::component::{Theme, ThemeMode, TitleBar};
use gpui_kit::{prelude::*, *};

mod actions;
mod backend;
mod bootstrap;
mod chrome;
mod components;
mod diagnostics;
mod model;
mod overview;
mod policy;
mod state;
mod theme;
mod views;

use state::Desktop;
use theme::{
    BLUE, BLUE_ACTIVE, BLUE_SOFT, HEADER_MUTED, INK, MONO_FONT, PAPER, RULE, RUST, SIDEBAR_BG,
    SURFACE, TITLE, UI_FONT,
};

pub fn run() {
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(|cx: &mut App| {
            gpui_kit::init(cx);
            gpui_kit::component::set_locale("zh-CN");
            Theme::change(ThemeMode::Light, None, cx);
            let theme = Theme::global_mut(cx);
            theme.font_family = UI_FONT.into();
            theme.font_size = px(14.);
            theme.mono_font_family = MONO_FONT.into();
            theme.background = rgb(PAPER).into();
            theme.foreground = rgb(INK).into();
            theme.primary = rgb(BLUE_ACTIVE).into();
            theme.primary_hover = rgb(BLUE).into();
            theme.primary_active = rgb(0x263d73).into();
            theme.primary_foreground = rgb(SURFACE).into();
            theme.secondary = rgb(0x18344c).into();
            theme.secondary_hover = rgb(0x234b67).into();
            theme.secondary_active = rgb(BLUE_ACTIVE).into();
            theme.secondary_foreground = rgb(HEADER_MUTED).into();
            theme.border = rgb(RULE).into();
            theme.input = rgb(theme::INPUT_BORDER).into();
            theme.ring = rgb(BLUE).into();
            theme.caret = rgb(BLUE).into();
            theme.danger = rgb(RUST).into();
            theme.danger_hover = rgb(0x9b3e1f).into();
            theme.selection = rgb(0xdbeafe).into();
            theme.sidebar = rgb(SIDEBAR_BG).into();
            theme.sidebar_foreground = rgb(INK).into();
            theme.sidebar_border = rgb(RULE).into();
            theme.sidebar_accent = rgb(BLUE_SOFT).into();
            theme.sidebar_accent_foreground = rgb(BLUE).into();
            theme.radius = px(10.);
            theme.radius_lg = px(10.);
            theme.shadow = true;
            let bounds = Bounds::centered(None, size(px(1120.), px(720.)), cx);
            let mut options = TitleBar::window_options();
            options.window_bounds = Some(WindowBounds::Windowed(bounds));
            options.window_min_size = Some(size(px(800.), px(620.)));
            let opened = gpui_kit::open_window(options, cx, |window, cx| {
                window.set_window_title(TITLE);
                cx.new(|cx| Desktop::new(window, cx))
            });
            if let Err(error) = opened {
                eprintln!("无法打开 WSL 代理控制台：{error}");
            }
            cx.activate(true);
        });
}
