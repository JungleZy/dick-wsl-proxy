//! `main.rs` 只做平台入口分发；此模块承载 Windows 专属 GPUI 实现，因此不合并。
use gpui::{prelude::*, *};
use gpui_component::{Root, Theme, ThemeMode};

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
use theme::{BLUE, INK, NAVY, PAPER, RULE, RUST, SURFACE, TITLE};

pub fn run() {
    Application::new().run(|cx: &mut App| {
        gpui_component::init(cx);
        gpui_component::set_locale("zh-CN");
        Theme::change(ThemeMode::Light, None, cx);
        let theme = Theme::global_mut(cx);
        theme.font_family = "Microsoft YaHei UI".into();
        theme.font_size = px(14.);
        theme.mono_font_family = "Consolas".into();
        theme.background = rgb(PAPER).into();
        theme.foreground = rgb(INK).into();
        theme.primary = rgb(BLUE).into();
        theme.primary_hover = rgb(0x1e40af).into();
        theme.primary_active = rgb(NAVY).into();
        theme.border = rgb(RULE).into();
        theme.input = rgb(SURFACE).into();
        theme.ring = rgb(BLUE).into();
        theme.caret = rgb(BLUE).into();
        theme.danger = rgb(RUST).into();
        theme.danger_hover = rgb(0x923c0a).into();
        theme.selection = rgb(0xdbeafe).into();
        theme.radius = px(7.);
        theme.shadow = true;
        let bounds = Bounds::centered(None, size(px(1280.), px(840.)), cx);
        let opened = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(1120.), px(720.))),
                ..Default::default()
            },
            |window, cx| {
                window.set_window_title(TITLE);
                let view = cx.new(|cx| Desktop::new(window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            },
        );
        if let Err(error) = opened {
            eprintln!("无法打开 WSL 代理控制台：{error}");
        }
        cx.activate(true);
    });
}
