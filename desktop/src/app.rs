//! `main.rs` 只做平台入口分发；此模块承载 Windows 专属 GPUI 实现，因此不合并。
use gpui_kit::component::TitleBar;
use gpui_kit::{prelude::*, *};

mod actions;
mod autostart;
mod backend;
mod bootstrap;
mod chrome;
mod components;
mod diagnostics;
mod distributions;
mod instance;
mod model;
mod overview;
mod policy;
mod state;
mod theme;
mod timezones;
mod tray;
mod views;

use state::Desktop;
use theme::TITLE;

const WINDOW_WIDTH: f32 = 980.;
const WINDOW_HEIGHT: f32 = 700.;

pub fn run() {
    let Some(_instance) = instance::acquire() else {
        return;
    };
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(|cx: &mut App| {
            gpui_kit::init(cx);
            gpui_kit::component::set_locale("zh-CN");
            theme::apply(theme::load_mode(), cx);
            let bounds = Bounds::centered(None, size(px(WINDOW_WIDTH), px(WINDOW_HEIGHT)), cx);
            let mut options = TitleBar::window_options();
            options.window_bounds = Some(WindowBounds::Windowed(bounds));
            options.is_resizable = false;
            options.window_min_size = Some(size(px(WINDOW_WIDTH), px(WINDOW_HEIGHT)));
            let opened = gpui_kit::open_window(options, cx, |window, cx| {
                window.set_window_title(TITLE);
                window.on_window_should_close(cx, |_window, _cx| {
                    if tray::consume_exit_request() {
                        true
                    } else {
                        tray::hide_main_window();
                        false
                    }
                });
                cx.new(|cx| Desktop::new(window, cx))
            });
            if let Err(error) = opened {
                eprintln!("无法打开 WSL 代理控制台：{error}");
            } else {
                tray::start();
            }
            cx.activate(true);
        });
}
