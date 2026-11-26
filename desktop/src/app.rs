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
mod drafts;
mod environment_facts;
mod instance;
mod integrity;
mod island;
mod model;
mod overview;
mod policy;
mod state;
mod theme;
mod timezones;
mod tray;
mod update;
mod views;

use state::Desktop;
use theme::TITLE;

const WINDOW_WIDTH: f32 = 980.;
const WINDOW_HEIGHT: f32 = 700.;

pub fn run() {
    // 先于单实例锁检查：Low 级别下托盘注册不了，关窗会把窗口藏进不存在的托盘、无法找回，
    // 所以直接提示并退出，也不占用单实例锁。
    if integrity::below_medium() {
        integrity::warn();
        return;
    }
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
                window.on_window_should_close(cx, |_window, cx| {
                    let closing = if tray::consume_exit_request() {
                        true
                    } else if tray::ready() {
                        tray::hide_main_window();
                        false
                    } else {
                        // 托盘图标没显示：藏起来就找不回窗口，所以照常关闭。
                        // 后台留着，再次打开 EXE 会重新连上。
                        true
                    };
                    // 岛也是 gpui 窗口：它还开着，主窗口关了进程也不会退出。
                    if closing {
                        island::close(cx);
                    }
                    closing
                });
                cx.new(|cx| Desktop::new(window, cx))
            });
            if let Err(error) = opened {
                // 这是 GUI 程序，没有控制台可看。不退出的话，进程没有窗口、没有托盘，
                // 却一直占着单实例锁，之后再打开 EXE 也毫无反应。
                integrity::alert(
                    "WSL Proxy 无法打开窗口",
                    &format!(
                        "无法打开 WSL 代理控制台的窗口，点击“确定”后退出。\n\n原因：{error}\n\n后台如果已在运行会保留，接管不受影响。"
                    ),
                );
                cx.quit();
                return;
            }
            tray::start();
            if island::enabled_preference() {
                island::open(cx);
            }
            cx.activate(true);
        });
}
