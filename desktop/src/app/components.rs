//! 无状态 UI 组件与展示格式化函数；不读取 Desktop 运行状态。

use gpui_kit::component::Sizable as _;
use gpui_kit::{prelude::*, *};
use serde_json::Value;

use super::theme::{BLUE, MUTED, SURFACE_SOFT, app_rgb as rgb};

pub(crate) fn text(value: &Value, key: &str, fallback: &str) -> String {
    value[key].as_str().unwrap_or(fallback).to_owned()
}
pub(crate) fn bytes(value: u64) -> String {
    if value >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", value as f64 / 1073741824.)
    } else if value >= 1024 * 1024 {
        format!("{:.1} MiB", value as f64 / 1048576.)
    } else if value >= 1024 {
        format!("{:.1} KiB", value as f64 / 1024.)
    } else {
        format!("{value} B")
    }
}
/// 后台发送的速率是浮点数；缺失时（未接管或状态未确认）显示「—」。
pub(crate) fn rate(value: &Value) -> String {
    value
        .as_f64()
        .map(|v| format!("{}/s", bytes(v.max(0.) as u64)))
        .unwrap_or_else(|| "—".into())
}

pub(crate) fn badge(label: impl Into<SharedString>, color: u32, background: u32) -> Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .px_2()
        .py_1()
        .bg(rgb(background))
        .rounded_full()
        .child(div().w(px(6.)).h(px(6.)).rounded_full().bg(rgb(color)))
        .child(
            div()
                .text_base()
                .font_weight(FontWeight::NORMAL)
                .text_color(rgb(color))
                .child(label.into()),
        )
}

pub(crate) fn fact(label: &'static str, value: impl Into<SharedString>, color: u32) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .flex_1()
        .min_w_0()
        .p_3()
        .bg(rgb(SURFACE_SOFT))
        .rounded_md()
        .child(
            div()
                .text_base()
                .font_weight(FontWeight::NORMAL)
                .text_color(rgb(MUTED))
                .child(label),
        )
        .child(
            div()
                .text_base()
                .font_family(super::theme::MONO_FONT)
                .font_weight(FontWeight::NORMAL)
                .text_color(rgb(color))
                .child(value.into()),
        )
}

pub(crate) fn icon(path: &'static str) -> gpui_kit::component::Icon {
    icon_size(path, 20.)
}

pub(crate) fn app_icon(size: f32) -> gpui_kit::component::Icon {
    gpui_kit::component::Icon::default()
        .data(br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 2 20 5v6c0 5.2-3.1 8.8-8 11-4.9-2.2-8-5.8-8-11V5l8-3Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M7.5 12h3l1.5-3 2.2 6 1.4-3h1.9" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>"##)
        .text_color(rgb(BLUE))
        .with_size(gpui_kit::component::Size::Size(px(size)))
}

pub(crate) fn icon_size(path: &'static str, size: f32) -> gpui_kit::component::Icon {
    gpui_kit::component::Icon::default()
        .path(path)
        .with_size(gpui_kit::component::Size::Size(px(size)))
}

/// 设计稿使用的线性图标。统一从这里生成，避免导航和状态栏混用不同图标集。
pub(crate) fn design_icon(name: &'static str, size: f32, color: u32) -> gpui_kit::component::Icon {
    let data: &'static [u8] = match name {
        "dashboard" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><rect x="3" y="3" width="5" height="5" rx="1" fill="none" stroke="currentColor" stroke-width="1.5"/><rect x="12" y="3" width="5" height="5" rx="1" fill="none" stroke="currentColor" stroke-width="1.5"/><rect x="3" y="12" width="5" height="5" rx="1" fill="none" stroke="currentColor" stroke-width="1.5"/><rect x="12" y="12" width="5" height="5" rx="1" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>"#,
        "environment" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M3 5h14v10H3zM6 8h8M6 11h5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>"#,
        "policy" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M4 5h12M4 10h12M4 15h12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="8" cy="5" r="2" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="13" cy="10" r="2" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="7" cy="15" r="2" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>"#,
        "connection" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M3 11h3l2-5 3 9 2-5h4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>"#,
        "logs" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M5 3h10v14H5zM8 7h4M8 10h4M8 13h3" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>"#,
        "settings" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><circle cx="10" cy="10" r="3" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10 2v3M10 15v3M2 10h3M15 10h3M4.3 4.3l2.1 2.1M13.6 13.6l2.1 2.1M15.7 4.3l-2.1 2.1M6.4 13.6l-2.1 2.1" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>"#,
        "sun" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><circle cx="10" cy="10" r="3.2" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10 2v2M10 16v2M2 10h2M16 10h2M4.3 4.3l1.4 1.4M14.3 14.3l1.4 1.4M15.7 4.3l-1.4 1.4M5.7 14.3l-1.4 1.4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>"#,
        "moon" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M15.8 13.8A6.5 6.5 0 0 1 6.2 4.2 6.5 6.5 0 1 0 15.8 13.8Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>"#,
        "online" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><circle cx="10" cy="10" r="5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M10 2v3M10 15v3" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>"#,
        "idle" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M10 2l6 2v5c0 4-2.5 7-6 9-3.5-2-6-5-6-9V4l6-2z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>"#,
        "storage" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><ellipse cx="10" cy="4" rx="6" ry="2" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M4 4v6c0 1 2.7 2 6 2s6-1 6-2V4M4 10v6c0 1 2.7 2 6 2s6-1 6-2v-6" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>"#,
        "target" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><circle cx="10" cy="10" r="6" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="10" cy="10" r="2" fill="currentColor"/><path d="M10 2v3M10 15v3M2 10h3M15 10h3" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>"#,
        "select" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><rect x="3.5" y="3.5" width="13" height="13" rx="2" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="m6.5 10 2.3 2.3 4.8-5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>"#,
        "witness" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M2 10s3-5 8-5 8 5 8 5-3 5-8 5-8-5-8-5Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><circle cx="10" cy="10" r="2" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>"#,
        "archive" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M3 5h14v11H3zM4 3h12l1 2H3l1-2Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M7 9h6M7 12h6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>"#,
        "trash" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M4 6h12M8 6V4h4v2M6 6l.8 11h6.4L14 6M8.5 9v5M11.5 9v5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>"#,
        "info" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><circle cx="10" cy="10" r="7" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10 9v5M10 6.5v.1" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>"#,
        "plus" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M10 4v12M4 10h12" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>"#,
        "refresh" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M16 8a6 6 0 0 0-10.8-2L4 8M4 5v3h3M4 12a6 6 0 0 0 10.8 2L16 12m0 3v-3h-3" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>"#,
        "save" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M4 3h10l2 2v12H4zM7 3v5h6V3M7 17v-5h6v5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>"#,
        "folder" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M3 5h5l2 2h7v8H3z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>"#,
        "close" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="m5 5 10 10M15 5 5 15" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>"#,
        "check" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="m4 10 4 4 8-8" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>"#,
        "play" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M8 5.5v9l7-4.5-7-4.5z" fill="currentColor"/></svg>"#,
        "edit" => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="m4 14.8-.6 2.8 2.8-.6L15.8 7.4 12.6 4.2 4 14.8Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="m11.4 5.4 3.2 3.2" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>"#,
        _ => br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><circle cx="10" cy="10" r="7" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>"#,
    };
    gpui_kit::component::Icon::default()
        .data(data)
        .text_color(rgb(color))
        .with_size(gpui_kit::component::Size::Size(px(size)))
}

pub(crate) fn status_dot(color: u32) -> Div {
    div().w(px(7.)).h(px(7.)).rounded_full().bg(rgb(color))
}
