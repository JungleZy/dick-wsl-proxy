//! 无状态 UI 组件与展示格式化函数；不读取 Desktop 运行状态。

use gpui::{prelude::*, *};
use serde_json::Value;

use super::theme::{BLUE, CYAN, INK, MUTED, RULE, SURFACE, SURFACE_SOFT};

pub(crate) fn text(value: &Value, key: &str, fallback: &str) -> String {
    value[key].as_str().unwrap_or(fallback).to_owned()
}
pub(crate) fn bytes(value: u64) -> String {
    if value >= 1024 * 1024 {
        format!("{:.1} MiB", value as f64 / 1048576.)
    } else if value >= 1024 {
        format!("{:.1} KiB", value as f64 / 1024.)
    } else {
        format!("{value} B")
    }
}
pub(crate) fn rate(value: &Value) -> String {
    value
        .as_f64()
        .map(|v| format!("{}/s", bytes(v.max(0.) as u64)))
        .unwrap_or_else(|| "未采样".into())
}

pub(crate) fn badge(label: impl Into<SharedString>, color: u32, background: u32) -> Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .px_2()
        .py_1()
        .bg(rgb(background))
        .rounded_md()
        .child(div().w(px(6.)).h(px(6.)).rounded_md().bg(rgb(color)))
        .child(
            div()
                .text_xs()
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(color))
                .child(label.into()),
        )
}

pub(crate) fn route_arrow() -> Div {
    div()
        .text_lg()
        .font_weight(FontWeight::BOLD)
        .text_color(rgb(BLUE))
        .child("→")
}

pub(crate) fn panel(title: &'static str, caption: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_4()
        .p_5()
        .bg(rgb(SURFACE))
        .border_1()
        .border_color(rgb(RULE))
        .rounded_md()
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .border_l_2()
                .border_color(rgb(CYAN))
                .pl_3()
                .child(
                    div()
                        .text_lg()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(INK))
                        .child(title),
                )
                .child(div().text_sm().text_color(rgb(MUTED)).child(caption.into())),
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
        .border_l_2()
        .border_color(rgb(RULE))
        .rounded_md()
        .child(
            div()
                .text_xs()
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(MUTED))
                .child(label),
        )
        .child(
            div()
                .text_base()
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(color))
                .child(value.into()),
        )
}
