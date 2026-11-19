//! 窗口 Render 壳层：负责顶栏、导航、确认条和底部状态栏。
use gpui::{prelude::*, *};
use gpui_component::button::ButtonVariants;

use super::backend::Kind;
use super::components::badge;
use super::model::{Page, UiAction};
use super::state::Desktop;
use super::theme::{
    BLUE, DANGER_BG, INK, MUTED, NAVY, PAPER, RULE, RUST, SUCCESS_BG, SURFACE,
    SURFACE_SOFT, TEAL, WARNING_BG, WHITE,
};
impl Render for Desktop {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let age = self
            .status_at
            .map(|time| format!("{} 秒前观测", time.elapsed().as_secs()))
            .unwrap_or_else(|| "暂无状态".into());
        let (connection_label, connection_color, connection_background) = if self.status_valid {
            ("后台在线", TEAL, SUCCESS_BG)
        } else {
            ("状态未知", RUST, DANGER_BG)
        };
        let mut body = div()
            .size_full()
            .flex()
            .flex_col()
            .font_family("Microsoft YaHei UI")
            .text_base()
            .text_color(rgb(INK))
            .bg(rgb(PAPER))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .px_6()
                    .py_5()
                    .bg(rgb(NAVY))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(
                                div()
                                    .w(px(38.))
                                    .h(px(38.))
                                    .flex()
                                    .items_center()
                                    .rounded_md()
                                    .bg(rgb(BLUE))
                                    .text_lg()
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(rgb(WHITE))
                                    .child("W"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(
                                        div()
                                            .text_2xl()
                                            .font_family("DengXian")
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(rgb(WHITE))
                                            .child("WSL 代理控制台"),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(rgb(0xb8c7d9))
                                            .child("单目标 / 独立后台 / 可恢复"),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(badge(
                                connection_label,
                                connection_color,
                                connection_background,
                            ))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(0xb8c7d9))
                                    .child(age),
                            )
                            .child(self.button(
                                "refresh",
                                "刷新状态",
                                UiAction::Refresh,
                                self.locked() || self.refreshing,
                                cx,
                            ))
                            .child(self.button(
                                "reconnect",
                                "重新连接后台",
                                UiAction::Reconnect,
                                self.locked() || self.refreshing,
                                cx,
                            )),
                    ),
            )
            .child(self.path_strip())
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .px_6()
                    .py_3()
                    .bg(rgb(SURFACE))
                    .border_b_1()
                    .border_color(rgb(RULE))
                    .child(
                        div()
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(MUTED))
                            .child("工作区"),
                    )
                    .children(
                        [
                            (Page::Overview, "总览", "tab-overview"),
                            (Page::Policy, "策略", "tab-policy"),
                            (Page::Diagnostics, "连接与诊断", "tab-diagnostics"),
                        ]
                        .into_iter()
                        .map(|(page, label, id)| {
                            let button = self.button(id, label, UiAction::Page(page), false, cx);
                            if self.page == page {
                                button.primary()
                            } else {
                                button.ghost()
                            }
                        }),
                    )
                    .child(div().flex_1())
                    .child(badge(
                        if self.dirty { "有未保存更改" } else { "草稿与后台分离" },
                        if self.dirty { RUST } else { MUTED },
                        if self.dirty { WARNING_BG } else { SURFACE_SOFT },
                    )),
            )
            .child(
                div()
                    .id("page-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p_6()
                    .child(match self.page {
                        Page::Overview => self.overview(cx),
                        Page::Policy => self.policy_page(cx),
                        Page::Diagnostics => self.diagnostics(cx),
                    }),
            );
        if let Some(confirmation) = &self.confirmation {
            body = body.child(
                div()
                    .px_6()
                    .py_4()
                    .bg(rgb(WARNING_BG))
                    .border_t_2()
                    .border_color(rgb(RUST))
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(badge("请确认", RUST, DANGER_BG))
                                    .child(
                                        div()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(rgb(RUST))
                                            .child(format!("确认{}", confirmation.kind.label())),
                                    ),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(MUTED))
                                    .child(format!("代数 {} · 需重新检查", confirmation.generation)),
                            ),
                    )
                    .child(
                        div()
                            .p_3()
                            .bg(rgb(SURFACE))
                            .rounded_md()
                            .text_sm()
                            .child(confirmation.message.clone()),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                self.button(
                                    "confirm",
                                    "执行",
                                    UiAction::Confirm,
                                    self.busy.is_some(),
                                    cx,
                                )
                                .danger(),
                            )
                            .child(self.button("cancel", "取消", UiAction::Cancel, false, cx)),
                    ),
            );
        }
        let (activity_label, activity_color, activity_background) = if self.busy.is_some() || self.reading {
            (self.busy.map(Kind::label).unwrap_or("读取中"), RUST, WARNING_BG)
        } else if self.error {
            ("需要处理", RUST, DANGER_BG)
        } else {
            ("关闭窗口不影响接管", MUTED, SURFACE_SOFT)
        };
        body.child(
            div()
                .px_6()
                .py_3()
                .bg(rgb(SURFACE))
                .border_t_1()
                .border_color(rgb(RULE))
                .flex()
                .items_center()
                .gap_4()
                .child(
                    div()
                        .flex()
                        .flex_1()
                        .flex_col()
                        .gap_1()
                        .child(
                            div()
                                .text_xs()
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(MUTED))
                                .child("提示"),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(rgb(if self.error { RUST } else { INK }))
                                .child(self.notice.clone()),
                        ),
                )
                .child(badge(
                    activity_label,
                    activity_color,
                    activity_background,
                )),
        )
    }
}
