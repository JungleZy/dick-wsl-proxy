//! 定义页面、输入字段、确认请求和 UI 操作等跨视图数据模型。
use gpui::Entity;
use gpui_component::input::InputState;
use serde_json::Value;

use super::backend::Kind;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Page {
    Overview,
    Policy,
    Diagnostics,
}
pub(crate) struct Fields {
    pub(crate) first_hop: Entity<InputState>,
    pub(crate) credential: Entity<InputState>,
    pub(crate) dns_upstream: Entity<InputState>,
    pub(crate) dns_tls_name: Entity<InputState>,
    pub(crate) health_domain: Entity<InputState>,
    pub(crate) direct_ips: Entity<InputState>,
    pub(crate) direct_domains: Entity<InputState>,
    pub(crate) direct_suffixes: Entity<InputState>,
    pub(crate) port: Entity<InputState>,
    pub(crate) env_path: Entity<InputState>,
}
pub(crate) struct Confirmation {
    pub(crate) kind: Kind,
    pub(crate) request: Value,
    pub(crate) generation: u64,
    pub(crate) message: String,
}
#[derive(Clone)]
pub(crate) enum UiAction {
    Page(Page),
    Refresh,
    Reconnect,
    List,
    Preflight,
    Save,
    Pick,
    Import,
    Forget,
    Probe,
    Prepare(Kind),
    Confirm,
    Cancel,
    Reveal,
}
