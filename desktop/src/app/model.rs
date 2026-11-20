//! 定义页面、输入字段、确认请求和 UI 操作等跨视图数据模型。
use gpui_kit::Entity;
use gpui_kit::component::input::{InputState, TextareaState};
use serde_json::Value;

use super::backend::Kind;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Page {
    Overview,
    Environment,
    Policy,
    Connection,
    Logs,
    Settings,
}

#[derive(Clone, Copy)]
pub(crate) struct TrafficSample {
    pub(crate) tx: f32,
    pub(crate) rx: f32,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum EnvironmentEditor {
    Create,
    Edit,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum LogFilter {
    All,
    Errors,
}

pub(crate) enum Field {
    Single(Entity<InputState>),
    Multi(Entity<TextareaState>),
}

impl Field {
    pub(crate) fn value(&self, cx: &gpui_kit::App) -> String {
        match self {
            Self::Single(state) => state.read(cx).value().trim().to_owned(),
            Self::Multi(state) => state.read(cx).value().trim().to_owned(),
        }
    }

    pub(crate) fn set_value(
        &self,
        value: impl Into<String>,
        window: &mut gpui_kit::Window,
        cx: &mut gpui_kit::App,
    ) {
        let value = value.into();
        match self {
            Self::Single(state) => state.update(cx, |state, cx| state.set_value(value, window, cx)),
            Self::Multi(state) => state.update(cx, |state, cx| state.set_value(value, window, cx)),
        }
    }
}

pub(crate) struct Fields {
    pub(crate) first_hop: Field,
    pub(crate) residential_ip: Field,
    pub(crate) residential_port: Field,
    pub(crate) residential_username: Field,
    pub(crate) residential_password: Field,
    pub(crate) dns_upstream: Field,
    pub(crate) dns_tls_name: Field,
    pub(crate) health_domain: Field,
    pub(crate) direct_ips: Field,
    pub(crate) direct_domains: Field,
    pub(crate) direct_suffixes: Field,
    pub(crate) port: Field,
    pub(crate) environment_name: Field,
    pub(crate) environment_source: Field,
    pub(crate) environment_install: Field,
    pub(crate) environment_backup: Field,
}
pub(crate) struct Confirmation {
    pub(crate) kind: Kind,
    pub(crate) request: Value,
    pub(crate) generation: u64,
    pub(crate) message: String,
}
#[derive(Clone)]
pub(crate) enum UiAction {
    List,
    Preflight,
    Save,
    Probe,
    Prepare(Kind),
    Reveal,
    EnvironmentCreate,
    EnvironmentSubmit,
    EnvironmentCancel,
    EnvironmentPickSource,
    EnvironmentPickInstall,
    EnvironmentPickBackup,
    LogFilter(LogFilter),
}
