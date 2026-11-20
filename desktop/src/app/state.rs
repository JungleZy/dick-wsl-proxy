//! 持有 GPUI 视图的运行时状态；字段只服务于桌面控制台内部模块。

use std::sync::mpsc::{Receiver, Sender};
use std::time::Instant;

use gpui_kit::{FocusHandle, Subscription};
use serde_json::Value;

use super::backend::{Job, Kind, Reply};
use super::model::{Confirmation, EnvironmentEditor, Fields, LogFilter, Page, TrafficSample};

pub(crate) struct Desktop {
    pub(crate) page: Page,
    pub(crate) log_filter: LogFilter,
    pub(crate) nav_focus: [FocusHandle; 6],
    pub(crate) fields: Fields,
    pub(crate) _subscriptions: Vec<Subscription>,
    pub(crate) sender: Sender<Job>,
    pub(crate) replies: Receiver<Reply>,
    pub(crate) epoch: u64,
    pub(crate) busy: Option<Kind>,
    pub(crate) reading: bool,
    pub(crate) refreshing: bool,
    pub(crate) last_poll: Instant,
    pub(crate) status: Value,
    pub(crate) status_at: Option<Instant>,
    pub(crate) status_valid: bool,
    pub(crate) traffic_history: Vec<TrafficSample>,
    pub(crate) distributions: Vec<Value>,
    pub(crate) selected: Option<String>,
    pub(crate) witness: Option<String>,
    pub(crate) saved_selected: Option<String>,
    pub(crate) saved_witness: Option<String>,
    pub(crate) profile: Value,
    pub(crate) residential: Value,
    pub(crate) profile_path: Option<String>,
    pub(crate) revision: Value,
    pub(crate) profile_exists: bool,
    pub(crate) dirty: bool,
    pub(crate) loading_fields: bool,
    pub(crate) saved_port: String,
    pub(crate) preflight: Option<Value>,
    pub(crate) preflight_key: Option<(String, String, u16)>,
    pub(crate) notice: String,
    pub(crate) error: bool,
    pub(crate) confirmation: Option<Confirmation>,
    pub(crate) export_path: Option<String>,
    pub(crate) environment_editor: Option<EnvironmentEditor>,
    pub(crate) environment_edit_target: Option<String>,
    pub(crate) environment_detail: Option<Value>,
    pub(crate) environment_zsh: bool,
    pub(crate) environment_chrome: bool,
    pub(crate) environment_chinese: bool,
}
