//! 持有 GPUI 视图的运行时状态；字段只服务于桌面控制台内部模块。

use std::sync::mpsc::{Receiver, Sender};
use std::time::Instant;

use gpui_kit::base::VirtualListScrollHandle;
use gpui_kit::{FocusHandle, Subscription};
use serde_json::Value;

use super::backend::{Job, Kind, Reply};
use super::drafts::{FailedSaves, SaveScope, Unsaved};
use super::model::{
    Confirmation, ConnectionFilter, ConnectionHistory, ConnectionRow,
    EnvironmentDistributionSelectState, EnvironmentEditor, EnvironmentResult, Fields, LogFilter,
    Page, PendingPrepare, RuntimeLog, TimezoneSelectState, TrafficSample,
};

pub(crate) struct Desktop {
    pub(crate) page: Page,
    pub(crate) log_filter: LogFilter,
    pub(crate) logs: Vec<RuntimeLog>,
    pub(crate) logs_total: u64,
    pub(crate) logs_has_more: bool,
    pub(crate) logs_refresh_pending: bool,
    pub(crate) logs_before_id: Option<i64>,
    pub(crate) logs_loading_more: bool,
    /// 日志是后台静默读取：同一时间只有一个在途请求，不置 `reading`，不改页面提示。
    pub(crate) logs_in_flight: bool,
    /// 最近一次读取日志失败的原因，只显示在日志页。
    pub(crate) logs_error: Option<String>,
    /// 首页事件时间线：最新几条运行日志，不受日志页筛选和搜索影响。
    pub(crate) events: Vec<RuntimeLog>,
    /// 至少读到过一次（含连接后台时一起读到的），用来区分「读取中」和「没有事件」。
    pub(crate) events_loaded: bool,
    pub(crate) events_in_flight: bool,
    /// 最近一次读取失败的原因，只显示在时间线卡片里。
    pub(crate) events_error: Option<String>,
    pub(crate) logs_scroll: VirtualListScrollHandle,
    /// 由 `accept_status` 从最近一次有效快照解析；状态未确认时页面不显示它们。
    pub(crate) live_connections: Vec<ConnectionRow>,
    /// 后台写进 SQLite 的已结束连接，按页读取。
    pub(crate) connection_history: ConnectionHistory,
    pub(crate) connection_filter: ConnectionFilter,
    /// 连接历史的环境名称筛选；`None` 表示全部环境。
    pub(crate) connection_environment: Option<String>,
    pub(crate) connections_scroll: VirtualListScrollHandle,
    pub(crate) nav_focus: [FocusHandle; 6],
    pub(crate) fields: Fields,
    pub(crate) timezone_select: gpui_kit::Entity<TimezoneSelectState>,
    pub(crate) environment_distribution_select:
        gpui_kit::Entity<EnvironmentDistributionSelectState>,
    pub(crate) _subscriptions: Vec<Subscription>,
    pub(crate) sender: Sender<Job>,
    pub(crate) replies: Receiver<Reply>,
    pub(crate) epoch: u64,
    pub(crate) busy: Option<Kind>,
    pub(crate) reading: bool,
    /// `reading` 为真时是哪一种读取；加载框据此显示文字，不借用页面提示。
    pub(crate) reading_kind: Option<Kind>,
    pub(crate) refreshing: bool,
    pub(crate) last_poll: Instant,
    pub(crate) status: Value,
    pub(crate) status_at: Option<Instant>,
    pub(crate) status_valid: bool,
    pub(crate) traffic_history: Vec<TrafficSample>,
    pub(crate) dns_history: Vec<f32>,
    pub(crate) dns_checked_at: Option<u64>,
    pub(crate) distributions: Vec<Value>,
    pub(crate) selected: Option<String>,
    pub(crate) saved_selected: Option<String>,
    pub(crate) profile: Value,
    pub(crate) residential: Value,
    pub(crate) profile_path: Option<String>,
    pub(crate) revision: Value,
    pub(crate) profile_exists: bool,
    /// 规则页、设置页各自有没有没保存的输入；每页的保存按钮只保存自己这一页。
    pub(crate) unsaved: Unsaved,
    /// 正在保存的是哪一页；回复到了只重置这一页的输入框。
    pub(crate) saving: Option<SaveScope>,
    /// 在途的保存是自动清除失效的接管目标，不是用户点的保存。
    pub(crate) clearing_target: bool,
    pub(crate) loading_fields: bool,
    pub(crate) saved_port: String,
    pub(crate) preflight: Option<Value>,
    pub(crate) pending_prepare: Option<PendingPrepare>,
    pub(crate) notice: String,
    pub(crate) error: bool,
    /// 保存失败、之后还没重新保存或编辑过的页面；只在那一页显示「保存失败」。
    pub(crate) failed_saves: FailedSaves,
    /// 备份、时区对话框里的校验错误；显示在对话框内，打开对话框时清空。
    pub(crate) dialog_error: Option<String>,
    pub(crate) autostart_enabled: bool,
    pub(crate) confirmation: Option<Confirmation>,
    pub(crate) confirmation_pending: bool,
    /// 本次启动尝试已经就缺少的内核能力问过一次；避免预检失败后反复弹框。
    pub(crate) kernel_prepare_offered: bool,
    /// 托盘「退出」进行中：停止接管成功后接着关闭后台，后台关闭后退出程序。
    pub(crate) exiting: bool,
    /// 退出时联系不上后台：等加载框关掉后询问是否只退出界面。
    pub(crate) exit_anyway_pending: bool,
    pub(crate) export_path: Option<String>,
    pub(crate) environment_editor: Option<EnvironmentEditor>,
    pub(crate) environment_edit_target: Option<String>,
    pub(crate) environment_selected: Option<String>,
    pub(crate) environment_detail: Option<Value>,
    pub(crate) environment_started: Option<Instant>,
    pub(crate) environment_timezone_only: bool,
    pub(crate) loading_dialog_open: bool,
    pub(crate) environment_result_dialog_open: bool,
    pub(crate) environment_result_pending: Option<EnvironmentResult>,
    pub(crate) backup_dialog_open: bool,
    pub(crate) environment_backup_target: Option<String>,
    pub(crate) backup_result_dialog_open: bool,
    pub(crate) backup_result_path: Option<String>,
    pub(crate) backup_result_pending: bool,
    pub(crate) timezone_dialog_open: bool,
    pub(crate) environment_zsh: bool,
    pub(crate) environment_chrome: bool,
    pub(crate) environment_chinese: bool,
    /// 最近一次 WSL 平台检查的报告、失败原因和开始检查的时刻。
    pub(crate) wsl_platform: Option<Value>,
    pub(crate) wsl_platform_error: Option<String>,
    pub(crate) wsl_platform_at: Option<Instant>,
    pub(crate) wsl_platform_checking: bool,
    /// 最近一次 WSL 升级的结果，含升级前后的版本。
    pub(crate) wsl_update_result: Option<Value>,
    /// 最近一次住宅代理检测的结果（带检测时的配置版本）、失败原因、完成时刻和是否在检测中。
    pub(crate) residential_probe: Option<Value>,
    pub(crate) residential_probe_error: Option<String>,
    pub(crate) residential_probe_at: Option<Instant>,
    pub(crate) residential_probe_checking: bool,
    /// 还没弹出的保存结果（规则页、设置页的保存，环境页的「设为目标」）：`Ok` 是成功提示，
    /// `Err` 是可读的失败原因。推通知要用 `Window`，所以先记在这里，下一次界面刷新时用
    /// gpui-kit 的 Notification 弹出，弹出后清空。
    pub(crate) save_notice: Option<Result<String, String>>,
}
