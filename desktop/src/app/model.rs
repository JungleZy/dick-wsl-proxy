//! 定义页面、输入字段、确认请求和 UI 操作等跨视图数据模型。
use gpui_kit::Entity;
use gpui_kit::component::input::{InputState, TextareaState};
use gpui_kit::component::select::{SearchableVec, SelectGroup, SelectState};
use serde_json::Value;

use super::backend::Kind;

pub(crate) type TimezoneSelectState = SelectState<SearchableVec<SelectGroup<&'static str>>>;
pub(crate) type EnvironmentDistributionSelectState =
    SelectState<SearchableVec<SelectGroup<&'static str>>>;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Page {
    Overview,
    Environment,
    Policy,
    Connection,
    Logs,
    Settings,
}

/// 环境操作的进度：后台写的进度文件，以及安装目录是否已经建好。两者都在后台线程读取，
/// 界面只读这份结果，免得映射盘或 UNC 路径不可达时卡住 UI 线程。
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EnvironmentProgress {
    /// 读的是哪一次操作（`Desktop::epoch`），旧操作的结果不显示。
    pub(crate) epoch: u64,
    pub(crate) target_ready: bool,
    pub(crate) marker: Option<(u8, String, String)>,
}

/// 解析后台写的进度文件：`percent`（超过 100 按 100 算）、`stage`、`detail`，缺任何一项都当作还没有进度。
pub(crate) fn progress_marker(text: &str) -> Option<(u8, String, String)> {
    let value = serde_json::from_str::<Value>(text).ok()?;
    Some((
        value["percent"].as_u64()?.min(100) as u8,
        value["stage"].as_str()?.to_owned(),
        value["detail"].as_str()?.to_owned(),
    ))
}

/// 一次有效状态快照里的速率（字节/秒）。`at` 是桌面端收到快照的时刻，用于标注横轴。
#[derive(Clone, Copy)]
pub(crate) struct TrafficSample {
    pub(crate) at: std::time::Instant,
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
    Warnings,
}

impl LogFilter {
    pub(crate) fn level(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::Errors => Some("error"),
            Self::Warnings => Some("warning"),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum ConnectionFilter {
    All,
    Active,
    Failed,
}

impl ConnectionFilter {
    /// 进行中的连接（来自后台状态快照）是否显示在当前筛选里。
    pub(crate) fn matches(self, row: &ConnectionRow) -> bool {
        match self {
            Self::All => true,
            Self::Active => row.active(),
            Self::Failed => row.failed(),
        }
    }

    /// 当前筛选要不要读取已落盘的记录；「活动」只看进行中的连接。
    pub(crate) fn history(self) -> bool {
        self != Self::Active
    }

    /// 查询已落盘记录时交给后台的状态条件。
    pub(crate) fn status(self) -> Option<&'static str> {
        (self == Self::Failed).then_some("failed")
    }
}

/// 连接页的一行：进行中的连接来自后台状态快照，已结束的连接来自 SQLite。
#[derive(Clone)]
pub(crate) struct ConnectionRow {
    /// SQLite 行号；只有已落盘的记录才有，用于分页和合并刷新结果。
    pub(crate) record_id: Option<i64>,
    /// 后台每次启动入口时的编号。流 ID 每次接管都从 1 重新计，两者合起来才唯一。
    pub(crate) session: u64,
    pub(crate) flow_id: u64,
    pub(crate) target: Option<String>,
    pub(crate) protocol: String,
    pub(crate) destination: Option<String>,
    pub(crate) route: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) status: String,
    pub(crate) stage: String,
    pub(crate) failure_stage: Option<String>,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_bytes: u64,
    /// 进行中的连接是已持续多久；已落盘的记录是从开始到结束用了多久。
    pub(crate) duration_ms: u64,
    /// 已落盘记录结束时的本地时间，例如 `11-22 14:02:31`。
    pub(crate) ended_at: Option<String>,
}

impl ConnectionRow {
    fn from_parts(value: &Value, session: u64, flow_id: u64, duration_ms: u64) -> Self {
        let owned = |key: &str| value[key].as_str().map(str::to_owned);
        Self {
            record_id: None,
            session,
            flow_id,
            target: owned("target"),
            protocol: owned("protocol").unwrap_or_default(),
            destination: owned("destination"),
            route: owned("route"),
            reason: owned("reason"),
            status: owned("status").unwrap_or_default(),
            stage: owned("stage").unwrap_or_default(),
            failure_stage: owned("failure_stage"),
            tx_bytes: value["tx_bytes"].as_u64().unwrap_or_default(),
            rx_bytes: value["rx_bytes"].as_u64().unwrap_or_default(),
            duration_ms,
            ended_at: owned("ended_at"),
        }
    }

    /// 后台状态快照里的一行。
    pub(crate) fn live(value: &Value, session: u64) -> Option<Self> {
        Some(Self::from_parts(
            value,
            session,
            value["id"].as_u64()?,
            value["age_ms"].as_u64().unwrap_or_default(),
        ))
    }

    /// SQLite 里的一条记录。
    pub(crate) fn persisted(value: &Value) -> Option<Self> {
        Some(Self {
            record_id: Some(value["id"].as_i64()?),
            ..Self::from_parts(
                value,
                value["session"].as_u64()?,
                value["flow_id"].as_u64()?,
                value["duration_ms"].as_u64().unwrap_or_default(),
            )
        })
    }

    /// 状态快照里要显示的连接：进行中的按新到旧。后台没有落盘时（旧版后台或存储不可用），
    /// 内存里最近结束的连接也一并显示，否则它们会在页面上消失。
    /// `target` 是快照里的当前接管目标：快照的每一行不带环境名，统一用它补上。
    pub(crate) fn live_list(connections: &Value, target: Option<&str>) -> Vec<Self> {
        let session = connections["session"].as_u64().unwrap_or_default();
        let active = connections["active"].as_array().into_iter().flatten().rev();
        let recent = (connections["persisted"] != true)
            .then(|| connections["recent"].as_array())
            .flatten()
            .into_iter()
            .flatten();
        active
            .chain(recent)
            .filter_map(|value| Self::live(value, session))
            .map(|row| Self {
                target: target.map(str::to_owned),
                ..row
            })
            .collect()
    }

    pub(crate) fn key(&self) -> (u64, u64) {
        (self.session, self.flow_id)
    }

    pub(crate) fn active(&self) -> bool {
        self.status == "active"
    }

    pub(crate) fn failed(&self) -> bool {
        self.status == "failed"
    }
}

/// 已落盘连接记录在窗口里的分页状态。
#[derive(Default)]
pub(crate) struct ConnectionHistory {
    pub(crate) rows: Vec<ConnectionRow>,
    /// 当前筛选是否至少读到过一页。
    pub(crate) loaded: bool,
    /// 在途请求对应的状态、环境筛选和是否为「加载更早」；回复与当前筛选不一致时丢弃。
    pub(crate) requested: Option<(ConnectionFilter, Option<String>, bool)>,
    pub(crate) has_more: bool,
    pub(crate) before_id: Option<i64>,
    /// 用户点过「加载更早」：定时刷新只合并第一页，不丢掉已加载的更早记录。
    pub(crate) extended: bool,
    pub(crate) total: Option<u64>,
    pub(crate) failed_total: Option<u64>,
    pub(crate) retention: Option<u64>,
    /// 后台没能写入 SQLite 的记录数（队列已满被丢弃加写入失败）。
    pub(crate) lost: u64,
    pub(crate) error: Option<String>,
}

impl ConnectionHistory {
    /// 换筛选后从第一页重新读。在途请求的标记要保留：它的回复按「筛选不一致」丢弃并重读，
    /// 否则会被当成新筛选的结果接受。
    pub(crate) fn reset(&mut self) {
        *self = Self {
            requested: self.requested.clone(),
            total: self.total,
            failed_total: self.failed_total,
            retention: self.retention,
            lost: self.lost,
            ..Self::default()
        };
    }

    pub(crate) fn accept(&mut self, value: &Value, append: bool) {
        let fresh = value["records"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(ConnectionRow::persisted)
            .collect::<Vec<_>>();
        let has_more = value["has_more"].as_bool().unwrap_or(false);
        let next_before_id = value["next_before_id"].as_i64();
        self.total = value["total"].as_u64();
        self.failed_total = value["failed_total"].as_u64();
        self.retention = value["retention_rows"].as_u64();
        self.lost = value["queue_dropped"].as_u64().unwrap_or_default()
            + value["write_failures"].as_u64().unwrap_or_default();
        self.error = None;
        self.loaded = true;
        if append {
            let oldest = self.rows.last().and_then(|row| row.record_id);
            self.rows.extend(
                fresh
                    .into_iter()
                    .filter(|row| oldest.is_none_or(|oldest| row.record_id < Some(oldest))),
            );
            self.has_more = has_more;
            self.before_id = next_before_id;
            self.extended = true;
            return;
        }
        // 第一页与已加载的记录相接时（第一页已含此前最新的那条，或者第一页就是全部），
        // 保留已加载的更早记录；否则两次刷新之间新增太多，只保留第一页并重置分页。
        let fresh_oldest = fresh.last().and_then(|row| row.record_id);
        let newest = self.rows.first().and_then(|row| row.record_id);
        let contiguous = !has_more
            || matches!((fresh_oldest, newest), (Some(oldest), Some(newest)) if oldest <= newest);
        if self.extended && contiguous && fresh_oldest.is_some() {
            let older = self
                .rows
                .drain(..)
                .filter(|row| row.record_id < fresh_oldest)
                .collect::<Vec<_>>();
            self.rows = fresh;
            self.rows.extend(older);
        } else {
            self.rows = fresh;
            self.has_more = has_more;
            self.before_id = next_before_id;
            self.extended = false;
        }
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeLog {
    pub(crate) id: i64,
    pub(crate) occurred_at: String,
    pub(crate) level: String,
    pub(crate) source: String,
    pub(crate) message: String,
    pub(crate) phase: Option<String>,
    pub(crate) target: Option<String>,
    pub(crate) generation: Option<u64>,
}

impl RuntimeLog {
    pub(crate) fn from_value(value: &Value) -> Option<Self> {
        Some(Self {
            id: value["id"].as_i64()?,
            occurred_at: value["occurred_at"].as_str()?.to_owned(),
            level: value["level"].as_str()?.to_owned(),
            source: value["source"].as_str()?.to_owned(),
            message: value["message"].as_str()?.to_owned(),
            phase: value["phase"].as_str().map(str::to_owned),
            target: value["target"].as_str().map(str::to_owned),
            generation: value["operation_generation"].as_u64(),
        })
    }

    /// 一行上下文「目标 · 阶段 · 代次」，日志页和首页时间线共用；都没有时为空。
    pub(crate) fn context(&self) -> String {
        let phase = self.phase.as_deref().map(|phase| match phase {
            "idle" => "空闲",
            "forwarding_managed" => "接管中",
            "forwarding_scoped" => "诊断转发",
            "recovery_required" => "需要恢复",
            _ => phase,
        });
        let mut parts = Vec::new();
        parts.extend(self.target.clone());
        parts.extend(phase.map(str::to_owned));
        parts.extend(
            self.generation
                .map(|generation| format!("代次 {generation}")),
        );
        parts.join(" · ")
    }
}

/// 输入框的状态句柄。克隆只复制句柄，指向同一个输入框。
#[derive(Clone)]
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
    pub(crate) log_search: Field,
    pub(crate) first_hop: Field,
    pub(crate) residential_ip: Field,
    pub(crate) residential_port: Field,
    pub(crate) residential_username: Field,
    pub(crate) residential_password: Field,
    pub(crate) dns_upstream: Field,
    pub(crate) dns_tls_name: Field,
    pub(crate) health_domain: Field,
    pub(crate) direct_dns_upstream: Field,
    pub(crate) direct_dns_tls_name: Field,
    pub(crate) direct_ips: Field,
    pub(crate) direct_domains: Field,
    pub(crate) direct_suffixes: Field,
    pub(crate) max_tcp_connections: Field,
    pub(crate) tcp_idle_timeout: Field,
    pub(crate) tcp_half_close_timeout: Field,
    pub(crate) port: Field,
    pub(crate) environment_name: Field,
    pub(crate) environment_distribution: Field,
    pub(crate) environment_install: Field,
    pub(crate) environment_backup: Field,
    pub(crate) environment_username: Field,
    pub(crate) environment_password: Field,
    pub(crate) environment_timezone: Field,
}
pub(crate) struct Confirmation {
    pub(crate) kind: Kind,
    pub(crate) request: Value,
    pub(crate) generation: u64,
    pub(crate) message: String,
    /// 这是托盘「退出」发起的停止：确认执行后才进入退出流程，取消则什么都不变。
    pub(crate) exit: bool,
}
pub(crate) struct PendingPrepare {
    pub(crate) kind: Kind,
    pub(crate) generation: u64,
    pub(crate) target: String,
    pub(crate) port: u16,
}
pub(crate) struct EnvironmentResult {
    pub(crate) kind: Kind,
    pub(crate) success: bool,
    pub(crate) message: String,
    pub(crate) timezone_only: bool,
}
#[derive(Clone)]
pub(crate) enum UiAction {
    List,
    /// 只保存这一页的输入。
    Save(super::drafts::SaveScope),
    Probe,
    Prepare(Kind),
    Reveal,
    EnvironmentCreate,
    EnvironmentSubmit,
    EnvironmentCancel,
    EnvironmentPickInstall,
    LogRefresh,
    LogLoadMore,
    LogFilter(LogFilter),
    Export,
    ResetDnsAliases,
    WslPlatformCheck,
    WslUpdate,
    ResidentialProbe,
    ConnectionFilter(ConnectionFilter),
    ConnectionEnvironment(Option<String>),
    ConnectionLoadMore,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{RuntimeLog, progress_marker};

    #[test]
    fn a_progress_file_needs_all_three_fields() {
        assert_eq!(
            progress_marker(r#"{"percent":140,"stage":"安装环境","detail":"apt"}"#),
            Some((100, "安装环境".into(), "apt".into()))
        );
        for partial in [
            r#"{"stage":"安装环境","detail":"apt"}"#,
            r#"{"percent":"40","stage":"安装环境","detail":"apt"}"#,
            r#"{"percent":40,"detail":"apt"}"#,
            r#"{"percent":40,"stage":"安装环境"}"#,
            // The controller may be halfway through writing the file.
            r#"{"percent":40,"stage":"#,
            "",
        ] {
            assert_eq!(progress_marker(partial), None, "{partial}");
        }
    }

    #[test]
    fn runtime_log_context_joins_target_phase_and_generation() {
        let log = |extra: serde_json::Value| {
            let mut value = json!({
                "id": 1, "occurred_at": "2026-11-23 21:16:13", "level": "info",
                "source": "status", "message": "已进入接管状态",
            });
            value
                .as_object_mut()
                .expect("object")
                .extend(extra.as_object().expect("object").clone());
            RuntimeLog::from_value(&value).expect("valid log")
        };
        let full = log(json!({
            "target": "Test-Target", "phase": "forwarding_managed", "operation_generation": 7,
        }));
        assert_eq!(full.context(), "Test-Target · 接管中 · 代次 7");
        assert_eq!(
            log(json!({"phase": "idle", "operation_generation": 3})).context(),
            "空闲 · 代次 3"
        );
        assert_eq!(
            log(json!({"phase": "unknown_phase"})).context(),
            "unknown_phase"
        );
        assert_eq!(log(json!({})).context(), "");
    }
}
