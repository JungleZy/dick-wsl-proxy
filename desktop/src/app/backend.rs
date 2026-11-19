//! 负责与 wsl-proxyctl 后台通信；不包含窗口状态或页面布局。
use std::sync::mpsc::{self, Receiver, Sender};

use serde_json::{Value, json};

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Kind {
    Bootstrap,
    Status,
    List,
    Preflight,
    Save,
    Import,
    Forget,
    Start,
    Switch,
    Stop,
    Export,
    Probe,
}

impl Kind {
    pub(crate) fn mutation(self) -> bool {
        matches!(
            self,
            Self::Save
                | Self::Import
                | Self::Forget
                | Self::Start
                | Self::Switch
                | Self::Stop
                | Self::Probe
        )
    }
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Bootstrap => "连接后台",
            Self::Status => "刷新状态",
            Self::List => "刷新列表",
            Self::Preflight => "运行预检",
            Self::Save => "保存策略",
            Self::Import => "导入凭据",
            Self::Forget => "删除凭据",
            Self::Start => "启动接管",
            Self::Switch => "切换目标",
            Self::Stop => "停止并恢复",
            Self::Export => "导出诊断",
            Self::Probe => "检测出口",
        }
    }
}
pub(crate) struct Job {
    pub(crate) kind: Kind,
    pub(crate) epoch: u64,
    pub(crate) request: Value,
}
pub(crate) struct Reply {
    pub(crate) kind: Kind,
    pub(crate) epoch: u64,
    pub(crate) result: Result<Value, String>,
    pub(crate) status: Option<Result<Value, String>>,
}

pub(crate) fn request(value: &Value) -> Result<Value, String> {
    let reply = wsl_proxyctl::ipc::request(value)?;
    if let Some(message) = reply.get("message").and_then(Value::as_str) {
        if let Some(code) = reply.get("code").and_then(Value::as_str) {
            return Err(format!("{code} · {message}"));
        }
    }
    Ok(reply)
}

pub(crate) fn worker() -> (Sender<Job>, Receiver<Reply>) {
    let (send, jobs) = mpsc::channel::<Job>();
    let (replies, receive) = mpsc::channel();
    std::thread::spawn(move || {
        for job in jobs {
            let result = if job.kind == Kind::Bootstrap {
                wsl_proxyctl::ipc::ensure_daemon().and_then(|()| {
                    Ok(json!({
                        "distributions": request(&json!({"command":"list"}))?,
                        "profile": request(&json!({"command":"profile_get"}))?,
                        "status": request(&json!({"command":"status"}))?
                    }))
                })
            } else {
                request(&job.request)
            };
            // A failed mutation may still have advanced recovery state. Never replay it.
            let status = job
                .kind
                .mutation()
                .then(|| request(&json!({"command":"status"})));
            if replies
                .send(Reply {
                    kind: job.kind,
                    epoch: job.epoch,
                    result,
                    status,
                })
                .is_err()
            {
                break;
            }
        }
        // Dropping a window is deliberately not a stop or daemon shutdown command.
    });
    (send, receive)
}
