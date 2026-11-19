//! 处理用户发起的校验、策略保存、接管、切换、停止和凭据操作。

use gpui::{prelude::*, *};
use gpui_component::input::InputState;
use serde_json::{Value, json};

use super::backend::Kind;
use super::components::text;
use super::model::Confirmation;
use super::state::Desktop;

impl Desktop {

    pub(crate) fn fail(&mut self, error: impl Into<String>, cx: &mut Context<Self>) {
        self.notice = error.into();
        self.error = true;
        cx.notify();
    }
    pub(crate) fn phase(&self) -> &str {
        if self.status_valid {
            self.status["phase"].as_str().unwrap_or("unknown")
        } else {
            "unknown"
        }
    }
    pub(crate) fn idle(&self) -> bool {
        self.status_valid && self.phase() == "idle"
    }
    pub(crate) fn generation(&self) -> Option<u64> {
        self.status_valid
            .then(|| self.status["operation_generation"].as_u64())
            .flatten()
    }
    pub(crate) fn locked(&self) -> bool {
        self.busy.is_some() || self.reading || self.confirmation.is_some()
    }
    pub(crate) fn field_value(field: &Entity<InputState>, cx: &App) -> String {
        field.read(cx).value().trim().to_owned()
    }
    pub(crate) fn profile_field_value(profile: &Value, key: &str, array: bool) -> String {
        if array {
            profile[key]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::trim)
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default()
        } else {
            profile[key].as_str().unwrap_or_default().trim().to_owned()
        }
    }
    pub(crate) fn draft_is_dirty(&self, cx: &App) -> bool {
        if self.selected != self.saved_selected
            || self.witness != self.saved_witness
            || Self::field_value(&self.fields.port, cx) != self.saved_port
        {
            return true;
        }
        for (field, key, array) in [
            (&self.fields.first_hop, "first_hop", false),
            (&self.fields.credential, "credential", false),
            (&self.fields.dns_upstream, "dns_upstream", false),
            (&self.fields.dns_tls_name, "dns_tls_name", false),
            (&self.fields.health_domain, "health_domain", false),
            (&self.fields.direct_ips, "direct_ips", true),
            (&self.fields.direct_domains, "direct_domains", true),
            (&self.fields.direct_suffixes, "direct_suffixes", true),
        ] {
            if Self::field_value(field, cx) != Self::profile_field_value(&self.profile, key, array) {
                return true;
            }
        }
        false
    }
    pub(crate) fn port(&self, cx: &App) -> Result<u16, &'static str> {
        Self::field_value(&self.fields.port, cx)
            .parse::<u16>()
            .ok()
            .filter(|port| *port >= 1024)
            .ok_or("端口需为 1024–65535 的整数。")
    }
    pub(crate) fn selection(&self, cx: &App) -> Result<(String, String, u16), String> {
        let target = self.selected.clone().ok_or("请选择目标 WSL。")?;
        if self.phase() == "forwarding_managed" {
            let owner = self.status["active_target"]
                .as_str()
                .and_then(|name| {
                    self.distributions
                        .iter()
                        .find(|d| d["name"].as_str() == Some(name))
                })
                .and_then(|d| d["id"].as_str())
                .ok_or("当前目标无法核对，请刷新列表。")?;
            if owner != target {
                return Ok((target, owner.to_owned(), self.port(cx)?));
            }
        }
        let witness = self
            .witness
            .clone()
            .ok_or("请选择不同的对照 WSL。")?;
        if target == witness {
            return Err("目标和对照不能相同。".into());
        }
        Ok((target, witness, self.port(cx)?))
    }
    pub(crate) fn draft(&self, cx: &App) -> Value {
        let mut profile = self.profile.as_object().cloned().unwrap_or_default();
        for (field, key, array) in [
            (&self.fields.first_hop, "first_hop", false),
            (&self.fields.credential, "credential", false),
            (&self.fields.dns_upstream, "dns_upstream", false),
            (&self.fields.dns_tls_name, "dns_tls_name", false),
            (&self.fields.health_domain, "health_domain", false),
            (&self.fields.direct_ips, "direct_ips", true),
            (&self.fields.direct_domains, "direct_domains", true),
            (&self.fields.direct_suffixes, "direct_suffixes", true),
        ] {
            let text = Self::field_value(field, cx);
            profile.insert(
                key.into(),
                if array {
                    json!(
                        text.lines()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                    )
                } else {
                    json!(text)
                },
            );
        }
        Value::Object(profile)
    }

    pub(crate) fn preflight(&mut self, cx: &mut Context<Self>) {
        match self.selection(cx) {
            Ok((target, witness, port)) => {
                self.preflight_key = Some((target.clone(), witness.clone(), port));
                self.send(
                    Kind::Preflight,
                    json!({"command":"preflight","target":target,"witness":witness,"port":port}),
                    cx,
                );
            }
            Err(error) => self.fail(error, cx),
        }
    }

    pub(crate) fn prepare(&mut self, kind: Kind, cx: &mut Context<Self>) {
        if self.locked() {
            return;
        }
        let Some(generation) = self.generation() else {
            self.fail("后台状态未确认，请先刷新。", cx);
            return;
        };
        if kind == Kind::Stop {
            self.confirmation = Some(Confirmation {
                kind, generation, request: json!({"command":"stop","expected_generation":generation}),
                message: "将停止接管并恢复直连。现有 TCP 连接会中断，需要重连；只清理本控制器的规则。".into(),
            });
            cx.notify();
            return;
        }
        if self.dirty || !self.profile_exists || self.profile_path.is_none() {
            self.fail(
                "请先保存策略和目标选择。未保存内容不会生效。",
                cx,
            );
            return;
        }
        let (target, witness, port) = match self.selection(cx) {
            Ok(value) => value,
            Err(error) => {
                self.fail(error, cx);
                return;
            }
        };
        if self.preflight_key.as_ref() != Some(&(target.clone(), witness.clone(), port))
            || self.preflight.as_ref().is_none_or(|p| p["passed"] != true)
        {
            self.fail("请先为当前目标运行预检。", cx);
            return;
        }
        let command = if kind == Kind::Start {
            "start"
        } else {
            "switch"
        };
        let mut request = json!({"command":command,"target":target,"port":port,"profile":self.profile_path,"profile_revision":self.revision,"expected_generation":generation});
        if kind == Kind::Start {
            request["witness"] = json!(witness);
        }
        self.confirmation = Some(Confirmation {
            kind,
            generation,
            request,
            message: if kind == Kind::Switch {
                format!(
                    "将从 {} 切换到 {target}。旧目标会先恢复直连；现有 TCP 连接需要重连。",
                    text(&self.status, "active_target", "当前目标")
                )
            } else {
                format!(
                    "将接管 {target} 的 TCP 和系统 DNS。非直连例外流量经代理链；对照 WSL 仅用于隔离检查。"
                )
            },
        });
        cx.notify();
    }

    pub(crate) fn confirm(&mut self, cx: &mut Context<Self>) {
        let Some(confirmation) = self.confirmation.take() else {
            return;
        };
        if self.generation() != Some(confirmation.generation) {
            self.fail("确认期间后台状态已变化，请刷新后重试。", cx);
            return;
        }
        self.send(confirmation.kind, confirmation.request, cx);
    }

    pub(crate) fn save(&mut self, cx: &mut Context<Self>) {
        let port = match self.port(cx) {
            Ok(port) => port,
            Err(error) => {
                self.fail(error, cx);
                return;
            }
        };
        self.send(Kind::Save, json!({"command":"profile_save","profile":self.draft(cx),"expected_revision":self.revision,
            "desktop":{"target":self.selected,"witness":self.witness,"port":port}}), cx);
    }

    pub(crate) fn credentials(&mut self, forget: bool, cx: &mut Context<Self>) {
        if !self.idle() {
            self.fail("凭据操作仅在后台空闲时可用。", cx);
            return;
        }
        let name = Self::field_value(&self.fields.credential, cx);
        if name.is_empty() {
            self.fail("请先填写凭据名称。", cx);
            return;
        }
        if forget {
            self.send(
                Kind::Forget,
                json!({"command":"forget_credential","name":name}),
                cx,
            );
        } else {
            let path = Self::field_value(&self.fields.env_path, cx);
            if path.is_empty() {
                self.fail("请选择 .env 文件或输入绝对 Windows 路径。", cx);
                return;
            }
            self.send(
                Kind::Import,
                json!({"command":"import_credential","name":name,"env_file":path}),
                cx,
            );
        }
    }

    pub(crate) fn choose_env(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let picker = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("选择住宅代理凭据 .env（不显示内容）".into()),
        });
        cx.spawn_in(window, async move |view, cx| match picker.await {
            Ok(Ok(Some(paths))) => {
                if let Some(path) = paths.first() {
                    let path = path.to_string_lossy().into_owned();
                    let _ = view.update_in(cx, |this, window, cx| {
                        this.fields
                            .env_path
                            .update(cx, |state, cx| state.set_value(path, window, cx));
                        this.notice = "已选择凭据文件。点击“导入命名凭据”才会由后台读取。".into();
                        cx.notify();
                    });
                }
            }
            Ok(Ok(None)) => {}
            _ => {
                let _ = view.update_in(cx, |this, _, cx| {
                    this.fail("无法打开文件选择器。可直接粘贴绝对 Windows 路径。", cx)
                });
            }
        })
        .detach();
    }
}