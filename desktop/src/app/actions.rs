//! 处理用户发起的校验、策略保存、接管、切换、停止和凭据操作。

use gpui_kit::component::{WindowExt, dialog::DialogButtonProps};
use gpui_kit::{prelude::*, *};
use serde_json::{Value, json};

use super::backend::Kind;
use super::components::text;
use super::model::{Confirmation, EnvironmentEditor, Field, PendingPrepare};
use super::state::Desktop;
use std::path::Path;

/// 转发限制输入框、策略字段名、允许范围、出错提示。
type LimitField<'a> = (
    &'a Field,
    &'static str,
    std::ops::RangeInclusive<u64>,
    &'static str,
);

fn valid_environment_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

impl Desktop {
    pub(crate) fn environment_install_path(base: &str, name: &str) -> String {
        let base_path = std::path::PathBuf::from(base);
        let already_named = base_path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case(name));
        let path = if already_named {
            base_path
        } else {
            base_path.join(name)
        };
        path.to_string_lossy().into_owned()
    }

    pub(crate) fn set_autostart(&mut self, enabled: bool, cx: &mut Context<Self>) {
        match super::autostart::set_enabled(enabled) {
            Ok(()) => {
                self.autostart_enabled = enabled;
                self.notice = if enabled {
                    "已启用开机自动启动。".into()
                } else {
                    "已关闭开机自动启动。".into()
                };
                self.error = false;
                cx.notify();
            }
            Err(error) => self.fail(format!("开机自启设置失败：{error}"), cx),
        }
    }

    pub(crate) fn fail(&mut self, error: impl Into<String>, cx: &mut Context<Self>) {
        self.notice = super::backend::humanize_error(&error.into());
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
    pub(crate) fn field_value(field: &Field, cx: &App) -> String {
        field.value(cx)
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
            profile[key]
                .as_str()
                .map(str::trim)
                .map(str::to_owned)
                .or_else(|| profile[key].as_u64().map(|value| value.to_string()))
                .unwrap_or_default()
        }
    }
    pub(crate) fn draft_is_dirty(&self, cx: &App) -> bool {
        if self.selected != self.saved_selected
            || Self::field_value(&self.fields.port, cx) != self.saved_port
        {
            return true;
        }
        for (field, key, array) in [
            (&self.fields.first_hop, "first_hop", false),
            (&self.fields.dns_upstream, "dns_upstream", false),
            (&self.fields.dns_tls_name, "dns_tls_name", false),
            (&self.fields.health_domain, "health_domain", false),
            (&self.fields.direct_ips, "direct_ips", true),
            (&self.fields.direct_domains, "direct_domains", true),
            (&self.fields.direct_suffixes, "direct_suffixes", true),
            (
                &self.fields.max_tcp_connections,
                "max_tcp_connections",
                false,
            ),
            (
                &self.fields.tcp_idle_timeout,
                "tcp_idle_timeout_seconds",
                false,
            ),
            (
                &self.fields.tcp_half_close_timeout,
                "tcp_half_close_timeout_seconds",
                false,
            ),
        ] {
            if Self::field_value(field, cx) != Self::profile_field_value(&self.profile, key, array)
            {
                return true;
            }
        }
        for (field, key) in [
            (&self.fields.residential_ip, "ip"),
            (&self.fields.residential_port, "port"),
            (&self.fields.residential_username, "username"),
            (&self.fields.residential_password, "password"),
        ] {
            if Self::field_value(field, cx)
                != Self::profile_field_value(&self.residential, key, false)
            {
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
    pub(crate) fn selection(&self, cx: &App) -> Result<(String, u16), String> {
        let target = self.selected.clone().ok_or("请选择目标 WSL。")?;
        Ok((target, self.port(cx)?))
    }

    fn environment_display_name(&self, target: &str) -> String {
        self.distributions
            .iter()
            .find(|distro| distro["id"].as_str() == Some(target))
            .and_then(|distro| distro["name"].as_str())
            .unwrap_or(target)
            .to_owned()
    }
    pub(crate) fn draft(&self, cx: &App) -> Value {
        let mut profile = self.profile.as_object().cloned().unwrap_or_default();
        for (field, key, array) in [
            (&self.fields.first_hop, "first_hop", false),
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
        for (field, key, _, _) in self.limit_fields() {
            let text = Self::field_value(field, cx);
            if text.is_empty() {
                // 空着就用后台的默认值。
                profile.remove(key);
            } else {
                profile.insert(
                    key.into(),
                    text.parse::<u64>()
                        .map_or_else(|_| json!(text), |value| json!(value)),
                );
            }
        }
        profile.insert("credential".into(), json!("desktop-residence"));
        Value::Object(profile)
    }

    /// 转发限制的输入框、策略字段名、允许范围和出错提示。
    fn limit_fields(&self) -> [LimitField<'_>; 3] {
        [
            (
                &self.fields.max_tcp_connections,
                "max_tcp_connections",
                16..=1024,
                "并发 TCP 上限需为 16–1024 的整数，留空为默认 256。",
            ),
            (
                &self.fields.tcp_idle_timeout,
                "tcp_idle_timeout_seconds",
                30..=86_400,
                "TCP 空闲断开时间需为 30–86400 秒的整数，留空为默认 1800。",
            ),
            (
                &self.fields.tcp_half_close_timeout,
                "tcp_half_close_timeout_seconds",
                5..=3_600,
                "半关闭等待时间需为 5–3600 秒的整数，留空为默认 60。",
            ),
        ]
    }

    fn limits_valid(&self, cx: &App) -> Result<(), &'static str> {
        for (field, _, range, message) in self.limit_fields() {
            let text = Self::field_value(field, cx);
            if !text.is_empty()
                && !text
                    .parse::<u64>()
                    .is_ok_and(|value| range.contains(&value))
            {
                return Err(message);
            }
        }
        Ok(())
    }

    pub(crate) fn residential_draft(&self, cx: &App) -> Result<Value, &'static str> {
        let port = self.residential_port(cx)?;
        Ok(json!({
            "ip": Self::field_value(&self.fields.residential_ip, cx),
            "port": port,
            "username": Self::field_value(&self.fields.residential_username, cx),
            "password": Self::field_value(&self.fields.residential_password, cx),
        }))
    }

    pub(crate) fn residential_port(&self, cx: &App) -> Result<u16, &'static str> {
        Self::field_value(&self.fields.residential_port, cx)
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or("住宅服务器端口需为 1–65535 的整数。")
    }

    pub(crate) fn open_confirmation_dialog(&self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(confirmation) = self.confirmation.as_ref() else {
            return;
        };
        let message = confirmation.message.clone();
        let view = cx.entity().clone();
        window.open_alert_dialog(cx, move |dialog, _, _| {
            let ok_view = view.clone();
            let cancel_view = view.clone();
            dialog
                .confirm()
                .title(
                    div()
                        .text_base()
                        .font_weight(FontWeight::NORMAL)
                        .child("确认保护操作"),
                )
                .button_props(
                    DialogButtonProps::default()
                        .ok_text("确认并执行")
                        .cancel_text("取消"),
                )
                .description(div().text_base().child(message.clone()))
                .on_ok(move |_, _, cx| {
                    ok_view.update(cx, |this, cx| this.confirm(cx));
                    true
                })
                .on_cancel(move |_, _, cx| {
                    cancel_view.update(cx, |this, cx| {
                        this.confirmation = None;
                        cx.notify();
                    });
                    true
                })
        });
    }

    pub(crate) fn open_prepare_confirmation(
        &mut self,
        pending: PendingPrepare,
        cx: &mut Context<Self>,
    ) {
        let PendingPrepare {
            kind,
            generation,
            target,
            port,
        } = pending;
        let command = if kind == Kind::Start {
            "start"
        } else {
            "switch"
        };
        let request = json!({
            "command":command,
            "target":target,
            "port":port,
            "profile":self.profile_path,
            "profile_revision":self.revision,
            "expected_generation":generation
        });
        let target_name = self.environment_display_name(&target);
        let message = if kind == Kind::Switch {
            let active_target = text(&self.status, "active_target", "当前目标");
            let active_target_name = self.environment_display_name(&active_target);
            format!(
                "将从 {} 切换到 {target_name}。旧目标会先恢复直连；现有 TCP 连接需要重连。",
                active_target_name
            )
        } else {
            format!("将接管 {target_name} 的 TCP 和系统 DNS。非直连例外流量经代理链。")
        };
        self.confirmation = Some(Confirmation {
            kind,
            generation,
            request,
            message,
        });
        self.confirmation_pending = true;
        cx.notify();
    }

    pub(crate) fn prepare(&mut self, kind: Kind, window: &mut Window, cx: &mut Context<Self>) {
        if self.locked() {
            return;
        }
        let Some(generation) = self.generation() else {
            self.fail("后台状态未确认，请先刷新。", cx);
            return;
        };
        if kind == Kind::Abandon {
            self.confirmation = Some(Confirmation {
                kind,
                generation,
                request: json!({"command":"abandon","confirm":true,"expected_generation":generation}),
                message: "目标发行版已不在 WSL 注册表里，无法清理它的规则。将释放本次接管占用的端口并清掉恢复记录。WSL 里可能还残留本次接管的规则：下次启动接管前，请先在终端执行一次 wsl --shutdown（会关闭所有发行版）。".into(),
            });
            self.open_confirmation_dialog(window, cx);
            cx.notify();
            return;
        }
        if kind == Kind::Stop {
            self.confirmation = Some(Confirmation {
                kind,
                generation,
                request: json!({"command":"stop","expected_generation":generation}),
                message:
                    "将停止接管并恢复直连。现有 TCP 连接会中断，需要重连；只清理本控制器的规则。"
                        .into(),
            });
            self.open_confirmation_dialog(window, cx);
            cx.notify();
            return;
        }
        if self.dirty || !self.profile_exists || self.profile_path.is_none() {
            self.fail("请先保存策略和目标选择。未保存内容不会生效。", cx);
            return;
        }
        self.pending_prepare = None;
        let (target, port) = match self.selection(cx) {
            Ok(value) => value,
            Err(error) => {
                self.fail(error, cx);
                return;
            }
        };
        self.preflight = None;
        self.pending_prepare = Some(PendingPrepare {
            kind,
            generation,
            target: target.clone(),
            port,
        });
        self.send(
            Kind::Preflight,
            json!({"command":"preflight","target":target,"port":port}),
            cx,
        );
    }

    /// 只在空闲时可用。只加载目标发行版里已经存在的模块，但影响共享内核，
    /// 所以要用户确认；不安装软件包、不启动接管。
    pub(crate) fn prepare_kernel(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.locked() {
            return;
        }
        if !self.idle() {
            self.fail("请先停止接管并恢复直连，再准备内核环境。", cx);
            return;
        }
        let Some(generation) = self.generation() else {
            self.fail("后台状态未确认，请先刷新。", cx);
            return;
        };
        let Some(target) = self.selected.clone() else {
            self.fail("请先选择目标 WSL。", cx);
            return;
        };
        let target_name = self.environment_display_name(&target);
        self.confirmation = Some(Confirmation {
            kind: Kind::PrepareKernel,
            generation,
            request: json!({
                "command":"prepare_kernel",
                "target":target,
                "confirm":true
            }),
            message: format!(
                "将为 {target_name} 加载发行版里已有的内核模块（含 xt_cgroup、ip6table_nat 等 12 个），并创建空的 filter/nat 表。这会影响同一 WSL 内核上的所有发行版，直到 WSL 重启；不安装软件包、不改 .wslconfig、不启动接管。"
            ),
        });
        self.open_confirmation_dialog(window, cx);
        cx.notify();
    }

    /// 只在空闲时可用。清空别名记录可能让旧别名分给别的域名，先确认。
    pub(crate) fn prepare_reset_dns_aliases(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.locked() {
            return;
        }
        if self.phase() != "idle" {
            self.fail("请先停止接管并恢复直连，再重置 DNS 别名。", cx);
            return;
        }
        let Some(generation) = self.generation() else {
            self.fail("后台状态未确认，请先刷新。", cx);
            return;
        };
        self.confirmation = Some(Confirmation {
            kind: Kind::ResetDnsAliases,
            generation,
            request: json!({"command":"reset_dns_aliases","confirm":true}),
            message: "将清空白名单域名的 DNS 别名记录（包括没写完的那次修改），只在提示 DNS 别名号段已用完或别名记录异常时使用。重置后旧别名可能分给别的域名：请先确认目标发行版里没有还在用旧解析结果的程序，例如重启目标发行版，或等几分钟再重置。".into(),
        });
        self.open_confirmation_dialog(window, cx);
        cx.notify();
    }

    pub(crate) fn confirm(&mut self, cx: &mut Context<Self>) {
        let Some(confirmation) = self.confirmation.take() else {
            return;
        };
        self.confirmation_pending = false;
        if self.generation() != Some(confirmation.generation) {
            self.fail("确认期间后台状态已变化，请刷新后重试。", cx);
            return;
        }
        self.send(confirmation.kind, confirmation.request, cx);
    }

    pub(crate) fn probe(&mut self, cx: &mut Context<Self>) {
        if self.phase() != "forwarding_managed" {
            self.fail("只有接管中的目标才能检测公网出口。", cx);
            return;
        }
        let Some(generation) = self.generation() else {
            self.fail("后台状态未确认，请先刷新。", cx);
            return;
        };
        self.send(
            Kind::Probe,
            json!({"command":"probe_exit","expected_generation":generation}),
            cx,
        );
    }

    pub(crate) fn save(&mut self, cx: &mut Context<Self>) {
        if let Err(error) = self.limits_valid(cx) {
            self.fail(error, cx);
            return;
        }
        let port = match self.port(cx) {
            Ok(port) => port,
            Err(error) => {
                self.fail(error, cx);
                return;
            }
        };
        let residential = match self.residential_draft(cx) {
            Ok(value) => value,
            Err(error) => {
                self.fail(error, cx);
                return;
            }
        };
        self.send(Kind::Save, json!({"command":"profile_save","profile":self.draft(cx),"residential":residential,"expected_revision":self.revision,
            "desktop":{"target":self.selected,"port":port}}), cx);
    }

    pub(crate) fn environment_create(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.locked() {
            return;
        }
        self.environment_editor = Some(EnvironmentEditor::Create);
        self.environment_edit_target = None;
        self.environment_selected = None;
        self.environment_detail = None;
        self.environment_started = None;
        self.environment_backup_target = None;
        self.backup_result_path = None;
        self.environment_zsh = true;
        self.environment_chrome = true;
        self.environment_chinese = true;
        self.fields.environment_name.set_value("", window, cx);
        self.fields
            .environment_distribution
            .set_value("Ubuntu-24.04", window, cx);
        self.environment_distribution_select
            .update(cx, |state, cx| {
                state.set_selected_value(&"Ubuntu-24.04", window, cx);
            });
        self.fields.environment_install.set_value("", window, cx);
        self.fields.environment_backup.set_value("", window, cx);
        self.fields
            .environment_username
            .set_value("dev", window, cx);
        self.fields.environment_password.set_value("", window, cx);
        self.fields.environment_timezone.set_value("", window, cx);
        self.environment_backup_target = None;
        self.notice = "选择发行版、安装目录和默认用户，然后创建环境。".into();
        self.error = false;
        cx.notify();
    }

    pub(crate) fn environment_edit(
        &mut self,
        name: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.locked() {
            return;
        }
        self.environment_editor = Some(EnvironmentEditor::Edit);
        self.environment_edit_target = Some(name.clone());
        self.environment_selected = Some(name.clone());
        self.fields
            .environment_name
            .set_value(name.clone(), window, cx);
        self.fields
            .environment_distribution
            .set_value("Ubuntu-24.04", window, cx);
        self.fields.environment_install.set_value("", window, cx);
        self.fields.environment_backup.set_value("", window, cx);
        self.fields.environment_username.set_value("", window, cx);
        self.fields.environment_password.set_value("", window, cx);
        self.fields.environment_timezone.set_value("", window, cx);
        self.send(
            Kind::EnvironmentView,
            json!({"command":"environment_view","name":name}),
            cx,
        );
    }

    pub(crate) fn environment_view(
        &mut self,
        name: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.locked() {
            return;
        }
        if self.environment_editor.is_some() {
            self.fail("请先取消或保存当前环境表单。", cx);
            return;
        }
        self.environment_selected = Some(name.clone());
        self.environment_editor = None;
        self.environment_edit_target = None;
        self.environment_detail = None;
        self.fields.environment_backup.set_value("", window, cx);
        self.fields.environment_timezone.set_value("", window, cx);
        self.environment_backup_target = None;
        self.send(
            Kind::EnvironmentView,
            json!({"command":"environment_view","name":name}),
            cx,
        );
    }

    pub(crate) fn open_target_environment(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.environment_editor.is_some() || self.locked() {
            return;
        }
        let Some(target) = self.selected.clone() else {
            return;
        };
        let detail_is_target = self
            .environment_detail
            .as_ref()
            .and_then(|detail| detail["id"].as_str())
            == Some(target.as_str());
        if detail_is_target {
            return;
        }
        self.environment_view(target, window, cx);
    }

    pub(crate) fn environment_submit(&mut self, cx: &mut Context<Self>) {
        if self.locked() {
            return;
        }
        let name = Self::field_value(&self.fields.environment_name, cx);
        if !valid_environment_name(&name) {
            self.fail(
                "环境名称只能使用字母、数字、点、下划线和短横线，且必须以字母或数字开头。",
                cx,
            );
            return;
        }
        let Some(editor) = self.environment_editor else {
            self.fail("请先点击新增环境或编辑。", cx);
            return;
        };
        let (kind, request) = match editor {
            EnvironmentEditor::Create => {
                let distribution = Self::field_value(&self.fields.environment_distribution, cx);
                let install_base = Self::field_value(&self.fields.environment_install, cx);
                let install = Self::environment_install_path(&install_base, &name);
                let username = Self::field_value(&self.fields.environment_username, cx);
                let password = Self::field_value(&self.fields.environment_password, cx);
                if distribution.is_empty() || install_base.is_empty() {
                    self.fail("新增环境需要发行版和安装目录。", cx);
                    return;
                }
                if std::path::Path::new(&install).exists() {
                    self.fail("实际环境目录已存在，请选择其他父目录或环境名称。", cx);
                    return;
                }
                if username.is_empty() || password.is_empty() {
                    self.fail("新增环境需要默认用户名和密码。", cx);
                    return;
                }
                (
                    Kind::EnvironmentCreate,
                    json!({
                        "command":"environment_create",
                        "name":name,
                        "distribution":distribution,
                        "install_path":install,
                        "username":username,
                        "password":password,
                        "install_zsh":self.environment_zsh,
                        "install_chrome":self.environment_chrome,
                        "install_chinese":self.environment_chinese
                    }),
                )
            }
            EnvironmentEditor::Edit => {
                let target = self
                    .environment_edit_target
                    .clone()
                    .unwrap_or_else(|| name.clone());
                (
                    Kind::EnvironmentEdit,
                    json!({
                        "command":"environment_edit",
                        "name":target,
                        "install_zsh":self.environment_zsh,
                        "install_chrome":self.environment_chrome,
                        "install_chinese":self.environment_chinese
                    }),
                )
            }
        };
        self.environment_timezone_only = false;
        if matches!(kind, Kind::EnvironmentCreate | Kind::EnvironmentEdit) {
            self.environment_started = Some(std::time::Instant::now());
        }
        self.send(kind, request, cx);
    }

    pub(crate) fn environment_timezone_save(&mut self, cx: &mut Context<Self>) -> bool {
        if self.locked() {
            return false;
        }
        let Some(name) = self.environment_selected.clone().or_else(|| {
            self.environment_detail
                .as_ref()?
                .get("name")?
                .as_str()
                .map(str::to_owned)
        }) else {
            self.fail("请先选择一个环境。", cx);
            return false;
        };
        let timezone = Self::field_value(&self.fields.environment_timezone, cx);
        if timezone.is_empty() {
            self.fail("请填写时区，例如 Asia/Shanghai。", cx);
            return false;
        }
        self.environment_timezone_only = true;
        self.environment_started = Some(std::time::Instant::now());
        self.send(
            Kind::EnvironmentEdit,
            json!({
                "command":"environment_edit",
                "name":name,
                "install_zsh":false,
                "install_chrome":false,
                "install_chinese":false,
                "timezone":timezone
            }),
            cx,
        );
        true
    }

    pub(crate) fn environment_backup(
        &mut self,
        name: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.locked() {
            return;
        }
        self.environment_backup_target = Some(name);
        self.fields.environment_backup.set_value("", window, cx);
        self.backup_dialog_open = true;
        self.open_backup_dialog(window, cx);
    }

    pub(crate) fn environment_backup_submit(&mut self, cx: &mut Context<Self>) -> bool {
        if self.locked() {
            return false;
        }
        let Some(name) = self.environment_backup_target.clone() else {
            self.fail("请先选择一个环境。", cx);
            return false;
        };
        let path = Self::field_value(&self.fields.environment_backup, cx);
        if path.is_empty() {
            self.fail("请填写备份文件路径。", cx);
            return false;
        }
        self.send(
            Kind::EnvironmentBackup,
            json!({"command":"environment_backup","name":name,"backup_path":path}),
            cx,
        );
        true
    }

    pub(crate) fn environment_delete(
        &mut self,
        name: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.locked() {
            return;
        }
        let view = cx.entity().clone();
        let confirm_name = name.clone();
        window.open_alert_dialog(cx, move |dialog, _, _| {
            let ok_view = view.clone();
            let cancel_view = view.clone();
            dialog
                .confirm()
                .title(
                    div()
                        .text_base()
                        .font_weight(FontWeight::NORMAL)
                        .child("删除环境"),
                )
                .button_props(
                    DialogButtonProps::default()
                        .ok_text("删除")
                        .cancel_text("取消"),
                )
                .description(div().text_base().child(format!(
                    "将注销 WSL 环境 {name}，环境内的文件和配置都会被删除。"
                )))
                .on_ok({
                    let confirm_name = confirm_name.clone();
                    move |_, _, cx| {
                        ok_view.update(cx, |this, cx| {
                            this.send(
                                Kind::EnvironmentDelete,
                                json!({
                                    "command":"environment_delete",
                                    "name":confirm_name.clone()
                                }),
                                cx,
                            );
                        });
                        true
                    }
                })
                .on_cancel(move |_, _, cx| {
                    cancel_view.update(cx, |_this, cx| cx.notify());
                    true
                })
        });
    }

    pub(crate) fn environment_cancel(&mut self, cx: &mut Context<Self>) {
        self.environment_editor = None;
        self.environment_edit_target = None;
        self.error = false;
        self.notice = "已取消编辑。".into();
        cx.notify();
    }

    pub(crate) fn environment_pick_install(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let picker = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("选择 WSL 安装目录".into()),
        });
        cx.spawn_in(window, async move |view, cx| match picker.await {
            Ok(Ok(Some(paths))) => {
                if let Some(path) = paths.first() {
                    let path = path.to_string_lossy().into_owned();
                    let _ = view.update_in(cx, |this, window, cx| {
                        this.fields.environment_install.set_value(path, window, cx);
                        cx.notify();
                    });
                }
            }
            Ok(Ok(None)) => {}
            _ => {
                let _ = view.update_in(cx, |this, _, cx| {
                    this.fail("无法打开文件夹选择器，请直接填写绝对路径。", cx)
                });
            }
        })
        .detach();
    }

    pub(crate) fn environment_pick_backup(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let picker = cx.prompt_for_new_path(Path::new("."), Some("wsl-environment.tar"));
        cx.spawn_in(window, async move |view, cx| match picker.await {
            Ok(Ok(Some(path))) => {
                let path = path.to_string_lossy().into_owned();
                let _ = view.update_in(cx, |this, window, cx| {
                    this.fields.environment_backup.set_value(path, window, cx);
                    cx.notify();
                });
            }
            Ok(Ok(None)) => {}
            _ => {
                let _ = view.update_in(cx, |this, _, cx| {
                    this.fail("无法打开保存位置选择器，请直接填写绝对路径。", cx)
                });
            }
        })
        .detach();
    }
}
