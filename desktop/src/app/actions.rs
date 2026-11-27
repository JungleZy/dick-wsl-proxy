//! 处理用户发起的校验、策略保存、接管、停止和凭据操作。

use gpui_kit::component::{WindowExt, button::ButtonVariant, dialog::DialogButtonProps};
use gpui_kit::{prelude::*, *};
use serde_json::{Value, json};

use super::backend::Kind;
use super::drafts::{
    PageDraft, ProfileField, SaveScope, Saved, Unsaved, environment_row, environment_save_request,
    ingress_port_value, names_target, profile_changed, residential_configured, residential_value,
    save_request, saved_fake_ip, saved_residential_protocol, saved_residential_text,
};
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

    /// 打开或关掉屏幕顶部状态岛。偏好写不进去时照样切换这一次，只是下次启动恢复原样。
    pub(crate) fn set_island(&mut self, enabled: bool, cx: &mut Context<Self>) {
        if enabled {
            super::island::open(cx);
        } else {
            super::island::close(cx);
        }
        self.island_enabled = enabled;
        match super::island::persist_enabled(enabled) {
            Ok(()) => {
                self.notice = if enabled {
                    "已打开屏幕顶部状态岛。".into()
                } else {
                    "已关闭屏幕顶部状态岛。".into()
                };
                self.error = false;
                cx.notify();
            }
            Err(error) => self.fail(
                format!("状态岛设置没能保存，下次启动会恢复原样：{error}"),
                cx,
            ),
        }
    }

    /// 设置页的全局不透明度滑块：拖动中立即重画状态岛和应用窗口；松手（`save`）时
    /// 再写注册表，拖动过程中不反复写。
    pub(crate) fn set_opacity(&mut self, percent: u32, save: bool, cx: &mut Context<Self>) {
        if super::opacity::percent() != percent {
            super::opacity::apply(percent);
            super::island::refresh(cx);
            // 应用窗口观察主界面，快照里的不透明度变了就重画。
            cx.notify();
        }
        if save && let Err(error) = super::opacity::save() {
            self.fail(format!("不透明度没能保存，下次启动会恢复原样：{error}"), cx);
        }
    }

    pub(crate) fn fail(&mut self, error: impl Into<String>, cx: &mut Context<Self>) {
        self.notice = super::backend::humanize_error(&error.into());
        self.error = true;
        cx.notify();
    }

    /// 对话框里的校验错误：显示在对话框内。全局错误条在遮罩后面，用户看不到。
    fn dialog_fail(&mut self, error: &str, cx: &mut Context<Self>) {
        self.dialog_error = Some(error.to_owned());
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
    /// 策略字段对应的输入框。
    pub(crate) fn profile_input(&self, field: ProfileField) -> &Field {
        match field {
            ProfileField::FirstHop => &self.fields.first_hop,
            ProfileField::DnsUpstream => &self.fields.dns_upstream,
            ProfileField::DnsTlsName => &self.fields.dns_tls_name,
            ProfileField::HealthDomain => &self.fields.health_domain,
            ProfileField::DirectDnsUpstream => &self.fields.direct_dns_upstream,
            ProfileField::DirectDnsTlsName => &self.fields.direct_dns_tls_name,
            ProfileField::DirectIps => &self.fields.direct_ips,
            ProfileField::DirectDomains => &self.fields.direct_domains,
            ProfileField::DirectSuffixes => &self.fields.direct_suffixes,
            ProfileField::MaxTcpConnections => &self.fields.max_tcp_connections,
            ProfileField::TcpIdleTimeout => &self.fields.tcp_idle_timeout,
            ProfileField::TcpHalfCloseTimeout => &self.fields.tcp_half_close_timeout,
        }
    }

    /// 勾选或取消设置页的「远端解析」。
    pub(crate) fn set_fake_ip_draft(&mut self, enabled: bool, cx: &mut Context<Self>) {
        self.fake_ip_draft = enabled;
        self.input_edited(Some(SaveScope::Settings), cx);
        cx.notify();
    }

    /// 选择环境页住宅代理的协议。
    pub(crate) fn set_residential_protocol_draft(
        &mut self,
        protocol: &'static str,
        cx: &mut Context<Self>,
    ) {
        self.residential_protocol_draft = protocol;
        self.input_edited(Some(SaveScope::Environment), cx);
        cx.notify();
    }

    /// 配置库里环境页正在看的那个环境的一行；没保存过时为 `None`。
    pub(crate) fn selected_row(&self) -> Option<&Value> {
        self.selected
            .as_deref()
            .and_then(|id| environment_row(&self.environments, id))
    }

    /// 正在看的环境已保存的住宅代理；没保存过时为 `null`。
    pub(crate) fn selected_residential(&self) -> Value {
        self.selected_row()
            .map(|row| row["residential"].clone())
            .unwrap_or(Value::Null)
    }

    /// 正在看的环境已保存的 Windows 入口端口；没保存过时为空，保存时由后台分配。
    pub(crate) fn selected_port_text(&self) -> String {
        self.selected_row()
            .and_then(|row| row["ingress_port"].as_u64())
            .map(|port| port.to_string())
            .unwrap_or_default()
    }

    /// 发行版名称对应的 ID；列表里没有时为 `None`。
    pub(crate) fn distro_id(&self, name: &str) -> Option<String> {
        self.distributions
            .iter()
            .find(|distro| names_target(distro, name))
            .and_then(|distro| distro["id"].as_str())
            .map(str::to_owned)
    }

    /// 后台记着的接管目标（接管中或需要恢复）的 ID；空闲或状态未确认时为 `None`。
    pub(crate) fn active_distro_id(&self) -> Option<String> {
        if !self.status_valid || self.phase() == "idle" {
            return None;
        }
        let name = self.status["active_target"]
            .as_str()
            .or_else(|| self.status["recorded_target"].as_str())?;
        self.distro_id(name)
    }

    pub(crate) fn residential_inputs(&self) -> [(&Field, &'static str); 4] {
        [
            (&self.fields.residential_ip, "ip"),
            (&self.fields.residential_port, "port"),
            (&self.fields.residential_username, "username"),
            (&self.fields.residential_password, "password"),
        ]
    }

    /// 环境页、规则页、设置页各自有没有改过还没保存的输入。环境页比的是正在看的那个环境。
    pub(crate) fn draft_unsaved(&self, cx: &App) -> Unsaved {
        let draft = |field| Self::field_value(self.profile_input(field), cx);
        let settings = self.fake_ip_draft != saved_fake_ip(&self.profile)
            || profile_changed(&self.profile, SaveScope::Settings, draft);
        let residential = self.selected_residential();
        let environment = self.selected.is_some()
            && (Self::field_value(&self.fields.port, cx) != self.selected_port_text()
                || self.residential_protocol_draft != saved_residential_protocol(&residential)
                || self.residential_inputs().into_iter().any(|(field, key)| {
                    Self::field_value(field, cx) != saved_residential_text(&residential, key)
                }));
        Unsaved {
            environment,
            policy: profile_changed(&self.profile, SaveScope::Policy, draft),
            settings,
        }
    }

    /// 编辑了某一页的输入框：重算各页的未保存状态；改的是保存失败那一页时，
    /// 标签从「保存失败」回到「有未保存修改」。
    pub(crate) fn input_edited(&mut self, scope: Option<SaveScope>, cx: &App) {
        self.preflight = None;
        self.pending_prepare = None;
        self.unsaved = self.draft_unsaved(cx);
        if let Some(scope) = scope {
            self.failed_saves.remove(scope);
        }
    }

    /// 启动接管前还没保存的内容；全部保存过时为 `None`。
    pub(crate) fn unsaved_message(&self) -> Option<String> {
        if let Some(pages) = self.unsaved.pages() {
            Some(format!(
                "{pages}有未保存的修改，请先在该页保存。未保存的内容不会生效。"
            ))
        } else if !self.profile_exists || self.profile_path.is_none() {
            Some("代理链设置还没有保存过，请先到设置页确认第一跳等设置并保存。".into())
        } else {
            None
        }
    }

    /// 要启动的环境和它已保存的入口端口：环境页正在看的那个，住宅代理要已经保存好。
    pub(crate) fn selection(&self) -> Result<(String, u16), String> {
        let target = self.selected.clone().ok_or("请先在环境页选一个环境。")?;
        let row = self.selected_row();
        if !residential_configured(row) {
            return Err("这个环境还没有保存住宅代理：先在环境页填写并保存。".into());
        }
        let port = row
            .and_then(|row| row["ingress_port"].as_u64())
            .and_then(|port| u16::try_from(port).ok())
            .ok_or("这个环境保存的 Windows 入口端口无效，请改正后保存。")?;
        Ok((target, port))
    }

    /// 环境页「启动接管」按钮为什么不能点；能点时为 `None`。
    pub(crate) fn start_blocker(&self) -> Option<String> {
        if !self.status_valid {
            return Some("后台状态未确认".into());
        }
        if let Some(active) = self.active_distro_id() {
            let name = self.environment_display_name(&active);
            return Some(format!(
                "{name} 正在接管或需要恢复；一次只能接管一个环境，请先停止它"
            ));
        }
        if self.phase() != "idle" {
            return Some("当前有接管任务，请先停止".into());
        }
        if let Some(message) = self.unsaved_message() {
            return Some(message);
        }
        self.selection().err()
    }

    /// 托盘「去恢复接管」：打开需要恢复的那个环境的页面。
    pub(crate) fn open_recovery_environment(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let name = self
            .active_distro_id()
            .map(|id| self.environment_display_name(&id));
        match name {
            Some(name) => {
                self.open_page(super::model::Page::Environment, cx);
                self.environment_view(name, window, cx);
            }
            None => self.open_page(super::model::Page::Overview, cx),
        }
    }

    pub(crate) fn environment_display_name(&self, target: &str) -> String {
        self.distributions
            .iter()
            .find(|distro| names_target(distro, target))
            .and_then(|distro| distro["name"].as_str())
            .unwrap_or(target)
            .to_owned()
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

    /// 住宅代理四项都空时按「还没配置」保存，否则端口必须有效。协议随选择一起保存。
    pub(crate) fn residential_draft(&self, cx: &App) -> Result<Value, &'static str> {
        residential_value(
            self.residential_protocol_draft,
            &Self::field_value(&self.fields.residential_ip, cx),
            &Self::field_value(&self.fields.residential_port, cx),
            &Self::field_value(&self.fields.residential_username, cx),
            &Self::field_value(&self.fields.residential_password, cx),
        )
    }

    pub(crate) fn open_confirmation_dialog(&self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(confirmation) = self.confirmation.as_ref() else {
            return;
        };
        let message = confirmation.message.clone();
        let kernel_prompt = confirmation.kind == Kind::PrepareKernel;
        let (title, ok_text) = if kernel_prompt {
            ("准备内核环境", "加载并继续")
        } else if confirmation.exit {
            ("退出 WSL Proxy", "停止接管并退出")
        } else {
            ("确认保护操作", "确认并执行")
        };
        let view = cx.entity().clone();
        window.open_alert_dialog(cx, move |dialog, _, _| {
            let ok_view = view.clone();
            let cancel_view = view.clone();
            dialog
                .confirm()
                .title(div().text_sm().font_weight(FontWeight::NORMAL).child(title))
                .button_props(
                    DialogButtonProps::default()
                        .ok_text(ok_text)
                        .cancel_text("取消"),
                )
                .description(div().text_sm().child(message.clone()))
                .on_ok(move |_, _, cx| {
                    ok_view.update(cx, |this, cx| this.confirm(cx));
                    true
                })
                .on_cancel(move |_, _, cx| {
                    cancel_view.update(cx, |this, cx| {
                        this.confirmation = None;
                        if kernel_prompt {
                            this.pending_prepare = None;
                            this.notice = "已取消加载内核能力；缺少这些能力时无法启动接管。".into();
                            this.error = true;
                        }
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
            port: _,
        } = pending;
        // 不带端口：后台用这个环境保存的入口端口。两个版本号让后台确认启动的正是
        // 界面上显示为已保存的共用配置和这个环境的住宅代理。
        let residential_revision = environment_row(&self.environments, &target)
            .map(|row| row["revision"].clone())
            .unwrap_or(Value::Null);
        let request = json!({
            "command":"start",
            "target":target,
            "profile":self.profile_path,
            "profile_revision":self.revision,
            "residential_revision":residential_revision,
            "expected_generation":generation
        });
        let target_name = self.environment_display_name(&target);
        let message = format!(
            "将用 {target_name} 自己的住宅代理接管它的 TCP、UDP 和系统 DNS；只有直连例外的 TCP 连接直连，其余经代理链。接管前会把 {target_name} 的时区改成住宅出口所在时区并重启它，其中正在运行的程序都会被结束。"
        );
        self.confirmation = Some(Confirmation {
            kind,
            generation,
            request,
            message,
            exit: false,
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
                exit: false,
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
                exit: false,
            });
            self.open_confirmation_dialog(window, cx);
            cx.notify();
            return;
        }
        if let Some(message) = self.unsaved_message() {
            self.fail(message, cx);
            return;
        }
        self.pending_prepare = None;
        self.kernel_prepare_offered = false;
        let (target, port) = match self.selection() {
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

    /// 启动前预检发现目标内核缺少所需能力时，把「加载目标已有模块」作为一次
    /// 确认，而不是常驻按钮；确认后由 PrepareKernel 的结果处理重新预检。
    pub(crate) fn prompt_kernel_prepare(
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
        let target_name = self.environment_display_name(&target);
        self.notice = format!("预检未通过：{target_name} 的内核缺少所需能力。");
        self.error = true;
        self.confirmation = Some(Confirmation {
            kind: Kind::PrepareKernel,
            generation,
            request: json!({
                "command":"prepare_kernel",
                "target":target.clone(),
                "confirm":true
            }),
            message: format!(
                "预检发现 {target_name} 缺少所需的内核能力（例如 xt_cgroup、ip6table_nat）。是否现在加载发行版里已有的模块、创建空的 filter/nat 表，并写入开机配置（/etc/modules-load.d/wsl-proxy.conf 和一个注册空表的 systemd oneshot），让以后 WSL 启动时自动准备好？这些文件会保留在发行版里，可手工删除；不安装软件包，也不启动接管。"
            ),
            exit: false,
        });
        self.pending_prepare = Some(PendingPrepare {
            kind,
            generation,
            target,
            port,
        });
        self.confirmation_pending = true;
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
            exit: false,
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
        // 只有停止真的发出去了才进入退出流程。
        self.exiting = confirmation.exit && self.busy == Some(confirmation.kind);
    }

    /// 检查 WSL 平台：进入设置页和点「检查」时调用。只读，不占界面，不发页面提示。
    pub(crate) fn check_wsl_platform(&mut self, cx: &mut Context<Self>) {
        if self.wsl_platform_checking || self.busy.is_some() {
            return;
        }
        // 后台状态未确认时检查发不出去；在卡片上说明原因，免得「检查」按钮点了没反应。
        if !self.status_valid {
            self.wsl_platform_error =
                Some("后台状态未确认，暂时无法检查；请先点底部状态栏的后台图标重新连接。".into());
            cx.notify();
            return;
        }
        self.send(Kind::WslPlatform, json!({"command":"wsl_platform"}), cx);
    }

    /// 升级 WSL 会替换 WSL 包并可能重启 WSL，先说明影响再交给后台任务。
    pub(crate) fn prompt_wsl_update(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.locked() {
            return;
        }
        if !self.idle() {
            self.fail("请先停止接管并恢复直连，再升级 WSL。", cx);
            return;
        }
        let report = self.wsl_platform.clone();
        if report
            .as_ref()
            .is_some_and(|report| report["wsl"]["installed"].as_bool() == Some(false))
        {
            self.fail(
                "没有找到 wsl.exe，请先安装 Windows Subsystem for Linux。",
                cx,
            );
            return;
        }
        let version = report
            .as_ref()
            .and_then(|report| report["wsl"]["version"].as_str())
            .unwrap_or("未读取");
        // 没检查过平台时不知道权限，不能当成标准用户。
        let elevated = report
            .as_ref()
            .and_then(|report| report["elevated"].as_bool());
        let mut message = format!(
            "将运行 wsl --update 升级 WSL 平台（当前 WSL {version}）。它会替换 WSL 包，并可能重启 WSL：所有发行版里的程序和后台服务都会停止。不修改发行版里的文件和配置，也不启动接管。\n\n升级可能要很久，最多等 30 分钟；超过 30 分钟会结束 wsl --update，WSL 可能停在升级到一半。等待期间请不要关闭本程序、不要退出后台，也不要做别的环境操作，否则结果可能看不到或被误报为失败。如果升级失败、超时或没看到结果，请在 PowerShell 里运行 wsl --version 核对版本，必要时自己再运行一次 wsl --update。"
        );
        match elevated {
            Some(false) => {
                message.push_str("当前以标准用户运行，Windows 可能弹出管理员权限提示。");
            }
            None => message.push_str("还没有读到当前权限，Windows 可能弹出管理员权限提示。"),
            Some(true) => {}
        }
        let view = cx.entity().clone();
        window.open_alert_dialog(cx, move |dialog, _, _| {
            let ok_view = view.clone();
            let cancel_view = view.clone();
            dialog
                .confirm()
                .title(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::NORMAL)
                        .child("升级 WSL 平台"),
                )
                .button_props(
                    DialogButtonProps::default()
                        .ok_text("升级")
                        .cancel_text("取消"),
                )
                .description(div().text_sm().child(message.clone()))
                .on_ok(move |_, _, cx| {
                    ok_view.update(cx, |this, cx| {
                        this.send(
                            Kind::WslUpdate,
                            json!({"command":"wsl_platform_update","confirm":true}),
                            cx,
                        );
                    });
                    true
                })
                .on_cancel(move |_, _, cx| {
                    cancel_view.update(cx, |_this, cx| cx.notify());
                    true
                })
        });
    }

    /// 检测住宅代理：用已保存的配置，从 Windows 直连和经宿主 SOCKS5 各登录一次。
    /// 直连那一路会把账号密码不经前置代理发出去，先说明再发。
    pub(crate) fn prompt_residential_probe(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.locked() || self.residential_probe_checking {
            return;
        }
        if !self.status_valid {
            self.fail(
                "后台状态未确认，暂时无法检测；请先点底部状态栏的后台图标重新连接。",
                cx,
            );
            return;
        }
        // 检测只读配置库，输入框里没保存的值不会被用上。
        if self.unsaved.contains(SaveScope::Environment)
            || self.unsaved.contains(SaveScope::Settings)
        {
            self.fail(
                "住宅代理或设置有未保存的修改；检测只用已保存的配置，请先保存。",
                cx,
            );
            return;
        }
        let Some(distro_id) = self.selected.clone() else {
            return;
        };
        if !self.profile_exists || !residential_configured(self.selected_row()) {
            self.fail(
                "这个环境还没有保存住宅代理，或者代理链设置还没保存过；请先保存。",
                cx,
            );
            return;
        }
        let residential = self.selected_residential();
        let credentials = if saved_residential_protocol(&residential) == "http" {
            "HTTP 代理的用户名和密码只做 Base64 编码，等于明文"
        } else {
            "SOCKS5 的用户名和密码是明文"
        };
        let message = format!(
            "将用这个环境已保存的住宅代理检测两条路：一条从 Windows 直接连住宅服务器，一条经宿主 SOCKS5 连过去。两条都会登录，并让住宅代理连一次 DNS 上游，各自最多 8 秒。直连那一条不经前置代理：{credentials}，会经本地网络直接发出，住宅服务商也会看到你的真实 IP。检测不改变接管状态和规则。"
        );
        let view = cx.entity().clone();
        window.open_alert_dialog(cx, move |dialog, _, _| {
            let ok_view = view.clone();
            let distro_id = distro_id.clone();
            let cancel_view = view.clone();
            dialog
                .confirm()
                .title(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::NORMAL)
                        .child("检测住宅代理"),
                )
                .button_props(
                    DialogButtonProps::default()
                        .ok_text("检测")
                        .cancel_text("取消"),
                )
                .description(div().text_sm().child(message.clone()))
                .on_ok(move |_, _, cx| {
                    let distro_id = distro_id.clone();
                    ok_view.update(cx, move |this, cx| {
                        this.send(
                            Kind::ResidentialProbe,
                            json!({"command":"residential_probe","confirm":true,"distro_id":distro_id}),
                            cx,
                        );
                    });
                    true
                })
                .on_cancel(move |_, _, cx| {
                    cancel_view.update(cx, |_this, cx| cx.notify());
                    true
                })
        });
    }

    /// 托盘「退出」。总要用户先确认：空闲或状态未知时问一句是否退出，确认后请求
    /// 关闭后台，由后台自己核对是否空闲；接管中或需要恢复时确认框说明会先停止并恢复
    /// 直连，停止成功、后台回到空闲后再关闭后台。任何一步没成功，程序都不退出，并提示原因。
    pub(crate) fn request_exit(&mut self, cx: &mut Context<Self>) {
        if self.locked() {
            self.fail("当前操作还没完成，程序没有退出；完成后再从托盘退出。", cx);
            return;
        }
        if matches!(self.phase(), "idle" | "unknown") {
            // 由 tick 在加载框关掉后打开确认框（打开对话框要用 `Window`）。
            self.exit_confirm_pending = true;
            cx.notify();
            return;
        }
        self.request_stop_and_exit(cx);
    }

    /// 空闲时的退出确认框。
    pub(crate) fn open_exit_confirm_dialog(&self, window: &mut Window, cx: &mut Context<Self>) {
        let view = cx.entity().clone();
        window.open_alert_dialog(cx, move |dialog, _, _| {
            let ok_view = view.clone();
            dialog
                .confirm()
                .title(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::NORMAL)
                        .child("退出 WSL Proxy"),
                )
                .button_props(
                    DialogButtonProps::default()
                        .ok_text("退出")
                        .cancel_text("取消"),
                )
                .description(
                    div()
                        .text_sm()
                        .child("会关闭后台、状态岛和应用窗口，程序完全退出。"),
                )
                .on_ok(move |_, _, cx| {
                    ok_view.update(cx, |this, cx| this.exit_confirmed(cx));
                    true
                })
                .on_cancel(|_, _, _| true)
        });
    }

    /// 用户在退出确认框里点了「退出」。确认框开着的时候状态可能变了（例如别处启动了
    /// 接管），所以按现在的状态再判断一次；已经不空闲就改走停止并退出的确认。
    fn exit_confirmed(&mut self, cx: &mut Context<Self>) {
        if self.locked() {
            self.fail("当前操作还没完成，程序没有退出；完成后再从托盘退出。", cx);
            return;
        }
        if matches!(self.phase(), "idle" | "unknown") {
            self.send_shutdown(cx);
        } else {
            self.request_stop_and_exit(cx);
        }
    }

    /// 接管中或需要恢复时的退出：先确认停止并恢复直连。
    fn request_stop_and_exit(&mut self, cx: &mut Context<Self>) {
        let Some(generation) = self.generation() else {
            self.fail("后台状态未确认，程序没有退出；请先刷新。", cx);
            return;
        };
        self.confirmation = Some(Confirmation {
            kind: Kind::Stop,
            generation,
            request: json!({"command":"stop","expected_generation":generation}),
            message: "退出程序会先停止接管并恢复直连，再关闭后台。现有 TCP 连接会中断，需要重连；只清理本控制器的规则。停止没有完成时程序不会退出。".into(),
            exit: true,
        });
        // 由 tick 在加载框关掉后再打开，免得被同一帧关加载框时一并关掉。
        self.confirmation_pending = true;
        cx.notify();
    }

    /// 发出关闭后台请求。连发都发不出去（界面的通信线程已退出）时，
    /// 后台状态无从确认，交给用户决定是否只退出界面。
    fn send_shutdown(&mut self, cx: &mut Context<Self>) {
        self.send(Kind::Shutdown, json!({"command":"shutdown_daemon"}), cx);
        self.exiting = self.reading;
        if !self.exiting {
            self.exit_anyway_pending = true;
        }
    }

    /// 退出流程中的停止有了结果。停止成功且后台回到空闲才关闭后台；
    /// 否则结束退出流程，保留原因提示，程序继续运行。
    pub(crate) fn continue_exit_after_stop(&mut self, succeeded: bool, cx: &mut Context<Self>) {
        if succeeded && self.idle() {
            self.send_shutdown(cx);
            return;
        }
        self.exiting = false;
        let reason = if succeeded {
            "停止后后台没有回到空闲状态，请查看总览。".to_owned()
        } else {
            self.notice.clone()
        };
        self.fail(format!("程序没有退出。{reason}"), cx);
    }

    /// 关闭后台的结果。成功（或后台本来就不在运行）就退出程序。
    /// 后台拒绝关闭（仍在接管、需要恢复或有环境操作）时不退出，提示原因并重新读取状态。
    /// 联系不上后台时无法确认它是否还在运行，由用户决定是否只退出界面，避免程序无法退出。
    pub(crate) fn finish_exit(&mut self, result: Result<Value, String>, cx: &mut Context<Self>) {
        match result {
            // 后台进程已经不在（例如接管中崩溃或被结束）：没有谁关闭过接管，
            // 它最后报告的阶段不是空闲时，目标里的规则可能还在，不能说成「已关闭」。
            Ok(value)
                if value["absent"] == true
                    && self.status["phase"]
                        .as_str()
                        .is_some_and(|phase| phase != "idle") =>
            {
                self.exiting = false;
                self.fail(
                    "后台已经不在运行，而它最后报告的状态不是空闲，接管可能没有停止，程序没有退出。点「刷新」重新连接后台后再停止接管。",
                    cx,
                );
                self.exit_anyway_reason = Some((
                    "后台已经不在运行",
                    "后台最后报告的状态是接管中或需要恢复，之后进程没了，没有人停止过接管：目标 WSL 里的接管规则可能还在，新连接会不通。重新打开程序（或点「刷新」）会重新拉起后台，再停止接管就能恢复直连。仍然退出的话，只关闭界面。",
                ));
                self.exit_anyway_pending = true;
            }
            Ok(_) => {
                self.notice = "后台已关闭，正在退出。".into();
                self.error = false;
                if !super::tray::quit_application() {
                    cx.quit();
                }
            }
            // 后台的拒绝已由 `backend::request` 译成中文；`ipc_` 开头的只会是通信失败。
            Err(error) if error.starts_with("ipc_") => {
                self.exiting = false;
                self.fail("联系不上后台，无法确认它是否还在运行，程序没有退出。", cx);
                self.exit_anyway_pending = true;
            }
            Err(error) => {
                self.exiting = false;
                self.fail(
                    format!("程序没有退出。{}", super::backend::humanize_error(&error)),
                    cx,
                );
                self.send(Kind::Status, json!({"command":"status"}), cx);
            }
        }
    }

    pub(crate) fn open_exit_anyway_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (title, description) = self.exit_anyway_reason.take().unwrap_or((
            "联系不上后台",
            "无法确认后台是否还在运行。仍然退出的话，只关闭界面：后台如果还在运行会保留，接管不会停止。之后可以重新打开程序再从托盘退出。",
        ));
        window.open_alert_dialog(cx, move |dialog, _, _| {
            dialog
                .confirm()
                .title(div().text_sm().font_weight(FontWeight::NORMAL).child(title))
                .button_props(
                    DialogButtonProps::default()
                        .ok_text("仍然退出界面")
                        .cancel_text("取消"),
                )
                .description(div().text_sm().child(description))
                .on_ok(move |_, _, cx| {
                    if !super::tray::quit_application() {
                        cx.quit();
                    }
                    true
                })
                .on_cancel(|_, _, _| true)
        });
    }

    pub(crate) fn probe(&mut self, cx: &mut Context<Self>) {
        // 托盘也能触发检测。确认框开着时发出修改类请求会清掉待确认的操作，
        // 之后点「确认」不会有任何反应，所以先拒绝。
        if self.locked() {
            self.fail(
                "当前有操作在进行或等待确认，完成或取消后再检测公网出口。",
                cx,
            );
            return;
        }
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

    /// 保存一页：规则页、设置页只发这一页的输入，其他页的字段用已保存的值；
    /// 环境页只保存正在看的那个环境的住宅代理和入口端口。
    pub(crate) fn save(&mut self, scope: SaveScope, cx: &mut Context<Self>) {
        let request = match scope {
            SaveScope::Environment => match self.environment_request(cx) {
                Ok(request) => request,
                Err(error) => {
                    self.save_notice = Some(Err(super::backend::humanize_error(&error)));
                    cx.notify();
                    return;
                }
            },
            SaveScope::Policy => self.page_request(PageDraft::Policy, cx),
            SaveScope::Settings => match self.limits_valid(cx) {
                Ok(()) => self.page_request(
                    PageDraft::Settings {
                        fake_ip: self.fake_ip_draft,
                    },
                    cx,
                ),
                // 校验结果和保存结果一样，用保存结果通知弹出。
                Err(error) => {
                    self.save_notice = Some(Err(super::backend::humanize_error(error)));
                    cx.notify();
                    return;
                }
            },
        };
        self.send_save(scope, request, cx);
    }

    fn page_request(&self, page: PageDraft, cx: &App) -> Value {
        let saved = Saved {
            profile: &self.profile,
            revision: &self.revision,
        };
        save_request(&saved, page, |field| {
            Self::field_value(self.profile_input(field), cx)
        })
    }

    /// 环境页的保存请求；输入框的值不合格时返回原因。
    fn environment_request(&self, cx: &App) -> Result<Value, String> {
        let distro_id = self.selected.clone().ok_or("请先选一个环境。")?;
        let residential = self.residential_draft(cx)?;
        let port = ingress_port_value(&Self::field_value(&self.fields.port, cx))?;
        let revision = self
            .selected_row()
            .map(|row| row["revision"].clone())
            .unwrap_or(Value::Null);
        Ok(environment_save_request(
            &distro_id,
            residential,
            port,
            &revision,
        ))
    }

    /// 把旧版本留下的那一份住宅代理分给正在看的环境，或者丢掉它。
    pub(crate) fn settle_unassigned_residential(&mut self, assign: bool, cx: &mut Context<Self>) {
        if self.locked() {
            return;
        }
        if self.unsaved.contains(SaveScope::Environment) {
            self.fail("这个环境的住宅代理有未保存的修改，请先保存。", cx);
            return;
        }
        let request = match (assign, self.selected.clone()) {
            (true, Some(distro_id)) => {
                json!({"command":"environment_residential_assign","distro_id":distro_id})
            }
            (true, None) => return,
            (false, _) => json!({"command":"environment_residential_discard"}),
        };
        if !self.send_save(SaveScope::Environment, request, cx) {
            self.fail("有操作正在进行，请稍后再试。", cx);
        }
    }

    /// 发出一页的保存。有别的操作在进行、请求没有发出时返回 `false`。
    fn send_save(&mut self, scope: SaveScope, request: Value, cx: &mut Context<Self>) -> bool {
        // 发出的修改类请求都会让 `epoch` 加一；没加说明请求被丢弃了，
        // 这时可能还有一次保存在途，不能覆盖它记下的页面。
        let epoch = self.epoch;
        let previous = self.saving.replace(scope);
        self.send(Kind::Save, request, cx);
        let sent = self.epoch != epoch;
        if !sent {
            self.saving = previous;
        }
        sent
    }

    pub(crate) fn environment_create(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.locked() {
            return;
        }
        self.environment_editor = Some(EnvironmentEditor::Create);
        self.environment_edit_target = None;
        self.environment_selected = None;
        self.select_environment(None, window, cx);
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
        self.select_environment(Some(&name), window, cx);
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
        self.select_environment(Some(&name), window, cx);
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

    /// 环境页换到另一个环境（`None` 表示不看任何环境）：住宅代理和入口端口输入框换成它
    /// 保存的值，检测结果清掉。`environment_selected` 每次改动都经过这里，`selected`
    /// 才总是详情里显示的那个环境。上一个环境没保存的修改会丢掉，所以提醒一句。
    pub(crate) fn select_environment(
        &mut self,
        name: Option<&str>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let id = name.and_then(|name| self.distro_id(name));
        if id.as_deref().map(str::to_ascii_lowercase)
            == self.selected.as_deref().map(str::to_ascii_lowercase)
        {
            return;
        }
        if self.unsaved.contains(SaveScope::Environment) {
            let previous = self
                .selected
                .as_deref()
                .map(|id| self.environment_display_name(id))
                .unwrap_or_default();
            self.reminder = Some(super::state::Reminder {
                message: format!("{previous} 的住宅代理有没保存的修改，换环境时已丢弃。"),
                warning: false,
            });
        }
        self.selected = id;
        self.residential_probe = None;
        self.residential_probe_error = None;
        self.residential_probe_at = None;
        self.load_environment_fields(window, cx);
    }

    /// 读当前环境详情对应环境里装的图形应用。静默读取，同一时间只读一次。
    pub(crate) fn refresh_environment_apps(&mut self, cx: &mut Context<Self>) {
        if self.environment_apps_loading {
            return;
        }
        let Some(name) = self
            .environment_detail
            .as_ref()
            .and_then(|detail| detail["name"].as_str())
            .map(str::to_owned)
        else {
            return;
        };
        self.environment_apps_requested = Some(name.clone());
        self.send(
            Kind::EnvironmentApps,
            json!({"command":"environment_apps","name":name}),
            cx,
        );
    }

    /// 应用列表里这个 ID 的显示名；列表里没有时用 ID 去掉 `.desktop`。
    pub(crate) fn environment_app_name(&self, id: &str) -> String {
        self.environment_apps
            .as_ref()
            .and_then(|apps| apps["apps"].as_array())
            .into_iter()
            .flatten()
            .find(|app| app["id"].as_str() == Some(id))
            .and_then(|app| app["name"].as_str())
            .unwrap_or_else(|| id.trim_end_matches(".desktop"))
            .to_owned()
    }

    /// 详情页的「已安装应用」按钮：打开（或叫到前面）应用窗口，并重读当前环境的列表。
    pub(crate) fn open_app_launcher(&mut self, cx: &mut Context<Self>) {
        if self.environment_detail.is_none() {
            return;
        }
        self.environment_launch_result = None;
        self.refresh_environment_apps(cx);
        let snapshot = self.launcher_snapshot();
        super::launcher::open(cx.entity(), snapshot, cx);
        cx.notify();
    }

    /// 应用窗口里的流量提示：这个环境没有在接管时，应用直连上网。和后台实际接管的
    /// 目标比，不是和环境页正在看的那个比。
    pub(crate) fn environment_traffic_hint(&self, name: &str) -> Option<&'static str> {
        let id = self
            .distributions
            .iter()
            .find(|distro| {
                distro["name"]
                    .as_str()
                    .is_some_and(|listed| listed.eq_ignore_ascii_case(name))
            })
            .and_then(|distro| distro["id"].as_str());
        let active = self.active_distro_id();
        let target = id.is_some_and(|id| {
            active
                .as_deref()
                .is_some_and(|active| active.eq_ignore_ascii_case(id))
        });
        if target {
            None
        } else if self.phase() == "idle" {
            Some("接管未启动，应用直连上网")
        } else {
            Some("不是接管目标，应用直连上网")
        }
    }

    /// 应用列表所属环境有没有 WSLg。只在确定不可用时返回 `false`；没读到（旧后台、
    /// 详情已换成别的环境）时照样让用户试。
    pub(crate) fn environment_apps_graphics(&self) -> bool {
        let listed = self
            .environment_apps
            .as_ref()
            .and_then(|apps| apps["name"].as_str());
        let detail = self.environment_detail.as_ref();
        let same = listed
            .zip(detail.and_then(|detail| detail["name"].as_str()))
            .is_some_and(|(listed, name)| listed.eq_ignore_ascii_case(name));
        !(same
            && detail.is_some_and(|detail| {
                super::environment_facts::graphics(&detail["features"]) == "WSLg 不可用"
            }))
    }

    /// 在环境里以默认用户启动一个应用。不要求空闲：在接管中的环境里开应用正是用途。
    pub(crate) fn environment_launch(&mut self, app: String, cx: &mut Context<Self>) {
        if self.environment_launching.is_some() || self.busy.is_some() {
            return;
        }
        let Some(name) = self
            .environment_apps
            .as_ref()
            .and_then(|apps| apps["name"].as_str())
            .map(str::to_owned)
        else {
            return;
        };
        self.environment_launching = Some(app.clone());
        self.environment_launch_result = None;
        self.send(
            Kind::EnvironmentLaunch,
            json!({"command":"environment_launch","name":name,"app":app}),
            cx,
        );
    }

    /// 后台确认正在接管时的接管目标（`active_target`，发行版 ID 或名称）；其余情况为空。
    pub(crate) fn island_target(&self) -> Option<&str> {
        if !self.status_valid || self.phase() != "forwarding_managed" {
            return None;
        }
        self.status["active_target"].as_str()
    }

    /// 每次刷新调用：接管目标变了就换一份岛上的应用列表并读一次，接管结束就清空。
    /// 清空要紧：图标是 `\\wsl.localhost` 下的文件，停止后还去读会把发行版又拉起来。
    pub(crate) fn sync_island_apps(&mut self, cx: &mut Context<Self>) {
        let target = self.island_target().map(str::to_owned);
        if target == self.island_apps_for {
            return;
        }
        self.island_apps = None;
        self.island_apps_error = None;
        self.island_apps_for = target;
        if self.island_apps_for.is_some() {
            self.request_island_apps(cx);
        }
    }

    pub(crate) fn request_island_apps(&mut self, cx: &mut Context<Self>) {
        if self.island_apps_loading {
            return;
        }
        let Some(target) = self.island_apps_for.clone() else {
            return;
        };
        self.island_apps_requested = Some(target.clone());
        self.send(
            Kind::IslandApps,
            json!({"command":"environment_apps","name":target}),
            cx,
        );
    }

    /// 岛上的应用胶囊该画什么。
    pub(crate) fn island_apps_state(&self) -> super::island::Apps {
        use super::island::Apps;
        if let Some(error) = &self.island_apps_error {
            return Apps::Failed(error.clone());
        }
        match self.island_apps.as_ref().and_then(super::launcher::tiles) {
            Some(tiles) => Apps::Listed(tiles),
            None => Apps::Loading,
        }
    }

    /// 处理岛上的点击：启动应用，或者重读失败的列表。
    pub(crate) fn handle_island_request(
        &mut self,
        request: super::island::Request,
        cx: &mut Context<Self>,
    ) {
        match request {
            super::island::Request::RetryApps => {
                if self.island_apps_for.is_some() {
                    self.island_apps_error = None;
                    self.request_island_apps(cx);
                }
            }
            super::island::Request::Launch(app) => {
                // 停止、切换进行中阶段还是「接管中」，这时启动的应用可能落在已经恢复直连的
                // 环境里；和环境页一样等操作结束。
                if self.island_launching.is_some() || self.busy.is_some() {
                    return;
                }
                let Some(name) = self
                    .island_apps
                    .as_ref()
                    .and_then(|apps| apps["name"].as_str())
                    .map(str::to_owned)
                else {
                    return;
                };
                self.island_launching = Some(app.clone());
                self.send(
                    Kind::IslandLaunch,
                    json!({"command":"environment_launch","name":name,"app":app}),
                    cx,
                );
            }
        }
        cx.notify();
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
            self.dialog_fail("请先选择一个环境。", cx);
            return false;
        };
        let timezone = Self::field_value(&self.fields.environment_timezone, cx);
        if timezone.is_empty() {
            self.dialog_fail("请选择时区。", cx);
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
            self.dialog_fail("请先选择一个环境。", cx);
            return false;
        };
        let path = Self::field_value(&self.fields.environment_backup, cx);
        if path.is_empty() {
            self.dialog_fail("请填写备份文件路径。", cx);
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
                        .text_sm()
                        .font_weight(FontWeight::NORMAL)
                        .child("删除环境"),
                )
                .button_props(
                    DialogButtonProps::default()
                        .ok_text("删除")
                        // 注销发行版并删除其中全部文件，不可恢复：用危险样式。
                        .ok_variant(ButtonVariant::Danger)
                        .cancel_text("取消"),
                )
                .description(div().text_sm().child(format!(
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
