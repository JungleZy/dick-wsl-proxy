use crate::{
    controller,
    desktop_store::{self, ResidentialSettings},
    environment::{self, InstallOptions},
    host,
    policy::{Config, profile::Preferences},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SqliteSave {
    profile: Config,
    desktop: Preferences,
    #[serde(default)]
    residential: Option<ResidentialSettings>,
    expected_revision: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentCreate {
    name: String,
    distribution: String,
    install_path: String,
    username: String,
    password: String,
    #[serde(default)]
    install_zsh: bool,
    #[serde(default)]
    install_chrome: bool,
    #[serde(default)]
    install_chinese: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentEdit {
    name: String,
    #[serde(default)]
    install_zsh: bool,
    #[serde(default)]
    install_chrome: bool,
    #[serde(default)]
    install_chinese: bool,
    #[serde(default)]
    timezone: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentKey {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentBackup {
    name: String,
    backup_path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentDelete {
    name: String,
}

fn environment_options(
    zsh: bool,
    chrome: bool,
    chinese: bool,
    username: Option<String>,
    password: Option<String>,
    timezone: Option<String>,
) -> InstallOptions {
    InstallOptions {
        zsh,
        chrome,
        chinese,
        username,
        password,
        timezone,
    }
}

fn require_idle(controller: &mut controller::Controller) -> Result<(), crate::command::Failure> {
    let phase = controller
        .status()
        .map_err(|error| crate::command::Failure::new("controller_error", error))?["phase"]
        .as_str()
        .unwrap_or("unknown")
        .to_owned();
    if phase != "idle" {
        return Err(crate::command::Failure::new(
            "environment_requires_idle",
            "先停止接管并恢复直连，再管理 WSL 环境",
        ));
    }
    Ok(())
}
fn profile_path() -> Result<PathBuf, String> {
    desktop_store::path()
}

fn sqlite_view(path: &Path) -> Result<Value, String> {
    let record = desktop_store::ensure(path)?;
    Ok(desktop_store::view(path, &record))
}

fn sqlite_save(path: &Path, req: SqliteSave) -> Result<Value, String> {
    let record = desktop_store::save(
        path,
        req.profile,
        req.desktop,
        req.residential,
        req.expected_revision,
    )?;
    Ok(desktop_store::view(path, &record))
}
// Diagnostics are an allowlist, not a recursive 'remove password' filter. No free-form
// strings, flow addresses, hostnames, distribution names, paths, or credential references.
fn sanitized(s: &Value) -> Value {
    let phase = s["phase"]
        .as_str()
        .filter(|p| {
            matches!(
                *p,
                "idle" | "recovery_required" | "forwarding_managed" | "forwarding_scoped"
            )
        })
        .unwrap_or("unknown");
    let mut counters = serde_json::Map::new();
    for k in [
        "chain_tcp",
        "direct_tcp",
        "direct_udp",
        "dns_tcp",
        "dns_udp",
        "chain_udp",
        "rejected_tcp",
        "rejected_udp",
        "metadata_queries",
        "metadata_successes",
        "metadata_transport_failures",
        "tcp_failures",
        "udp_failures",
    ] {
        if let Some(n) = s["forwarding"]["counters"][k].as_u64() {
            counters.insert(k.into(), n.into());
        }
    }
    json!({"schema":1,"phase":phase,"operation_generation":s["operation_generation"].as_u64(),"dns_managed":s["dns_managed"].as_bool(),"fresh_udp_dns":s["startup_verified"]["fresh_udp_dns"].as_bool(),"fresh_tcp_dns":s["startup_verified"]["fresh_tcp_dns"].as_bool(),"https_status":s["startup_verified"]["https_status"].as_u64(),"tx_bytes":s["forwarding"]["traffic"]["tx_bytes"].as_u64(),"rx_bytes":s["forwarding"]["traffic"]["rx_bytes"].as_u64(),"counters":counters})
}
fn export(controller: &controller::Controller) -> Result<Value, String> {
    let doc = sanitized(&controller.status()?);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "invalid_clock")?
        .as_nanos();
    let path = host::state_dir()?.join(format!("diagnostics-{now}.json"));
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(&mut f, &doc).map_err(|e| e.to_string())?;
    f.flush().map_err(|e| e.to_string())?;
    Ok(json!({"path":path}))
}

pub fn handle(mut request: Value, controller: &mut controller::Controller) -> (Value, bool) {
    let result = (|| -> Result<(Value, bool), crate::command::Failure> {
        let bad = |m: String| crate::command::Failure::new("desktop_request_failed", m);
        let cmd = request
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("missing_command".into()))?
            .to_owned();
        let data = match cmd.as_str() {
            "profile_get" => {
                let p = profile_path().map_err(bad)?;
                sqlite_view(&p).map_err(bad)?
            }
            "profile_save" => {
                let request = request
                    .as_object_mut()
                    .ok_or_else(|| bad("invalid_request".into()))?;
                request.remove("command");
                let req =
                    serde_json::from_value::<SqliteSave>(Value::Object(std::mem::take(request)))
                        .map_err(|_| bad("invalid_desktop_profile_fields".into()))?;
                sqlite_save(&profile_path().map_err(bad)?, req).map_err(bad)?
            }
            "environment_view" => {
                let request = request
                    .as_object_mut()
                    .ok_or_else(|| bad("invalid_environment_fields".into()))?;
                request.remove("command");
                let req = serde_json::from_value::<EnvironmentKey>(Value::Object(std::mem::take(
                    request,
                )))
                .map_err(|_| bad("invalid_environment_fields".into()))?;
                environment::view(&req.name).map_err(bad)?
            }
            "environment_create" => {
                require_idle(controller)?;
                let request = request
                    .as_object_mut()
                    .ok_or_else(|| bad("invalid_environment_fields".into()))?;
                request.remove("command");
                let req = serde_json::from_value::<EnvironmentCreate>(Value::Object(
                    std::mem::take(request),
                ))
                .map_err(|_| bad("invalid_environment_fields".into()))?;
                let environment = environment::create(
                    &req.name,
                    &req.distribution,
                    &req.install_path,
                    environment_options(
                        req.install_zsh,
                        req.install_chrome,
                        req.install_chinese,
                        Some(req.username.clone()),
                        Some(req.password.clone()),
                        None,
                    ),
                )
                .map_err(bad)?;
                json!({"environment":environment,"distributions":host::distributions().map_err(bad)?})
            }
            "environment_edit" => {
                require_idle(controller)?;
                let request = request
                    .as_object_mut()
                    .ok_or_else(|| bad("invalid_environment_fields".into()))?;
                request.remove("command");
                let req = serde_json::from_value::<EnvironmentEdit>(Value::Object(std::mem::take(
                    request,
                )))
                .map_err(|_| bad("invalid_environment_fields".into()))?;
                let environment = environment::edit(
                    &req.name,
                    environment_options(
                        req.install_zsh,
                        req.install_chrome,
                        req.install_chinese,
                        None,
                        None,
                        req.timezone,
                    ),
                )
                .map_err(bad)?;
                json!({"environment":environment})
            }
            "environment_backup" => {
                require_idle(controller)?;
                let request = request
                    .as_object_mut()
                    .ok_or_else(|| bad("invalid_environment_fields".into()))?;
                request.remove("command");
                let req = serde_json::from_value::<EnvironmentBackup>(Value::Object(
                    std::mem::take(request),
                ))
                .map_err(|_| bad("invalid_environment_fields".into()))?;
                let backup = environment::backup(&req.name, &req.backup_path).map_err(bad)?;
                json!({"backup":backup})
            }
            "environment_delete" => {
                require_idle(controller)?;
                let request = request
                    .as_object_mut()
                    .ok_or_else(|| bad("invalid_environment_fields".into()))?;
                request.remove("command");
                let req = serde_json::from_value::<EnvironmentDelete>(Value::Object(
                    std::mem::take(request),
                ))
                .map_err(|_| bad("invalid_environment_fields".into()))?;
                let environment = environment::remove(&req.name).map_err(bad)?;
                json!({
                    "environment":environment,
                    "distributions":host::distributions().map_err(bad)?
                })
            }
            "export_diagnostics" => export(controller).map_err(bad)?,
            "probe_exit" => {
                let generation = request["expected_generation"]
                    .as_u64()
                    .ok_or_else(|| bad("expected_generation_required".into()))?;
                controller.probe_exit(generation).map_err(bad)?;
                controller.status().map_err(bad)?
            }
            "shutdown_daemon" => {
                if controller.status().map_err(bad)?["phase"] != "idle" {
                    return Err(bad("stop_and_restore_before_daemon_shutdown".into()));
                }
                return Ok((json!({"shutdown":true}), true));
            }
            "list" | "status" | "preflight" | "import_credential" | "forget_credential"
            | "start" | "switch" | "stop" => {
                if matches!(&*cmd, "start" | "switch" | "stop")
                    && request["expected_generation"].as_u64().is_none()
                {
                    return Err(bad("expected_generation_required".into()));
                }
                if matches!(&*cmd, "start" | "switch") && request["profile"].is_string() {
                    let path = profile_path().map_err(bad)?;
                    let expect = request.as_object_mut().unwrap().remove("profile_revision");
                    let current_revision = desktop_store::revision(&path).map_err(bad)?;
                    let current_revision = current_revision.to_string();
                    if request["profile"].as_str().map(Path::new) != Some(path.as_path())
                        || current_revision == "0"
                        || expect.as_ref().and_then(Value::as_str)
                            != Some(current_revision.as_str())
                    {
                        return Err(bad("saved_profile_revision_required".into()));
                    }
                }
                let req = serde_json::from_value::<crate::command::Command>(request)
                    .map_err(|_| bad("invalid_request_fields".into()))?;
                return crate::command::dispatch_result(req, controller).map(|(_, v)| (v, false));
            }
            _ => return Err(bad("command_not_available_on_desktop_channel".into())),
        };
        Ok((data, false))
    })();
    result.unwrap_or_else(|e| (json!({"code":e.code,"message":e.message}), false))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exported_diagnostic_omits_network_identifiers_and_free_text() {
        let v = sanitized(
            &json!({"phase":"forwarding_managed","active_target":"secret","issue":"secret","active_policy":{"credential":"secret"},"forwarding":{"traffic":{"tx_bytes":12},"connections":{"recent":[{"destination":"secret"}]},"counters":{"chain_tcp":4,"last_error":"secret"}}}),
        );
        assert!(!v.to_string().contains("secret"));
        assert_eq!(v["tx_bytes"], 12);
        assert_eq!(v["counters"]["chain_tcp"], 4);
    }
}
