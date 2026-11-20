use crate::{
    controller,
    host,
    policy::{profile::{Document, Preferences}, Config},
    transition,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Save {
    profile: Config,
    desktop: Preferences,
    expected_revision: Option<String>,
}
fn profile_path() -> Result<PathBuf, String> {
    Ok(host::state_dir()?.join("desktop-policy.json"))
}
const MAX: usize = 256 * 1024;
fn read_doc(path: &Path) -> Result<Option<Document>, String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("desktop_profile_open:{e}")),
    };
    let meta = f.metadata().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err("desktop_profile_reparse_point".into());
        }
    }
    if !meta.is_file() || meta.len() > MAX as u64 {
        return Err("desktop_profile_not_regular_or_too_large".into());
    }
    let mut bytes = Vec::new();
    f.take((MAX + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX {
        return Err("desktop_profile_too_large".into());
    }
    let doc: Document = serde_json::from_slice(&bytes).map_err(|_| "desktop_profile_invalid")?;
    if doc.revision == 0 {
        return Err("desktop_profile_revision_invalid".into());
    }
    doc.profile.validate_draft()?;
    doc.desktop.validate()?;
    Ok(Some(doc))
}
fn view(path: &Path, doc: Option<Document>) -> Value {
    match doc {
        Some(d) => {
            json!({"exists":true,"revision":d.revision.to_string(),"path":path,"profile":d.profile,"desktop":d.desktop})
        }
        None => {
            json!({"exists":false,"revision":null,"path":path,"desktop":Preferences::default(),"profile":{"first_hop":"127.0.0.1:7892","credential":"my-residence","dns_upstream":"223.5.5.5:443","dns_tls_name":"dns.alidns.com","health_domain":"ippure.com","direct_ips":[],"direct_domains":[],"direct_suffixes":[],"allow_loopback_residential":false}})
        }
    }
}
fn save(path: &Path, req: Save) -> Result<Value, String> {
    req.profile.validate_draft()?;
    req.desktop.validate()?;
    let current = read_doc(path)?.map(|d| d.revision);
    if req.expected_revision != current.map(|n| n.to_string()) {
        return Err("stale_profile_revision: reload the saved profile".into());
    }
    let d = Document {
        revision: current
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("revision_exhausted")?,
        profile: req.profile,
        desktop: req.desktop,
    };
    let bytes = serde_json::to_vec_pretty(&d).map_err(|e| e.to_string())?;
    if bytes.len() > MAX {
        return Err("desktop_profile_too_large".into());
    }
    let tmp = path.with_file_name(format!(
        "desktop-policy-{}-{}.tmp",
        std::process::id(),
        d.revision
    ));
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .map_err(|e| e.to_string())?;
    let commit = (|| {
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        transition::atomic_replace(&tmp, path)
    })();
    if let Err(e) = commit {
        let _ = fs::remove_file(tmp);
        return Err(format!("desktop_profile_commit:{e}"));
    }
    Ok(view(path, Some(d)))
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
                view(&p, read_doc(&p).map_err(bad)?)
            }
            "profile_save" => {
                let request = request
                    .as_object_mut()
                    .ok_or_else(|| bad("invalid_request".into()))?;
                request.remove("command");
                let req = serde_json::from_value::<Save>(Value::Object(std::mem::take(request)))
                    .map_err(|_| bad("invalid_desktop_profile_fields".into()))?;
                save(&profile_path().map_err(bad)?, req).map_err(bad)?
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
                    if request["profile"].as_str().map(Path::new) != Some(path.as_path())
                        || read_doc(&path).map_err(bad)?.is_none_or(|d| {
                            expect.as_ref().and_then(Value::as_str) != Some(&d.revision.to_string())
                        })
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
    #[test]
    fn stale_editor_cannot_overwrite_a_newer_policy() {
        let p = std::env::temp_dir().join(format!("wpl-profile-cas-{}.json", std::process::id()));
        let defaults = view(&p, None);
        let make = || Save {
            profile: serde_json::from_value(defaults["profile"].clone()).unwrap(),
            desktop: Preferences::default(),
            expected_revision: None,
        };
        let first = save(&p, make()).unwrap();
        let stale = save(&p, make()).unwrap_err();
        let current = read_doc(&p).unwrap().unwrap();
        fs::remove_file(&p).unwrap();
        assert_eq!(first["revision"], "1");
        assert!(stale.contains("stale_profile"));
        assert_eq!(current.revision, 1);
    }
}
