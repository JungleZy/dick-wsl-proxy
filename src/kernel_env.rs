//! Explicit cold-kernel preparation requested by the operator.
//!
//! Preflight stays read-only and never loads modules. This module is the only
//! path that changes the shared WSL kernel for that purpose: it loads module
//! files already shipped with the target, registers empty legacy tables, and
//! records what it saw. It never installs packages, writes persistent
//! configuration, unloads modules or touches rules.

use crate::host::Distro;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SCRIPT: &str = include_str!("guest/kernel_env.py");
const TIMEOUT: Duration = Duration::from_secs(45);

/// Fixed set of modules the takeover rules need. Kept in the same order as
/// `guest/kernel_env.py`; the guest response is rejected if it differs.
pub const REQUIRED_MODULES: [&str; 12] = [
    "ip_tables",
    "iptable_filter",
    "iptable_nat",
    "ip6_tables",
    "ip6table_filter",
    "ip6table_nat",
    "xt_cgroup",
    "xt_connmark",
    "xt_conntrack",
    "xt_comment",
    "xt_mark",
    "xt_nat",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Family {
    pub v4: Vec<String>,
    pub v6: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tables {
    pub before: Family,
    pub after: Family,
    pub added: Family,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailedModule {
    pub module: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TableFailure {
    pub family: String,
    pub table: String,
    pub reason: String,
}

/// What one preparation changed on the shared kernel. Serialized into the
/// command response and flattened into the on-disk record.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preparation {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    pub kernel_release: String,
    pub boot_id: String,
    pub netns: String,
    pub modules_dir: bool,
    pub modules_required: Vec<String>,
    pub modules_before: Vec<String>,
    pub modules_added: Vec<String>,
    pub modules_failed: Vec<FailedModule>,
    pub tables: Tables,
    pub table_failures: Vec<TableFailure>,
}

/// Loads the fixed module set and registers the empty tables. The guest decides
/// what is already present; a module that cannot be loaded is reported, not
/// retried and never forced.
pub fn prepare(distro: &Distro) -> Result<Preparation, String> {
    let script = format!(
        "if [ ! -x /usr/bin/python3 ]; then printf '%s\\n' '{{\"ok\":false,\"error\":\"python3_missing\"}}'; exit 0; fi\n\
         exec /usr/bin/python3 -I - <<'WSLPROXY_KERNEL_ENV_PY'\n{SCRIPT}\nWSLPROXY_KERNEL_ENV_PY\n"
    );
    let output = crate::host::guest_script_with_timeout(distro, &script, TIMEOUT)
        .map_err(|error| format!("kernel_env_guest_failed: {error}"))?;
    interpret(&output)
}

/// A refusal carries no evidence: only `ok` and a known reason. Anything else
/// must match the full evidence contract, so a truncated report is rejected
/// instead of being read as "nothing needed preparation".
#[derive(Deserialize)]
#[serde(untagged)]
enum GuestResponse {
    Evidence(Box<Preparation>),
    Refusal { ok: bool, error: String },
}

fn interpret(output: &str) -> Result<Preparation, String> {
    let response: GuestResponse = serde_json::from_str(output.trim())
        .map_err(|error| format!("kernel_env_invalid_response: {error}"))?;
    let preparation = match response {
        GuestResponse::Evidence(preparation) => *preparation,
        GuestResponse::Refusal { ok: false, error } => {
            if !matches!(
                error.as_str(),
                "root_required" | "python3_missing" | "internal_error"
            ) {
                return Err("kernel_env_invalid_refusal".into());
            }
            return Err(format!("kernel_env_refused: {error}"));
        }
        GuestResponse::Refusal { ok: true, .. } => {
            return Err("kernel_env_invalid_refusal".into());
        }
    };
    validate(&preparation)?;
    if !preparation.ok {
        return Err(format!(
            "kernel_env_refused: {}",
            preparation.error.as_deref().unwrap_or("unknown")
        ));
    }
    Ok(preparation)
}

fn module_name(value: &str) -> bool {
    (2..=64).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn table_name(value: &str) -> bool {
    matches!(value, "filter" | "nat" | "mangle" | "raw" | "security")
}

fn text(value: &str, limit: usize) -> bool {
    value
        .chars()
        .all(|character| character.is_ascii_graphic() || character == ' ')
        && value.len() <= limit
}

fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn check_modules(values: &[String], label: &str) -> Result<(), String> {
    if values.len() > REQUIRED_MODULES.len() {
        return Err(format!("kernel_env_{label}_too_many"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if !module_name(value) || !REQUIRED_MODULES.contains(&value.as_str()) {
            return Err(format!("kernel_env_{label}_invalid"));
        }
        if !seen.insert(value.as_str()) {
            return Err(format!("kernel_env_{label}_duplicate"));
        }
    }
    Ok(())
}

fn check_family(family: &Family, label: &str) -> Result<(), String> {
    for values in [&family.v4, &family.v6] {
        if values.len() > 16 || !sorted_unique(values) {
            return Err(format!("kernel_env_tables_{label}_not_sorted"));
        }
        if let Some(value) = values.iter().find(|value| !table_name(value)) {
            return Err(format!("kernel_env_tables_{label}_invalid:{value}"));
        }
    }
    Ok(())
}

fn validate(preparation: &Preparation) -> Result<(), String> {
    if !preparation.ok {
        let error = preparation.error.as_deref().unwrap_or_default();
        if !matches!(
            error,
            "root_required" | "python3_missing" | "internal_error"
        ) {
            return Err("kernel_env_invalid_refusal".into());
        }
        return Ok(());
    }
    if preparation.error.is_some() {
        return Err("kernel_env_unexpected_error".into());
    }
    if preparation.kernel_release.is_empty()
        || !text(&preparation.kernel_release, 128)
        || preparation.kernel_release.trim() != preparation.kernel_release
    {
        return Err("kernel_env_invalid_release".into());
    }
    if !preparation.boot_id.is_empty()
        && (!(8..=64).contains(&preparation.boot_id.len())
            || !preparation
                .boot_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-'))
    {
        return Err("kernel_env_invalid_boot_id".into());
    }
    if !preparation.netns.is_empty() {
        let namespace = preparation
            .netns
            .strip_prefix("net:[")
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or_default();
        if namespace.is_empty() || !namespace.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("kernel_env_invalid_netns".into());
        }
    }
    if preparation.modules_required.len() != REQUIRED_MODULES.len()
        || !preparation
            .modules_required
            .iter()
            .map(String::as_str)
            .eq(REQUIRED_MODULES)
    {
        return Err("kernel_env_unexpected_required_modules".into());
    }
    check_modules(&preparation.modules_before, "before")?;
    check_modules(&preparation.modules_added, "added")?;
    if preparation
        .modules_added
        .iter()
        .any(|module| preparation.modules_before.contains(module))
    {
        return Err("kernel_env_added_already_present".into());
    }
    if preparation.modules_failed.len() > REQUIRED_MODULES.len() {
        return Err("kernel_env_failed_too_many".into());
    }
    let mut failed = BTreeSet::new();
    for failure in &preparation.modules_failed {
        if !module_name(&failure.module)
            || !REQUIRED_MODULES.contains(&failure.module.as_str())
            || !failed.insert(failure.module.as_str())
            || preparation.modules_before.contains(&failure.module)
            || preparation.modules_added.contains(&failure.module)
        {
            return Err("kernel_env_failed_invalid".into());
        }
        if failure.reason.is_empty() || !text(&failure.reason, 256) {
            return Err("kernel_env_failed_reason_invalid".into());
        }
    }
    check_family(&preparation.tables.before, "before")?;
    check_family(&preparation.tables.after, "after")?;
    check_family(&preparation.tables.added, "added")?;
    for (before, after, added) in [
        (
            &preparation.tables.before.v4,
            &preparation.tables.after.v4,
            &preparation.tables.added.v4,
        ),
        (
            &preparation.tables.before.v6,
            &preparation.tables.after.v6,
            &preparation.tables.added.v6,
        ),
    ] {
        if before.iter().any(|table| !after.contains(table)) {
            return Err("kernel_env_table_removed".into());
        }
        let expected: Vec<&String> = after
            .iter()
            .filter(|table| !before.contains(table))
            .collect();
        if expected.len() != added.len()
            || expected
                .iter()
                .zip(added.iter())
                .any(|(expected, actual)| *expected != actual)
        {
            return Err("kernel_env_table_added_mismatch".into());
        }
    }
    if preparation.table_failures.len() > 8 {
        return Err("kernel_env_table_failures_too_many".into());
    }
    for failure in &preparation.table_failures {
        if !matches!(failure.family.as_str(), "v4" | "v6")
            || !table_name(&failure.table)
            || failure.reason.is_empty()
            || !text(&failure.reason, 256)
        {
            return Err("kernel_env_table_failure_invalid".into());
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct RecordTarget<'a> {
    id: &'a str,
    name: &'a str,
    version: u32,
}

#[derive(Serialize)]
struct Record<'a> {
    schema_version: u8,
    prepared_at: u64,
    target: RecordTarget<'a>,
    #[serde(flatten)]
    preparation: &'a Preparation,
}

/// Writes the last preparation to the per-user state directory. The record is
/// diagnostic: a failed write is reported but does not undo the kernel change.
pub fn record(distro: &Distro, preparation: &Preparation) -> Result<PathBuf, String> {
    let directory = crate::host::state_dir()?;
    fs::create_dir_all(&directory).map_err(|error| format!("kernel_env_record_dir: {error}"))?;
    let path = directory.join("kernel-env.json");
    let temporary = directory.join("kernel-env.json.tmp");
    let _ = fs::remove_file(&temporary);
    let record = Record {
        schema_version: 1,
        prepared_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or_default(),
        target: RecordTarget {
            id: &distro.id,
            name: &distro.name,
            version: distro.version,
        },
        preparation,
    };
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("kernel_env_record_open: {error}"))?;
        serde_json::to_writer_pretty(&mut file, &record)
            .map_err(|error| format!("kernel_env_record_write: {error}"))?;
        file.write_all(b"\n")
            .map_err(|error| format!("kernel_env_record_write: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("kernel_env_record_sync: {error}"))?;
        fs::rename(&temporary, &path).map_err(|error| format!("kernel_env_record_rename: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map(|()| path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn sample() -> Value {
        json!({
            "ok": true,
            "kernel_release": "6.18.58.1-microsoft-standard-WSL2",
            "boot_id": "0d6b0bd1-f150-44b2-91f0-692b8c2c40d7",
            "netns": "net:[4026531833]",
            "modules_dir": true,
            "modules_required": REQUIRED_MODULES,
            "modules_before": ["iptable_nat"],
            "modules_added": ["xt_cgroup"],
            "modules_failed": [],
            "tables": {
                "before": {"v4": ["nat"], "v6": []},
                "after": {"v4": ["filter", "nat"], "v6": ["filter", "nat"]},
                "added": {"v4": ["filter"], "v6": ["filter", "nat"]}
            },
            "table_failures": []
        })
    }

    fn accept(value: &Value) -> Preparation {
        let preparation: Preparation = serde_json::from_value(value.clone()).unwrap();
        validate(&preparation).unwrap();
        preparation
    }

    #[test]
    fn accepts_a_complete_preparation_and_counts_it() {
        let preparation = accept(&sample());
        assert_eq!(preparation.modules_added.len(), 1);
        assert_eq!(
            preparation.tables.added.v4.len() + preparation.tables.added.v6.len(),
            3
        );
        assert!(preparation.modules_failed.is_empty());
    }

    #[test]
    fn rejects_unknown_fields_and_bad_identity_evidence() {
        let mut value = sample();
        value["extra"] = json!(true);
        assert!(serde_json::from_value::<Preparation>(value).is_err());

        for (key, bad) in [
            ("boot_id", json!("not a boot id; rm -rf /")),
            ("netns", json!("pid:[1]")),
            ("kernel_release", json!("")),
        ] {
            let mut value = sample();
            value[key] = bad;
            assert!(
                validate(&serde_json::from_value(value).unwrap()).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn rejects_module_sets_that_do_not_match_the_contract() {
        let mut value = sample();
        value["modules_required"] = json!(["xt_cgroup"]);
        assert!(validate(&serde_json::from_value(value).unwrap()).is_err());

        let mut value = sample();
        value["modules_added"] = json!(["xt_cgroup", "xt_cgroup"]);
        assert!(validate(&serde_json::from_value(value).unwrap()).is_err());

        let mut value = sample();
        value["modules_added"] = json!(["iptable_nat"]);
        assert!(validate(&serde_json::from_value(value).unwrap()).is_err());

        let mut value = sample();
        value["modules_failed"] = json!([
            {"module": "xt_cgroup", "reason": "not_available"}
        ]);
        assert!(validate(&serde_json::from_value(value).unwrap()).is_err());

        let mut value = sample();
        value["modules_failed"] = json!([
            {"module": "xt_cgroup", "reason": "x".repeat(300)}
        ]);
        assert!(validate(&serde_json::from_value(value).unwrap()).is_err());
    }

    #[test]
    fn rejects_table_evidence_that_does_not_add_up() {
        let mut value = sample();
        value["tables"]["added"]["v4"] = json!([]);
        assert!(validate(&serde_json::from_value(value).unwrap()).is_err());

        let mut value = sample();
        value["tables"]["after"]["v4"] = json!(["filter"]);
        assert!(validate(&serde_json::from_value(value).unwrap()).is_err());

        let mut value = sample();
        value["tables"]["before"]["v6"] = json!(["mangle"]);
        assert!(validate(&serde_json::from_value(value).unwrap()).is_err());
    }

    #[test]
    fn accepts_only_known_explicit_refusals() {
        for error in ["root_required", "python3_missing", "internal_error"] {
            let response = json!({"ok": false, "error": error}).to_string();
            let failure = interpret(&response).unwrap_err();
            assert!(failure.contains(error), "{failure}");
        }
        for response in [
            json!({"ok": false, "error": "exec_failed: rm -rf"}).to_string(),
            json!({"ok": false}).to_string(),
            json!({"ok": true}).to_string(),
            "not json".into(),
        ] {
            assert!(interpret(&response).is_err(), "{response}");
        }
    }

    #[test]
    fn rejects_a_truncated_evidence_report() {
        let mut value = sample();
        value.as_object_mut().unwrap().remove("tables");
        assert!(interpret(&value.to_string()).is_err());
    }
}
