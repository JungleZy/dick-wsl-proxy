//! SQLite-backed desktop profile and residential settings.

use crate::{
    credential, host,
    policy::{Config, profile::Preferences},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_CREDENTIAL_NAME: &str = "desktop-residence";
const MAX_TEXT: usize = 256 * 1024;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentialSettings {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) password: String,
}

pub(crate) struct Record {
    pub(crate) revision: u64,
    pub(crate) profile: Config,
    pub(crate) desktop: Preferences,
    pub(crate) residential: ResidentialSettings,
}

pub(crate) fn path() -> Result<PathBuf, String> {
    Ok(host::state_dir()?.join("desktop.sqlite"))
}

fn default_profile() -> Result<Config, String> {
    serde_json::from_value(serde_json::json!({
        "first_hop":"127.0.0.1:7892",
        "credential":DEFAULT_CREDENTIAL_NAME,
        "dns_upstream":"223.5.5.5:443",
        "dns_tls_name":"dns.alidns.com",
        "health_domain":"ippure.com",
        "direct_ips":[],
        "direct_domains":[],
        "direct_suffixes":[],
        "allow_loopback_residential":false
    }))
    .map_err(|_| "desktop_store_default_profile_invalid".into())
}

fn env_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_dir() {
        candidates.extend(current.ancestors().map(|root| root.join(".env")));
    }
    if let Ok(exe) = std::env::current_exe() {
        candidates.extend(
            exe.ancestors()
                .flat_map(|root| [root.join(".env"), root.join("..\\.env")]),
        );
    }
    candidates
}

fn default_residential() -> ResidentialSettings {
    for candidate in env_candidates() {
        if let Ok(bytes) = fs::read(&candidate)
            && let Ok(value) = credential::parse_env_bytes(&bytes)
        {
            return credential::settings(&value);
        }
    }
    ResidentialSettings::default()
}

fn open(path: &Path) -> Result<Connection, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("desktop_store_directory:{e}"))?;
    }
    let connection = Connection::open(path).map_err(|e| format!("desktop_store_open:{e}"))?;
    connection
        .busy_timeout(std::time::Duration::from_secs(2))
        .map_err(|e| format!("desktop_store_busy_timeout:{e}"))?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS desktop_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                revision INTEGER NOT NULL,
                profile_json TEXT NOT NULL,
                desktop_json TEXT NOT NULL,
                residential_ip TEXT NOT NULL,
                residential_port INTEGER NOT NULL,
                residential_username TEXT NOT NULL,
                residential_password TEXT NOT NULL
            );",
        )
        .map_err(|e| format!("desktop_store_schema:{e}"))?;
    Ok(connection)
}

fn decode_row(row: &rusqlite::Row<'_>) -> Result<Record, rusqlite::Error> {
    let revision: i64 = row.get(0)?;
    let profile_json: String = row.get(1)?;
    let desktop_json: String = row.get(2)?;
    let profile: Config =
        serde_json::from_str(&profile_json).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let desktop: Preferences =
        serde_json::from_str(&desktop_json).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(Record {
        revision: revision
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        profile,
        desktop,
        residential: ResidentialSettings {
            ip: row.get(3)?,
            port: row.get(4)?,
            username: row.get(5)?,
            password: row.get(6)?,
        },
    })
}

fn read_optional(connection: &Connection) -> Result<Option<Record>, String> {
    let record = connection
        .query_row(
            "SELECT revision, profile_json, desktop_json, residential_ip, residential_port, residential_username, residential_password FROM desktop_state WHERE id = 1",
            [],
            decode_row,
        )
        .optional()
        .map_err(|e| format!("desktop_store_read:{e}"))?;
    match record {
        Some(record)
            if record.profile.validate_draft().is_ok() && record.desktop.validate().is_ok() =>
        {
            Ok(Some(record))
        }
        Some(_) => Err("desktop_store_invalid".into()),
        None => Ok(None),
    }
}

pub(crate) fn ensure(path: &Path) -> Result<Record, String> {
    let connection = open(path)?;
    if let Some(record) = read_optional(&connection)? {
        if record.residential.ip.is_empty() {
            let residential = default_residential();
            if !residential.ip.is_empty() {
                connection
                    .execute(
                        "UPDATE desktop_state SET residential_ip=?1, residential_port=?2, residential_username=?3, residential_password=?4 WHERE id=1",
                        params![
                            residential.ip,
                            residential.port,
                            residential.username,
                            residential.password
                        ],
                    )
                    .map_err(|e| format!("desktop_store_env_hydrate:{e}"))?;
                return Ok(Record {
                    residential,
                    ..record
                });
            }
        }
        return Ok(record);
    }
    let legacy_path = path.with_file_name("desktop-policy.json");
    if let Ok(bytes) = fs::read(&legacy_path) {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Legacy {
            revision: u64,
            profile: Config,
            desktop: Preferences,
        }
        if let Ok(legacy) = serde_json::from_slice::<Legacy>(&bytes)
            && legacy.revision > 0
            && legacy.profile.validate_draft().is_ok()
            && legacy.desktop.validate().is_ok()
        {
            let residential = default_residential();
            let profile_json = serde_json::to_string(&legacy.profile).map_err(|e| e.to_string())?;
            let desktop_json = serde_json::to_string(&legacy.desktop).map_err(|e| e.to_string())?;
            connection
                    .execute(
                        "INSERT OR REPLACE INTO desktop_state (id, revision, profile_json, desktop_json, residential_ip, residential_port, residential_username, residential_password) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            legacy.revision,
                            profile_json,
                            desktop_json,
                            residential.ip,
                            residential.port,
                            residential.username,
                            residential.password
                        ],
                    )
                    .map_err(|e| format!("desktop_store_legacy_migrate:{e}"))?;
            return Ok(Record {
                revision: legacy.revision,
                profile: legacy.profile,
                desktop: legacy.desktop,
                residential,
            });
        }
    }
    let profile = default_profile()?;
    let desktop = Preferences::default();
    let residential = default_residential();
    profile.validate_draft()?;
    desktop.validate()?;
    let profile_json = serde_json::to_string(&profile).map_err(|e| e.to_string())?;
    let desktop_json = serde_json::to_string(&desktop).map_err(|e| e.to_string())?;
    connection
        .execute(
            "INSERT OR REPLACE INTO desktop_state (id, revision, profile_json, desktop_json, residential_ip, residential_port, residential_username, residential_password) VALUES (1, 0, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![profile_json, desktop_json, residential.ip, residential.port, residential.username, residential.password],
        )
        .map_err(|e| format!("desktop_store_default:{e}"))?;
    Ok(Record {
        revision: 0,
        profile,
        desktop,
        residential,
    })
}

pub(crate) fn load(path: &Path) -> Result<Record, String> {
    let connection = open(path)?;
    read_optional(&connection)?.ok_or_else(|| "desktop_store_missing".into())
}

pub(crate) fn revision(path: &Path) -> Result<u64, String> {
    Ok(ensure(path)?.revision)
}

pub(crate) fn save(
    path: &Path,
    profile: Config,
    desktop: Preferences,
    residential: Option<ResidentialSettings>,
    expected_revision: Option<String>,
) -> Result<Record, String> {
    profile.validate_draft()?;
    desktop.validate()?;
    let current = ensure(path)?;
    if expected_revision != Some(current.revision.to_string())
        && !(expected_revision.is_none() && current.revision == 0)
    {
        return Err("stale_profile_revision: reload the saved profile".into());
    }
    let residential = residential.unwrap_or(current.residential);
    let credential = credential::from_settings(&residential)?;
    let _ = credential.endpoint();
    let profile_json = serde_json::to_string(&profile).map_err(|e| e.to_string())?;
    let desktop_json = serde_json::to_string(&desktop).map_err(|e| e.to_string())?;
    if profile_json.len() + desktop_json.len() + residential.password.len() > MAX_TEXT {
        return Err("desktop_store_too_large".into());
    }
    let next = current
        .revision
        .checked_add(1)
        .ok_or("revision_exhausted")?;
    let connection = open(path)?;
    let transaction = connection
        .unchecked_transaction()
        .map_err(|e| format!("desktop_store_transaction:{e}"))?;
    let changed = transaction
        .execute(
            "UPDATE desktop_state SET revision=?1, profile_json=?2, desktop_json=?3, residential_ip=?4, residential_port=?5, residential_username=?6, residential_password=?7 WHERE id=1 AND revision=?8",
            params![next, profile_json, desktop_json, residential.ip, residential.port, residential.username, residential.password, current.revision],
        )
        .map_err(|e| format!("desktop_store_save:{e}"))?;
    if changed != 1 {
        return Err("stale_profile_revision: reload the saved profile".into());
    }
    transaction
        .commit()
        .map_err(|e| format!("desktop_store_commit:{e}"))?;
    Ok(Record {
        revision: next,
        profile,
        desktop,
        residential,
    })
}

pub(crate) fn load_runtime(path: &Path) -> Result<(Config, credential::Residential), String> {
    let record = load(path)?;
    if record.revision == 0 {
        return Err("desktop_store_not_saved".into());
    }
    let residential = credential::from_settings(&record.residential)?;
    Ok((record.profile, residential))
}

pub(crate) fn view(path: &Path, record: &Record) -> Value {
    serde_json::json!({
        "exists": record.revision > 0,
        "revision": if record.revision > 0 { Some(record.revision.to_string()) } else { None::<String> },
        "path": path,
        "profile": record.profile.clone(),
        "desktop": record.desktop.clone(),
        "residential": record.residential.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_profile_has_revision_cas_and_runtime_credentials() {
        let path =
            std::env::temp_dir().join(format!("wpl-desktop-store-{}.sqlite", std::process::id()));
        let _ = fs::remove_file(&path);
        let initial = ensure(&path).unwrap();
        assert_eq!(initial.revision, 0);
        let residential = ResidentialSettings {
            ip: "198.51.100.2".into(),
            port: 1080,
            username: "fixture-user".into(),
            password: "fixture-password".into(),
        };
        let saved = save(
            &path,
            initial.profile.clone(),
            initial.desktop.clone(),
            Some(residential.clone()),
            Some("0".into()),
        )
        .unwrap();
        assert_eq!(saved.revision, 1);
        assert!(
            save(
                &path,
                initial.profile.clone(),
                initial.desktop.clone(),
                Some(residential.clone()),
                Some("0".into()),
            )
            .is_err()
        );
        let (_, loaded) = load_runtime(&path).unwrap();
        assert_eq!(loaded.endpoint().ip().to_string(), residential.ip);
        assert_eq!(loaded.endpoint().port(), residential.port);
        let _ = fs::remove_file(path);
    }
}
