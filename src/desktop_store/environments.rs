//! Per-environment residential proxy and ingress port (decision 40). Each row
//! is keyed by the distribution's registry GUID, so renaming a distribution
//! keeps its settings and unregistering it lets them be removed.

use super::{MAX_TEXT, ResidentialSettings, ensure, open};
use crate::{credential, host};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::path::Path;

/// The first ingress port handed out; the old single-target default.
pub(crate) const FIRST_INGRESS_PORT: u16 = 43531;

#[derive(Clone, Serialize, PartialEq, Eq)]
pub(crate) struct EnvironmentRecord {
    pub(crate) distro_id: String,
    /// Bumped on every write; the desktop sends it back on save and start, and
    /// compares it with a residential check's result to see if it is stale.
    #[serde(serialize_with = "revision_text")]
    pub(crate) revision: u64,
    pub(crate) residential: ResidentialSettings,
    pub(crate) ingress_port: u16,
}

/// Leaves the proxy out, so a failed assertion cannot print the password.
impl std::fmt::Debug for EnvironmentRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvironmentRecord")
            .field("distro_id", &self.distro_id)
            .field("revision", &self.revision)
            .field("ingress_port", &self.ingress_port)
            .finish_non_exhaustive()
    }
}

fn revision_text<S: serde::Serializer>(revision: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&revision.to_string())
}

pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS environment_residential (
    distro_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    ingress_port INTEGER NOT NULL UNIQUE
);";

/// Registry GUIDs are compared without regard to case.
fn key(distro_id: &str) -> Result<String, String> {
    let id = distro_id.trim();
    if id.is_empty() || id.len() > 64 || id.chars().any(char::is_control) {
        return Err("invalid_distro_id".into());
    }
    Ok(id.to_ascii_lowercase())
}

fn decode(row: &rusqlite::Row<'_>) -> Result<EnvironmentRecord, rusqlite::Error> {
    let revision: i64 = row.get(1)?;
    let protocol: String = row.get(2)?;
    Ok(EnvironmentRecord {
        distro_id: row.get(0)?,
        revision: revision
            .try_into()
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, revision))?,
        residential: ResidentialSettings {
            protocol: credential::Protocol::parse(&protocol).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    "unknown residential protocol".into(),
                )
            })?,
            ip: row.get(3)?,
            port: row.get(4)?,
            username: row.get(5)?,
            password: row.get(6)?,
        },
        ingress_port: row.get(7)?,
    })
}

const COLUMNS: &str = "distro_id, revision, protocol, ip, port, username, password, ingress_port";

fn read(connection: &Connection, id: &str) -> Result<Option<EnvironmentRecord>, String> {
    connection
        .query_row(
            &format!("SELECT {COLUMNS} FROM environment_residential WHERE distro_id = ?1"),
            [id],
            decode,
        )
        .optional()
        .map_err(|e| format!("desktop_store_environment_read:{e}"))
}

fn read_all(connection: &Connection) -> Result<Vec<EnvironmentRecord>, String> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {COLUMNS} FROM environment_residential ORDER BY distro_id"
        ))
        .map_err(|e| format!("desktop_store_environment_read:{e}"))?;
    statement
        .query_map([], decode)
        .map_err(|e| format!("desktop_store_environment_read:{e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("desktop_store_environment_read:{e}"))
}

/// The smallest port from 43531 up that no other environment holds.
fn free_port(connection: &Connection, except: &str) -> Result<u16, String> {
    let taken: Vec<u16> = read_all(connection)?
        .into_iter()
        .filter(|row| row.distro_id != except)
        .map(|row| row.ingress_port)
        .collect();
    (FIRST_INGRESS_PORT..=u16::MAX)
        .find(|port| !taken.contains(port))
        .ok_or_else(|| "ingress_ports_exhausted".into())
}

fn check_port(connection: &Connection, id: &str, port: u16) -> Result<(), String> {
    if port < 1024 {
        return Err("invalid_ingress_port".into());
    }
    if read_all(connection)?
        .iter()
        .any(|row| row.distro_id != id && row.ingress_port == port)
    {
        return Err("ingress_port_in_use".into());
    }
    Ok(())
}

/// Empty means not configured yet; anything partly filled must parse.
fn check_residential(residential: &ResidentialSettings) -> Result<(), String> {
    if !residential.is_blank() {
        let _ = credential::from_settings(residential)?.endpoint();
    }
    if residential.ip.len() + residential.username.len() + residential.password.len() > MAX_TEXT {
        return Err("desktop_store_too_large".into());
    }
    Ok(())
}

fn write(connection: &Connection, row: &EnvironmentRecord) -> Result<(), String> {
    let revision = i64::try_from(row.revision).map_err(|_| "revision_exhausted")?;
    connection
        .execute(
            &format!(
                // An upsert, not INSERT OR REPLACE: that would silently
                // delete another environment's row on an ingress port clash.
                "INSERT INTO environment_residential ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(distro_id) DO UPDATE SET revision=excluded.revision, protocol=excluded.protocol, ip=excluded.ip, port=excluded.port, username=excluded.username, password=excluded.password, ingress_port=excluded.ingress_port"
            ),
            params![
                row.distro_id,
                revision,
                row.residential.protocol.as_str(),
                row.residential.ip,
                row.residential.port,
                row.residential.username,
                row.residential.password,
                row.ingress_port,
            ],
        )
        .map(|_| ())
        .map_err(|e| format!("desktop_store_environment_write:{e}"))
}

pub(crate) fn environment(
    path: &Path,
    distro_id: &str,
) -> Result<Option<EnvironmentRecord>, String> {
    let id = key(distro_id)?;
    read(&open(path)?, &id)
}

pub(crate) fn environments(path: &Path) -> Result<Vec<EnvironmentRecord>, String> {
    read_all(&open(path)?)
}

/// Saves one environment's residential proxy and ingress port. A new row with
/// no port given gets the first free one. `expected_revision` must name the
/// revision the caller loaded; a row that does not exist yet expects none.
pub(crate) fn save_environment(
    path: &Path,
    distro_id: &str,
    residential: ResidentialSettings,
    ingress_port: Option<u16>,
    expected_revision: Option<String>,
) -> Result<EnvironmentRecord, String> {
    let id = key(distro_id)?;
    check_residential(&residential)?;
    let connection = open(path)?;
    let transaction = connection
        .unchecked_transaction()
        .map_err(|e| format!("desktop_store_transaction:{e}"))?;
    let current = read(&transaction, &id)?;
    if expected_revision != current.as_ref().map(|row| row.revision.to_string()) {
        return Err("stale_environment_revision: reload the saved environment".into());
    }
    let ingress_port = match (ingress_port, &current) {
        (Some(port), _) => port,
        (None, Some(row)) => row.ingress_port,
        (None, None) => free_port(&transaction, &id)?,
    };
    check_port(&transaction, &id, ingress_port)?;
    let row = EnvironmentRecord {
        revision: match &current {
            Some(row) => row.revision.checked_add(1).ok_or("revision_exhausted")?,
            None => 1,
        },
        distro_id: id,
        residential,
        ingress_port,
    };
    write(&transaction, &row)?;
    transaction
        .commit()
        .map_err(|e| format!("desktop_store_commit:{e}"))?;
    Ok(row)
}

/// Removes an environment's row, for example after the distribution is deleted.
pub(crate) fn delete_environment(path: &Path, distro_id: &str) -> Result<(), String> {
    let id = key(distro_id)?;
    open(path)?
        .execute(
            "DELETE FROM environment_residential WHERE distro_id = ?1",
            [id],
        )
        .map(|_| ())
        .map_err(|e| format!("desktop_store_environment_delete:{e}"))
}

/// The saved profile and this environment's residential proxy, for a start.
pub(crate) fn load_runtime(
    path: &Path,
    distro_id: &str,
) -> Result<(crate::policy::Config, credential::Residential, u16), String> {
    let record = ensure(path)?;
    if record.revision == 0 {
        return Err("desktop_store_not_saved".into());
    }
    let row = environment(path, distro_id)?.ok_or("residential_credential_incomplete")?;
    let residential = credential::from_settings(&row.residential)
        .map_err(|_| "residential_credential_incomplete".to_string())?;
    Ok((record.profile, residential, row.ingress_port))
}

/// The distribution the old single residential block belonged to: the saved
/// target, matched by exact name or by GUID, as the old start command did.
fn legacy_owner<'a>(target: &str, distros: &'a [host::Distro]) -> Option<&'a host::Distro> {
    let mut hits = distros
        .iter()
        .filter(|d| d.name == target || d.id.eq_ignore_ascii_case(target));
    let first = hits.next()?;
    hits.next().is_none().then_some(first)
}

/// Moves the old single residential block into `id`'s row, keeping the old
/// ingress port when no other environment holds it, then clears the block and
/// the saved target. Refuses to overwrite a row that already has a proxy.
fn move_legacy(connection: &Connection, id: &str) -> Result<EnvironmentRecord, String> {
    let transaction = connection
        .unchecked_transaction()
        .map_err(|e| format!("desktop_store_transaction:{e}"))?;
    let legacy = super::read_optional(&transaction)?.ok_or("unassigned_residential_missing")?;
    if legacy.residential.is_blank() {
        return Err("unassigned_residential_missing".into());
    }
    let current = read(&transaction, id)?;
    if current
        .as_ref()
        .is_some_and(|row| !row.residential.is_blank())
    {
        return Err("environment_residential_exists".into());
    }
    let ingress_port = match &current {
        Some(row) => row.ingress_port,
        None if check_port(&transaction, id, legacy.desktop.port).is_ok() => legacy.desktop.port,
        None => free_port(&transaction, id)?,
    };
    let row = EnvironmentRecord {
        distro_id: id.to_owned(),
        revision: match &current {
            Some(row) => row.revision.checked_add(1).ok_or("revision_exhausted")?,
            None => 1,
        },
        residential: legacy.residential,
        ingress_port,
    };
    write(&transaction, &row)?;
    let mut desktop = legacy.desktop;
    desktop.target = None;
    let desktop_json = serde_json::to_string(&desktop).map_err(|e| e.to_string())?;
    let blank = ResidentialSettings::default();
    transaction
        .execute(
            "UPDATE desktop_state SET desktop_json=?1, residential_ip=?2, residential_port=?3, residential_username=?4, residential_password=?5, residential_protocol=?6 WHERE id=1",
            params![desktop_json, blank.ip, blank.port, blank.username, blank.password, blank.protocol.as_str()],
        )
        .map_err(|e| format!("desktop_store_residential:{e}"))?;
    transaction
        .commit()
        .map_err(|e| format!("desktop_store_commit:{e}"))?;
    Ok(row)
}

/// Gives the old single residential block to the environment it was saved
/// for, when that environment is still registered and has no proxy of its
/// own. Otherwise the block stays as it is, reported as unassigned until the
/// user assigns it. Returns the environment it moved to.
pub(crate) fn adopt_legacy_residential(
    path: &Path,
    distros: &[host::Distro],
) -> Result<Option<String>, String> {
    let connection = open(path)?;
    let Some(legacy) = super::read_optional(&connection)? else {
        return Ok(None);
    };
    if legacy.residential.is_blank() {
        return Ok(None);
    }
    let Some(owner) = legacy
        .desktop
        .target
        .as_deref()
        .and_then(|target| legacy_owner(target, distros))
    else {
        return Ok(None);
    };
    let id = key(&owner.id)?;
    match move_legacy(&connection, &id) {
        Ok(_) => Ok(Some(id)),
        Err(error) if error == "environment_residential_exists" => Ok(None),
        Err(error) => Err(error),
    }
}

/// The user's explicit choice of where the unassigned block goes.
pub(crate) fn assign_legacy_residential(
    path: &Path,
    distro_id: &str,
) -> Result<EnvironmentRecord, String> {
    let id = key(distro_id)?;
    move_legacy(&open(path)?, &id)
}

/// Drops the unassigned block without giving it to any environment.
pub(crate) fn discard_legacy_residential(path: &Path) -> Result<(), String> {
    let blank = ResidentialSettings::default();
    super::ensure(path)?;
    open(path)?
        .execute(
            "UPDATE desktop_state SET residential_ip=?1, residential_port=?2, residential_username=?3, residential_password=?4, residential_protocol=?5 WHERE id=1",
            params![blank.ip, blank.port, blank.username, blank.password, blank.protocol.as_str()],
        )
        .map(|_| ())
        .map_err(|e| format!("desktop_store_residential:{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "wpl-environments-{name}-{}.sqlite",
            std::process::id()
        ));
        for suffix in ["", "-wal", "-shm"] {
            let mut file = path.as_os_str().to_owned();
            file.push(suffix);
            let _ = std::fs::remove_file(file);
        }
        path
    }

    fn proxy(ip: &str) -> ResidentialSettings {
        ResidentialSettings {
            protocol: credential::Protocol::Socks5,
            ip: ip.into(),
            port: 1080,
            username: "fixture-user".into(),
            password: "fixture-password".into(),
        }
    }

    fn distro(id: &str, name: &str) -> host::Distro {
        host::Distro {
            id: id.into(),
            name: name.into(),
            base_path: format!("C:\\{name}"),
            version: 2,
        }
    }

    #[test]
    fn each_environment_gets_its_own_row_port_and_revision() {
        let path = store("rows");
        let a = save_environment(&path, "{AAAA}", proxy("198.51.100.1"), None, None).unwrap();
        let b = save_environment(&path, "{bbbb}", proxy("198.51.100.2"), None, None).unwrap();
        assert_eq!((a.ingress_port, b.ingress_port), (43531, 43532));
        assert_eq!(a.distro_id, "{aaaa}");
        // Case does not matter; a stale or missing revision is refused.
        assert!(save_environment(&path, "{aaaa}", proxy("198.51.100.3"), None, None).is_err());
        assert!(
            save_environment(
                &path,
                "{aaaa}",
                proxy("198.51.100.3"),
                None,
                Some("2".into())
            )
            .is_err()
        );
        let a = save_environment(
            &path,
            "{aaaa}",
            proxy("198.51.100.3"),
            None,
            Some("1".into()),
        )
        .unwrap();
        assert_eq!((a.revision, a.ingress_port), (2, 43531));
        // Two environments never share an ingress port.
        assert_eq!(
            save_environment(
                &path,
                "{bbbb}",
                proxy("198.51.100.2"),
                Some(43531),
                Some("1".into())
            )
            .unwrap_err(),
            "ingress_port_in_use"
        );
        assert!(
            environment(&path, "{AAAA}").unwrap().unwrap().residential == proxy("198.51.100.3")
        );
        delete_environment(&path, "{AAAA}").unwrap();
        assert!(environment(&path, "{aaaa}").unwrap().is_none());
        // The freed port goes to the next new environment.
        let c = save_environment(&path, "{cccc}", proxy("198.51.100.4"), None, None).unwrap();
        assert_eq!(c.ingress_port, 43531);
        assert_eq!(environments(&path).unwrap().len(), 2);
    }

    #[test]
    fn the_old_block_moves_to_its_saved_target_or_stays_unassigned() {
        let path = store("legacy");
        let initial = ensure(&path).unwrap();
        super::super::update_residential(&path, None, proxy("198.51.100.9")).unwrap();
        let mut desktop = initial.desktop.clone();
        desktop.target = Some("Target".into());
        desktop.port = 43600;
        open(&path)
            .unwrap()
            .execute(
                "UPDATE desktop_state SET desktop_json=?1",
                [serde_json::to_string(&desktop).unwrap()],
            )
            .unwrap();
        // The saved target is not registered: nothing moves.
        let other = [distro("{1111}", "Other")];
        assert_eq!(adopt_legacy_residential(&path, &other).unwrap(), None);
        assert!(!ensure(&path).unwrap().residential.is_blank());
        // Matched by name, it moves with its old port, and the block is cleared.
        let registered = [distro("{2222}", "Target"), distro("{1111}", "Other")];
        assert_eq!(
            adopt_legacy_residential(&path, &registered)
                .unwrap()
                .as_deref(),
            Some("{2222}")
        );
        let row = environment(&path, "{2222}").unwrap().unwrap();
        assert!(row.residential == proxy("198.51.100.9"));
        assert_eq!(row.ingress_port, 43600);
        let after = ensure(&path).unwrap();
        assert!(after.residential.is_blank());
        assert!(after.desktop.target.is_none());
        assert_eq!(adopt_legacy_residential(&path, &registered).unwrap(), None);
    }

    #[test]
    fn an_unassigned_block_is_assigned_only_to_an_environment_without_a_proxy() {
        let path = store("assign");
        ensure(&path).unwrap();
        super::super::update_residential(&path, None, proxy("198.51.100.9")).unwrap();
        save_environment(&path, "{1111}", proxy("198.51.100.1"), None, None).unwrap();
        assert_eq!(
            assign_legacy_residential(&path, "{1111}").unwrap_err(),
            "environment_residential_exists"
        );
        let row = assign_legacy_residential(&path, "{2222}").unwrap();
        assert_eq!(row.ingress_port, 43532);
        assert_eq!(
            assign_legacy_residential(&path, "{3333}").unwrap_err(),
            "unassigned_residential_missing"
        );
        super::super::update_residential(&path, None, proxy("198.51.100.8")).unwrap();
        discard_legacy_residential(&path).unwrap();
        assert!(ensure(&path).unwrap().residential.is_blank());
    }

    #[test]
    fn a_start_reads_only_its_own_environment() {
        let path = store("runtime");
        let record = ensure(&path).unwrap();
        super::super::save(&path, record.profile, Some("0".into())).unwrap();
        save_environment(&path, "{1111}", proxy("198.51.100.1"), None, None).unwrap();
        let (_, residential, port) = load_runtime(&path, "{1111}").unwrap();
        assert_eq!(residential.endpoint().ip().to_string(), "198.51.100.1");
        assert_eq!(port, 43531);
        assert_eq!(
            load_runtime(&path, "{2222}").err().unwrap(),
            "residential_credential_incomplete"
        );
        save_environment(&path, "{2222}", ResidentialSettings::default(), None, None).unwrap();
        assert_eq!(
            load_runtime(&path, "{2222}").err().unwrap(),
            "residential_credential_incomplete"
        );
    }
}
