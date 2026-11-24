//! SQLite-backed desktop profile, runtime snapshots, and event logs.

use crate::{
    credential, host,
    ingress::{FinishedFlow, FlowEvent},
    policy::{Config, domestic, profile::Preferences},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const DEFAULT_CREDENTIAL_NAME: &str = "desktop-residence";
const MAX_TEXT: usize = 256 * 1024;
const MAX_LOG_MESSAGE: usize = 512;
const MAX_LOG_SEARCH: usize = 128;
/// Newest runtime log rows kept; older rows are deleted on insert.
const MAX_LOG_ROWS: i64 = 10_000;
/// Newest connection records kept; older rows are deleted after each written batch.
const MAX_CONNECTION_ROWS: i64 = 50_000;
/// Finished flows are written in one transaction per batch: at most this many rows,
/// collected for at most this long after the first one arrives.
const CONNECTION_BATCH_ROWS: usize = 512;
const CONNECTION_BATCH_WINDOW: Duration = Duration::from_millis(500);
/// Finished flows lost because their batch could not be written.
static CONNECTION_WRITE_FAILURES: AtomicU64 = AtomicU64::new(0);
/// Snapshot fields whose change is a state transition worth a log row.
const STATE_KEYS: [&str; 5] = [
    "phase",
    "active_target",
    "operation_generation",
    "config_generation",
    "dns_managed",
];

/// Last state recorded per store. The desktop polls status every two seconds;
/// polls that only move traffic counters return here without opening SQLite.
static LAST_RUNTIME_STATE: Mutex<Option<(PathBuf, Value)>> = Mutex::new(None);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RuntimeLogEntry {
    pub(crate) id: i64,
    pub(crate) occurred_at: String,
    pub(crate) level: String,
    pub(crate) source: String,
    pub(crate) message: String,
    pub(crate) phase: Option<String>,
    pub(crate) target: Option<String>,
    pub(crate) generation: Option<u64>,
}

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
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

const FILE_NAME: &str = "desktop.sqlite";

/// The store lives beside the EXE. Earlier releases kept it in the per-user
/// state directory; the first call after such an upgrade moves it here.
pub(crate) fn path() -> Result<PathBuf, String> {
    let path = host::data_dir()?.join(FILE_NAME);
    if let Ok(directory) = host::state_dir() {
        adopt_legacy(&directory.join(FILE_NAME), &path)?;
    }
    Ok(path)
}

/// Copies a store left at `legacy` to `path`, then removes the old files.
/// Every caller holds the controller lock, so no other process has either file
/// open; the mutex orders this process's own threads. An existing store at
/// `path` is never replaced. The old store is removed only after the copy is
/// complete and flushed to disk, so an interrupted move is simply retried, and
/// a failure is reported instead of silently starting with an empty store.
fn adopt_legacy(legacy: &Path, path: &Path) -> Result<(), String> {
    static MOVING: Mutex<()> = Mutex::new(());
    let _guard = MOVING.lock().unwrap_or_else(PoisonError::into_inner);
    let failed = |error: &dyn std::fmt::Display| {
        format!(
            "desktop_store_migration_failed:{}:{error}",
            legacy.display()
        )
    };
    if path.try_exists().map_err(|e| failed(&e))? || !legacy.try_exists().map_err(|e| failed(&e))? {
        return Ok(());
    }
    let staging = path.with_file_name(format!("{FILE_NAME}.migrating"));
    let _ = fs::remove_file(&staging);
    let target = staging
        .to_str()
        .ok_or_else(|| failed(&"non_unicode_path"))?;
    {
        let source = Connection::open(legacy).map_err(|e| failed(&e))?;
        source
            .busy_timeout(Duration::from_secs(2))
            .map_err(|e| failed(&e))?;
        // VACUUM INTO also reads committed WAL content, so -wal/-shm need no copy.
        source
            .execute("VACUUM INTO ?1", [target])
            .map_err(|e| failed(&e))?;
    }
    fs::OpenOptions::new()
        .write(true)
        .open(&staging)
        .and_then(|file| file.sync_all())
        .map_err(|e| failed(&e))?;
    fs::rename(&staging, path).map_err(|e| failed(&e))?;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = legacy.as_os_str().to_owned();
        name.push(suffix);
        let _ = fs::remove_file(name);
    }
    Ok(())
}

fn default_profile() -> Result<Config, String> {
    serde_json::from_value(serde_json::json!({
        "first_hop":"127.0.0.1:7892",
        "credential":DEFAULT_CREDENTIAL_NAME,
        // A domestic resolver would undo what managed system DNS is for.
        "dns_upstream":"8.8.8.8:443",
        "dns_tls_name":"dns.google",
        "health_domain":"ippure.com",
        "direct_ips":[],
        "direct_domains":[],
        // Only a brand-new store starts with these; existing stores keep their rules.
        "direct_suffixes":domestic::DIRECT_SUFFIXES,
        "allow_loopback_residential":false
    }))
    .map_err(|_| "desktop_store_default_profile_invalid".into())
}

fn open(path: &Path) -> Result<Connection, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("desktop_store_directory:{e}"))?;
    }
    // The path names the folder, so a read-only install location is recognisable.
    let connection =
        Connection::open(path).map_err(|e| format!("desktop_store_open:{}:{e}", path.display()))?;
    connection
        .busy_timeout(std::time::Duration::from_secs(2))
        .map_err(|e| format!("desktop_store_busy_timeout:{e}"))?;
    // Some redirected or network volumes cannot hold WAL's shared-memory index.
    // SQLite then keeps its rollback journal: slower under concurrent writes, but
    // correct with the busy timeout. Stay usable and say so once per process.
    let journal_mode: Result<String, _> =
        connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0));
    let wal = journal_mode
        .as_ref()
        .is_ok_and(|mode| mode.eq_ignore_ascii_case("wal"));
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
            );
            CREATE TABLE IF NOT EXISTS runtime_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                updated_at INTEGER NOT NULL,
                snapshot_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runtime_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at INTEGER NOT NULL,
                level TEXT NOT NULL CHECK (level IN ('info', 'warning', 'error')),
                source TEXT NOT NULL,
                message TEXT NOT NULL,
                phase TEXT,
                target TEXT,
                operation_generation INTEGER
            );
            CREATE INDEX IF NOT EXISTS runtime_logs_occurred_idx
                ON runtime_logs (occurred_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS runtime_logs_level_idx
                ON runtime_logs (level, occurred_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS runtime_logs_source_idx
                ON runtime_logs (source, occurred_at DESC, id DESC);
            CREATE TABLE IF NOT EXISTS connection_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session INTEGER NOT NULL,
                flow_id INTEGER NOT NULL,
                target TEXT,
                protocol TEXT NOT NULL,
                destination TEXT,
                route TEXT,
                reason TEXT,
                status TEXT NOT NULL,
                stage TEXT NOT NULL,
                failure_stage TEXT,
                tx_bytes INTEGER NOT NULL,
                rx_bytes INTEGER NOT NULL,
                started_at_ms INTEGER NOT NULL,
                ended_at_ms INTEGER NOT NULL,
                UNIQUE (session, flow_id)
            );
            CREATE INDEX IF NOT EXISTS connection_records_status_idx
                ON connection_records (status, id DESC);
            CREATE INDEX IF NOT EXISTS connection_records_target_idx
                ON connection_records (target, id DESC);",
        )
        .map_err(|e| format!("desktop_store_schema:{e}"))?;
    if !wal && !WAL_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) {
        let _ = insert_runtime_log(
            &connection,
            now_unix_seconds().unwrap_or_default(),
            LogEntry {
                level: "warning",
                source: "storage",
                message: &wal_fallback_message(&journal_mode),
                phase: None,
                target: None,
                generation: None,
            },
        );
    }
    Ok(connection)
}

/// Set once the rollback-journal fallback has been logged by this process.
static WAL_FALLBACK_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn wal_fallback_message(journal_mode: &Result<String, rusqlite::Error>) -> String {
    match journal_mode {
        Ok(mode) => format!(
            "数据库所在位置不支持 WAL，已改用 SQLite 日志模式 {mode} 继续运行；功能不受影响，并发写入会慢一些"
        ),
        Err(error) => format!(
            "数据库开启 WAL 失败（{error}），已按 SQLite 默认日志模式继续运行；功能不受影响，并发写入会慢一些"
        ),
    }
}

fn now_unix_seconds() -> Result<i64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().try_into().unwrap_or(i64::MAX))
        .map_err(|_| "desktop_store_clock_before_epoch".into())
}

fn clipped(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

/// One runtime log row, clipped to the column limits when it is stored.
struct LogEntry<'a> {
    level: &'a str,
    source: &'a str,
    message: &'a str,
    phase: Option<&'a str>,
    target: Option<&'a str>,
    generation: Option<u64>,
}

fn insert_runtime_log(
    connection: &Connection,
    occurred_at: i64,
    entry: LogEntry<'_>,
) -> Result<(), String> {
    let LogEntry {
        level,
        source,
        message,
        phase,
        target,
        generation,
    } = entry;
    let level = match level {
        "warning" | "error" => level,
        _ => "info",
    };
    let generation = generation.and_then(|value| i64::try_from(value).ok());
    connection
        .execute(
            "INSERT INTO runtime_logs
                (occurred_at, level, source, message, phase, target, operation_generation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                occurred_at,
                level,
                clipped(source, 64),
                clipped(message, MAX_LOG_MESSAGE),
                phase.map(|value| clipped(value, 64)),
                target.map(|value| clipped(value, 128)),
                generation,
            ],
        )
        .map_err(|error| format!("desktop_store_log_insert:{error}"))?;
    prune_runtime_logs(connection, MAX_LOG_ROWS)
}

fn prune_runtime_logs(connection: &Connection, keep: i64) -> Result<(), String> {
    connection
        .execute(
            "DELETE FROM runtime_logs
             WHERE id <= (SELECT id FROM runtime_logs ORDER BY id DESC LIMIT 1 OFFSET ?1)",
            params![keep],
        )
        .map(|_| ())
        .map_err(|error| format!("desktop_store_log_prune:{error}"))
}

pub(crate) fn append_runtime_log(
    path: &Path,
    level: &str,
    source: &str,
    message: &str,
    phase: Option<&str>,
    target: Option<&str>,
    generation: Option<u64>,
) -> Result<(), String> {
    let connection = open(path)?;
    insert_runtime_log(
        &connection,
        now_unix_seconds()?,
        LogEntry {
            level,
            source,
            message,
            phase,
            target,
            generation,
        },
    )
}

fn runtime_snapshot(status: &Value) -> Value {
    let counters = [
        "chain_tcp",
        "direct_tcp",
        "direct_udp",
        "dns_tcp",
        "dns_udp",
        "chain_udp",
        "rejected_tcp",
        "rejected_udp",
        "tcp_capacity_rejections",
        "metadata_queries",
        "metadata_successes",
        "metadata_transport_failures",
        "tcp_failures",
        "udp_failures",
    ]
    .into_iter()
    .filter_map(|key| {
        status["forwarding"]["counters"][key]
            .as_u64()
            .map(|value| (key.to_owned(), value.into()))
    })
    .collect::<serde_json::Map<_, _>>();
    serde_json::json!({
        "phase": status["phase"].as_str().unwrap_or("unknown"),
        // In recovery_required, active_target is set only while the guest
        // inspection succeeds; the journal's recorded_target keeps the state
        // key stable so a flaky inspection does not log a new error each poll.
        "active_target": status["active_target"]
            .as_str()
            .or_else(|| status["recorded_target"].as_str()),
        "operation_generation": status["operation_generation"].as_u64(),
        "config_generation": status["config_generation"].as_u64(),
        "dns_managed": status["dns_managed"].as_bool(),
        "tx_bytes": status["forwarding"]["traffic"]["tx_bytes"].as_u64(),
        "rx_bytes": status["forwarding"]["traffic"]["rx_bytes"].as_u64(),
        "counters": counters,
    })
}

fn snapshot_event(snapshot: &Value) -> (&'static str, String) {
    match snapshot["phase"].as_str().unwrap_or("unknown") {
        "forwarding_managed" => ("info", "已进入接管状态".into()),
        "forwarding_scoped" => ("warning", "已进入诊断转发状态".into()),
        "recovery_required" => ("error", "检测到未完成操作，需要恢复".into()),
        "idle" => ("info", "当前处于空闲状态".into()),
        _ => ("warning", "后台状态暂时未知".into()),
    }
}

fn state_key(snapshot: &Value) -> Value {
    Value::Object(
        STATE_KEYS
            .iter()
            .map(|key| ((*key).to_owned(), snapshot[*key].clone()))
            .collect(),
    )
}

/// Persist the snapshot of the last state transition and log the transition.
/// The stored row is compared across daemon restarts; metrics-only changes
/// neither touch the database nor log anything.
pub(crate) fn record_runtime_snapshot(path: &Path, status: &Value) -> Result<(), String> {
    let snapshot = runtime_snapshot(status);
    let key = state_key(&snapshot);
    let mut last = LAST_RUNTIME_STATE
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if last
        .as_ref()
        .is_some_and(|(cached_path, cached_key)| cached_path == path && *cached_key == key)
    {
        return Ok(());
    }
    let connection = open(path)?;
    let previous = connection
        .query_row(
            "SELECT snapshot_json FROM runtime_state WHERE id = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| format!("desktop_store_snapshot_read:{error}"))?;
    let state_changed = previous
        .as_deref()
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
        .is_none_or(|previous| state_key(&previous) != key);
    if state_changed {
        let snapshot_json = serde_json::to_string(&snapshot)
            .map_err(|error| format!("desktop_store_snapshot_encode:{error}"))?;
        let now = now_unix_seconds()?;
        connection
            .execute(
                "INSERT INTO runtime_state (id, updated_at, snapshot_json)
                 VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at,
                     snapshot_json=excluded.snapshot_json",
                params![now, snapshot_json],
            )
            .map_err(|error| format!("desktop_store_snapshot_write:{error}"))?;
        let (level, message) = snapshot_event(&snapshot);
        insert_runtime_log(
            &connection,
            now,
            LogEntry {
                level,
                source: "runtime",
                message: &message,
                phase: snapshot["phase"].as_str(),
                target: snapshot["active_target"].as_str(),
                generation: snapshot["operation_generation"].as_u64(),
            },
        )?;
    }
    *last = Some((path.to_path_buf(), key));
    Ok(())
}

pub(crate) fn runtime_logs(
    path: &Path,
    level: Option<&str>,
    search: Option<&str>,
    before_id: Option<i64>,
    limit: u32,
) -> Result<Value, String> {
    let connection = open(path)?;
    let level = level.filter(|value| matches!(*value, "info" | "warning" | "error"));
    let search = search
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| clipped(value, MAX_LOG_SEARCH));
    let limit = i64::from(limit.clamp(1, 5000));
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM runtime_logs
             WHERE (?1 IS NULL OR level = ?1)
               AND (?2 IS NULL OR instr(lower(message), lower(?2)) > 0
                    OR instr(lower(source), lower(?2)) > 0
                    OR instr(lower(COALESCE(target, '')), lower(?2)) > 0)",
            params![level, search],
            |row| row.get(0),
        )
        .map_err(|error| format!("desktop_store_log_count:{error}"))?;
    let mut statement = connection
        .prepare(
            "SELECT id,
                    strftime('%Y-%m-%d %H:%M:%S', occurred_at, 'unixepoch', 'localtime'),
                    level, source, message, phase, target, operation_generation
             FROM runtime_logs
             WHERE (?1 IS NULL OR level = ?1)
               AND (?2 IS NULL OR instr(lower(message), lower(?2)) > 0
                    OR instr(lower(source), lower(?2)) > 0
                    OR instr(lower(COALESCE(target, '')), lower(?2)) > 0)
               AND (?3 IS NULL OR id < ?3)
             ORDER BY id DESC
             LIMIT ?4",
        )
        .map_err(|error| format!("desktop_store_log_query:{error}"))?;
    let rows = statement
        .query_map(params![level, search, before_id, limit + 1], |row| {
            Ok(RuntimeLogEntry {
                id: row.get(0)?,
                occurred_at: row.get(1)?,
                level: row.get(2)?,
                source: row.get(3)?,
                message: row.get(4)?,
                phase: row.get(5)?,
                target: row.get(6)?,
                generation: row
                    .get::<_, Option<i64>>(7)?
                    .and_then(|value| u64::try_from(value).ok()),
            })
        })
        .map_err(|error| format!("desktop_store_log_query:{error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("desktop_store_log_decode:{error}"))?;
    let has_more = rows.len() > limit as usize;
    let mut rows = rows;
    if has_more {
        rows.pop();
    }
    let next_before_id = has_more.then(|| rows.last().map(|row| row.id)).flatten();
    Ok(serde_json::json!({
        "logs": rows.into_iter().map(|row| serde_json::json!({
            "id": row.id,
            "occurred_at": row.occurred_at,
            "level": row.level,
            "source": row.source,
            "message": row.message,
            "phase": row.phase,
            "target": row.target,
            "operation_generation": row.generation,
        })).collect::<Vec<_>>(),
        "total": count,
        "has_more": has_more,
        "next_before_id": next_before_id,
    }))
}

fn sql_int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// One row per session and flow id: a flow offered again (a spawn failure noticed
/// after the flow was dropped) replaces its earlier final state.
fn insert_connection_batch(
    connection: &mut Connection,
    flows: &[FinishedFlow],
) -> Result<(), String> {
    let transaction = connection
        .transaction()
        .map_err(|error| format!("desktop_store_connection_begin:{error}"))?;
    {
        let mut statement = transaction
            .prepare_cached(
                "INSERT INTO connection_records
                    (session, flow_id, target, protocol, destination, route, reason, status,
                     stage, failure_stage, tx_bytes, rx_bytes, started_at_ms, ended_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                 ON CONFLICT (session, flow_id) DO UPDATE SET
                    destination = excluded.destination, route = excluded.route,
                    reason = excluded.reason, status = excluded.status, stage = excluded.stage,
                    failure_stage = excluded.failure_stage, tx_bytes = excluded.tx_bytes,
                    rx_bytes = excluded.rx_bytes, ended_at_ms = excluded.ended_at_ms",
            )
            .map_err(|error| format!("desktop_store_connection_insert:{error}"))?;
        for flow in flows {
            statement
                .execute(params![
                    sql_int(flow.session),
                    sql_int(flow.flow_id),
                    flow.target.as_deref().map(|value| clipped(value, 128)),
                    flow.protocol,
                    flow.destination.map(|value| value.to_string()),
                    flow.route,
                    flow.reason,
                    flow.status,
                    flow.stage,
                    flow.failure_stage,
                    sql_int(flow.tx_bytes),
                    sql_int(flow.rx_bytes),
                    sql_int(flow.started_unix_ms),
                    sql_int(flow.ended_unix_ms),
                ])
                .map_err(|error| format!("desktop_store_connection_insert:{error}"))?;
        }
    }
    prune_connection_records(&transaction, MAX_CONNECTION_ROWS)?;
    transaction
        .commit()
        .map_err(|error| format!("desktop_store_connection_commit:{error}"))
}

fn prune_connection_records(connection: &Connection, keep: i64) -> Result<(), String> {
    connection
        .execute(
            "DELETE FROM connection_records
             WHERE id <= (SELECT id FROM connection_records ORDER BY id DESC LIMIT 1 OFFSET ?1)",
            params![keep],
        )
        .map(|_| ())
        .map_err(|error| format!("desktop_store_connection_prune:{error}"))
}

/// Writes finished flows until every sender is gone. A batch that cannot be written
/// is counted and discarded, and the database is reopened for the next batch.
/// Forwarding threads never wait on this thread.
pub(crate) fn spawn_connection_recorder(
    path: PathBuf,
    events: Receiver<FlowEvent>,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("connection-recorder".into())
        .spawn(move || {
            let mut connection: Option<Connection> = None;
            while let Ok(first) = events.recv() {
                let deadline = Instant::now() + CONNECTION_BATCH_WINDOW;
                let mut batch = Vec::new();
                let mut flushes = Vec::new();
                let mut next = Some(first);
                while let Some(event) = next.take() {
                    match event {
                        FlowEvent::Finished(flow) => batch.push(flow),
                        FlowEvent::Flush(done) => flushes.push(done),
                    }
                    if !flushes.is_empty() || batch.len() >= CONNECTION_BATCH_ROWS {
                        break;
                    }
                    next = events
                        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                        .ok();
                }
                if !batch.is_empty() {
                    if connection.is_none() {
                        connection = open(&path).ok();
                    }
                    let written = connection.as_mut().is_some_and(|connection| {
                        insert_connection_batch(connection, &batch).is_ok()
                    });
                    if !written {
                        CONNECTION_WRITE_FAILURES.fetch_add(batch.len() as u64, Ordering::Relaxed);
                        connection = None;
                    }
                }
                for done in flushes {
                    let _ = done.send(());
                }
            }
        })
}

/// Newest finished connections first, paged by `before_id`. Status and target
/// are optional exact filters.
pub(crate) fn connection_records(
    path: &Path,
    status: Option<&str>,
    target: Option<&str>,
    before_id: Option<i64>,
    limit: u32,
) -> Result<Value, String> {
    let connection = open(path)?;
    let status = status.filter(|value| *value == "failed");
    let target = target.filter(|value| !value.is_empty());
    let limit = i64::from(limit.clamp(1, 1000));
    let count = |sql: &str| {
        connection
            .query_row(sql, params![status, target], |row| row.get::<_, i64>(0))
            .map_err(|error| format!("desktop_store_connection_count:{error}"))
    };
    let total = count(
        "SELECT COUNT(*) FROM connection_records
         WHERE (?1 IS NULL OR status = ?1)
           AND (?2 IS NULL OR target = ?2)",
    )?;
    let failed_total = connection
        .query_row(
            "SELECT COUNT(*) FROM connection_records
             WHERE status = 'failed'
               AND (?1 IS NULL OR target = ?1)",
            params![target],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| format!("desktop_store_connection_count:{error}"))?;
    let mut statement = connection
        .prepare(
            "SELECT id, session, flow_id, target, protocol, destination, route, reason, status,
                    stage, failure_stage, tx_bytes, rx_bytes,
                    MAX(ended_at_ms - started_at_ms, 0),
                    strftime('%m-%d %H:%M:%S', ended_at_ms / 1000, 'unixepoch', 'localtime')
             FROM connection_records
             WHERE (?1 IS NULL OR status = ?1)
               AND (?2 IS NULL OR target = ?2)
               AND (?3 IS NULL OR id < ?3)
             ORDER BY id DESC
             LIMIT ?4",
        )
        .map_err(|error| format!("desktop_store_connection_query:{error}"))?;
    let mut rows = statement
        .query_map(params![status, target, before_id, limit + 1], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "session": row.get::<_, i64>(1)?,
                "flow_id": row.get::<_, i64>(2)?,
                "target": row.get::<_, Option<String>>(3)?,
                "protocol": row.get::<_, String>(4)?,
                "destination": row.get::<_, Option<String>>(5)?,
                "route": row.get::<_, Option<String>>(6)?,
                "reason": row.get::<_, Option<String>>(7)?,
                "status": row.get::<_, String>(8)?,
                "stage": row.get::<_, String>(9)?,
                "failure_stage": row.get::<_, Option<String>>(10)?,
                "tx_bytes": row.get::<_, i64>(11)?,
                "rx_bytes": row.get::<_, i64>(12)?,
                "duration_ms": row.get::<_, i64>(13)?,
                "ended_at": row.get::<_, String>(14)?,
            }))
        })
        .map_err(|error| format!("desktop_store_connection_query:{error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("desktop_store_connection_decode:{error}"))?;
    let has_more = rows.len() > limit as usize;
    if has_more {
        rows.pop();
    }
    let next_before_id = has_more
        .then(|| rows.last().and_then(|row| row["id"].as_i64()))
        .flatten();
    Ok(serde_json::json!({
        "records": rows,
        "total": total,
        "failed_total": failed_total,
        "has_more": has_more,
        "next_before_id": next_before_id,
        "retention_rows": MAX_CONNECTION_ROWS,
        "write_failures": CONNECTION_WRITE_FAILURES.load(Ordering::Relaxed),
    }))
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
            let residential = ResidentialSettings::default();
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
    let residential = ResidentialSettings::default();
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
    ensure(path)
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
    // Empty means not configured yet; anything partly filled must parse.
    if residential != ResidentialSettings::default() {
        let credential = credential::from_settings(&residential)?;
        let _ = credential.endpoint();
    }
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
    let residential = credential::from_settings(&record.residential)
        .map_err(|_| "residential_credential_incomplete".to_string())?;
    Ok((record.profile, residential))
}

/// Residential settings for a policy file: the profile references the local
/// store instead of carrying credentials itself.
pub(crate) fn load_credential() -> Result<credential::Residential, String> {
    let record = load(&path()?)?;
    credential::from_settings(&record.residential)
        .map_err(|_| "residential_credential_incomplete".into())
}

/// Replaces the residential block (import or forget) without touching the rest
/// of the policy. An unsaved store keeps revision 0 so the profile still has to
/// be saved by the user.
pub(crate) fn update_residential(
    path: &Path,
    name: Option<String>,
    residential: ResidentialSettings,
) -> Result<Record, String> {
    if residential != ResidentialSettings::default() {
        credential::from_settings(&residential)?;
    }
    let current = ensure(path)?;
    let mut profile = current.profile;
    if let Some(name) = name {
        profile.set_credential(name);
    }
    let profile_json = serde_json::to_string(&profile).map_err(|e| e.to_string())?;
    if profile_json.len() + residential.password.len() > MAX_TEXT {
        return Err("desktop_store_too_large".into());
    }
    let next = if current.revision == 0 {
        0
    } else {
        current
            .revision
            .checked_add(1)
            .ok_or("revision_exhausted")?
    };
    let connection = open(path)?;
    let changed = connection
        .execute(
            "UPDATE desktop_state SET revision=?1, profile_json=?2, residential_ip=?3, residential_port=?4, residential_username=?5, residential_password=?6 WHERE id=1 AND revision=?7",
            params![
                next,
                profile_json,
                residential.ip,
                residential.port,
                residential.username,
                residential.password,
                current.revision
            ],
        )
        .map_err(|e| format!("desktop_store_residential:{e}"))?;
    if changed != 1 {
        return Err("stale_profile_revision: reload the saved profile".into());
    }
    Ok(Record {
        revision: next,
        profile,
        desktop: current.desktop,
        residential,
    })
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
    fn a_volume_without_wal_keeps_the_store_usable() {
        // An in-memory database reports journal mode "memory", like a volume
        // that cannot hold WAL's shared-memory index.
        let connection = open(Path::new(":memory:")).unwrap();
        insert_runtime_log(
            &connection,
            1,
            LogEntry {
                level: "info",
                source: "runtime",
                message: "ok",
                phase: None,
                target: None,
                generation: None,
            },
        )
        .unwrap();
        let rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM runtime_logs WHERE source = 'runtime'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 1);
        assert!(WAL_FALLBACK_LOGGED.load(Ordering::Relaxed));
        assert!(wal_fallback_message(&Ok("memory".into())).contains("memory"));
    }

    #[test]
    fn legacy_store_moves_beside_the_executable_once() {
        let root = std::env::temp_dir().join(format!(
            "wpl-store-migration-{}-{}",
            std::process::id(),
            now_unix_seconds().unwrap()
        ));
        let legacy_dir = root.join("state");
        let data_dir = root.join("program");
        fs::create_dir_all(&legacy_dir).unwrap();
        fs::create_dir_all(&data_dir).unwrap();
        let legacy = legacy_dir.join(FILE_NAME);
        let path = data_dir.join(FILE_NAME);
        let initial = ensure(&legacy).unwrap();
        let residential = ResidentialSettings {
            ip: "198.51.100.2".into(),
            port: 1080,
            username: "fixture-user".into(),
            password: "fixture-password".into(),
        };
        save(
            &legacy,
            initial.profile.clone(),
            initial.desktop.clone(),
            Some(residential),
            Some("0".into()),
        )
        .unwrap();

        adopt_legacy(&legacy, &path).unwrap();
        assert_eq!(revision(&path).unwrap(), 1);
        assert!(!legacy.exists());
        assert!(!data_dir.join(format!("{FILE_NAME}.migrating")).exists());

        // A store already beside the EXE wins; a later legacy file is left alone.
        ensure(&legacy).unwrap();
        adopt_legacy(&legacy, &path).unwrap();
        assert_eq!(revision(&path).unwrap(), 1);
        assert!(legacy.exists());
        let _ = fs::remove_dir_all(root);
    }

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
        // The password is part of the SQLite row; no Windows credential is used.
        assert!(load(&path).unwrap().residential == residential);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn only_a_new_store_starts_with_the_built_in_direct_suffixes() {
        let path = std::env::temp_dir().join(format!(
            "wpl-default-rules-store-{}.sqlite",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let initial = ensure(&path).unwrap();
        initial.profile.validate_draft().unwrap();
        let profile = serde_json::to_value(&initial.profile).unwrap();
        assert_eq!(
            profile["direct_suffixes"],
            serde_json::json!(domestic::DIRECT_SUFFIXES)
        );
        assert_eq!(profile["direct_domains"], serde_json::json!([]));
        assert_eq!(profile["direct_ips"], serde_json::json!([]));

        // Rules the user saved, even none, are never refilled on a later open.
        let mut cleared = profile.clone();
        cleared["direct_suffixes"] = serde_json::json!([]);
        save(
            &path,
            serde_json::from_value(cleared).unwrap(),
            initial.desktop.clone(),
            None,
            None,
        )
        .unwrap();
        let reopened = serde_json::to_value(load(&path).unwrap().profile).unwrap();
        assert_eq!(reopened["direct_suffixes"], serde_json::json!([]));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn residential_block_is_empty_until_written_and_import_bumps_a_saved_revision() {
        let path = std::env::temp_dir().join(format!(
            "wpl-residential-store-{}.sqlite",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let initial = ensure(&path).unwrap();
        assert!(initial.residential == ResidentialSettings::default());
        let settings = ResidentialSettings {
            ip: "198.51.100.7".into(),
            port: 1080,
            username: "fixture-user".into(),
            password: "fixture-password".into(),
        };
        // An unsaved store keeps revision 0; the user still has to save the profile.
        let imported =
            update_residential(&path, Some("fixture-residence".into()), settings.clone()).unwrap();
        assert_eq!(imported.revision, 0);
        let stored = load(&path).unwrap();
        assert!(stored.residential == settings);
        assert_eq!(
            serde_json::to_value(&stored.profile).unwrap()["credential"],
            "fixture-residence"
        );

        let saved = save(
            &path,
            initial.profile.clone(),
            initial.desktop.clone(),
            Some(settings.clone()),
            Some("0".into()),
        )
        .unwrap();
        assert_eq!(saved.revision, 1);
        let cleared = update_residential(&path, None, ResidentialSettings::default()).unwrap();
        assert_eq!(cleared.revision, 2);
        assert!(load(&path).unwrap().residential == ResidentialSettings::default());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn runtime_logs_are_persisted_and_filtered_in_sqlite() {
        let path = std::env::temp_dir().join(format!(
            "wpl-runtime-store-{}-{}.sqlite",
            std::process::id(),
            now_unix_seconds().unwrap()
        ));
        let _ = fs::remove_file(&path);
        append_runtime_log(
            &path,
            "info",
            "lifecycle",
            "已开始接管",
            Some("forwarding_managed"),
            Some("Test-Target"),
            Some(4),
        )
        .unwrap();
        append_runtime_log(
            &path,
            "error",
            "lifecycle",
            "操作失败",
            Some("recovery_required"),
            None,
            Some(5),
        )
        .unwrap();
        let errors = runtime_logs(&path, Some("error"), None, None, 50).unwrap();
        assert_eq!(errors["total"], 1);
        assert_eq!(errors["logs"][0]["level"], "error");
        let searched = runtime_logs(&path, None, Some("Test-Target"), None, 50).unwrap();
        assert_eq!(searched["total"], 1);
        assert_eq!(searched["logs"][0]["operation_generation"], 4);
        let first_page = runtime_logs(&path, None, None, None, 1).unwrap();
        assert_eq!(first_page["logs"].as_array().map(Vec::len), Some(1));
        assert_eq!(first_page["has_more"], true);
        let older =
            runtime_logs(&path, None, None, first_page["next_before_id"].as_i64(), 1).unwrap();
        assert_eq!(older["logs"][0]["operation_generation"], 4);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn runtime_snapshot_only_logs_state_transitions() {
        let path = std::env::temp_dir().join(format!(
            "wpl-runtime-snapshot-{}-{}.sqlite",
            std::process::id(),
            now_unix_seconds().unwrap()
        ));
        let _ = fs::remove_file(&path);
        let status = serde_json::json!({
            "phase": "idle",
            "operation_generation": 1,
            "dns_managed": false,
            "forwarding": {"traffic": {"tx_bytes": 1, "rx_bytes": 2}, "counters": {"direct_tcp": 1}}
        });
        record_runtime_snapshot(&path, &status).unwrap();
        let mut changed_metrics = status.clone();
        changed_metrics["forwarding"]["traffic"]["tx_bytes"] = 9.into();
        record_runtime_snapshot(&path, &changed_metrics).unwrap();
        let logs = runtime_logs(&path, None, None, None, 50).unwrap();
        assert_eq!(logs["total"], 1);
        let mut changed_phase = changed_metrics;
        changed_phase["phase"] = "recovery_required".into();
        record_runtime_snapshot(&path, &changed_phase).unwrap();
        let logs = runtime_logs(&path, None, None, None, 50).unwrap();
        assert_eq!(logs["total"], 2);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn metrics_only_polls_do_not_rewrite_the_stored_snapshot() {
        let path = std::env::temp_dir().join(format!(
            "wpl-runtime-metrics-{}-{}.sqlite",
            std::process::id(),
            now_unix_seconds().unwrap()
        ));
        let _ = fs::remove_file(&path);
        let mut status = serde_json::json!({
            "phase": "idle",
            "operation_generation": 1,
            "forwarding": {"traffic": {"tx_bytes": 1}}
        });
        record_runtime_snapshot(&path, &status).unwrap();
        status["forwarding"]["traffic"]["tx_bytes"] = 99.into();
        record_runtime_snapshot(&path, &status).unwrap();
        let stored: String = open(&path)
            .unwrap()
            .query_row(
                "SELECT snapshot_json FROM runtime_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let stored: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(stored["tx_bytes"], 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn flaky_recovery_inspection_does_not_log_every_poll() {
        let path = std::env::temp_dir().join(format!(
            "wpl-runtime-recovery-{}-{}.sqlite",
            std::process::id(),
            now_unix_seconds().unwrap()
        ));
        let _ = fs::remove_file(&path);
        let verified = serde_json::json!({
            "phase": "recovery_required",
            "operation_generation": 7,
            "active_target": "Test-Target",
            "recorded_target": "Test-Target"
        });
        let mut unverified = verified.clone();
        unverified["active_target"] = Value::Null;
        for status in [&verified, &unverified, &verified, &unverified] {
            record_runtime_snapshot(&path, status).unwrap();
        }
        let logs = runtime_logs(&path, None, None, None, 50).unwrap();
        assert_eq!(logs["total"], 1);
        assert_eq!(logs["logs"][0]["target"], "Test-Target");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn runtime_logs_keep_only_the_newest_rows() {
        let path = std::env::temp_dir().join(format!(
            "wpl-runtime-prune-{}-{}.sqlite",
            std::process::id(),
            now_unix_seconds().unwrap()
        ));
        let _ = fs::remove_file(&path);
        for generation in 1..=5 {
            append_runtime_log(
                &path,
                "info",
                "lifecycle",
                "row",
                None,
                None,
                Some(generation),
            )
            .unwrap();
        }
        prune_runtime_logs(&open(&path).unwrap(), 2).unwrap();
        let logs = runtime_logs(&path, None, None, None, 50).unwrap();
        assert_eq!(logs["total"], 2);
        assert_eq!(logs["logs"][0]["operation_generation"], 5);
        assert_eq!(logs["logs"][1]["operation_generation"], 4);
        let _ = fs::remove_file(path);
    }

    fn connection_store(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "wpl-connections-{name}-{}-{}.sqlite",
            std::process::id(),
            now_unix_seconds().unwrap()
        ));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn sqlite_store_uses_wal_journal_mode() {
        let path = connection_store("wal");
        let connection = open(&path).unwrap();
        let mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        drop(connection);
        let _ = fs::remove_file(path);
    }

    fn finished_flow(flow_id: u64, status: &'static str) -> FinishedFlow {
        FinishedFlow {
            session: 1_700_000_000_000,
            flow_id,
            target: Some("Test-Target".into()),
            protocol: "tcp",
            destination: Some(std::net::SocketAddr::from(([192, 0, 2, 9], 443))),
            route: Some("chain"),
            reason: Some("default_chain"),
            status,
            stage: "connect",
            failure_stage: (status == "failed").then_some("connect"),
            tx_bytes: 100,
            rx_bytes: 2048,
            started_unix_ms: 1_700_000_000_000,
            ended_unix_ms: 1_700_000_001_500,
        }
    }

    #[test]
    fn connection_records_are_paged_newest_first_and_filtered() {
        let path = connection_store("paged");
        let mut connection = open(&path).unwrap();
        let flows = (1..=5)
            .map(|id| finished_flow(id, if id % 2 == 0 { "failed" } else { "completed" }))
            .collect::<Vec<_>>();
        insert_connection_batch(&mut connection, &flows).unwrap();
        let first = connection_records(&path, None, None, None, 2).unwrap();
        assert_eq!(first["total"], 5);
        assert_eq!(first["failed_total"], 2);
        assert_eq!(first["has_more"], true);
        let ids = |page: &Value| {
            page["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["flow_id"].as_i64().unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(&first), [5, 4]);
        let row = &first["records"][0];
        assert_eq!(row["destination"], "192.0.2.9:443");
        assert_eq!(row["target"], "Test-Target");
        assert_eq!(row["duration_ms"], 1500);
        assert_eq!(
            row["ended_at"].as_str().unwrap().len(),
            "11-14 22:13:21".len()
        );
        let second =
            connection_records(&path, None, None, first["next_before_id"].as_i64(), 2).unwrap();
        assert_eq!(ids(&second), [3, 2]);
        let failed = connection_records(&path, Some("failed"), None, None, 50).unwrap();
        assert_eq!(ids(&failed), [4, 2]);
        assert_eq!(failed["records"][0]["failure_stage"], "connect");
        let mut other_target = finished_flow(6, "completed");
        other_target.target = Some("Other-Target".into());
        insert_connection_batch(&mut connection, &[other_target]).unwrap();
        let other = connection_records(&path, None, Some("Other-Target"), None, 50).unwrap();
        assert_eq!(other["total"], 1);
        assert_eq!(other["failed_total"], 0);
        assert_eq!(other["records"][0]["target"], "Other-Target");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_reoffered_flow_replaces_its_row_and_old_rows_are_pruned() {
        let path = connection_store("upsert");
        let mut connection = open(&path).unwrap();
        insert_connection_batch(&mut connection, &[finished_flow(1, "completed")]).unwrap();
        insert_connection_batch(&mut connection, &[finished_flow(1, "failed")]).unwrap();
        let rows = connection_records(&path, None, None, None, 50).unwrap();
        assert_eq!(rows["total"], 1);
        assert_eq!(rows["records"][0]["status"], "failed");
        let flows = (2..=6)
            .map(|id| finished_flow(id, "completed"))
            .collect::<Vec<_>>();
        insert_connection_batch(&mut connection, &flows).unwrap();
        prune_connection_records(&connection, 3).unwrap();
        let rows = connection_records(&path, None, None, None, 50).unwrap();
        assert_eq!(rows["total"], 3);
        assert_eq!(rows["records"][0]["flow_id"], 6);
        assert_eq!(rows["records"][2]["flow_id"], 4);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn the_recorder_writes_queued_flows_before_acknowledging_a_flush() {
        let path = connection_store("recorder");
        let (sender, events) = std::sync::mpsc::sync_channel(16);
        let handle = spawn_connection_recorder(path.clone(), events).unwrap();
        for id in 1..=3 {
            sender
                .send(FlowEvent::Finished(finished_flow(id, "completed")))
                .unwrap();
        }
        let (done, wait) = std::sync::mpsc::channel();
        sender.send(FlowEvent::Flush(done)).unwrap();
        wait.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(
            connection_records(&path, None, None, None, 50).unwrap()["total"],
            3
        );
        drop(sender);
        handle.join().unwrap();
        let _ = fs::remove_file(path);
    }
}
