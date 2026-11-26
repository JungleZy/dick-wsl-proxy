mod command;
mod controller;
mod credential;
mod desktop_control;
mod desktop_store;
mod environment;
mod host;
mod ingress;
mod kernel;
mod kernel_env;
mod lease;
mod managed;
mod managed_dns;
mod plan;
mod policy;
mod ports;
mod probe;
mod query_bridge;
mod transition;
mod wsl_platform;

use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use clap::Parser;
use command::{Command, Failure};

/// Finished flows waiting for the connection recorder. A takeover stop ends up to 256
/// active rows at once; beyond this many queued rows, new ones are counted and dropped.
const CONNECTION_QUEUE: usize = 8192;

/// How often a serving process re-checks that the live target still carries
/// this takeover's rules. Detection, not prevention: traffic from a restarted
/// target can leave unprotected until the next check.
const PROTECTION_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Recovers a poisoned lock instead of failing every later command. That is
/// safe because nothing on the controller path catches unwinds: a panic while
/// a command holds the lock ends the process, and the next one recovers from
/// the journal. Only the protection watch, a separate thread, can poison the
/// lock and leave the process running, and it holds the lock only briefly.
fn owned(controller: &Mutex<controller::Controller>) -> MutexGuard<'_, controller::Controller> {
    controller
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Checks protection about every 30 seconds. Each round takes the controller
/// lock twice, briefly, to start and to record, and never waits for it: a busy
/// lock drops the round, which is retried a second later. The slow observation
/// in between runs without the lock, so a stop never waits behind it.
struct ProtectionWatch {
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

/// Logs a panic of the watch thread, which `ProtectionWatch::drop` would
/// otherwise swallow while checks silently stop.
struct WatchPanicLog<'a>(&'a Option<PathBuf>);

impl Drop for WatchPanicLog<'_> {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Some(path) = self.0
        {
            let _ = desktop_store::append_runtime_log(
                path,
                "error",
                "protection",
                "保护检查意外停止，之后不会再定期确认接管规则是否仍然有效。停止接管后重新启动即可恢复检查。",
                None,
                None,
                None,
            );
        }
    }
}

fn try_owned(
    controller: &Mutex<controller::Controller>,
) -> Option<MutexGuard<'_, controller::Controller>> {
    match controller.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}

impl ProtectionWatch {
    fn spawn(controller: Arc<Mutex<controller::Controller>>, store: Option<PathBuf>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = std::thread::Builder::new()
            .name("protection-watch".into())
            .spawn(move || {
                let _panic_log = WatchPanicLog(&store);
                let mut next = Instant::now() + PROTECTION_CHECK_INTERVAL;
                while !stopping.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_secs(1));
                    if stopping.load(Ordering::Acquire) || Instant::now() < next {
                        continue;
                    }
                    let Some(mut guard) = try_owned(&controller) else {
                        continue;
                    };
                    let round = guard.watch_round();
                    let recovery = round.is_none().then(|| guard.recovery_round()).flatten();
                    drop(guard);
                    let Some(round) = round else {
                        next = Instant::now() + PROTECTION_CHECK_INTERVAL;
                        // Decision 33: a takeover this controller only knows
                        // from the journal is blocked when its rules are gone.
                        if let Some(recovery) = recovery
                            && recovery.due()
                            && !stopping.load(Ordering::Acquire)
                            && let Some(mut guard) = try_owned(&controller)
                        {
                            let target = recovery.plan().target.name.clone();
                            let note = guard.finish_recovery(recovery);
                            drop(guard);
                            if let (Some((level, message)), Some(path)) = (note, &store) {
                                let _ = desktop_store::append_runtime_log(
                                    path,
                                    level,
                                    "protection",
                                    &message,
                                    None,
                                    Some(&target),
                                    None,
                                );
                            }
                        }
                        continue;
                    };
                    let finding = round.observe();
                    if stopping.load(Ordering::Acquire) {
                        break;
                    }
                    // `ProtectionWatch::drop` joins this thread: never block on
                    // the lock, so a dropper holding it cannot deadlock.
                    let Some(mut guard) = try_owned(&controller) else {
                        continue;
                    };
                    let target = round.target().to_owned();
                    let outcome = guard.finish_watch(round, finding);
                    let log = |level: &str, message: &str, outcome: Option<&str>| {
                        if let Some(path) = &store {
                            let _ = desktop_store::append_runtime_log(
                                path,
                                level,
                                "protection",
                                message,
                                outcome,
                                Some(&target),
                                None,
                            );
                        }
                    };
                    if let Some(reason) = &outcome.lost {
                        log(
                            "error",
                            &protection_lost_message(reason),
                            Some("recovery_required"),
                        );
                    }
                    if let Some((level, message)) = &outcome.note {
                        log(level, message, None);
                    }
                    // Decision 33: block while still holding the lock that
                    // rechecked this takeover, so a stop, which removes the
                    // block with the rest, can never have run in between.
                    if let Some(plan) = &outcome.block
                        && let Some((level, message)) = guard.record_block(kernel::block(plan))
                    {
                        log(level, &message, None);
                    }
                    drop(guard);
                    next = Instant::now() + PROTECTION_CHECK_INTERVAL;
                }
            })
            .ok();
        Self { stop, worker }
    }
}

/// How long a daemon being started waits for a busy controller lock; well
/// inside the desktop's 15-second start deadline.
const DAEMON_LOCK_WAIT: Duration = Duration::from_secs(10);

/// Decision 33 with no controller left: while no process holds this user's
/// controller lock, the port custodian blocks the recorded target whose
/// rules are gone. The read-only check runs without the lock; the recheck and
/// the block run under it, so a controller starting meanwhile (which would
/// get `controller_busy` for those seconds) and any stop it runs come before
/// or after, never in between. Logs only when the outcome changes.
fn custodian_round(cookie: u32, store: &Option<PathBuf>, last: &mut Option<Result<(), String>>) {
    // A live controller checks for itself; do not duplicate its guest calls.
    if host::acquire().is_err() {
        return;
    }
    let Some(round) = controller::RecoveryRound::recorded() else {
        return;
    };
    if round.plan().cookie != cookie || !round.due() {
        return;
    }
    let Ok(_lock) = host::acquire() else {
        return;
    };
    if !round.current() {
        return;
    }
    let outcome = kernel::block(round.plan()).map(|_| ());
    if last.as_ref() == Some(&outcome) {
        return;
    }
    if let Some(path) = store {
        let (level, message) = match &outcome {
            Ok(()) => (
                "warning",
                "后台不在，已由端口持有进程在目标里断网：目标本机进程新发起的连接一律丢弃（回环除外），目标的 Docker 容器不在其内。请重新连接后台，停止接管并恢复直连。".to_owned(),
            ),
            Err(error) => (
                "error",
                format!("后台不在，端口持有进程在目标里断网失败（{error}），目标的新连接可能直连。请尽快重新连接后台并停止接管。"),
            ),
        };
        let _ = desktop_store::append_runtime_log(
            path,
            level,
            "protection",
            &message,
            None,
            Some(&round.plan().target.name),
            None,
        );
    }
    *last = Some(outcome);
}

/// The operator-facing log line for a `protection_lost: <kind>: ...` reason.
fn protection_lost_message(reason: &str) -> String {
    let mut parts = reason.splitn(3, ": ");
    let _ = parts.next();
    let kind = parts.next().unwrap_or_default();
    let detail = parts.next().unwrap_or_default();
    let cause = match kind {
        "restarted" => "目标发行版或 WSL 重启过，本次接管的规则已不再生效".to_owned(),
        "rules_incomplete" | "rules_missing" => {
            "目标发行版里本次接管的规则已缺失或不完整".to_owned()
        }
        "target_unregistered" => {
            return "目标发行版已被注销，无法再停止或清理它。请在概览页点「放弃本次记录」，并在下次启动接管前执行一次 wsl --shutdown。".into();
        }
        "environment_changed" => format!(
            "目标发行版的环境变了（{}），无法再确认本次接管覆盖它的全部流量",
            detail.split(':').next().unwrap_or(detail)
        ),
        _ => "无法再确认本次接管仍然有效".to_owned(),
    };
    if matches!(kind, "restarted" | "rules_incomplete" | "rules_missing") {
        // Decision 33: the block follows at once; its own line says how it went.
        return format!(
            "{cause}，它的新连接可能已不经代理，正在目标里断网。请停止接管并恢复，再重新启动接管。"
        );
    }
    format!("{cause}，它的新连接可能已不经代理。请停止接管并恢复，再重新启动接管。")
}

impl Drop for ProtectionWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Parser)]
#[command(
    version,
    about = "WSL2 single-target controller — scoped TCP/UDP ingress"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn run(command: Command) -> Result<u8, Failure> {
    if matches!(command, Command::Rpc) {
        use std::io::Read;
        const LIMIT: u64 = 1024 * 1024;
        let mut bytes = Vec::new();
        io::stdin()
            .lock()
            .take(LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| Failure::new("rpc_input", e.to_string()))?;
        if bytes.len() as u64 > LIMIT {
            return Err(Failure::new("rpc_input", "Request exceeds limit"));
        }
        let req = serde_json::from_slice(without_bom(&bytes))
            .map_err(|_| Failure::new("rpc_input", "Expected one JSON request"))?;
        let reply =
            wsl_proxyctl::ipc::request(&req).map_err(|e| Failure::new("rpc_transport", e))?;
        let rc = if reply.get("code").is_some() {
            1
        } else if reply.get("passed").and_then(|v| v.as_bool()) == Some(false) {
            2
        } else {
            0
        };
        command::emit(&reply)?;
        return Ok(rc);
    }
    if let Command::LeaseWorker { cookie } = command {
        let plan = controller::journal::load()
            .map_err(|e| Failure::new("lease_journal", e))?
            .filter(|p| p.cookie == cookie)
            .ok_or_else(|| Failure::new("lease_journal", "Instance no longer present"))?;
        let store = desktop_store::path().ok();
        let mut last = None;
        lease::worker(&plan, || custodian_round(cookie, &store, &mut last))
            .map_err(|e| Failure::new("lease_worker", e))?;
        return Ok(0);
    }
    // The port custodian of a lost takeover may hold the lock for the few
    // seconds it blocks the target (decision 33): a daemon being started
    // waits that out rather than fail as busy.
    let acquire = || {
        let deadline = Instant::now() + DAEMON_LOCK_WAIT;
        loop {
            match host::acquire() {
                #[cfg(windows)]
                Err(host::LockError::Busy)
                    if matches!(command, Command::Daemon) && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(250));
                }
                result => return result,
            }
        }
    };
    let _lock = acquire().map_err(|e| match e {
        #[cfg(windows)]
        host::LockError::Busy => Failure::new(
            "controller_busy",
            "Another controller holds this Windows user's lock",
        ),
        host::LockError::Other(s) => Failure::new("lock_failed", s),
    })?;
    let controller = Arc::new(Mutex::new(controller::Controller::default()));
    if matches!(command, Command::Maintenance) {
        // Do not start WSL, try recovery or even consult a live guest. A journal or pending
        // transition is sufficient reason to refuse. _lock stays alive across the handshake.
        let record =
            transition::load().map_err(|e| Failure::new("maintenance_state_unknown", e))?;
        let active = controller::journal::load()
            .map_err(|e| Failure::new("maintenance_state_unknown", e))?;
        if active.is_some() || record.pending.is_some() {
            return Err(Failure::new(
                "maintenance_requires_restore",
                "Restore the existing target before updating or uninstalling",
            ));
        }
        command::emit(
            &serde_json::json!({"maintenance":true,"protocol":1,"phase":"idle","operation_generation":record.generation,"version":env!("CARGO_PKG_VERSION"),"pid":std::process::id()}),
        )?;
        use std::io::Read;
        let mut release = Vec::new();
        io::stdin()
            .lock()
            .take(16)
            .read_until(b'\n', &mut release)
            .map_err(|e| Failure::new("maintenance_input", e.to_string()))?;
        if !maintenance_release(&release) {
            return Err(Failure::new(
                "maintenance_input",
                "Expected release or end of input",
            ));
        }
        return Ok(0);
    }
    if matches!(command, Command::Daemon) {
        let store = desktop_store::path().ok();
        if let Some(path) = &store {
            let _ = desktop_store::append_runtime_log(
                path,
                "info",
                "runtime",
                "后台服务已启动",
                None,
                None,
                None,
            );
        }
        // Every takeover served by this daemon keeps its finished connections in the
        // desktop store. Without a recorder, forwarding behaves exactly as before.
        let recorder = store.clone().and_then(|path| {
            let (sink, events) = ingress::FlowSink::new(CONNECTION_QUEUE);
            desktop_store::spawn_connection_recorder(path, events).ok()?;
            ingress::install_flow_sink(sink.clone());
            Some(sink)
        });
        let watch = ProtectionWatch::spawn(Arc::clone(&controller), store);
        let served =
            wsl_proxyctl::ipc::serve(|req| desktop_control::handle(req, &mut owned(&controller)));
        drop(watch);
        if let Some(sink) = &recorder {
            // shutdown_daemon is accepted only when idle, so every flow has already ended
            // and been queued; wait for the last batch before the process exits.
            let _ = sink.flush(std::time::Duration::from_secs(5));
        }
        served.map_err(|e| Failure::new("daemon_failed", e))?;
        return Ok(0);
    }
    if matches!(command, Command::Session) {
        command::dispatch(Command::Status, &mut owned(&controller))?;
    } else {
        let foreground = matches!(command, Command::Start { .. } | Command::StartScoped { .. });
        let rc = command::dispatch(command, &mut owned(&controller))?;
        if !foreground || rc != 0 {
            return Ok(rc);
        }
    }
    let watch = ProtectionWatch::spawn(Arc::clone(&controller), None);
    for (index, line) in io::stdin().lock().lines().enumerate() {
        // A broken input or output stream must still reach the stop below,
        // exactly like EOF. One undecodable line is reported and reading goes on.
        let line = match line {
            Ok(line) => line,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                if command::emit(&Failure::new("invalid_request", error.to_string())).is_err() {
                    break;
                }
                continue;
            }
            Err(error) => {
                let _ = command::emit(&Failure::new("input_failed", error.to_string()));
                break;
            }
        };
        let line = if index == 0 {
            line.strip_prefix('\u{feff}').unwrap_or(&line)
        } else {
            &line
        };
        let result = serde_json::from_str(line)
            .map_err(|e| Failure::new("invalid_request", e.to_string()))
            .and_then(|req| command::dispatch(req, &mut owned(&controller)));
        if let Err(e) = result
            && command::emit(&e).is_err()
        {
            break;
        }
    }
    drop(watch);
    let mut controller = owned(&controller);
    if controller.live.is_some() {
        controller
            .stop()
            .map_err(|e| Failure::new("restore_failed", e))?;
    }
    Ok(0)
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            let code = if e.code == "controller_busy" { 3 } else { 1 };
            if let Err(write_error) = command::emit(&e) {
                eprintln!("{}", write_error.message);
            }
            ExitCode::from(code)
        }
    }
}

/// `bytes` without one UTF-8 BOM at its start. Windows PowerShell 5.1 begins a
/// child's standard input with a BOM when the console input code page is
/// UTF-8 (`chcp 65001`, or Windows set to use UTF-8 for all languages, as on
/// GitHub's Windows runners). The installer talks to `rpc` and `maintenance`
/// that way; without this, such a console reported every finished install or
/// uninstall as failed and could not shut down an idle backend.
fn without_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
}

/// Whether the installer's last line to a maintenance helper releases it:
/// `release` with LF or CRLF, or end of input, after an optional BOM.
fn maintenance_release(line: &[u8]) -> bool {
    matches!(without_bom(line), b"" | b"release\n" | b"release\r\n")
}

#[cfg(test)]
mod tests {
    use super::{maintenance_release, without_bom};

    #[test]
    fn only_one_leading_bom_is_dropped_from_a_request() {
        assert_eq!(
            without_bom(b"\xEF\xBB\xBF{\"command\":\"status\"}"),
            b"{\"command\":\"status\"}"
        );
        assert_eq!(without_bom(b"{}"), b"{}");
        assert_eq!(
            without_bom(b"\xEF\xBB\xBF\xEF\xBB\xBF{}"),
            b"\xEF\xBB\xBF{}"
        );
        assert!(
            serde_json::from_slice::<serde_json::Value>(without_bom(
                b"\xEF\xBB\xBF{\"command\":\"status\"}"
            ))
            .is_ok()
        );
    }

    #[test]
    fn maintenance_release_accepts_a_utf8_bom_and_nothing_else() {
        for line in [
            &b""[..],
            b"release\n",
            b"release\r\n",
            b"\xEF\xBB\xBF",
            b"\xEF\xBB\xBFrelease\n",
            b"\xEF\xBB\xBFrelease\r\n",
        ] {
            assert!(maintenance_release(line), "{line:?}");
        }
        for line in [
            &b"release"[..],
            b"\xEF\xBB\xBFrelease",
            b"Release\n",
            b"release now\n",
            b"\xEF\xBB\xBF\xEF\xBB\xBFrelease\n",
            b"\n",
        ] {
            assert!(!maintenance_release(line), "{line:?}");
        }
    }
}
