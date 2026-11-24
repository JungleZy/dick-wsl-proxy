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
                    drop(guard);
                    let Some(round) = round else {
                        next = Instant::now() + PROTECTION_CHECK_INTERVAL;
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
                    let lost = guard.finish_watch(round, finding);
                    drop(guard);
                    next = Instant::now() + PROTECTION_CHECK_INTERVAL;
                    if let (Some(reason), Some(path)) = (lost, &store) {
                        let _ = desktop_store::append_runtime_log(
                            path,
                            "error",
                            "protection",
                            &protection_lost_message(&reason),
                            Some("recovery_required"),
                            Some(&target),
                            None,
                        );
                    }
                }
            })
            .ok();
        Self { stop, worker }
    }
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
        let req = serde_json::from_slice(&bytes)
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
        lease::worker(&plan).map_err(|e| Failure::new("lease_worker", e))?;
        return Ok(0);
    }
    let _lock = host::acquire().map_err(|e| match e {
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
        let mut release = String::new();
        io::stdin()
            .lock()
            .take(10)
            .read_line(&mut release)
            .map_err(|e| Failure::new("maintenance_input", e.to_string()))?;
        if !matches!(release.as_str(), "" | "release\n" | "release\r\n") {
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
    for line in io::stdin().lock().lines() {
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
        let result = serde_json::from_str(&line)
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
