mod command;
mod controller;
mod credential;
mod desktop_control;
mod desktop_store;
mod environment;
mod host;
mod ingress;
mod kernel;
mod lease;
mod managed;
mod managed_dns;
mod plan;
mod policy;
mod ports;
mod probe;
mod query_bridge;
mod transition;

use std::io::{self, BufRead};
use std::process::ExitCode;

use clap::Parser;
use command::{Command, Failure};

/// Finished flows waiting for the connection recorder. A takeover stop ends up to 256
/// active rows at once; beyond this many queued rows, new ones are counted and dropped.
const CONNECTION_QUEUE: usize = 8192;

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
    let mut controller = controller::Controller::default();
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
        let recorder = store.and_then(|path| {
            let (sink, events) = ingress::FlowSink::new(CONNECTION_QUEUE);
            desktop_store::spawn_connection_recorder(path, events).ok()?;
            ingress::install_flow_sink(sink.clone());
            Some(sink)
        });
        let served = wsl_proxyctl::ipc::serve(|req| desktop_control::handle(req, &mut controller));
        if let Some(sink) = &recorder {
            // shutdown_daemon is accepted only when idle, so every flow has already ended
            // and been queued; wait for the last batch before the process exits.
            let _ = sink.flush(std::time::Duration::from_secs(5));
        }
        served.map_err(|e| Failure::new("daemon_failed", e))?;
        return Ok(0);
    }
    if matches!(command, Command::Session) {
        command::dispatch(Command::Status, &mut controller)?;
    } else {
        let foreground = matches!(command, Command::Start { .. } | Command::StartScoped { .. });
        let rc = command::dispatch(command, &mut controller)?;
        if !foreground || rc != 0 {
            return Ok(rc);
        }
    }
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|e| Failure::new("input_failed", e.to_string()))?;
        let result = serde_json::from_str(&line)
            .map_err(|e| Failure::new("invalid_request", e.to_string()))
            .and_then(|req| command::dispatch(req, &mut controller));
        if let Err(e) = result {
            command::emit(&e)?;
        }
    }
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
