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
        wsl_proxyctl::ipc::serve(|req| desktop_control::handle(req, &mut controller))
            .map_err(|e| Failure::new("daemon_failed", e))?;
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
