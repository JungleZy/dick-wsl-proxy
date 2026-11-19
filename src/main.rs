mod credential;
mod host;
mod ingress;
mod kernel;
mod lease;
mod lifecycle;
mod m1;
mod m2;
mod managed_dns;
mod policy;
mod ports;
mod probe;
mod query_bridge;
mod transition;

use std::io::{self, BufRead, Write};
use std::net::SocketAddrV4;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(
    version,
    about = "WSL2 single-target controller — scoped TCP/UDP ingress"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    /// Enumerate registered distributions without starting them.
    List,
    /// Report live state (or a recorded instance requiring recovery).
    Status,
    /// Inspect only the named target and optional isolation witness (WSL may start them).
    Preflight {
        target: String,
        #[arg(long)]
        witness: Option<String>,
        #[arg(long, default_value = "43531")]
        #[serde(default = "default_port")]
        port: NonZeroU16,
    },
    /// Enable the single-target policy including protected system DNS.
    Start {
        target: String,
        #[arg(long)]
        witness: String,
        #[arg(long, default_value = "43531")]
        #[serde(default = "default_port")]
        port: NonZeroU16,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        expected_generation: Option<u64>,
    },
    /// M1 diagnostic only: local test tuples without a proxy policy or DNS interception.
    StartScoped {
        target: String,
        #[arg(long)]
        witness: String,
        #[arg(long, default_value = "43531")]
        #[serde(default = "default_port")]
        port: NonZeroU16,
        #[arg(long = "origin", required = true)]
        origins: Vec<SocketAddrV4>,
        #[arg(long)]
        expected_generation: Option<u64>,
    },
    /// Switch the live managed owner; obtain expected-generation from its last status.
    Switch {
        target: String,
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        port: Option<NonZeroU16>,
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    /// Store a residential proxy credential in the current user's Windows vault.
    ImportCredential {
        #[arg(long)]
        name: String,
        #[arg(long)]
        env_file: PathBuf,
    },
    /// Remove only the named wsl-proxyctl credential from the current user's vault.
    ForgetCredential {
        #[arg(long)]
        name: String,
    },
    /// Restore this session's target, or recover a journal left by an exited process.
    Stop {
        #[arg(long)]
        expected_generation: Option<u64>,
    },
    #[command(hide = true)]
    #[serde(skip)]
    LeaseWorker { cookie: u32 },
    /// Hold the per-user lock and accept JSON-line commands; EOF stops the owned ingress.
    Session,
}

fn default_port() -> NonZeroU16 {
    NonZeroU16::new(43531).unwrap()
}

#[derive(Serialize)]
struct Failure {
    code: &'static str,
    message: String,
}

impl Failure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn emit(value: &impl Serialize) -> Result<(), Failure> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value)
        .map_err(|e| Failure::new("output_failed", e.to_string()))?;
    writeln!(out)
        .and_then(|_| out.flush())
        .map_err(|e| Failure::new("output_failed", e.to_string()))
}

fn find<'a>(all: &'a [host::Distro], key: &str) -> Result<&'a host::Distro, Failure> {
    let mut hits = all
        .iter()
        .filter(|d| d.name == key || d.id.eq_ignore_ascii_case(key));
    let first = hits.next().ok_or_else(|| {
        Failure::new(
            "not_registered",
            format!("No registered distribution: {key}"),
        )
    })?;
    if hits.next().is_some() {
        return Err(Failure::new("ambiguous_target", key));
    }
    if first.version != 2 {
        return Err(Failure::new("not_wsl2", &first.name));
    }
    Ok(first)
}

#[derive(Serialize)]
struct Observation<'a> {
    distribution: &'a host::Distro,
    snapshot: probe::Snapshot,
}

fn observe(d: &host::Distro) -> Result<Observation<'_>, Failure> {
    let snapshot =
        probe::inspect(d).map_err(|e| Failure::new("probe_failed", format!("{}: {e}", d.name)))?;
    Ok(Observation {
        distribution: d,
        snapshot,
    })
}

#[derive(Serialize)]
struct Preflight<'a> {
    schema_version: u8,
    controller: serde_json::Value,
    target: Observation<'a>,
    witness: Option<Observation<'a>>,
    ingress: Option<ports::PortCheck>,
    ingress_reserved_by_current_owner: bool,
    blockers: Vec<String>,
    passed: bool,
}

fn preflight<'a>(
    all: &'a [host::Distro],
    key: &str,
    witness: Option<&str>,
    port: NonZeroU16,
    controller: serde_json::Value,
    owned_ingress: Option<SocketAddrV4>,
) -> Result<Preflight<'a>, Failure> {
    let target = find(all, key)?;
    let reference = witness.map(|k| find(all, k)).transpose()?;
    if reference.is_some_and(|w| w.id.eq_ignore_ascii_case(&target.id)) {
        return Err(Failure::new(
            "same_distribution",
            "Target and witness must be different registrations",
        ));
    }
    let target = observe(target)?;
    let witness = reference.map(observe).transpose()?;
    let s = &target.snapshot;
    let mut blockers = s.blockers.clone();
    match witness.as_ref().map(|w| &w.snapshot) {
        None => blockers.push("isolation_witness_missing".into()),
        Some(w) if !s.identity_valid || !w.identity_valid => {
            blockers.push("isolation_identity_unverified".into())
        }
        Some(w) if s.cgroup_root == w.cgroup_root || s.cgroup_ns == w.cgroup_ns => {
            blockers.push("shared_cgroup_boundary".into())
        }
        Some(_) => (),
    }
    let address = s
        .gateway
        .filter(|ip| {
            !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback() && !ip.is_broadcast()
        })
        .map(|ip| SocketAddrV4::new(ip, port.get()));
    let reserved = address.is_some() && address == owned_ingress;
    let ingress = address
        .filter(|_| !reserved)
        .map(|addr| ports::check(*addr.ip(), port));
    match (&ingress, reserved) {
        (None, false) => blockers.push("host_gateway_unverified".into()),
        (Some(p), _) if !p.available() => blockers.push("host_port_unavailable".into()),
        _ => (),
    }
    let passed = blockers.is_empty();
    Ok(Preflight {
        schema_version: 1,
        controller,
        target,
        witness,
        ingress,
        ingress_reserved_by_current_owner: reserved,
        blockers,
        passed,
    })
}

fn dispatch(request: Command, controller: &mut m1::Controller) -> Result<u8, Failure> {
    let registry = || host::distributions().map_err(|e| Failure::new("enumeration_failed", e));
    let error = |e: String| Failure::new("controller_error", e);
    match request {
        Command::List => emit(&registry()?)?,
        Command::Status => emit(&controller.status().map_err(error)?)?,
        Command::Preflight {
            target,
            witness,
            port,
        } => {
            let all = registry()?;
            let result = preflight(
                &all,
                &target,
                witness.as_deref(),
                port,
                controller.status().map_err(error)?,
                None,
            )?;
            emit(&result)?;
            return Ok(if result.passed { 0 } else { 2 });
        }
        Command::ImportCredential { name, env_file } => {
            credential::import(&name, &env_file).map_err(error)?;
            emit(&serde_json::json!({"credential_imported":true}))?;
        }
        Command::ForgetCredential { name } => {
            if m1::load().map_err(error)?.is_some()
                || transition::load().map_err(error)?.pending.is_some()
            {
                return Err(Failure::new(
                    "target_already_owned",
                    "Stop before changing stored credentials",
                ));
            }
            credential::remove(&name).map_err(error)?;
            emit(&serde_json::json!({"credential_removed":true}))?;
        }
        Command::Switch {
            target,
            expected_generation,
            port,
            profile,
        } => {
            let (source, old_runtime) = controller
                .switch_source(expected_generation)
                .map_err(error)?;
            let port = port
                .unwrap_or_else(|| NonZeroU16::new(source.ingress.port()).expect("validated port"));
            let all = registry()?;
            if find(&all, &target)?
                .id
                .eq_ignore_ascii_case(&source.target.id)
            {
                return Err(Failure::new("same_target", "Already managing this target"));
            }
            let result = preflight(
                &all,
                &target,
                Some(&source.target.id),
                port,
                controller.status().map_err(error)?,
                Some(source.ingress),
            )?;
            if !result.passed {
                emit(&result)?;
                return Ok(2);
            }
            let runtime = match profile {
                Some(path) => m2::Runtime::from_file(&path),
                None => old_runtime.for_next_target(),
            }
            .map_err(error)?;
            let resolver = m2::resolver(&result.target.snapshot).map_err(error)?;
            let new = m1::Plan::new(
                result.target.distribution,
                &result.target.snapshot,
                port,
                Vec::new(),
                Some(resolver),
            )
            .map_err(error)?;
            controller
                .switch(expected_generation, new, runtime)
                .map_err(error)?;
            emit(&controller.status().map_err(error)?)?;
        }
        request @ (Command::Start { .. } | Command::StartScoped { .. }) => {
            let (target, witness, port, origins, profile, expected_generation) = match request {
                Command::Start {
                    target,
                    witness,
                    port,
                    profile,
                    expected_generation,
                } => (
                    target,
                    witness,
                    port,
                    Vec::new(),
                    Some(profile),
                    expected_generation,
                ),
                Command::StartScoped {
                    target,
                    witness,
                    port,
                    origins,
                    expected_generation,
                } => (target, witness, port, origins, None, expected_generation),
                _ => unreachable!(),
            };
            if lifecycle::checked(expected_generation)
                .map_err(error)?
                .pending
                .is_some()
                || m1::load().map_err(error)?.is_some()
            {
                return Err(Failure::new(
                    "target_already_owned",
                    "Explicitly stop the previous target before starting",
                ));
            }
            let all = registry()?;
            let result = preflight(
                &all,
                &target,
                Some(&witness),
                port,
                controller.status().map_err(error)?,
                None,
            )?;
            if !result.passed {
                emit(&result)?;
                return Ok(2);
            }
            let runtime = profile
                .as_deref()
                .map(m2::Runtime::from_file)
                .transpose()
                .map_err(error)?;
            let resolver = if runtime.is_some() {
                Some(m2::resolver(&result.target.snapshot).map_err(error)?)
            } else {
                None
            };
            let plan = m1::Plan::new(
                result.target.distribution,
                &result.target.snapshot,
                port,
                origins,
                resolver,
            )
            .map_err(error)?;
            controller
                .start(plan, runtime, expected_generation)
                .map_err(error)?;
            emit(&controller.status().map_err(error)?)?;
        }
        Command::Stop {
            expected_generation,
        } => {
            lifecycle::checked(expected_generation).map_err(error)?;
            controller.stop().map_err(error)?;
            emit(&controller.status().map_err(error)?)?;
        }
        Command::Session | Command::LeaseWorker { .. } => {
            return Err(Failure::new(
                "invalid_request",
                "Cannot nest a controller session or custodian",
            ));
        }
    }
    Ok(0)
}

fn run(command: Command) -> Result<u8, Failure> {
    if let Command::LeaseWorker { cookie } = command {
        let plan = m1::load()
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
    let mut controller = m1::Controller::default();
    if matches!(command, Command::Session) {
        dispatch(Command::Status, &mut controller)?;
    } else {
        let foreground = matches!(command, Command::Start { .. } | Command::StartScoped { .. });
        let rc = dispatch(command, &mut controller)?;
        if !foreground || rc != 0 {
            return Ok(rc);
        }
    }
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|e| Failure::new("input_failed", e.to_string()))?;
        let result = serde_json::from_str(&line)
            .map_err(|e| Failure::new("invalid_request", e.to_string()))
            .and_then(|req| dispatch(req, &mut controller));
        if let Err(e) = result {
            emit(&e)?;
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
            if let Err(write_error) = emit(&e) {
                eprintln!("{}", write_error.message);
            }
            ExitCode::from(code)
        }
    }
}
