use crate::{
    controller, credential, desktop_store, host, kernel_env, managed, managed_dns, plan, ports,
    probe, transition, wsl_platform,
};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::net::SocketAddrV4;
use std::num::NonZeroU16;
use std::path::PathBuf;

#[derive(Subcommand, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Command {
    /// Enumerate registered distributions without starting them.
    List,
    /// Report live state (or a recorded instance requiring recovery).
    Status,
    /// Inspect only the named target (WSL may start it).
    Preflight {
        target: String,
        #[arg(long, default_value = "43531")]
        #[serde(default = "default_port")]
        port: NonZeroU16,
    },
    /// Load the target's already-installed kernel modules and register empty
    /// legacy tables. Run only while idle; never installs packages.
    PrepareKernel {
        target: String,
        #[arg(long)]
        confirm: bool,
    },
    /// Read-only report of the WSL platform: `wsl.exe`, its kernel and the
    /// registered distributions. Starts no distribution and changes nothing.
    WslPlatform,
    /// Run `wsl --update`. It replaces the WSL package and may restart WSL, so
    /// it requires idle state and an explicit `--confirm`.
    WslPlatformUpdate {
        #[arg(long)]
        confirm: bool,
    },
    /// Lab diagnostic: time CONNECT by address and by name through the
    /// configured first hop and residential proxy, on tunnels authenticated
    /// beforehand. Sends nothing through the tunnels; needs no takeover.
    #[command(hide = true)]
    ChainProbe {
        #[arg(long = "name", required = true)]
        names: Vec<String>,
        #[arg(long, default_value = "443")]
        #[serde(default = "default_probe_port")]
        port: u16,
        #[arg(long, default_value = "5")]
        #[serde(default = "default_probe_rounds")]
        rounds: u32,
    },
    /// Enable the single-target policy including protected system DNS.
    Start {
        target: String,
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
    /// Import a literal .env into the local SQLite store's residential block.
    ImportCredential {
        #[arg(long)]
        name: String,
        #[arg(long)]
        env_file: PathBuf,
    },
    /// Clear the residential block in the local SQLite store.
    ForgetCredential {
        #[arg(long)]
        name: String,
    },
    /// Restore this session's target, or recover a journal left by an exited process.
    Stop {
        #[arg(long)]
        expected_generation: Option<u64>,
    },
    /// Release a takeover whose target distribution is no longer registered:
    /// frees its Windows ports and recovery records. Run `wsl --shutdown`
    /// before the next start; rules may remain in a running WSL VM.
    Abandon {
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        expected_generation: Option<u64>,
    },
    /// Reset the durable DNS alias ledger after an explicit idle-state confirmation.
    ResetDnsAliases {
        #[arg(long)]
        confirm: bool,
    },
    /// Installer-only: hold the current-user controller lock while idle until release or EOF.
    #[serde(skip)]
    Maintenance,
    /// Run the current-user desktop broker independently of any window.
    #[serde(skip)]
    Daemon,
    /// Submit one JSON request on stdin to an already running desktop broker.
    #[serde(skip)]
    Rpc,
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
pub(crate) struct Failure {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl Failure {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub(crate) fn emit(value: &impl Serialize) -> Result<(), Failure> {
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
    ingress: Option<ports::PortCheck>,
    ingress_reserved_by_current_owner: bool,
    blockers: Vec<String>,
    passed: bool,
}

fn preflight<'a>(
    all: &'a [host::Distro],
    key: &str,
    port: NonZeroU16,
    controller: serde_json::Value,
    owned_ingress: Option<SocketAddrV4>,
) -> Result<Preflight<'a>, Failure> {
    let target = find(all, key)?;
    let target = observe(target)?;
    let s = &target.snapshot;
    let mut blockers = s.blockers.clone();
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
        ingress,
        ingress_reserved_by_current_owner: reserved,
        blockers,
        passed,
    })
}

/// `wsl --update` replaces the WSL package and may restart WSL, which drops the
/// rules of a live takeover. The CLI and the desktop channel share this check so
/// both refuse in the same situations.
pub(crate) fn wsl_update_ready(
    controller: &mut controller::Controller,
    confirm: bool,
) -> Result<(), Failure> {
    if !confirm {
        return Err(Failure::new(
            "confirmation_required",
            "Pass --confirm: wsl --update restarts WSL and stops every distribution",
        ));
    }
    let state = controller
        .status()
        .map_err(|error| Failure::new("controller_error", error))?;
    if state["phase"] != "idle" {
        return Err(Failure::new(
            "wsl_update_requires_idle",
            "Stop the target and restore direct networking first",
        ));
    }
    if controller::journal::load()
        .map_err(|error| Failure::new("controller_error", error))?
        .is_some()
        || transition::load()
            .map_err(|error| Failure::new("controller_error", error))?
            .pending
            .is_some()
    {
        return Err(Failure::new(
            "target_already_owned",
            "Restore the recorded target before updating WSL",
        ));
    }
    Ok(())
}

pub(crate) fn dispatch_result(
    request: Command,
    controller: &mut controller::Controller,
) -> Result<(u8, serde_json::Value), Failure> {
    let registry = || host::distributions().map_err(|e| Failure::new("enumeration_failed", e));
    let error = |e: String| Failure::new("controller_error", e);
    let response = match request {
        Command::List => serde_json::json!(registry()?),
        Command::Status => controller.status().map_err(error)?,
        Command::Preflight { target, port } => {
            let all = registry()?;
            let state = controller.status().map_err(error)?;
            // Switching to a new target must not test-bind over the daemon's own exclusive
            // sockets. The active controller target is the only owner that can reserve them.
            let reserved = if state["phase"] == "forwarding_managed" {
                let active = state["active_target"].as_str();
                let candidate = find(&all, &target)?;
                if active.is_some_and(|name| name != candidate.name) {
                    let generation = state["operation_generation"]
                        .as_u64()
                        .ok_or_else(|| error("missing_operation_generation".into()))?;
                    Some(
                        controller
                            .switch_source(generation)
                            .map_err(error)?
                            .0
                            .ingress,
                    )
                } else {
                    None
                }
            } else {
                None
            };
            let result = preflight(&all, &target, port, state, reserved)?;
            return Ok((if result.passed { 0 } else { 2 }, serde_json::json!(result)));
        }
        Command::PrepareKernel { target, confirm } => {
            if !confirm {
                return Err(Failure::new(
                    "confirmation_required",
                    "Pass --confirm after stopping any takeover: loading modules changes the shared WSL kernel",
                ));
            }
            let state = controller.status().map_err(error)?;
            if state["phase"] != "idle" {
                return Err(Failure::new(
                    "kernel_prepare_requires_idle",
                    "Stop the target and restore direct networking first",
                ));
            }
            if controller::journal::load().map_err(error)?.is_some()
                || transition::load().map_err(error)?.pending.is_some()
            {
                return Err(Failure::new(
                    "target_already_owned",
                    "Restore the recorded target before preparing the kernel",
                ));
            }
            let all = registry()?;
            let distro = find(&all, &target)?;
            let preparation = kernel_env::prepare(distro).map_err(|e| {
                Failure::new("kernel_prepare_failed", format!("{}: {e}", distro.name))
            })?;
            let (record_path, record_error) = match kernel_env::record(distro, &preparation) {
                Ok(path) => (Some(path.to_string_lossy().into_owned()), None),
                Err(error) => (None, Some(error)),
            };
            let (blockers, inspection_error) = match probe::inspect(distro) {
                Ok(snapshot) => (snapshot.blockers, None),
                Err(error) => (Vec::new(), Some(error)),
            };
            serde_json::json!({
                "schema_version": 1,
                "target": distro,
                "preparation": preparation,
                "record_path": record_path,
                "record_error": record_error,
                "blockers": blockers,
                "inspection_error": inspection_error,
            })
        }
        Command::WslPlatform => {
            wsl_platform::inspect().map_err(|error| Failure::new("wsl_platform_failed", error))?
        }
        Command::WslPlatformUpdate { confirm } => {
            wsl_update_ready(controller, confirm)?;
            wsl_platform::update().map_err(|error| {
                let code = match error.as_str() {
                    "wsl_not_installed" => "wsl_not_installed",
                    _ => "wsl_update_failed",
                };
                Failure::new(code, error)
            })?
        }
        Command::ChainProbe {
            names,
            port,
            rounds,
        } => chain_probe(&names, port, rounds.clamp(1, 20)).map_err(error)?,
        Command::ImportCredential { name, env_file } => {
            credential::valid_name(&name).map_err(error)?;
            let settings = credential::settings_from_file(&env_file).map_err(error)?;
            let record = desktop_store::update_residential(
                &desktop_store::path().map_err(error)?,
                Some(name),
                settings,
            )
            .map_err(error)?;
            serde_json::json!({
                "credential_imported":true,
                "revision":record.revision.to_string()
            })
        }
        Command::ForgetCredential { name } => {
            credential::valid_name(&name).map_err(error)?;
            if controller::journal::load().map_err(error)?.is_some()
                || transition::load().map_err(error)?.pending.is_some()
            {
                return Err(Failure::new(
                    "target_already_owned",
                    "Stop before changing stored credentials",
                ));
            }
            let record = desktop_store::update_residential(
                &desktop_store::path().map_err(error)?,
                None,
                desktop_store::ResidentialSettings::default(),
            )
            .map_err(error)?;
            serde_json::json!({
                "credential_removed":true,
                "revision":record.revision.to_string()
            })
        }
        Command::ResetDnsAliases { confirm } => {
            if !confirm {
                return Err(Failure::new(
                    "confirmation_required",
                    "Pass --confirm after stopping the target and allowing cached DNS aliases to expire",
                ));
            }
            let state = controller.status().map_err(error)?;
            if state["phase"] != "idle" {
                return Err(Failure::new(
                    "target_already_owned",
                    "Stop the target and confirm idle state before resetting DNS aliases",
                ));
            }
            managed_dns::reset_aliases().map_err(error)?;
            serde_json::json!({"dns_aliases_reset":true})
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
                port,
                controller.status().map_err(error)?,
                Some(source.ingress),
            )?;
            if !result.passed {
                return Ok((2, serde_json::json!(result)));
            }
            let runtime = match profile {
                Some(path) => managed::Runtime::from_file(&path),
                None => old_runtime.for_next_target(),
            }
            .map_err(error)?;
            let resolver = managed::resolver(&result.target.snapshot).map_err(error)?;
            runtime
                .dns
                .set_search_suffixes(managed::search_suffixes(&result.target.snapshot));
            let new = plan::Plan::new(
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
            controller.status().map_err(error)?
        }
        Command::Start {
            target,
            port,
            profile,
            expected_generation,
        } => {
            return start(
                controller,
                &target,
                port,
                Vec::new(),
                Some(profile),
                expected_generation,
            );
        }
        Command::StartScoped {
            target,
            port,
            origins,
            expected_generation,
        } => {
            return start(
                controller,
                &target,
                port,
                origins,
                None,
                expected_generation,
            );
        }
        Command::Stop {
            expected_generation,
        } => {
            controller::lifecycle::checked(expected_generation).map_err(error)?;
            controller.stop().map_err(error)?;
            controller.status().map_err(error)?
        }
        Command::Abandon {
            confirm,
            expected_generation,
        } => {
            if !confirm {
                return Err(Failure::new(
                    "confirmation_required",
                    "Pass --confirm after verifying the target distribution was unregistered; run wsl --shutdown before the next start",
                ));
            }
            let abandoned = controller.abandon(expected_generation).map_err(error)?;
            let mut status = controller.status().map_err(error)?;
            status["abandoned"] = abandoned;
            status
        }
        Command::Session
        | Command::Daemon
        | Command::Rpc
        | Command::Maintenance
        | Command::LeaseWorker { .. } => {
            return Err(Failure::new(
                "invalid_request",
                "Cannot nest a controller session or custodian",
            ));
        }
    };
    Ok((0, response))
}

/// Starts a managed (`profile`) or scoped (`origins`) takeover. A failed
/// preflight is returned with exit code 2, as the CLI reports it.
fn start(
    controller: &mut controller::Controller,
    target: &str,
    port: NonZeroU16,
    origins: Vec<SocketAddrV4>,
    profile: Option<PathBuf>,
    expected_generation: Option<u64>,
) -> Result<(u8, serde_json::Value), Failure> {
    let error = |e: String| Failure::new("controller_error", e);
    if controller::lifecycle::checked(expected_generation)
        .map_err(error)?
        .pending
        .is_some()
        || controller::journal::load().map_err(error)?.is_some()
    {
        return Err(Failure::new(
            "target_already_owned",
            "Explicitly stop the previous target before starting",
        ));
    }
    let all = host::distributions().map_err(|e| Failure::new("enumeration_failed", e))?;
    let result = preflight(
        &all,
        target,
        port,
        controller.status().map_err(error)?,
        None,
    )?;
    if !result.passed {
        return Ok((2, serde_json::json!(result)));
    }
    let runtime = profile
        .as_deref()
        .map(managed::Runtime::from_file)
        .transpose()
        .map_err(error)?;
    let resolver = match &runtime {
        Some(runtime) => {
            runtime
                .dns
                .set_search_suffixes(managed::search_suffixes(&result.target.snapshot));
            Some(managed::resolver(&result.target.snapshot).map_err(error)?)
        }
        None => None,
    };
    let plan = plan::Plan::new(
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
    Ok((0, controller.status().map_err(error)?))
}

pub(crate) fn dispatch(
    request: Command,
    controller: &mut controller::Controller,
) -> Result<u8, Failure> {
    let (rc, response) = dispatch_result(request, controller)?;
    emit(&response)?;
    Ok(rc)
}

fn default_probe_port() -> u16 {
    443
}

fn default_probe_rounds() -> u32 {
    5
}

/// Times CONNECT by address and by name, alternating which goes first, for
/// each non-allowlisted name. Credentials stay inside the policy.
fn chain_probe(names: &[String], port: u16, rounds: u32) -> Result<serde_json::Value, String> {
    use crate::policy::ChainTarget;
    use std::net::{SocketAddr, SocketAddrV4};
    let runtime = managed::Runtime::from_file(&desktop_store::path()?)?;
    let mut results = Vec::new();
    for name in names {
        if runtime.policy.allows_domain(name) {
            results.push(serde_json::json!({"name": name, "skipped": "allowlisted"}));
            continue;
        }
        let address = match runtime.dns.resolve_ipv4(name) {
            Ok(addresses) if !addresses.is_empty() => addresses[0],
            Ok(_) => {
                results.push(serde_json::json!({"name": name, "error": "no A record"}));
                continue;
            }
            Err(error) => {
                results.push(serde_json::json!({"name": name, "error": error}));
                continue;
            }
        };
        let by_address = ChainTarget::Address(SocketAddr::V4(SocketAddrV4::new(address, port)));
        let by_name = ChainTarget::Name(name.clone(), port);
        let (mut address_ms, mut name_ms, mut errors) = (Vec::new(), Vec::new(), Vec::new());
        for round in 0..rounds {
            let order = if round % 2 == 0 {
                [(&by_address, true), (&by_name, false)]
            } else {
                [(&by_name, false), (&by_address, true)]
            };
            for (target, is_address) in order {
                match runtime.policy.probe_connect(target) {
                    Ok(elapsed) => {
                        let ms = elapsed.as_secs_f64() * 1000.0;
                        if is_address {
                            address_ms.push(ms);
                        } else {
                            name_ms.push(ms);
                        }
                    }
                    Err(error) => errors.push(serde_json::json!({
                        "by": if is_address { "address" } else { "name" },
                        "error": error,
                    })),
                }
            }
        }
        results.push(serde_json::json!({
            "name": name,
            "address": address.to_string(),
            "by_address_ms": address_ms,
            "by_name_ms": name_ms,
            "errors": errors,
        }));
    }
    Ok(serde_json::json!({ "chain_probe": results }))
}
