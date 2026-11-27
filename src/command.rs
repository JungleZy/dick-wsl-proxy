use crate::{
    controller, credential, desktop_store, environment, host, kernel_env, managed, managed_dns,
    plan, ports, probe, transition, wsl_platform,
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
        /// The environment whose residential proxy to use.
        #[arg(long)]
        target: String,
        #[arg(long = "name", required = true)]
        names: Vec<String>,
        #[arg(long, default_value = "443")]
        #[serde(default = "default_probe_port")]
        port: u16,
        #[arg(long, default_value = "5")]
        #[serde(default = "default_probe_rounds")]
        rounds: u32,
    },
    /// Enable the single-target policy including protected system DNS, with
    /// the target's own residential proxy. First sets the target's timezone to
    /// the residential exit's and restarts the target, ending every process in
    /// it. Without `--port`, uses the ingress port saved for the target.
    Start {
        target: String,
        #[arg(long)]
        #[serde(default)]
        port: Option<NonZeroU16>,
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
    /// Import a literal .env as one environment's residential proxy in the
    /// local SQLite store. The environment keeps its ingress port.
    ImportCredential {
        #[arg(long)]
        name: String,
        /// The environment, by name or registry GUID.
        #[arg(long)]
        target: String,
        #[arg(long)]
        env_file: PathBuf,
    },
    /// Clear one environment's residential proxy in the local SQLite store,
    /// or without `--target` the old unassigned one.
    ForgetCredential {
        #[arg(long)]
        name: String,
        #[arg(long)]
        target: Option<String>,
    },
    /// Restore one environment's target, or recover a journal left by an
    /// exited process. Without `--target`, the only environment taken over.
    Stop {
        #[arg(long)]
        expected_generation: Option<u64>,
        /// The environment, by name or registry GUID.
        #[arg(long)]
        #[serde(default)]
        target: Option<String>,
    },
    /// Release a takeover whose target distribution is no longer registered:
    /// frees its Windows ports and recovery records, and deletes its rules
    /// from another environment still taken over (decision 41). With none,
    /// run `wsl --shutdown` before the next start.
    Abandon {
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        expected_generation: Option<u64>,
        /// The environment, by its registry GUID (it is no longer
        /// registered, so its name cannot be looked up).
        #[arg(long)]
        #[serde(default)]
        target: Option<String>,
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
    // `wsl --update` may restart WSL: every takeover must be stopped.
    if controller
        .any_owned()
        .map_err(|error| Failure::new("controller_error", error))?
    {
        return Err(Failure::new(
            "wsl_update_requires_idle",
            "Stop every takeover and restore direct networking first",
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
            // Checking a target that is taken over must not test-bind over
            // its own exclusive sockets; every other environment has a port
            // of its own (decision 40).
            let candidate = find(&all, &target)?.id.clone();
            let reserved = controller
                .live_ingresses()
                .into_iter()
                .find(|(id, _)| id.eq_ignore_ascii_case(&candidate))
                .map(|(_, ingress)| ingress);
            let result = preflight(&all, &target, port, state, reserved)?;
            return Ok((if result.passed { 0 } else { 2 }, serde_json::json!(result)));
        }
        Command::PrepareKernel { target, confirm } => {
            if !confirm {
                return Err(Failure::new(
                    "confirmation_required",
                    "Pass --confirm after stopping this target's takeover: loading modules changes the shared WSL kernel",
                ));
            }
            // Only this environment must be idle (decision 40): loading a
            // module adds to the shared kernel, and the legacy tables it
            // registers cannot touch another takeover's private tables
            // (decision 41).
            let all = registry()?;
            let distro = find(&all, &target)?;
            if controller.owned(&distro.id).map_err(error)? {
                return Err(Failure::new(
                    "kernel_prepare_requires_idle",
                    "Stop this target's takeover and restore direct networking first",
                ));
            }
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
            target,
            names,
            port,
            rounds,
        } => {
            let all = registry()?;
            let distro = find(&all, &target)?;
            chain_probe(&distro.id, &names, port, rounds.clamp(1, 20)).map_err(error)?
        }
        Command::ImportCredential {
            name,
            target,
            env_file,
        } => {
            credential::valid_name(&name).map_err(error)?;
            let settings = credential::settings_from_file(&env_file).map_err(error)?;
            let all = registry()?;
            let distro = find(&all, &target)?;
            let path = desktop_store::path().map_err(error)?;
            let record = replace_residential(&path, &distro.id, settings).map_err(error)?;
            desktop_store::set_credential_name(&path, name).map_err(error)?;
            serde_json::json!({
                "credential_imported":true,
                "target":distro.name,
                "revision":record.revision.to_string(),
                "ingress_port":record.ingress_port,
            })
        }
        Command::ForgetCredential { name, target } => {
            credential::valid_name(&name).map_err(error)?;
            let path = desktop_store::path().map_err(error)?;
            let Some(target) = target else {
                desktop_store::discard_legacy_residential(&path).map_err(error)?;
                return Ok((0, serde_json::json!({"credential_removed":true})));
            };
            let all = registry()?;
            let distro = find(&all, &target)?;
            // The proxy of a live or recorded takeover stays until it is stopped.
            if owned_by(&distro.id).map_err(error)? {
                return Err(Failure::new(
                    "target_already_owned",
                    "Stop this target before changing its stored credentials",
                ));
            }
            let record = replace_residential(
                &path,
                &distro.id,
                desktop_store::ResidentialSettings::default(),
            )
            .map_err(error)?;
            serde_json::json!({
                "credential_removed":true,
                "target":distro.name,
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
            // One alias ledger serves every environment (decision 40).
            if controller.any_owned().map_err(error)? {
                return Err(Failure::new(
                    "target_already_owned",
                    "Stop every takeover and confirm idle state before resetting DNS aliases",
                ));
            }
            managed_dns::reset_aliases().map_err(error)?;
            serde_json::json!({"dns_aliases_reset":true})
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
                Some(port),
                origins,
                None,
                expected_generation,
            );
        }
        Command::Stop {
            expected_generation,
            target,
        } => {
            let scope = scope_of(controller, target.as_deref())?;
            controller::lifecycle::checked(&scope, expected_generation).map_err(error)?;
            controller.session(&scope).stop().map_err(error)?;
            let status = controller.session_status(&scope).map_err(error)?;
            with_unproven_left(controller, &scope, status)
        }
        Command::Abandon {
            confirm,
            expected_generation,
            target,
        } => {
            if !confirm {
                return Err(Failure::new(
                    "confirmation_required",
                    "Pass --confirm after verifying the target distribution was unregistered; run wsl --shutdown before the next start",
                ));
            }
            let scope = scope_of(controller, target.as_deref())?;
            let abandoned = controller
                .abandon(&scope, expected_generation)
                .map_err(error)?;
            let mut status = controller.session_status(&scope).map_err(error)?;
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
    port: Option<NonZeroU16>,
    origins: Vec<SocketAddrV4>,
    profile: Option<PathBuf>,
    expected_generation: Option<u64>,
) -> Result<(u8, serde_json::Value), Failure> {
    let error = |e: String| Failure::new("controller_error", e);
    let all = host::distributions().map_err(|e| Failure::new("enumeration_failed", e))?;
    let distro_id = find(&all, target)?.id.clone();
    // Other environments may be taken over (decision 40); this one may not.
    let scope = transition::scope(&distro_id).map_err(error)?;
    controller::lifecycle::checked(&scope, expected_generation).map_err(error)?;
    if controller.owned(&distro_id).map_err(error)? {
        return Err(Failure::new(
            "target_already_owned",
            "Explicitly stop this target's takeover before starting it again",
        ));
    }
    docker_limit(controller, find(&all, target)?)?;
    let port = match (port, profile.as_deref()) {
        (Some(port), _) => port,
        (None, Some(path)) if managed::is_store(path) => {
            // A store from before decision 40 still holds one shared proxy.
            desktop_store::adopt_legacy_residential(path, &all).map_err(error)?;
            let row = desktop_store::environment(path, &distro_id)
                .map_err(error)?
                .ok_or_else(|| error("residential_credential_incomplete".into()))?;
            NonZeroU16::new(row.ingress_port).ok_or_else(|| error("invalid_ingress_port".into()))?
        }
        (None, _) => default_port(),
    };
    let first = preflight(
        &all,
        target,
        port,
        controller.status().map_err(error)?,
        None,
    )?;
    if !first.passed {
        return Ok((2, serde_json::json!(first)));
    }
    let runtime = profile
        .as_deref()
        .map(|path| managed::Runtime::from_file(path, &distro_id))
        .transpose()
        .map_err(error)?;
    let restarted;
    let mut synced_timezone = None;
    let result = match &runtime {
        Some(runtime) => {
            let timezone =
                environment::timezone::sync_and_restart(runtime, first.target.distribution)
                    .map_err(|e| Failure::new("timezone_sync_failed", e))?;
            // The restart made the snapshot stale: everything below uses a fresh one.
            restarted = host::distributions().map_err(|e| Failure::new("enumeration_failed", e))?;
            let result = preflight(
                &restarted,
                target,
                port,
                controller.status().map_err(error)?,
                None,
            )?;
            if !result.passed {
                let mut refused = serde_json::json!(result);
                refused["timezone_synced"] = serde_json::json!(timezone);
                return Ok((2, refused));
            }
            synced_timezone = Some(timezone);
            result
        }
        None => first,
    };
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
    Ok((
        0,
        with_timezone(
            controller.session_status(&scope).map_err(error)?,
            synced_timezone,
        ),
    ))
}

/// Tells the caller which timezone the target was set to before its restart.
fn with_timezone(mut response: serde_json::Value, timezone: Option<String>) -> serde_json::Value {
    if let (Some(timezone), Some(object)) = (timezone, response.as_object_mut()) {
        object.insert("timezone_synced".into(), serde_json::json!(timezone));
    }
    response
}

pub(crate) fn dispatch(
    request: Command,
    controller: &mut controller::Controller,
) -> Result<u8, Failure> {
    let (rc, response) = dispatch_result(request, controller)?;
    emit(&response)?;
    Ok(rc)
}

/// At most one environment taken over at a time runs Docker (decision 40):
/// two would share the `docker0` bridge name and its address range in the
/// one network stack. Refused before anything changes in the target.
fn docker_limit(controller: &controller::Controller, distro: &host::Distro) -> Result<(), Failure> {
    let Some(other) = controller.other_with_containers(&distro.id) else {
        return Ok(());
    };
    let active = host::guest_script(
        distro,
        "systemctl is-active --quiet docker.service && echo active || echo inactive",
    )
    .map_err(|e| Failure::new("probe_failed", format!("{}: {e}", distro.name)))?;
    if active.trim() == "active" {
        return Err(Failure::new(
            "docker_in_two_takeovers",
            format!(
                "{other} is taken over and runs Docker; stop Docker in {} or that takeover first",
                distro.name
            ),
        ));
    }
    Ok(())
}

/// Whether a live or recorded takeover names this environment. Reads only
/// its records: a live takeover always has a journal.
pub(crate) fn owned_by(distro_id: &str) -> Result<bool, String> {
    let scope = transition::scope(distro_id)?;
    Ok(controller::journal::load(&scope)?.is_some() || transition::load(&scope)?.pending.is_some())
}

/// The record scope of a command's target: a registered distribution by
/// name or GUID, a GUID alone (an unregistered one, for abandon), or with
/// none named the only environment taken over.
fn scope_of(controller: &controller::Controller, target: Option<&str>) -> Result<String, Failure> {
    let error = |e: String| Failure::new("controller_error", e);
    let Some(target) = target else {
        return controller.resolve(None).map_err(error);
    };
    if let Ok(scope) = transition::scope(target) {
        return Ok(scope);
    }
    let all = host::distributions().map_err(|e| Failure::new("enumeration_failed", e))?;
    transition::scope(&find(&all, target)?.id).map_err(error)
}

/// Replaces one environment's residential proxy, keeping its ingress port.
fn replace_residential(
    path: &std::path::Path,
    distro_id: &str,
    residential: desktop_store::ResidentialSettings,
) -> Result<desktop_store::EnvironmentRecord, String> {
    let current = desktop_store::environment(path, distro_id)?;
    desktop_store::save_environment(
        path,
        distro_id,
        residential,
        None,
        current.map(|row| row.revision.to_string()),
    )
}

fn default_probe_port() -> u16 {
    443
}

fn default_probe_rounds() -> u32 {
    5
}

/// Times CONNECT by address and by name, alternating which goes first, for
/// each non-allowlisted name. Credentials stay inside the policy.
fn chain_probe(
    distro_id: &str,
    names: &[String],
    port: u16,
    rounds: u32,
) -> Result<serde_json::Value, String> {
    use crate::policy::ChainTarget;
    use std::net::{SocketAddr, SocketAddrV4};
    let runtime = managed::Runtime::from_file(&desktop_store::path()?, distro_id)?;
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

/// Adds, once, how many entries carrying the old takeover's mark the stop
/// left in the target because they could not be proven its own
/// (decision 20); omitted when there were none.
fn with_unproven_left(
    controller: &mut controller::Controller,
    scope: &str,
    mut status: serde_json::Value,
) -> serde_json::Value {
    let left = controller.session(scope).take_unproven_left();
    if left > 0 {
        status["unproven_mappings_left"] = left.into();
    }
    status
}
