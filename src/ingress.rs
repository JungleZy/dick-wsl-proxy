use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::net::{
    Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream, UdpSocket,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc::Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use socket2::{Protocol, Type};

use crate::plan::Plan;
use crate::policy::UdpChain;
use crate::query_bridge::Lookup;
mod metadata_lane;
use metadata_lane::{MetadataLane, Observation};

mod flow_stats;
use flow_stats::{Flow, FlowStats};
mod metadata_timing;
use metadata_timing::MetadataTiming;
mod udp_admission;
use udp_admission::{Retirement as UdpRetirement, UdpActivity};
mod udp_pump;
use udp_pump::UdpPump;
mod tcp;
use tcp::{forward_tcp, transient};
mod ipv6;

const MAX_TCP: usize = 64;
const MAX_UDP: usize = 128;
const ACCEPT_BATCH: usize = 16;
const UDP_BATCH: usize = 16;
const MAX_DNS_UDP: usize = 8;
const BUFFER_SIZE: usize = 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
// A conntrack snapshot is a per-packet authorization check. A stalled WSL
// helper must fail the affected flow quickly instead of freezing the UDP loop
// for the helper's full transport deadline.
const METADATA_WAIT_TIMEOUT: Duration = Duration::from_secs(4);
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ERROR_BYTES: usize = 512;

/// Owns both exclusive ingress binds and every forwarding worker.
///
/// Payloads are opaque: there is deliberately no destination-hint protocol.
/// Only an authenticated kernel lookup of the actual socket peer selects an origin.
/// The separate lease holder retains duplicate binds until the controller restores
/// kernel state, even after this owner stops or the controller crashes.
pub struct Ingress {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<Result<(), String>>>,
    ipv6_worker: Option<JoinHandle<Result<(), String>>>,
}

impl Ingress {
    pub fn bind(
        plan: &Plan,
        runtime: Option<Arc<crate::managed::Runtime>>,
    ) -> Result<Self, String> {
        validate(plan)?;
        if plan.system_dns.is_some() != runtime.is_some() {
            return Err("M2 ingress requires exactly one matching policy runtime".into());
        }
        let tcp = crate::ports::bind_exclusive(plan.ingress, Type::STREAM, Protocol::TCP)
            .map_err(|e| format!("bind TCP ingress {}: {e}", plan.ingress))?;
        let udp = crate::ports::bind_exclusive(plan.ingress, Type::DGRAM, Protocol::UDP)
            .map_err(|e| format!("bind UDP ingress {}: {e}", plan.ingress))?;
        tcp.listen(MAX_TCP as i32)
            .map_err(|e| format!("listen on TCP ingress: {e}"))?;
        tcp.set_nonblocking(true)
            .map_err(|e| format!("configure TCP ingress: {e}"))?;
        udp.set_nonblocking(true)
            .map_err(|e| format!("configure UDP ingress: {e}"))?;
        let ipv6_sockets = if let Some(ipv6) = &plan.ipv6 {
            let tcp6 = crate::ports::bind_exclusive_v6(ipv6.ingress, Type::STREAM, Protocol::TCP)
                .map_err(|e| format!("bind IPv6 TCP ingress {}: {e}", ipv6.ingress))?;
            let udp6 = crate::ports::bind_exclusive_v6(ipv6.ingress, Type::DGRAM, Protocol::UDP)
                .map_err(|e| format!("bind IPv6 UDP ingress {}: {e}", ipv6.ingress))?;
            tcp6.listen(MAX_TCP as i32)
                .map_err(|e| format!("listen on IPv6 TCP ingress: {e}"))?;
            tcp6.set_nonblocking(true)
                .map_err(|e| format!("configure IPv6 TCP ingress: {e}"))?;
            udp6.set_nonblocking(true)
                .map_err(|e| format!("configure IPv6 UDP ingress: {e}"))?;
            Some((tcp6, udp6))
        } else {
            None
        };
        // Authenticate the transient metadata lane before handing duplicate binds
        // to the lease owner. A failed handshake must not leave a custody lease.
        let shared = Arc::new(Shared::new());
        let bridge = MetadataLane::start(plan, Arc::clone(&shared.stopping))?;
        crate::lease::reserve(
            plan,
            &tcp,
            &udp,
            ipv6_sockets.as_ref().map(|(tcp, udp)| (tcp, udp)),
        )?;

        *lock(&shared.bridge) = Some(bridge);
        let worker_shared = Arc::clone(&shared);
        let plan = Arc::new(plan.clone());
        let worker_plan = Arc::clone(&plan);
        let worker_runtime = runtime.clone();
        let worker = match thread::Builder::new()
            .name("m1-ingress".into())
            .spawn(move || {
                let result = run(
                    worker_plan,
                    tcp.into(),
                    udp.into(),
                    Arc::clone(&worker_shared),
                    worker_runtime,
                );
                if let Err(error) = &result {
                    worker_shared.fail(error.clone());
                }
                result
            }) {
            Ok(worker) => worker,
            Err(error) => {
                shared.request_stop();
                if let Some(mut bridge) = lock(&shared.bridge).take() {
                    let _ = bridge.close();
                }
                let _ = crate::lease::release(&plan);
                return Err(format!("start ingress worker: {error}"));
            }
        };
        let ipv6_worker = if let Some((tcp6, udp6)) = ipv6_sockets {
            let worker_shared = Arc::clone(&shared);
            let worker_plan = Arc::clone(&plan);
            let runtime = runtime.clone();
            let lease_plan = Arc::clone(&plan);
            match thread::Builder::new()
                .name("m1-ingress-ipv6".into())
                .spawn(move || {
                    ipv6::run(
                        worker_plan,
                        tcp6.into(),
                        udp6.into(),
                        worker_shared,
                        runtime,
                    )
                }) {
                Ok(worker) => Some(worker),
                Err(error) => {
                    shared.request_stop();
                    let _ = worker.join();
                    if let Some(mut bridge) = lock(&shared.bridge).take() {
                        let _ = bridge.close();
                    }
                    let _ = crate::lease::release(&lease_plan);
                    return Err(format!("start IPv6 ingress worker: {error}"));
                }
            }
        } else {
            None
        };
        Ok(Self {
            shared,
            worker: Some(worker),
            ipv6_worker,
        })
    }

    /// Stops forwarding, joins all workers, and releases this owner's binds.
    /// Metadata queries and connects have bounded deadlines. The metadata process
    /// is closed only after every forwarding worker has drained.
    pub fn stop(&mut self) -> Result<(), String> {
        self.shared.request_stop();
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => self.shared.fail(error),
                Err(_) => self.shared.fail("ingress worker panicked".into()),
            }
        }
        if let Some(worker) = self.ipv6_worker.take() {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => self.shared.fail(error),
                Err(_) => self.shared.fail("IPv6 ingress worker panicked".into()),
            }
        }
        if let Some(mut bridge) = lock(&self.shared.bridge).take()
            && let Err(error) = bridge.close()
        {
            self.shared.fail(error);
        }
        // Report the old forwarding failure once. All handles are joined; a retry
        // must be able to finish releasing the custody socket and recovery journal.
        match lock(&self.shared.failure).take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub fn health(&self) -> Result<(), String> {
        if let Some(error) = lock(&self.shared.failure).as_ref() {
            return Err(error.clone());
        }
        match self.worker.as_ref() {
            Some(worker) if !worker.is_finished() && !self.shared.is_stopping() => {
                if self
                    .ipv6_worker
                    .as_ref()
                    .is_some_and(|worker| worker.is_finished())
                {
                    Err("IPv6 ingress worker stopped unexpectedly".into())
                } else {
                    Ok(())
                }
            }
            Some(_) => Err("ingress worker stopped unexpectedly".into()),
            None => Err("ingress is stopped".into()),
        }
    }

    pub fn diagnostics(&self) -> serde_json::Value {
        let active_tcp = lock(&self.shared.active).len();
        let (connections, traffic) = self.shared.flows.snapshot();
        serde_json::json!({
            "active_tcp": active_tcp,
            "healthy": self.health().is_ok(),
            "active_dns_udp": self.shared.dns_udp_active.load(Ordering::Acquire),
            "stopping": self.shared.is_stopping(),
            "counters": &*lock(&self.shared.counters),
            "metadata_latency": lock(&self.shared.timing).snapshot(),
            "connections": connections,
            "traffic": traffic,
        })
    }

    pub(crate) fn chain_tcp_attempts(&self) -> u64 {
        lock(&self.shared.counters).chain_tcp
    }
}

impl Drop for Ingress {
    fn drop(&mut self) {
        if self.worker.is_some()
            && let Err(error) = self.stop()
        {
            eprintln!("M1 ingress shutdown: {error}");
        }
    }
}

fn validate(plan: &Plan) -> Result<(), String> {
    let valid_ip = |ip: Ipv4Addr| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast();
    if plan.cookie == 0
        || !valid_ip(plan.guest)
        || !valid_ip(*plan.ingress.ip())
        || plan.ingress.port() == 0
        || plan.origins.is_empty() != plan.system_dns.is_some()
        || plan.system_dns.is_some_and(|ip| !valid_ip(ip))
        || plan
            .origins
            .iter()
            .any(|origin| !valid_ip(*origin.ip()) || origin.port() == 0 || *origin == plan.ingress)
    {
        return Err("invalid ingress plan or origin enumeration".into());
    }
    Ok(())
}

// A panicking worker must not poison the shutdown path and strand owned sockets.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

struct ActiveTcp {
    client: TcpStream,
    origin: Option<TcpStream>,
}

#[derive(Default, serde::Serialize)]
struct HealthCounters {
    metadata_queries: u64,
    metadata_successes: u64,
    metadata_tcp_failures: u64,
    metadata_udp_failures: u64,
    metadata_transport_failures: u64,
    tcp_failures: u64,
    udp_failures: u64,
    direct_tcp: u64,
    direct_udp: u64,
    chain_tcp: u64,
    chain_udp: u64,
    dns_tcp: u64,
    dns_udp: u64,
    rejected_tcp: u64,
    rejected_udp: u64,
    dns_udp_capacity_rejections: u64,
    udp_capacity_rejections: u64,
    udp_quiet_reclaims: u64,
    udp_idle_expirations: u64,
    udp_idle_with_response_debt: u64,
    last_error: Option<String>,
}

struct Shared {
    stopping: Arc<AtomicBool>,
    failure: Mutex<Option<String>>,
    active: Mutex<HashMap<SocketAddrV4, ActiveTcp>>,
    bridge: Mutex<Option<MetadataLane>>,
    dns_udp_active: std::sync::atomic::AtomicUsize,
    counters: Mutex<HealthCounters>,
    timing: Mutex<MetadataTiming>,
    flows: Arc<FlowStats>,
}

impl Shared {
    fn new() -> Self {
        Self {
            stopping: Arc::new(AtomicBool::new(false)),
            failure: Mutex::new(None),
            active: Mutex::new(HashMap::new()),
            bridge: Mutex::new(None),
            dns_udp_active: std::sync::atomic::AtomicUsize::new(0),
            counters: Mutex::new(HealthCounters::default()),
            timing: Mutex::new(MetadataTiming::default()),
            flows: Arc::new(FlowStats::new()),
        }
    }

    fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    fn request_stop(&self) {
        self.stopping.store(true, Ordering::Release);
        for active in lock(&self.active).values() {
            let _ = active.client.shutdown(Shutdown::Both);
            if let Some(origin) = &active.origin {
                let _ = origin.shutdown(Shutdown::Both);
            }
        }
    }

    fn fail(&self, error: String) {
        let mut failure = lock(&self.failure);
        if failure.is_none() {
            *failure = Some(error);
        }
        drop(failure);
        self.request_stop();
    }

    fn record_metadata_result<T>(&self, protocol: &str, result: &Result<T, String>) {
        let mut counters = lock(&self.counters);
        counters.metadata_queries = counters.metadata_queries.saturating_add(1);
        match result {
            Ok(_) => {
                counters.metadata_successes = counters.metadata_successes.saturating_add(1);
            }
            Err(error) => {
                let failures = if protocol == "tcp" {
                    &mut counters.metadata_tcp_failures
                } else {
                    &mut counters.metadata_udp_failures
                };
                *failures = failures.saturating_add(1);
                if error.starts_with("query_transport_") {
                    counters.metadata_transport_failures =
                        counters.metadata_transport_failures.saturating_add(1);
                }
            }
        }
    }

    fn record_metadata(&self, protocol: &str, result: &Result<SocketAddrV4, String>) {
        self.record_metadata_result(protocol, result);
    }

    #[allow(dead_code)] // Used by the pending IPv6 transparent ingress worker.
    fn record_metadata_v6(&self, protocol: &str, result: &Result<SocketAddrV6, String>) {
        self.record_metadata_result(protocol, result);
    }

    fn record_error(&self, protocol: &str, mut error: String) {
        let mut counters = lock(&self.counters);
        let failures = if protocol == "tcp" {
            &mut counters.tcp_failures
        } else {
            &mut counters.udp_failures
        };
        *failures = failures.saturating_add(1);
        // Diagnostics contain no wire payloads, domain names, or policy/chain
        // errors; remove terminal controls from local transport errors as well.
        error.retain(|character| !character.is_control());
        let mut end = error.len().min(MAX_ERROR_BYTES);
        while !error.is_char_boundary(end) {
            end -= 1;
        }
        error.truncate(end);
        counters.last_error = Some(error);
    }

    fn register(
        self: &Arc<Self>,
        peer: SocketAddrV4,
        client: &TcpStream,
    ) -> Result<Option<TcpRegistration>, String> {
        let mut active = lock(&self.active);
        if self.is_stopping() || active.len() >= MAX_TCP || active.contains_key(&peer) {
            return Ok(None);
        }
        let client = client
            .try_clone()
            .map_err(|e| format!("retain TCP shutdown handle: {e}"))?;
        active.insert(
            peer,
            ActiveTcp {
                client,
                origin: None,
            },
        );
        Ok(Some(TcpRegistration {
            shared: Arc::clone(self),
            peer,
            flow: self.flows.begin("tcp"),
        }))
    }
}

struct TcpRegistration {
    shared: Arc<Shared>,
    peer: SocketAddrV4,
    flow: Flow,
}

impl TcpRegistration {
    fn attach_origin(&self, origin: &TcpStream) -> Result<(), String> {
        let mut active = lock(&self.shared.active);
        if self.shared.is_stopping() {
            let _ = origin.shutdown(Shutdown::Both);
            return Err("ingress is stopping".into());
        }
        let entry = active
            .get_mut(&self.peer)
            .ok_or_else(|| "TCP shutdown registration disappeared".to_string())?;
        entry.origin = Some(
            origin
                .try_clone()
                .map_err(|e| format!("retain origin shutdown handle: {e}"))?,
        );
        Ok(())
    }
}

impl Drop for TcpRegistration {
    fn drop(&mut self) {
        lock(&self.shared.active).remove(&self.peer);
    }
}

struct TcpWorkers {
    shared: Arc<Shared>,
    handles: Vec<JoinHandle<()>>,
}

impl TcpWorkers {
    fn reap(&mut self) -> Result<(), String> {
        let mut index = 0;
        while index < self.handles.len() {
            if self.handles[index].is_finished() {
                if self.handles.swap_remove(index).join().is_err() {
                    return Err("TCP forwarding worker panicked".into());
                }
            } else {
                index += 1;
            }
        }
        Ok(())
    }
}

impl Drop for TcpWorkers {
    fn drop(&mut self) {
        // This guard also runs if the listener panics: dropping join handles alone
        // would detach live forwarding threads and violate stop's ownership rule.
        self.shared.request_stop();
        for handle in self.handles.drain(..) {
            if handle.join().is_err() {
                self.shared.fail("TCP forwarding worker panicked".into());
            }
        }
    }
}

struct PendingDestination {
    started: Instant,
    observation: Result<Receiver<Observation>, String>,
}

fn destination(
    plan: &Plan,
    protocol: &'static str,
    peer: SocketAddrV4,
    shared: &Shared,
) -> Result<SocketAddrV4, String> {
    finish_destination(
        plan,
        protocol,
        submit_destination(plan, protocol, peer, shared),
        shared,
    )
}

fn submit_destination(
    plan: &Plan,
    protocol: &'static str,
    peer: SocketAddrV4,
    shared: &Shared,
) -> PendingDestination {
    let started = Instant::now();
    let observation = if shared.is_stopping() || peer.ip() != &plan.guest || peer.port() == 0 {
        Err("unauthorized ingress peer or stopped ingress".into())
    } else {
        lock(&shared.bridge)
            .as_ref()
            .ok_or_else(|| "query_transport_closed: metadata bridge is closed".to_owned())
            .and_then(|lane| {
                lane.submit(Lookup {
                    protocol,
                    peer: SocketAddr::V4(peer),
                })
            })
    };
    PendingDestination {
        started,
        observation,
    }
}

fn finish_destination(
    plan: &Plan,
    protocol: &str,
    pending: PendingDestination,
    shared: &Shared,
) -> Result<SocketAddrV4, String> {
    let observation = pending.observation.and_then(|rx| {
        rx.recv_timeout(METADATA_WAIT_TIMEOUT)
            .map_err(|error| match error {
                std::sync::mpsc::RecvTimeoutError::Timeout => "query_transport_timeout".to_owned(),
                std::sync::mpsc::RecvTimeoutError::Disconnected => {
                    "query_transport_dispatch_closed".to_owned()
                }
            })
    });
    finish_observation(plan, protocol, pending.started, observation, shared)
}

struct DestinationGroup {
    started: Instant,
    observations: Result<std::vec::IntoIter<Observation>, String>,
}

impl DestinationGroup {
    fn next(&mut self, plan: &Plan, shared: &Shared) -> Result<SocketAddrV4, String> {
        let observation = match &mut self.observations {
            Ok(observations) => observations
                .next()
                .ok_or_else(|| "query_transport_incomplete_group".to_owned()),
            Err(error) => Err(error.clone()),
        };
        finish_observation(plan, "udp", self.started, observation, shared)
    }

    #[allow(dead_code)] // Used by the pending IPv6 transparent ingress worker.
    fn next_v6(&mut self, plan: &Plan, shared: &Shared) -> Result<SocketAddrV6, String> {
        let observation = match &mut self.observations {
            Ok(observations) => observations
                .next()
                .ok_or_else(|| "query_transport_incomplete_group".to_owned()),
            Err(error) => Err(error.clone()),
        };
        finish_observation_v6(plan, "udp", self.started, observation, shared)
    }
}

fn destination_group(plan: &Plan, keys: &[Lookup], shared: &Shared) -> DestinationGroup {
    let started = Instant::now();
    let receiver = if shared.is_stopping()
        || keys.iter().any(|key| {
            !matches!(
                key.peer,
                SocketAddr::V4(peer) if peer.ip() == &plan.guest && peer.port() != 0
            )
        }) {
        Err("unauthorized ingress peer or stopped ingress".into())
    } else {
        lock(&shared.bridge)
            .as_ref()
            .ok_or_else(|| "query_transport_closed: metadata bridge is closed".to_owned())
            .and_then(|lane| lane.submit_group(keys))
    };
    let observations = receiver
        .and_then(|rx| {
            rx.recv_timeout(METADATA_WAIT_TIMEOUT)
                .map_err(|error| match error {
                    std::sync::mpsc::RecvTimeoutError::Timeout => {
                        "query_transport_timeout".to_owned()
                    }
                    std::sync::mpsc::RecvTimeoutError::Disconnected => {
                        "query_transport_dispatch_closed".to_owned()
                    }
                })
        })
        .and_then(|observations| {
            if observations.len() == keys.len() {
                Ok(observations.into_iter())
            } else {
                Err("query_transport_incomplete_group".to_owned())
            }
        });
    DestinationGroup {
        started,
        observations,
    }
}

fn finish_observation(
    plan: &Plan,
    protocol: &str,
    started: Instant,
    observation: Result<Observation, String>,
    shared: &Shared,
) -> Result<SocketAddrV4, String> {
    let result = observation
        .and_then(|obs| {
            lock(&shared.timing).observe(
                obs.started.saturating_duration_since(started),
                obs.elapsed,
                obs.batch,
                obs.guest_us,
            );
            obs.origin
        })
        .and_then(|origin| {
            let SocketAddr::V4(origin) = origin else {
                return Err("IPv6 origin requires the IPv6 ingress path".into());
            };
            let ip = *origin.ip();
            if shared.is_stopping()
                || origin == plan.ingress
                || origin.port() == 0
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || (plan.system_dns.is_none() && !plan.origins.contains(&origin))
            {
                Err("origin lookup is no longer authorized".into())
            } else {
                Ok(origin)
            }
        });
    shared.record_metadata(protocol, &result);
    result
}

#[allow(dead_code)] // Used by the pending IPv6 transparent ingress worker.
fn finish_observation_v6(
    plan: &Plan,
    protocol: &str,
    started: Instant,
    observation: Result<Observation, String>,
    shared: &Shared,
) -> Result<SocketAddrV6, String> {
    let result = observation
        .and_then(|obs| {
            lock(&shared.timing).observe(
                obs.started.saturating_duration_since(started),
                obs.elapsed,
                obs.batch,
                obs.guest_us,
            );
            obs.origin
        })
        .and_then(|origin| {
            let SocketAddr::V6(origin) = origin else {
                return Err("IPv4 origin requires the IPv4 ingress path".into());
            };
            let Some(ipv6) = &plan.ipv6 else {
                return Err("IPv6 ingress identity is unavailable".into());
            };
            if shared.is_stopping()
                || origin == ipv6.ingress
                || origin.port() == 0
                || origin.ip().is_unspecified()
                || origin.ip().is_multicast()
                || origin.ip().is_loopback()
                || origin.ip().to_ipv4_mapped().is_some()
                || origin.ip().is_unicast_link_local()
            {
                Err("IPv6 origin lookup is no longer authorized".into())
            } else {
                Ok(origin)
            }
        });
    shared.record_metadata_v6(protocol, &result);
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Dns,
    Direct(SocketAddrV4),
    Chain,
}

// This runs only after the kernel metadata bridge has authorized the peer and
// original endpoint. DNS aliases are never inferred from application payloads.
fn route_details(
    plan: &Plan,
    runtime: Option<&crate::managed::Runtime>,
    _protocol: &str,
    original: SocketAddrV4,
) -> Result<(Route, &'static str), String> {
    let Some(runtime) = runtime else {
        return Ok((Route::Direct(original), "enumerated_origin"));
    };
    if plan.system_dns == Some(*original.ip()) && original.port() == 53 {
        return Ok((Route::Dns, "system_dns"));
    }
    if original.port() == 53 {
        return Err("alternate plaintext DNS destination rejected".into());
    }
    if original == plan.ingress || runtime.policy.is_reserved_endpoint(original) {
        return Err("reserved business endpoint rejected".into());
    }
    let alias = runtime
        .dns
        .direct_alias(*original.ip())
        .map_err(|_| "unknown or expired managed DNS alias rejected".to_string())?;
    let actual = SocketAddrV4::new(alias.unwrap_or(*original.ip()), original.port());
    if actual == plan.ingress || runtime.policy.is_reserved_endpoint(actual) {
        return Err("reserved resolved business endpoint rejected".into());
    }
    if alias.is_some() {
        Ok((Route::Direct(actual), "domain_alias"))
    } else if runtime.policy.allows_ip(*actual.ip()) {
        Ok((Route::Direct(actual), "ip_or_cidr"))
    } else {
        Ok((Route::Chain, "default_chain"))
    }
}

fn route(
    plan: &Plan,
    runtime: Option<&crate::managed::Runtime>,
    protocol: &str,
    original: SocketAddrV4,
) -> Result<Route, String> {
    route_details(plan, runtime, protocol, original).map(|(route, _)| route)
}

fn select_route(
    plan: &Plan,
    runtime: Option<&crate::managed::Runtime>,
    protocol: &str,
    original: SocketAddrV4,
    flow: &Flow,
    shared: &Shared,
) -> Result<Route, String> {
    let result = route_details(plan, runtime, protocol, original).map(|(route, reason)| {
        flow.selected(
            match route {
                Route::Dns => "dns",
                Route::Direct(_) => "direct",
                Route::Chain => "chain",
            },
            reason,
        );
        route
    });
    if result.is_err() {
        flow.failed();
    }
    let mut counters = lock(&shared.counters);
    let counter = match (&result, protocol) {
        (Ok(Route::Dns), "tcp") => &mut counters.dns_tcp,
        (Ok(Route::Dns), _) => &mut counters.dns_udp,
        (Ok(Route::Direct(_)), "tcp") => &mut counters.direct_tcp,
        (Ok(Route::Direct(_)), _) => &mut counters.direct_udp,
        (Ok(Route::Chain), "tcp") => &mut counters.chain_tcp,
        (Ok(Route::Chain), _) => &mut counters.chain_udp,
        (Err(_), "tcp") => &mut counters.rejected_tcp,
        (Err(_), _) => &mut counters.rejected_udp,
    };
    *counter = counter.saturating_add(1);
    result
}

fn run(
    plan: Arc<Plan>,
    listener: TcpListener,
    udp: UdpSocket,
    shared: Arc<Shared>,
    runtime: Option<Arc<crate::managed::Runtime>>,
) -> Result<(), String> {
    let mut workers = TcpWorkers {
        shared: Arc::clone(&shared),
        handles: Vec::with_capacity(MAX_TCP),
    };
    let mut dns_workers = TcpWorkers {
        shared: Arc::clone(&shared),
        handles: Vec::with_capacity(MAX_DNS_UDP),
    };
    let mut flows: BTreeMap<SocketAddrV4, UdpFlow> = BTreeMap::new();
    let mut pump = UdpPump::new();
    let mut pending = Vec::with_capacity(UDP_BATCH);
    let mut keys = Vec::with_capacity(UDP_BATCH);
    while !shared.is_stopping() {
        let mut made_progress = false;
        workers.reap()?;
        dns_workers.reap()?;
        for _ in 0..ACCEPT_BATCH {
            if shared.is_stopping() {
                break;
            }
            let client = match listener.accept() {
                Ok((client, _)) => {
                    made_progress = true;
                    client
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if transient(&error) => continue,
                Err(error) => return Err(format!("TCP ingress accept failed: {error}")),
            };
            let peer = match client.peer_addr() {
                Ok(SocketAddr::V4(peer)) if peer.ip() == &plan.guest => peer,
                _ => continue,
            };
            if workers.handles.len() >= MAX_TCP {
                continue;
            }
            let Some(registration) = shared.register(peer, &client)? else {
                continue;
            };
            let plan = Arc::clone(&plan);
            let worker_shared = Arc::clone(&shared);
            let runtime = runtime.clone();
            let spawn_failure = registration.flow.failure_marker();
            let worker = thread::Builder::new()
                .name("m1-tcp".into())
                .spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        forward_tcp(&plan, client, &registration, runtime.as_deref())
                    }));
                    if worker_shared.is_stopping() {
                        registration.flow.stopped();
                    }
                    match result {
                        Ok(Err(error)) => {
                            if !worker_shared.is_stopping() {
                                registration.flow.failed();
                                worker_shared.record_error("tcp", error);
                            }
                        }
                        Err(_) => {
                            registration.flow.failed();
                            worker_shared.fail("TCP forwarding worker panicked".into());
                        }
                        _ => {}
                    }
                })
                .map_err(|e| {
                    spawn_failure.failed();
                    format!("start TCP forwarding worker: {e}")
                })?;
            workers.handles.push(worker);
        }
        keys.clear();
        for (slot, buffer) in pump.buffers.iter_mut().enumerate() {
            if shared.is_stopping() {
                break;
            }
            let (size, peer) = match udp.recv_from(buffer) {
                Ok((size, SocketAddr::V4(peer)))
                    if peer.ip() == &plan.guest && peer.port() != 0 =>
                {
                    (size, peer)
                }
                Ok(_) => {
                    made_progress = true;
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                // Windows can report ICMP from a guest that sent then closed its
                // UDP socket on this unconnected listener's next receive.
                Err(error)
                    if transient(&error) || error.kind() == io::ErrorKind::ConnectionReset =>
                {
                    continue;
                }
                Err(error) => return Err(format!("UDP ingress receive failed: {error}")),
            };
            made_progress = true;
            pending.push((slot, size, peer));
            keys.push(Lookup {
                protocol: "udp",
                peer: SocketAddr::V4(peer),
            });
        }
        let mut observations =
            (!pending.is_empty()).then(|| destination_group(&plan, &keys, &shared));
        for (slot, size, peer) in pending.drain(..) {
            let datagram = &pump.buffers[slot];
            let origin = match observations
                .as_mut()
                .expect("received UDP group")
                .next(&plan, &shared)
            {
                Ok(origin) => origin,
                Err(error) => {
                    if let Some(flow) = flows.remove(&peer) {
                        flow.stats.stage("metadata");
                        flow.stats.failed();
                    } else {
                        shared.flows.begin("udp").failed();
                    }
                    shared.record_error("udp", error);
                    continue;
                }
            };
            let mut new_stats = if flows.get(&peer).is_some_and(|flow| flow.origin == origin) {
                None
            } else {
                flows.remove(&peer);
                let stats = shared.flows.begin("udp");
                stats.destination(origin);
                Some(stats)
            };
            let stats = new_stats.as_ref().unwrap_or_else(|| &flows[&peer].stats);
            stats.stage("policy");
            let (target, chained) =
                match select_route(&plan, runtime.as_deref(), "udp", origin, stats, &shared) {
                    Ok(Route::Direct(target)) => (Some(target), false),
                    Ok(Route::Dns) => {
                        stats.stage("dns");
                        let runtime = runtime.as_ref().expect("DNS route requires M2 runtime");
                        if dns_workers.handles.len() >= MAX_DNS_UDP {
                            stats.failed();
                            let mut counters = lock(&shared.counters);
                            counters.dns_udp_capacity_rejections =
                                counters.dns_udp_capacity_rejections.saturating_add(1);
                            counters.last_error = Some("UDP DNS worker capacity reached".into());
                            continue;
                        }
                        schedule_dns_udp(
                            &plan,
                            runtime,
                            &udp,
                            (origin, peer),
                            &datagram[..size],
                            new_stats.expect("DNS is never a retained direct UDP flow"),
                            &mut dns_workers,
                        )?;
                        continue;
                    }
                    Ok(Route::Chain) => (None, true),
                    Err(error) => {
                        flows.remove(&peer);
                        shared.record_error("udp", error);
                        continue;
                    }
                };
            if flows
                .get(&peer)
                .is_some_and(|flow| flow.origin != origin || flow.target != target)
                && let Some(previous) = flows.remove(&peer)
            {
                new_stats = Some(previous.stats);
            }
            if !flows.contains_key(&peer) {
                if shared.is_stopping() || !admit_udp(&mut flows, &shared, Instant::now()) {
                    if let Some(stats) = &new_stats {
                        if shared.is_stopping() {
                            stats.stopped();
                        } else {
                            stats.stage("connect");
                            stats.failed();
                        }
                    }
                    continue;
                }
                let stats = new_stats.expect("new UDP mapping has an accounting record");
                stats.stage("connect");
                let flow = if chained {
                    let Some(runtime) = runtime.as_ref() else {
                        stats.failed();
                        shared.record_error("udp", "UDP chain requires managed runtime".into());
                        continue;
                    };
                    match UdpFlow::connect_chain(origin, origin, &runtime.policy, stats) {
                        Ok(flow) => flow,
                        Err(error) => {
                            shared.record_error("udp", error);
                            continue;
                        }
                    }
                } else {
                    let target = target.expect("direct UDP route has a target");
                    match UdpFlow::connect(origin, target, stats) {
                        Ok(flow) => flow,
                        Err(error) => {
                            shared.record_error("udp", format!("create origin socket: {error}"));
                            continue;
                        }
                    }
                };
                // Socket creation and UDP connect do not yield this lane. Reuse
                // this datagram's authorization; replies are checked separately.
                flows.insert(peer, flow);
            }
            if shared.is_stopping() {
                break;
            }
            let flow = flows.get_mut(&peer).expect("UDP flow was just selected");
            flow.stats.stage("relay");
            match flow.socket.send(&datagram[..size]) {
                Ok(sent) if sent == size => {
                    flow.stats.tx(sent);
                    flow.activity.sent(Instant::now());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => {
                    flow.stats.failed();
                    shared.record_error("udp", format!("origin send failed: {result:?}"));
                    flows.remove(&peer);
                }
            }
        }
        made_progress |= pump.collect(&mut flows, &shared);
        if !pump.is_empty() {
            keys.clear();
            keys.extend(pump.keys());
            let observations = destination_group(&plan, &keys, &shared);
            pump.forward(
                &plan,
                runtime.as_deref(),
                &udp,
                &mut flows,
                observations,
                &shared,
            );
        }
        if !made_progress && !shared.is_stopping() {
            udp_pump::wait(&listener, &udp, &mut flows, &shared)?;
        }
    }
    for flow in flows.values() {
        flow.stats.stopped();
    }
    Ok(())
}

struct DnsUdpSlot(Arc<Shared>);

impl Drop for DnsUdpSlot {
    fn drop(&mut self) {
        self.0.dns_udp_active.fetch_sub(1, Ordering::AcqRel);
    }
}

// At most eight independent DNS jobs retain one datagram each. There is no
// waiting queue: overload is rejected. Upstream DNS deadlines therefore cannot
// stall the ingress UDP loop, and every job is joined before socket release.
fn schedule_dns_udp(
    plan: &Arc<Plan>,
    runtime: &Arc<crate::managed::Runtime>,
    udp: &UdpSocket,
    (original, peer): (SocketAddrV4, SocketAddrV4),
    request: &[u8],
    stats: Flow,
    workers: &mut TcpWorkers,
) -> Result<(), String> {
    let socket = udp.try_clone().map_err(|_| {
        stats.failed();
        "retain DNS UDP reply socket".to_string()
    })?;
    let plan = Arc::clone(plan);
    let runtime = Arc::clone(runtime);
    let request = request.to_vec();
    let shared = Arc::clone(&workers.shared);
    shared.dns_udp_active.fetch_add(1, Ordering::AcqRel);
    let slot = DnsUdpSlot(Arc::clone(&shared));
    stats.tx(request.len());
    let spawn_failure = stats.failure_marker();
    let worker = thread::Builder::new()
        .name("m2-dns-udp".into())
        .spawn(move || {
            let _slot = slot;
            let result = (|| {
                if shared.is_stopping() {
                    return Ok(());
                }
                let answer = runtime
                    .dns
                    .answer(&request)
                    .map_err(|_| "managed UDP DNS answer failed".to_string())?;
                stats.stage("metadata");
                if destination(&plan, "udp", peer, &shared)? != original
                    || route(&plan, Some(&runtime), "udp", original)? != Route::Dns
                {
                    return Err("UDP DNS mapping changed before reply".into());
                }
                if shared.is_stopping() {
                    return Ok(());
                }
                stats.stage("dns");
                match socket.send_to(&answer, peer) {
                    Ok(size) if size == answer.len() => {
                        stats.rx(size);
                        Ok(())
                    }
                    _ => Err("managed UDP DNS reply failed".into()),
                }
            })();
            if shared.is_stopping() {
                stats.stopped();
            } else if let Err(error) = result {
                stats.failed();
                shared.record_error("udp", error);
            }
        })
        .map_err(|_| {
            spawn_failure.failed();
            "start managed UDP DNS worker".to_string()
        })?;
    workers.handles.push(worker);
    Ok(())
}

fn read_dns_query(client: &mut impl Read, request: &mut Vec<u8>) -> Result<bool, String> {
    // Clean EOF is valid only between frames, never inside the two-byte prefix.
    let mut length = [0u8; 2];
    loop {
        match client.read(&mut length[..1]) {
            Ok(0) => return Ok(false),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("TCP DNS frame read failed".into()),
        }
    }
    client
        .read_exact(&mut length[1..])
        .map_err(|_| "incomplete TCP DNS length frame".to_string())?;
    let size = usize::from(u16::from_be_bytes(length));
    if size < 12 {
        return Err("invalid TCP DNS frame length".into());
    }
    request.resize(size, 0);
    client
        .read_exact(request)
        .map_err(|_| "incomplete TCP DNS query frame".to_string())?;
    Ok(true)
}

fn serve_dns_tcp(
    plan: &Plan,
    runtime: &crate::managed::Runtime,
    mut client: TcpStream,
    registration: &TcpRegistration,
    original: SocketAddrV4,
) -> Result<(), String> {
    let shared = &registration.shared;
    client
        .set_nonblocking(false)
        .map_err(|_| "configure TCP DNS blocking mode".to_string())?;
    client
        .set_read_timeout(Some(TCP_IDLE_TIMEOUT))
        .map_err(|_| "configure TCP DNS read deadline".to_string())?;
    client
        .set_write_timeout(Some(CONNECT_TIMEOUT))
        .map_err(|_| "configure TCP DNS write deadline".to_string())?;
    let mut client = Metered {
        inner: &mut client,
        flow: &registration.flow,
    };
    let mut request = Vec::new();
    while !shared.is_stopping() {
        if !read_dns_query(&mut client, &mut request)? {
            return Ok(());
        }
        if destination(plan, "tcp", registration.peer, shared)? != original
            || route(plan, Some(runtime), "tcp", original)? != Route::Dns
        {
            return Err("TCP DNS mapping changed before query".into());
        }
        let answer = runtime
            .dns
            .answer_tcp(&request)
            .map_err(|_| "managed TCP DNS answer failed".to_string())?;
        let size = u16::try_from(answer.len())
            .map_err(|_| "managed TCP DNS response exceeds frame limit".to_string())?;
        if shared.is_stopping() {
            return Ok(());
        }
        if destination(plan, "tcp", registration.peer, shared)? != original {
            return Err("TCP DNS mapping changed before reply".into());
        }
        client
            .write_all(&size.to_be_bytes())
            .and_then(|()| client.write_all(&answer))
            .map_err(|_| "TCP DNS response write failed".to_string())?;
    }
    Ok(())
}

fn record_udp_retirement(flow: &UdpFlow, reason: UdpRetirement, shared: &Shared) {
    let mut counters = lock(&shared.counters);
    match reason {
        UdpRetirement::Idle => {
            counters.udp_idle_expirations = counters.udp_idle_expirations.saturating_add(1);
            if flow.activity.has_response_debt() {
                counters.udp_idle_with_response_debt =
                    counters.udp_idle_with_response_debt.saturating_add(1);
            }
        }
        UdpRetirement::Quiet => {
            counters.udp_quiet_reclaims = counters.udp_quiet_reclaims.saturating_add(1);
        }
    }
}

fn admit_udp(flows: &mut BTreeMap<SocketAddrV4, UdpFlow>, shared: &Shared, now: Instant) -> bool {
    if flows.len() < MAX_UDP {
        return true;
    }
    // At most MAX_UDP entries are inspected, without probing receive queues or
    // allocating a candidate list. Endpoint order breaks timestamp ties so the
    // victim is deterministic even when multiple flows have the same activity.
    let victim = flows
        .iter()
        .filter_map(|(peer, flow)| {
            flow.activity
                .reclaimable(now)
                .map(|reason| (reason.priority(), flow.activity.touched(), *peer, reason))
        })
        .min_by_key(|(priority, touched, peer, _)| (*priority, *touched, *peer));
    if let Some((_, _, peer, reason)) = victim {
        let flow = flows.remove(&peer).expect("UDP admission victim exists");
        record_udp_retirement(&flow, reason, shared);
        // Dropping both socket and its accounting owner precedes replacement;
        // never retarget a socket that could still receive an old-origin reply.
        drop(flow);
        return true;
    }
    {
        let mut counters = lock(&shared.counters);
        counters.udp_capacity_rejections = counters.udp_capacity_rejections.saturating_add(1);
    }
    shared.record_error("udp", "UDP flow capacity reached: all mappings busy".into());
    false
}

struct UdpFlow {
    generation: u64,
    origin: SocketAddrV4,
    target: Option<SocketAddrV4>,
    socket: UdpTransport,
    activity: UdpActivity,
    stats: Flow,
}

enum UdpTransport {
    Direct(UdpSocket),
    Chain(UdpChain),
}

impl UdpTransport {
    fn send(&self, payload: &[u8]) -> io::Result<usize> {
        match self {
            Self::Direct(socket) => socket.send(payload),
            Self::Chain(chain) => chain.send(payload),
        }
    }

    fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Direct(socket) => socket.recv(buffer),
            Self::Chain(chain) => chain.recv(buffer),
        }
    }

    #[cfg(test)]
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            Self::Direct(socket) => socket.set_nonblocking(nonblocking),
            Self::Chain(chain) => chain.set_nonblocking(nonblocking),
        }
    }

    #[cfg(test)]
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Direct(socket) => socket.set_read_timeout(timeout),
            Self::Chain(chain) => chain.set_read_timeout(timeout),
        }
    }

    #[cfg(test)]
    fn peek(&self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Direct(socket) => socket.peek(buffer),
            Self::Chain(chain) => chain.peek(buffer),
        }
    }

    #[cfg(windows)]
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        match self {
            Self::Direct(socket) => {
                use std::os::windows::io::AsRawSocket;
                socket.as_raw_socket()
            }
            Self::Chain(chain) => chain.as_raw_socket(),
        }
    }
}

impl UdpFlow {
    fn connect(origin: SocketAddrV4, target: SocketAddrV4, stats: Flow) -> io::Result<Self> {
        let result: io::Result<UdpSocket> = (|| {
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
            socket.set_nonblocking(true)?;
            socket.connect(target)?;
            Ok(socket)
        })();
        if result.is_err() {
            stats.failed();
        }
        let socket = result?;
        stats.stage("relay");
        Ok(Self {
            generation: next_udp_generation(),
            origin,
            target: Some(target),
            socket: UdpTransport::Direct(socket),
            activity: UdpActivity::new(Instant::now()),
            stats,
        })
    }

    fn connect_chain(
        origin: SocketAddrV4,
        target: SocketAddrV4,
        policy: &crate::policy::Policy,
        stats: Flow,
    ) -> Result<Self, String> {
        let socket = match policy.chain_udp(target) {
            Ok(socket) => socket,
            Err(error) => {
                stats.failed();
                return Err(error);
            }
        };
        if let Err(error) = socket.set_nonblocking(true) {
            stats.failed();
            return Err(format!("configure chained UDP socket: {error}"));
        }
        stats.stage("relay");
        Ok(Self {
            generation: next_udp_generation(),
            origin,
            target: None,
            socket: UdpTransport::Chain(socket),
            activity: UdpActivity::new(Instant::now()),
            stats,
        })
    }
}

fn next_udp_generation() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        value.checked_add(1)
    })
    .expect("UDP flow generation exhausted")
}

/// DNS terminates locally; count actual reads/writes, including partial framing,
/// without retaining the DNS question or changing frame handling.
struct Metered<'a, T> {
    inner: &'a mut T,
    flow: &'a Flow,
}

impl<T: Read> Read for Metered<'_, T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let size = self.inner.read(buffer)?;
        self.flow.tx(size);
        Ok(size)
    }
}

impl<T: Write> Write for Metered<'_, T> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let size = self.inner.write(buffer)?;
        self.flow.rx(size);
        Ok(size)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests;
