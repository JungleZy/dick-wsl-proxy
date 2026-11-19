use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc::Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use socket2::{Protocol, Type};

use crate::m1::Plan;
use crate::query_bridge::Lookup;
#[path = "metadata_lane.rs"]
mod metadata_lane;
use metadata_lane::{MetadataLane, Observation};

#[path = "flow_stats.rs"]
mod flow_stats;
use flow_stats::{Flow, FlowStats};
#[path = "metadata_timing.rs"]
mod metadata_timing;
use metadata_timing::MetadataTiming;
#[path = "udp_admission.rs"]
mod udp_admission;
use udp_admission::{Retirement as UdpRetirement, UdpActivity};
#[path = "udp_pump.rs"]
mod udp_pump;
use udp_pump::UdpPump;

const MAX_TCP: usize = 64;
const MAX_UDP: usize = 128;
const ACCEPT_BATCH: usize = 16;
const UDP_BATCH: usize = 16;
const MAX_DNS_UDP: usize = 8;
const BUFFER_SIZE: usize = 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
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
}

impl Ingress {
    pub fn bind(plan: &Plan, runtime: Option<Arc<crate::m2::Runtime>>) -> Result<Self, String> {
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
        // Authenticate the transient metadata lane before handing duplicate binds
        // to the lease owner. A failed handshake must not leave a custody lease.
        let shared = Arc::new(Shared::new());
        let bridge = MetadataLane::start(plan, Arc::clone(&shared.stopping))?;
        crate::lease::reserve(plan, &tcp, &udp)?;

        *lock(&shared.bridge) = Some(bridge);
        let worker_shared = Arc::clone(&shared);
        let plan = Arc::new(plan.clone());
        let worker = thread::Builder::new()
            .name("m1-ingress".into())
            .spawn(move || {
                let result = run(
                    plan,
                    tcp.into(),
                    udp.into(),
                    Arc::clone(&worker_shared),
                    runtime,
                );
                if let Err(error) = &result {
                    worker_shared.fail(error.clone());
                }
                result
            })
            .map_err(|e| format!("start ingress worker: {e}"))?;
        Ok(Self {
            shared,
            worker: Some(worker),
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
            Some(worker) if !worker.is_finished() && !self.shared.is_stopping() => Ok(()),
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

    fn record_metadata(&self, protocol: &str, result: &Result<SocketAddrV4, String>) {
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
            .and_then(|lane| lane.submit(Lookup { protocol, peer }))
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
        rx.recv()
            .map_err(|_| "query_transport_dispatch_closed".to_owned())
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
}

fn destination_group(plan: &Plan, keys: &[Lookup], shared: &Shared) -> DestinationGroup {
    let started = Instant::now();
    let receiver = if shared.is_stopping()
        || keys
            .iter()
            .any(|key| key.peer.ip() != &plan.guest || key.peer.port() == 0)
    {
        Err("unauthorized ingress peer or stopped ingress".into())
    } else {
        lock(&shared.bridge)
            .as_ref()
            .ok_or_else(|| "query_transport_closed: metadata bridge is closed".to_owned())
            .and_then(|lane| lane.submit_group(keys))
    };
    let observations = receiver
        .and_then(|rx| {
            rx.recv()
                .map_err(|_| "query_transport_dispatch_closed".to_owned())
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
    runtime: Option<&crate::m2::Runtime>,
    protocol: &str,
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
    } else if protocol == "tcp" {
        Ok((Route::Chain, "default_chain"))
    } else {
        Err("non-whitelisted UDP rejected: two-hop UDP is unavailable".into())
    }
}

fn route(
    plan: &Plan,
    runtime: Option<&crate::m2::Runtime>,
    protocol: &str,
    original: SocketAddrV4,
) -> Result<Route, String> {
    route_details(plan, runtime, protocol, original).map(|(route, _)| route)
}

fn select_route(
    plan: &Plan,
    runtime: Option<&crate::m2::Runtime>,
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
        (Ok(Route::Chain), _) => &mut counters.chain_tcp,
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
    runtime: Option<Arc<crate::m2::Runtime>>,
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
                peer,
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
            let target =
                match select_route(&plan, runtime.as_deref(), "udp", origin, stats, &shared) {
                    Ok(Route::Direct(target)) => target,
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
                    Ok(Route::Chain) => {
                        // There is no authenticated two-hop UDP implementation.
                        stats.failed();
                        flows.remove(&peer);
                        shared.record_error("udp", "UDP chain transport unavailable".into());
                        continue;
                    }
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
                let flow = match UdpFlow::connect(origin, target, stats) {
                    Ok(flow) => flow,
                    Err(error) => {
                        shared.record_error("udp", format!("create origin socket: {error}"));
                        continue;
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
    runtime: &Arc<crate::m2::Runtime>,
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
    runtime: &crate::m2::Runtime,
    mut client: TcpStream,
    registration: &TcpRegistration,
    original: SocketAddrV4,
) -> Result<(), String> {
    let shared = &registration.shared;
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
    target: SocketAddrV4,
    socket: UdpSocket,
    activity: UdpActivity,
    stats: Flow,
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
            target,
            socket,
            activity: UdpActivity::new(Instant::now()),
            stats,
        })
    }
}

fn next_udp_generation() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
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

fn forward_tcp(
    plan: &Plan,
    client: TcpStream,
    registration: &TcpRegistration,
    runtime: Option<&crate::m2::Runtime>,
) -> Result<(), String> {
    let shared = &registration.shared;
    let flow = &registration.flow;
    let origin = destination(plan, "tcp", registration.peer, shared)?;
    flow.destination(origin);
    let selected = select_route(plan, runtime, "tcp", origin, flow, shared)?;
    if selected == Route::Dns {
        flow.stage("dns");
        return serve_dns_tcp(
            plan,
            runtime.expect("DNS route requires M2 runtime"),
            client,
            registration,
            origin,
        );
    }
    if shared.is_stopping() {
        return Ok(());
    }
    flow.stage("connect");
    let upstream = match selected {
        Route::Direct(target) => {
            TcpStream::connect_timeout(&SocketAddr::V4(target), CONNECT_TIMEOUT)
                .map_err(|e| format!("connect to authorized direct endpoint: {e}"))?
        }
        Route::Chain => runtime
            .expect("chain route requires M2 runtime")
            .policy
            .chain(origin)
            .map_err(|_| "two-hop TCP chain connect failed".to_string())?,
        Route::Dns => unreachable!("DNS handled internally"),
    };
    registration.attach_origin(&upstream)?;
    flow.stage("metadata");
    if client.peer_addr().ok() != Some(SocketAddr::V4(registration.peer))
        || destination(plan, "tcp", registration.peer, shared)? != origin
        || route(plan, runtime, "tcp", origin)? != selected
    {
        return Err("TCP mapping changed while connecting to origin".into());
    }
    flow.stage("relay");
    relay(client, upstream, shared, flow).map_err(|e| format!("relay: {e}"))
}

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
    )
}

struct Pipe {
    buffer: [u8; BUFFER_SIZE],
    start: usize,
    end: usize,
    eof: bool,
    shutdown: bool,
}

impl Pipe {
    fn new() -> Self {
        Self {
            buffer: [0; BUFFER_SIZE],
            start: 0,
            end: 0,
            eof: false,
            shutdown: false,
        }
    }

    fn pump(
        &mut self,
        source: &mut TcpStream,
        target: &mut TcpStream,
        flow: &Flow,
        upload: bool,
    ) -> io::Result<bool> {
        let mut progressed = false;
        if self.start == self.end && !self.eof {
            match source.read(&mut self.buffer) {
                Ok(0) => self.eof = true,
                Ok(size) => {
                    self.start = 0;
                    self.end = size;
                    progressed = true;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        if self.start < self.end {
            match target.write(&self.buffer[self.start..self.end]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(size) => {
                    self.start += size;
                    if upload {
                        flow.tx(size);
                    } else {
                        flow.rx(size);
                    }
                    progressed = true;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        if self.eof && self.start == self.end && !self.shutdown {
            target.shutdown(Shutdown::Write)?;
            self.shutdown = true;
            progressed = true;
        }
        Ok(progressed)
    }
}

fn relay(
    mut client: TcpStream,
    mut upstream: TcpStream,
    shared: &Shared,
    flow: &Flow,
) -> io::Result<()> {
    client.set_nonblocking(true)?;
    upstream.set_nonblocking(true)?;
    let mut request = Pipe::new();
    let mut response = Pipe::new();
    let mut touched = Instant::now();
    let mut half_closed = None;
    while !shared.is_stopping() {
        let mut progressed = request.pump(&mut client, &mut upstream, flow, true)?;
        if shared.is_stopping() {
            break;
        }
        progressed |= response.pump(&mut upstream, &mut client, flow, false)?;
        if request.shutdown && response.shutdown {
            return Ok(());
        }
        let now = Instant::now();
        if progressed {
            touched = now;
        }
        if request.eof || response.eof {
            let since = half_closed.get_or_insert(now);
            if now.duration_since(*since) >= HALF_CLOSE_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP half-close deadline",
                ));
            }
        }
        if now.duration_since(touched) >= TCP_IDLE_TIMEOUT {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "TCP idle deadline"));
        }
        if !progressed {
            thread::sleep(POLL_INTERVAL);
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        for socket in [&client, &server] {
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
        }
        (client, server)
    }

    #[test]
    fn tcp_relays_both_directions_and_preserves_half_close() {
        let (mut client, ingress) = tcp_pair();
        let (upstream, mut origin) = tcp_pair();
        let shared = Arc::new(Shared::new());
        let relay_shared = Arc::clone(&shared);
        let flow = shared.flows.begin("tcp");
        let destination = match upstream.peer_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        flow.destination(destination);
        flow.selected("direct", "enumerated_origin");
        flow.stage("relay");
        let worker = thread::spawn(move || relay(ingress, upstream, &relay_shared, &flow));

        // The server speaks first, while the client's write half remains open.
        origin.write_all(b"greeting").unwrap();
        let mut greeting = [0; 8];
        client.read_exact(&mut greeting).unwrap();
        assert_eq!(&greeting, b"greeting");
        let request = vec![42u8; BUFFER_SIZE * 4 + 7];
        client.write_all(&request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut received = Vec::new();
        origin.read_to_end(&mut received).unwrap();
        assert_eq!(received, request);
        origin.write_all(b"after client EOF").unwrap();
        origin.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"after client EOF");
        worker.join().unwrap().unwrap();
        let ingress = Ingress {
            shared,
            worker: None,
        };
        let diagnostics = ingress.diagnostics();
        let traffic = &diagnostics["traffic"];
        assert_eq!(traffic["tx_bytes"], request.len() as u64);
        assert_eq!(traffic["rx_bytes"], 24);
        let row = &diagnostics["connections"]["recent"][0];
        assert_eq!(row["destination"], destination.to_string());
        assert_eq!(row["route"], "direct");
        assert_eq!(row["status"], "completed");
        assert_eq!(row["tx_bytes"], request.len() as u64);
        assert_eq!(row["rx_bytes"], 24);
        assert!(
            diagnostics["connections"]["active"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn dns_metering_counts_partial_transport_without_retaining_questions() {
        struct ShortWriter {
            written: usize,
        }
        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.written == 3 {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                let size = bytes.len().min(3 - self.written);
                self.written += size;
                Ok(size)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let shared = Arc::new(Shared::new());
        let flow = shared.flows.begin("tcp");
        flow.destination("192.0.2.53:53".parse().unwrap());
        flow.selected("dns", "system_dns");
        flow.stage("dns");
        let mut input = io::Cursor::new([0, 12, 1]);
        let mut metered = Metered {
            inner: &mut input,
            flow: &flow,
        };
        assert!(read_dns_query(&mut metered, &mut Vec::new()).is_err());
        let mut output = ShortWriter { written: 0 };
        let mut metered = Metered {
            inner: &mut output,
            flow: &flow,
        };
        assert!(metered.write_all(&[1; 5]).is_err());
        flow.failed();
        drop(flow);
        let ingress = Ingress {
            shared,
            worker: None,
        };
        let diagnostics = ingress.diagnostics();
        assert_eq!(diagnostics["traffic"]["tx_bytes"], 3);
        assert_eq!(diagnostics["traffic"]["rx_bytes"], 3);
        assert_eq!(
            diagnostics["connections"]["recent"][0]["failure_stage"],
            "dns"
        );
    }

    #[test]
    fn stop_shuts_registered_streams_and_joins_relay() {
        let (mut client, ingress) = tcp_pair();
        let (upstream, mut origin) = tcp_pair();
        let peer = match ingress.peer_addr().unwrap() {
            SocketAddr::V4(peer) => peer,
            _ => unreachable!(),
        };
        let shared = Arc::new(Shared::new());
        let registration = shared.register(peer, &ingress).unwrap().unwrap();
        registration.attach_origin(&upstream).unwrap();
        let relay_shared = Arc::clone(&shared);
        let worker =
            thread::spawn(move || relay(ingress, upstream, &relay_shared, &registration.flow));
        shared.request_stop();
        // Repeated stops do not re-register or detach anything.
        shared.request_stop();
        worker.join().unwrap().unwrap();
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
        assert_eq!(origin.read(&mut byte).unwrap(), 0);
        assert!(lock(&shared.active).is_empty());
    }

    #[test]
    fn stopped_owner_refuses_new_shutdown_registrations() {
        let (_, ingress) = tcp_pair();
        let peer = match ingress.peer_addr().unwrap() {
            SocketAddr::V4(peer) => peer,
            _ => unreachable!(),
        };
        let shared = Arc::new(Shared::new());
        shared.request_stop();
        assert!(shared.register(peer, &ingress).unwrap().is_none());
    }

    fn udp_table_peer(index: usize) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 20_000 + index as u16)
    }

    fn full_udp_table(
        shared: &Shared,
        now: Instant,
        answered: bool,
    ) -> (UdpSocket, BTreeMap<SocketAddrV4, UdpFlow>) {
        let origin = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        origin
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let SocketAddr::V4(address) = origin.local_addr().unwrap() else {
            unreachable!()
        };
        let mut flows = BTreeMap::new();
        for index in 0..MAX_UDP {
            let stats = shared.flows.begin("udp");
            stats.destination(address);
            stats.selected("direct", "enumerated_origin");
            let mut flow = UdpFlow::connect(address, address, stats).unwrap();
            for _ in 0..if answered { 2 } else { 1 } {
                assert_eq!(flow.socket.send(b"x").unwrap(), 1);
                flow.stats.tx(1);
                flow.activity.sent(now);
                let mut byte = [0];
                let (size, source) = origin.recv_from(&mut byte).unwrap();
                assert_eq!(size, 1);
                if answered {
                    origin.send_to(&byte, source).unwrap();
                    flow.socket.set_nonblocking(false).unwrap();
                    flow.socket
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    assert_eq!(flow.socket.recv(&mut byte).unwrap(), 1);
                    flow.socket.set_nonblocking(true).unwrap();
                    flow.stats.rx(1);
                    flow.activity.replied(now);
                }
            }
            flows.insert(udp_table_peer(index), flow);
        }
        (origin, flows)
    }

    #[test]
    fn udp_full_table_reclaims_completed_reused_lru_without_touching_inflight() {
        let shared = Shared::new();
        let now = Instant::now();
        let (origin, mut flows) = full_udp_table(&shared, now, true);
        // The oldest socket is reused again and becomes genuinely busy. The
        // next two have identical activity, so endpoint order breaks the tie.
        let busy = flows.get_mut(&udp_table_peer(0)).unwrap();
        assert_eq!(busy.socket.send(b"busy").unwrap(), 4);
        busy.stats.tx(4);
        busy.activity.sent(now);
        let mut packet = [0; 8];
        assert_eq!(origin.recv_from(&mut packet).unwrap().0, 4);
        for index in 3..MAX_UDP {
            let flow = flows.get_mut(&udp_table_peer(index)).unwrap();
            flow.activity.sent(now + Duration::from_millis(1));
            flow.activity.replied(now + Duration::from_millis(1));
        }
        assert!(admit_udp(&mut flows, &shared, now + Duration::from_secs(1)));
        assert_eq!(flows.len(), MAX_UDP - 1);
        assert!(flows.contains_key(&udp_table_peer(0)));
        assert!(!flows.contains_key(&udp_table_peer(1)));
        assert!(flows.contains_key(&udp_table_peer(2)));
        let replacement_peer = udp_table_peer(MAX_UDP);
        let SocketAddr::V4(address) = origin.local_addr().unwrap() else {
            unreachable!()
        };
        let mut replacement =
            UdpFlow::connect(address, address, shared.flows.begin("udp")).unwrap();
        assert_eq!(replacement.socket.send(b"new").unwrap(), 3);
        replacement.stats.tx(3);
        replacement.activity.sent(now + Duration::from_secs(1));
        assert_eq!(origin.recv_from(&mut packet).unwrap().0, 3);
        flows.insert(replacement_peer, replacement);
        assert_eq!(flows.len(), MAX_UDP);
        assert!(admit_udp(&mut flows, &shared, now + Duration::from_secs(1)));
        assert!(flows.contains_key(&replacement_peer));
        assert!(flows.contains_key(&udp_table_peer(0)));
        assert!(!flows.contains_key(&udp_table_peer(2)));
        let counters = lock(&shared.counters);
        assert_eq!(counters.udp_quiet_reclaims, 2);
        assert_eq!(counters.udp_capacity_rejections, 0);
        assert_eq!(counters.udp_failures, 0);
    }

    #[test]
    fn udp_full_table_rejects_when_every_real_exchange_is_unanswered() {
        let shared = Shared::new();
        let now = Instant::now();
        let (_origin, mut flows) = full_udp_table(&shared, now, false);
        let mut byte = [0];
        for flow in flows.values() {
            assert_eq!(
                flow.socket.recv(&mut byte).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
        // Empty receive queues must not turn the 128 in-flight sends into
        // eviction candidates. No extra socket or accounting owner is retained.
        assert!(!admit_udp(
            &mut flows,
            &shared,
            now + Duration::from_secs(1)
        ));
        assert_eq!(flows.len(), MAX_UDP);
        let counters = lock(&shared.counters);
        assert_eq!(counters.udp_capacity_rejections, 1);
        assert_eq!(counters.udp_quiet_reclaims, 0);
        assert_eq!(counters.udp_idle_expirations, 0);
        assert_eq!(counters.udp_failures, 1);
        assert_eq!(
            counters.last_error.as_deref(),
            Some("UDP flow capacity reached: all mappings busy")
        );
    }

    #[test]
    fn udp_pressure_prefers_long_idle_unanswered_flow_and_accounts_once() {
        let shared = Shared::new();
        let now = Instant::now();
        let (_origin, mut flows) = full_udp_table(&shared, now, true);
        let idle_peer = udp_table_peer(7);
        flows.get_mut(&idle_peer).unwrap().activity.sent(now);
        for (peer, flow) in &mut flows {
            if *peer != idle_peer {
                flow.activity.sent(now + Duration::from_secs(2));
                flow.activity.replied(now + Duration::from_secs(2));
            }
        }
        assert!(admit_udp(
            &mut flows,
            &shared,
            now + Duration::from_secs(31)
        ));
        assert!(!flows.contains_key(&idle_peer));
        assert_eq!(flows.len(), MAX_UDP - 1);
        // Admission below capacity does not shorten anyone's ordinary lease.
        assert!(admit_udp(
            &mut flows,
            &shared,
            now + Duration::from_secs(31)
        ));
        assert_eq!(flows.len(), MAX_UDP - 1);
        let counters = lock(&shared.counters);
        assert_eq!(counters.udp_idle_expirations, 1);
        assert_eq!(counters.udp_idle_with_response_debt, 1);
        assert_eq!(counters.udp_quiet_reclaims, 0);
        // Response debt is observational, not an application timeout: legitimate
        // fire-and-forget UDP does not become a transport failure at idle expiry.
        assert_eq!(counters.udp_failures, 0);
    }

    #[test]
    fn udp_flow_keeps_source_for_multiple_and_empty_datagrams() {
        let origin = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        origin
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let address = match origin.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let stats = Arc::new(FlowStats::new());
        let flow = UdpFlow::connect(address, address, stats.begin("udp")).unwrap();
        let mut source = None;
        let mut buffer = [0; 32];
        for message in [b"first".as_slice(), b"".as_slice(), b"third".as_slice()] {
            assert_eq!(flow.socket.send(message).unwrap(), message.len());
            let (size, peer) = origin.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..size], message);
            assert_eq!(*source.get_or_insert(peer), peer);
            origin.send_to(message, peer).unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match flow.socket.recv(&mut buffer) {
                    Ok(size) => {
                        assert_eq!(&buffer[..size], message);
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "UDP reply timed out");
                        thread::sleep(POLL_INTERVAL);
                    }
                    Err(error) => panic!("UDP reply: {error}"),
                }
            }
        }
    }

    #[test]
    fn unavailable_metadata_never_falls_back_to_an_enumerated_origin() {
        let guest = Ipv4Addr::new(172, 20, 0, 2);
        let plan = Plan {
            target: crate::host::Distro {
                id: "test-id".into(),
                name: "test-distro".into(),
                base_path: "test-path".into(),
                version: 2,
            },
            cgroup_ns: "test-cgroup-ns".into(),
            cgroup_root: "/test-cgroup".into(),
            boot_id: "test-boot".into(),
            guest,
            ingress: SocketAddrV4::new(Ipv4Addr::new(172, 20, 0, 1), 18080),
            origins: vec![SocketAddrV4::new(guest, 443)],
            system_dns: None,
            cookie: 1,
        };
        let shared = Shared::new();
        let peer = SocketAddrV4::new(guest, 49152);
        for protocol in ["tcp", "udp"] {
            let error = destination(&plan, protocol, peer, &shared).unwrap_err();
            assert!(error.starts_with("query_transport_closed:"));
        }
        let counters = lock(&shared.counters);
        assert_eq!(counters.metadata_queries, 2);
        assert_eq!(counters.metadata_transport_failures, 2);
        assert_eq!(counters.metadata_successes, 0);
        assert!(!shared.is_stopping());
        assert!(lock(&shared.failure).is_none());
        drop(counters);

        let origin = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let SocketAddr::V4(target) = origin.local_addr().unwrap() else {
            unreachable!()
        };
        let mut flow =
            UdpFlow::connect(plan.origins[0], target, shared.flows.begin("udp")).unwrap();
        let now = Instant::now();
        flow.activity.sent(now);
        for _ in 0..2 {
            let mut observations = destination_group(
                &plan,
                &[Lookup {
                    protocol: "udp",
                    peer,
                }],
                &shared,
            );
            let error = observations.next(&plan, &shared).unwrap_err();
            assert!(error.starts_with("query_transport_closed:"));
            // Failed authorization never clears response debt or permits early
            // pressure reclaim; the production loop also drops this mapping.
            assert_eq!(
                flow.activity.reclaimable(now + Duration::from_secs(1)),
                None
            );
        }
        let counters = lock(&shared.counters);
        assert_eq!(counters.metadata_queries, 4);
        assert_eq!(counters.metadata_transport_failures, 4);
        assert_eq!(counters.metadata_successes, 0);
    }

    #[test]
    fn metadata_failures_are_visible_without_stopping_ingress() {
        let shared = Arc::new(Shared::new());
        let udp_error = "query_lookup_missing: UDP mapping expired".to_string();
        shared.record_metadata("udp", &Err(udp_error.clone()));
        shared.record_error("udp", udp_error);
        let tcp_error = "query_transport_read: metadata lane closed".to_string();
        shared.record_metadata("tcp", &Err(tcp_error.clone()));
        shared.record_error("tcp", tcp_error);
        shared.record_metadata("udp", &Ok(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443)));

        let ingress = Ingress {
            shared: Arc::clone(&shared),
            worker: None,
        };
        let diagnostics = ingress.diagnostics();
        let counters = &diagnostics["counters"];
        assert_eq!(counters["metadata_queries"], 3);
        assert_eq!(counters["metadata_successes"], 1);
        assert_eq!(counters["metadata_tcp_failures"], 1);
        assert_eq!(counters["metadata_udp_failures"], 1);
        assert_eq!(counters["metadata_transport_failures"], 1);
        assert_eq!(counters["tcp_failures"], 1);
        assert_eq!(counters["udp_failures"], 1);
        assert_eq!(
            counters["last_error"],
            "query_transport_read: metadata lane closed"
        );
        assert!(!shared.is_stopping());
        assert!(lock(&shared.failure).is_none());
    }

    #[test]
    fn diagnostics_saturate_and_bound_utf8_errors() {
        let shared = Shared::new();
        {
            let mut counters = lock(&shared.counters);
            counters.metadata_queries = u64::MAX;
            counters.metadata_udp_failures = u64::MAX;
            counters.metadata_transport_failures = u64::MAX;
            counters.udp_failures = u64::MAX;
        }
        let error = format!("query_transport_read: {}", "界".repeat(MAX_ERROR_BYTES));
        shared.record_metadata("udp", &Err(error.clone()));
        shared.record_error("udp", error);

        let counters = lock(&shared.counters);
        assert_eq!(counters.metadata_queries, u64::MAX);
        assert_eq!(counters.metadata_udp_failures, u64::MAX);
        assert_eq!(counters.metadata_transport_failures, u64::MAX);
        assert_eq!(counters.udp_failures, u64::MAX);
        let error = counters.last_error.as_ref().unwrap();
        assert!(error.len() <= MAX_ERROR_BYTES);
        assert!(error.starts_with("query_transport_read: "));
        assert!(error.ends_with('界'));
    }

    #[test]
    fn dns_tcp_reads_multiple_frames_without_merging_or_losing_eof() {
        let first = [1u8; 12];
        let second = [2u8; 19];
        let mut wire = Vec::new();
        for query in [first.as_slice(), second.as_slice()] {
            wire.extend_from_slice(&(query.len() as u16).to_be_bytes());
            wire.extend_from_slice(query);
        }
        let mut wire = io::Cursor::new(wire);
        let mut query = Vec::new();
        assert!(read_dns_query(&mut wire, &mut query).unwrap());
        assert_eq!(query, first);
        assert!(read_dns_query(&mut wire, &mut query).unwrap());
        assert_eq!(query, second);
        assert!(!read_dns_query(&mut wire, &mut query).unwrap());
    }

    #[test]
    fn dns_tcp_rejects_partial_prefix_partial_payload_and_short_query() {
        for wire in [vec![0], vec![0, 12, 1], vec![0, 0], vec![0, 11]] {
            assert!(read_dns_query(&mut io::Cursor::new(wire), &mut Vec::new()).is_err());
        }
    }

    #[test]
    fn dns_udp_slot_releases_capacity_when_unwinding() {
        let shared = Arc::new(Shared::new());
        shared.dns_udp_active.store(1, Ordering::Release);
        let slot = DnsUdpSlot(Arc::clone(&shared));
        let result = std::panic::catch_unwind(move || {
            let _slot = slot;
            panic!("test worker panic");
        });
        assert!(result.is_err());
        assert_eq!(shared.dns_udp_active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn stop_drains_workers_and_reports_prior_failure_once() {
        let shared = Arc::new(Shared::new());
        shared.fail("prior forwarding failure".into());
        let drained = Arc::new(AtomicBool::new(false));
        let worker_drained = Arc::clone(&drained);
        let worker = thread::spawn(move || {
            worker_drained.store(true, Ordering::Release);
            Ok(())
        });
        let mut ingress = Ingress {
            shared,
            worker: Some(worker),
        };

        assert_eq!(ingress.stop().unwrap_err(), "prior forwarding failure");
        assert!(drained.load(Ordering::Acquire));
        assert!(ingress.worker.is_none());
        ingress.stop().unwrap();
    }
}
