use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use socket2::{Protocol, Type};

use crate::m1::Plan;
use crate::query_bridge::QueryBridge;

const MAX_TCP: usize = 64;
const MAX_UDP: usize = 128;
const ACCEPT_BATCH: usize = 16;
const UDP_BATCH: usize = 4;
const UDP_REPLY_BATCH: usize = 4;
const MAX_DNS_UDP: usize = 8;
const BUFFER_SIZE: usize = 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(15);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
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
        let bridge = QueryBridge::open(plan)?;
        crate::lease::reserve(plan, &tcp, &udp)?;

        let shared = Arc::new(Shared::new());
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
        serde_json::json!({
            "active_tcp": active_tcp,
            "healthy": self.health().is_ok(),
            "active_dns_udp": self.shared.dns_udp_active.load(Ordering::Acquire),
            "stopping": self.shared.is_stopping(),
            "counters": &*lock(&self.shared.counters),
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
    last_error: Option<String>,
}

struct Shared {
    stopping: AtomicBool,
    failure: Mutex<Option<String>>,
    active: Mutex<HashMap<SocketAddrV4, ActiveTcp>>,
    bridge: Mutex<Option<QueryBridge>>,
    dns_udp_active: std::sync::atomic::AtomicUsize,
    counters: Mutex<HealthCounters>,
}

impl Shared {
    fn new() -> Self {
        Self {
            stopping: AtomicBool::new(false),
            failure: Mutex::new(None),
            active: Mutex::new(HashMap::new()),
            bridge: Mutex::new(None),
            dns_udp_active: std::sync::atomic::AtomicUsize::new(0),
            counters: Mutex::new(HealthCounters::default()),
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
        }))
    }
}

struct TcpRegistration {
    shared: Arc<Shared>,
    peer: SocketAddrV4,
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

fn destination(
    plan: &Plan,
    protocol: &str,
    peer: SocketAddrV4,
    shared: &Shared,
) -> Result<SocketAddrV4, String> {
    if shared.is_stopping() || peer.ip() != &plan.guest || peer.port() == 0 {
        return Err("unauthorized ingress peer or stopped ingress".into());
    }
    let result = {
        let mut bridge = lock(&shared.bridge);
        // Workers queued behind another lookup must not start a new command
        // after stop has begun.
        if shared.is_stopping() {
            return Err("ingress is stopping".into());
        }
        bridge
            .as_mut()
            .ok_or_else(|| "query_transport_closed: metadata bridge is closed".to_string())
            .and_then(|bridge| bridge.query(protocol, peer))
    }
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
fn route(
    plan: &Plan,
    runtime: Option<&crate::m2::Runtime>,
    protocol: &str,
    original: SocketAddrV4,
) -> Result<Route, String> {
    let Some(runtime) = runtime else {
        return Ok(Route::Direct(original));
    };
    if plan.system_dns == Some(*original.ip()) && original.port() == 53 {
        return Ok(Route::Dns);
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
    if alias.is_some() || runtime.policy.allows_ip(*actual.ip()) {
        Ok(Route::Direct(actual))
    } else if protocol == "tcp" {
        Ok(Route::Chain)
    } else {
        Err("non-whitelisted UDP rejected: two-hop UDP is unavailable".into())
    }
}

fn select_route(
    plan: &Plan,
    runtime: Option<&crate::m2::Runtime>,
    protocol: &str,
    original: SocketAddrV4,
    shared: &Shared,
) -> Result<Route, String> {
    let result = route(plan, runtime, protocol, original);
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
    let mut flows: HashMap<SocketAddrV4, UdpFlow> = HashMap::new();
    // One reusable buffer holds every legal IPv4 UDP payload, including an empty
    // datagram. UDP receive length zero is data, never an EOF indication.
    let mut datagram = [0u8; 65_535];
    while !shared.is_stopping() {
        workers.reap()?;
        dns_workers.reap()?;
        for _ in 0..ACCEPT_BATCH {
            if shared.is_stopping() {
                break;
            }
            let client = match listener.accept() {
                Ok((client, _)) => client,
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
            let worker = thread::Builder::new()
                .name("m1-tcp".into())
                .spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        forward_tcp(&plan, client, &registration, runtime.as_deref())
                    }));
                    match result {
                        Ok(Err(error)) if !worker_shared.is_stopping() => {
                            worker_shared.record_error("tcp", error);
                        }
                        Err(_) => worker_shared.fail("TCP forwarding worker panicked".into()),
                        _ => {}
                    }
                })
                .map_err(|e| format!("start TCP forwarding worker: {e}"))?;
            workers.handles.push(worker);
        }
        for _ in 0..UDP_BATCH {
            if shared.is_stopping() {
                break;
            }
            let (size, peer) = match udp.recv_from(&mut datagram) {
                Ok((size, SocketAddr::V4(peer))) if peer.ip() == &plan.guest => (size, peer),
                Ok(_) => continue,
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
            let origin = match destination(&plan, "udp", peer, &shared) {
                Ok(origin) => origin,
                Err(error) => {
                    shared.record_error("udp", error);
                    flows.remove(&peer);
                    continue;
                }
            };
            let target = match select_route(&plan, runtime.as_deref(), "udp", origin, &shared) {
                Ok(Route::Direct(target)) => target,
                Ok(Route::Dns) => {
                    flows.remove(&peer);
                    let runtime = runtime.as_ref().expect("DNS route requires M2 runtime");
                    if dns_workers.handles.len() >= MAX_DNS_UDP {
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
                        peer,
                        origin,
                        &datagram[..size],
                        &mut dns_workers,
                    )?;
                    continue;
                }
                Ok(Route::Chain) => {
                    // There is no authenticated two-hop UDP implementation.
                    // Never reinterpret a missing UDP transport as direct access.
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
            {
                flows.remove(&peer);
            }
            if !flows.contains_key(&peer) {
                if flows.len() >= MAX_UDP || shared.is_stopping() {
                    continue;
                }
                let flow = match UdpFlow::connect(origin, target) {
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
            match flow.socket.send(&datagram[..size]) {
                Ok(sent) if sent == size => flow.touched = Instant::now(),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => {
                    shared.record_error("udp", format!("origin send failed: {result:?}"));
                    flows.remove(&peer);
                }
            }
        }
        flows.retain(|peer, flow| {
            if shared.is_stopping() || flow.touched.elapsed() >= UDP_IDLE_TIMEOUT {
                return false;
            }
            for _ in 0..UDP_REPLY_BATCH {
                if shared.is_stopping() {
                    return false;
                }
                let size = match flow.socket.recv(&mut datagram) {
                    Ok(size) => size,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        shared.record_error("udp", format!("origin receive failed: {error}"));
                        return false;
                    }
                };
                match destination(&plan, "udp", *peer, &shared) {
                    Ok(origin) if origin == flow.origin => {}
                    Ok(_) => {
                        shared.record_error("udp", "UDP mapping changed before reply".into());
                        return false;
                    }
                    Err(error) => {
                        shared.record_error("udp", error);
                        return false;
                    }
                }
                match route(&plan, runtime.as_deref(), "udp", flow.origin) {
                    Ok(Route::Direct(target)) if target == flow.target => {}
                    _ => {
                        shared.record_error("udp", "UDP route expired before reply".into());
                        return false;
                    }
                }
                if shared.is_stopping() {
                    return false;
                }
                match udp.send_to(&datagram[..size], *peer) {
                    Ok(sent) if sent == size => flow.touched = Instant::now(),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    result => {
                        shared.record_error("udp", format!("guest send failed: {result:?}"));
                        return false;
                    }
                }
            }
            true
        });
        thread::sleep(POLL_INTERVAL);
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
    peer: SocketAddrV4,
    original: SocketAddrV4,
    request: &[u8],
    workers: &mut TcpWorkers,
) -> Result<(), String> {
    let socket = udp
        .try_clone()
        .map_err(|_| "retain DNS UDP reply socket".to_string())?;
    let plan = Arc::clone(plan);
    let runtime = Arc::clone(runtime);
    let request = request.to_vec();
    let shared = Arc::clone(&workers.shared);
    shared.dns_udp_active.fetch_add(1, Ordering::AcqRel);
    let slot = DnsUdpSlot(Arc::clone(&shared));
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
                if destination(&plan, "udp", peer, &shared)? != original
                    || route(&plan, Some(&runtime), "udp", original)? != Route::Dns
                {
                    return Err("UDP DNS mapping changed before reply".into());
                }
                if shared.is_stopping() {
                    return Ok(());
                }
                match socket.send_to(&answer, peer) {
                    Ok(size) if size == answer.len() => Ok(()),
                    _ => Err("managed UDP DNS reply failed".into()),
                }
            })();
            if let Err(error) = result
                && !shared.is_stopping()
            {
                shared.record_error("udp", error);
            }
        })
        .map_err(|_| "start managed UDP DNS worker".to_string())?;
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

struct UdpFlow {
    origin: SocketAddrV4,
    target: SocketAddrV4,
    socket: UdpSocket,
    touched: Instant,
}

impl UdpFlow {
    fn connect(origin: SocketAddrV4, target: SocketAddrV4) -> io::Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.set_nonblocking(true)?;
        socket.connect(target)?;
        Ok(Self {
            origin,
            target,
            socket,
            touched: Instant::now(),
        })
    }
}

fn forward_tcp(
    plan: &Plan,
    client: TcpStream,
    registration: &TcpRegistration,
    runtime: Option<&crate::m2::Runtime>,
) -> Result<(), String> {
    let shared = &registration.shared;
    let origin = destination(plan, "tcp", registration.peer, shared)?;
    let selected = select_route(plan, runtime, "tcp", origin, shared)?;
    if selected == Route::Dns {
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
    if client.peer_addr().ok() != Some(SocketAddr::V4(registration.peer))
        || destination(plan, "tcp", registration.peer, shared)? != origin
        || route(plan, runtime, "tcp", origin)? != selected
    {
        return Err("TCP mapping changed while connecting to origin".into());
    }
    relay(client, upstream, shared).map_err(|e| format!("relay: {e}"))
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

    fn pump(&mut self, source: &mut TcpStream, target: &mut TcpStream) -> io::Result<bool> {
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

fn relay(mut client: TcpStream, mut upstream: TcpStream, shared: &Shared) -> io::Result<()> {
    client.set_nonblocking(true)?;
    upstream.set_nonblocking(true)?;
    let mut request = Pipe::new();
    let mut response = Pipe::new();
    let mut touched = Instant::now();
    let mut half_closed = None;
    while !shared.is_stopping() {
        let mut progressed = request.pump(&mut client, &mut upstream)?;
        if shared.is_stopping() {
            break;
        }
        progressed |= response.pump(&mut upstream, &mut client)?;
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
        let worker = thread::spawn(move || relay(ingress, upstream, &relay_shared));

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
        let worker = thread::spawn(move || {
            let _registration = registration;
            relay(ingress, upstream, &relay_shared)
        });
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
        let flow = UdpFlow::connect(address, address).unwrap();
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
