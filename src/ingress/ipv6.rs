//! IPv6 ingress worker. It shares the authenticated metadata lane with the
//! IPv4 worker and keeps the transport-specific state local to this module.

use super::udp_chain_setup::{ChainSetups, Hold, Ready};
use super::{
    Flow, Plan, Shared, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpChain, UdpSocket, lock,
};
use crate::plan::Ipv6Plan;
use crate::query_bridge::Lookup;
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(not(windows))]
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// An IPv6 UDP mapping with no traffic this long is retired. A full table
/// refuses new mappings instead of evicting, so this stays short.
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

struct UdpFlow {
    peer: SocketAddrV6,
    origin: SocketAddrV6,
    socket: UdpTransport,
    chained: bool,
    stats: Flow,
    touched: Instant,
}

enum UdpTransport {
    Direct(UdpSocket),
    Chain(UdpChain),
}

impl UdpTransport {
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            Self::Direct(socket) => socket.set_nonblocking(nonblocking),
            Self::Chain(chain) => chain.set_nonblocking(nonblocking),
        }
    }

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

pub(super) fn run(
    plan: Arc<Plan>,
    listener: TcpListener,
    ingress: UdpSocket,
    shared: Arc<Shared>,
    runtime: Option<Arc<crate::managed::Runtime>>,
) -> Result<(), String> {
    let ipv6 = plan
        .ipv6
        .as_ref()
        .ok_or("IPv6 ingress plan missing")?
        .clone();
    // Dropped on every exit, including `?`: shuts the clients down and joins
    // every relay.
    let mut tcp_workers = TcpWorkers {
        shared: Arc::clone(&shared),
        active: Arc::new(Mutex::new(BTreeMap::new())),
        handles: Vec::new(),
    };
    let mut udp_flows = BTreeMap::new();
    // Dropped on every exit, including `?`: joins running setups.
    let mut chain_setups = ChainSetups::new();
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("configure IPv6 listener: {e}"))?;
    ingress
        .set_nonblocking(true)
        .map_err(|e| format!("configure IPv6 UDP ingress: {e}"))?;
    while !shared.is_stopping() {
        tcp_workers.reap()?;
        let mut progressed = accept_tcp(
            &plan,
            &ipv6,
            &listener,
            &shared,
            runtime.clone(),
            &mut tcp_workers,
        )?;
        progressed |= receive_udp(
            &plan,
            &ipv6,
            &ingress,
            &shared,
            runtime.as_ref(),
            &mut udp_flows,
            &mut chain_setups,
        )?;
        progressed |= collect_udp(
            &plan,
            &ipv6,
            &ingress,
            &shared,
            runtime.as_deref(),
            &mut udp_flows,
        );
        // TCP relays run on their own threads. Without new work, block on socket
        // readiness (bounded by the poll interval) instead of spinning while any
        // connection or UDP mapping is open.
        if !progressed && !shared.is_stopping() {
            wait(&listener, &ingress, &mut udp_flows, &shared)?;
        }
    }
    for flow in udp_flows.into_values() {
        flow.stats.stopped();
    }
    Ok(())
}

/// The IPv6 TCP relay threads and the client handles that interrupt them.
/// `Shared::request_stop` only reaches the IPv4 clients, so this guard shuts
/// these down itself when `run` returns, `?` and panics included: no relay
/// outlives the ingress that `Ingress::stop` reports as joined.
struct TcpWorkers {
    shared: Arc<Shared>,
    active: Arc<Mutex<BTreeMap<SocketAddrV6, TcpStream>>>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl TcpWorkers {
    fn reap(&mut self) -> Result<(), String> {
        let mut index = 0;
        while index < self.handles.len() {
            if self.handles[index].is_finished() {
                if self.handles.swap_remove(index).join().is_err() {
                    return Err("IPv6 TCP forwarding worker panicked".into());
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
        // The guard is a temporary of this statement: each relay locks `active`
        // to deregister, so it must be released before the joins below.
        for client in lock(&self.active).values() {
            let _ = client.shutdown(std::net::Shutdown::Both);
        }
        for handle in self.handles.drain(..) {
            if handle.join().is_err() {
                self.shared
                    .record_failure("IPv6 TCP forwarding worker panicked".into());
            }
        }
    }
}

fn accept_tcp(
    plan: &Arc<Plan>,
    ipv6: &Ipv6Plan,
    listener: &TcpListener,
    shared: &Arc<Shared>,
    runtime: Option<Arc<crate::managed::Runtime>>,
    workers: &mut TcpWorkers,
) -> Result<bool, String> {
    let active = &workers.active;
    let mut progressed = false;
    for _ in 0..super::ACCEPT_BATCH {
        let (client, peer) = match listener.accept() {
            Ok((client, SocketAddr::V6(peer))) if peer.ip() == &ipv6.guest => {
                progressed = true;
                (client, peer)
            }
            Ok((_, _)) => {
                progressed = true;
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if super::tcp::transient(&error) => continue,
            // The connection stays queued until resources return.
            Err(error) if super::tcp::exhausted(&error) => {
                shared.record_error("tcp", format!("IPv6 TCP ingress accept deferred: {error}"));
                thread::sleep(super::RESOURCE_BACKOFF);
                break;
            }
            Err(error) => return Err(format!("IPv6 TCP ingress accept failed: {error}")),
        };
        if workers.handles.len() >= shared.limits.max_tcp {
            shared.reject_tcp_at_capacity();
            continue;
        }
        // A handle or thread that cannot be created fails this connection only.
        let retained = match client.try_clone() {
            Ok(retained) => retained,
            Err(error) => {
                shared.reject_tcp(
                    "resource_limit",
                    format!("retain IPv6 TCP shutdown handle: {error}"),
                );
                continue;
            }
        };
        lock(active).insert(peer, retained);
        let plan = Arc::clone(plan);
        let worker_shared = Arc::clone(shared);
        let worker_active = Arc::clone(active);
        let runtime = runtime.clone();
        let spawned = thread::Builder::new()
            .name("m1-tcp-ipv6".into())
            .spawn(move || {
                let result = forward_tcp(plan, client, peer, worker_shared.clone(), runtime);
                lock(&worker_active).remove(&peer);
                if let Err(error) = result
                    && !worker_shared.is_stopping()
                {
                    worker_shared.record_error("tcp", error);
                }
            });
        match spawned {
            Ok(worker) => workers.handles.push(worker),
            Err(error) => {
                lock(active).remove(&peer);
                shared.reject_tcp(
                    "resource_limit",
                    format!("start IPv6 TCP forwarding worker: {error}"),
                );
            }
        }
    }
    Ok(progressed)
}

fn forward_tcp(
    plan: Arc<Plan>,
    client: TcpStream,
    peer: SocketAddrV6,
    shared: Arc<Shared>,
    runtime: Option<Arc<crate::managed::Runtime>>,
) -> Result<(), String> {
    let flow = shared.flows.begin("tcp");
    flow.stage("metadata");
    let origin = destination_v6(&plan, "tcp", peer, &shared)?;
    flow.destination(SocketAddr::V6(origin));
    let runtime = runtime.as_ref().ok_or("IPv6 managed runtime missing")?;
    let chained = route_v6(runtime, origin)?;
    let upstream = if !chained {
        flow.selected("direct", "ip_or_cidr");
        TcpStream::connect_timeout(&SocketAddr::V6(origin), CONNECT_TIMEOUT)
            .map_err(|e| format!("connect IPv6 direct endpoint: {e}"))?
    } else {
        flow.selected("chain", "default_chain");
        runtime
            .policy
            .chain_ipv6(origin)
            .map_err(|e| format!("IPv6 two-hop chain failed: {e}"))?
    };
    flow.stage("relay");
    match super::tcp::relay(client, upstream, &shared, &flow) {
        Ok(super::tcp::Ended::ClientReset) => {
            shared.record_client_reset();
            Ok(())
        }
        Ok(super::tcp::Ended::Closed) => Ok(()),
        Err(error) => Err(format!("IPv6 relay: {error}")),
    }
}

fn receive_udp(
    plan: &Arc<Plan>,
    ipv6: &Ipv6Plan,
    ingress: &UdpSocket,
    shared: &Arc<Shared>,
    policy: Option<&Arc<crate::managed::Runtime>>,
    flows: &mut BTreeMap<SocketAddrV6, UdpFlow>,
    setups: &mut ChainSetups<SocketAddrV6, UdpChain>,
) -> Result<bool, String> {
    let mut progressed = false;
    // A finished setup installs its flow; its held datagram then takes the
    // normal path, including a fresh kernel authorization, before it is sent.
    for ready in setups.finished(Instant::now(), super::UDP_BATCH) {
        progressed = true;
        if let Some((peer, datagram)) = install_chain(ready, flows, shared) {
            handle_udp(plan, shared, policy, flows, setups, peer, &datagram);
        }
    }
    let mut buffer = [0; 65_535];
    // Bounded like the IPv4 lane so a busy guest cannot starve reply collection.
    for _ in 0..super::UDP_BATCH {
        if shared.is_stopping() {
            break;
        }
        let (size, peer) = match ingress.recv_from(&mut buffer) {
            Ok((size, SocketAddr::V6(peer))) if peer.ip() == &ipv6.guest && peer.port() != 0 => {
                progressed = true;
                (size, peer)
            }
            Ok(_) => {
                progressed = true;
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            // As on the IPv4 listener: Windows reports an ICMP port-unreachable
            // for an earlier reply to a guest socket that has since closed on
            // this unconnected socket's next receive. It concerns one finished
            // exchange, not the listener.
            Err(error) if super::tcp::transient(&error) => {
                progressed = true;
                continue;
            }
            Err(error) => return Err(format!("IPv6 UDP ingress receive failed: {error}")),
        };
        handle_udp(plan, shared, policy, flows, setups, peer, &buffer[..size]);
    }
    Ok(progressed)
}

/// Authorizes one guest datagram against the kernel and relays it, creating
/// its mapping first when needed. Every failure stays with this datagram.
fn handle_udp(
    plan: &Arc<Plan>,
    shared: &Arc<Shared>,
    policy: Option<&Arc<crate::managed::Runtime>>,
    flows: &mut BTreeMap<SocketAddrV6, UdpFlow>,
    setups: &mut ChainSetups<SocketAddrV6, UdpChain>,
    peer: SocketAddrV6,
    datagram: &[u8],
) {
    let origin = match destination_v6(plan, "udp", peer, shared) {
        Ok(origin) => origin,
        Err(error) => {
            if !shared.is_stopping() {
                shared.record_error("udp", error);
            }
            return;
        }
    };
    let Some(runtime) = policy else {
        shared.record_error("udp", "IPv6 UDP runtime missing".into());
        return;
    };
    let chained = match route_v6(runtime, origin) {
        Ok(chained) => chained,
        Err(error) => {
            shared.record_error("udp", error);
            return;
        }
    };
    let flow = if let Some(flow) = flows.get_mut(&peer) {
        if flow.origin != origin || flow.chained != chained {
            flows.remove(&peer);
            None
        } else {
            Some(flow)
        }
    } else {
        None
    };
    if flow.is_none() {
        // This mapping's two-hop setup is running (its first datagram is held)
        // or failed moments ago: no new record per retransmission.
        match setups.hold(peer, SocketAddr::V6(origin), Instant::now()) {
            Hold::No => {}
            Hold::Pending => return,
            Hold::BackedOff => {
                let mut counters = lock(&shared.counters);
                counters.udp_chain_backoff_drops =
                    counters.udp_chain_backoff_drops.saturating_add(1);
                return;
            }
        }
        if flows.len() >= super::MAX_UDP {
            {
                let mut counters = lock(&shared.counters);
                counters.udp_capacity_rejections =
                    counters.udp_capacity_rejections.saturating_add(1);
            }
            shared.record_error("udp", "IPv6 UDP flow capacity reached".into());
            return;
        }
        if chained {
            let stats = shared.flows.begin("udp");
            stats.destination(SocketAddr::V6(origin));
            stats.selected("chain", "default_chain");
            stats.stage("connect");
            if shared.is_stopping() {
                stats.stopped();
                return;
            }
            super::start_chain_setup(
                setups,
                peer,
                SocketAddr::V6(origin),
                datagram,
                stats,
                runtime,
                shared,
            );
            return;
        }
        // A socket that cannot be created or configured fails this mapping
        // only, exactly like an IPv4 origin socket.
        let socket = match direct_socket(origin) {
            Ok(socket) => UdpTransport::Direct(socket),
            Err(error) => {
                shared.record_error("udp", format!("create IPv6 origin UDP socket: {error}"));
                return;
            }
        };
        if let Err(error) = socket.set_nonblocking(true) {
            shared.record_error("udp", format!("configure IPv6 origin UDP socket: {error}"));
            return;
        }
        let stats = shared.flows.begin("udp");
        stats.destination(SocketAddr::V6(origin));
        stats.selected("direct", "ip_or_cidr");
        flows.insert(
            peer,
            UdpFlow {
                peer,
                origin,
                socket,
                chained,
                stats,
                touched: Instant::now(),
            },
        );
    }
    if let Some(flow) = flows.get_mut(&peer) {
        flow.stats.stage("relay");
        match flow.socket.send(datagram) {
            Ok(sent) if sent == datagram.len() => {
                flow.stats.tx(sent);
                flow.touched = Instant::now();
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            result => {
                flow.stats.failed();
                shared.record_error("udp", format!("send IPv6 origin packet failed: {result:?}"));
                flows.remove(&peer);
            }
        }
    }
}

/// Installs a finished IPv6 chain setup and returns its held datagram.
fn install_chain(
    ready: Ready<SocketAddrV6, UdpChain>,
    flows: &mut BTreeMap<SocketAddrV6, UdpFlow>,
    shared: &Shared,
) -> Option<(SocketAddrV6, Vec<u8>)> {
    let Ready {
        peer,
        origin,
        stats,
        datagram,
        result,
    } = ready;
    if shared.is_stopping() {
        stats.stopped();
        return None;
    }
    let chain = match result {
        Ok(chain) => chain,
        Err(error) => {
            stats.failed();
            shared.record_error("udp", format!("IPv6 UDP chain setup failed: {error}"));
            return None;
        }
    };
    let SocketAddr::V6(origin) = origin else {
        stats.failed();
        return None;
    };
    // Another route took this guest socket while the chain was built.
    if flows.contains_key(&peer) {
        stats.failed();
        return None;
    }
    if flows.len() >= super::MAX_UDP {
        stats.failed();
        {
            let mut counters = lock(&shared.counters);
            counters.udp_capacity_rejections = counters.udp_capacity_rejections.saturating_add(1);
        }
        shared.record_error("udp", "IPv6 UDP flow capacity reached".into());
        return None;
    }
    if let Err(error) = chain.set_nonblocking(true) {
        stats.failed();
        shared.record_error("udp", format!("configure IPv6 origin UDP socket: {error}"));
        return None;
    }
    flows.insert(
        peer,
        UdpFlow {
            peer,
            origin,
            socket: UdpTransport::Chain(chain),
            chained: true,
            stats,
            touched: Instant::now(),
        },
    );
    Some((peer, datagram))
}

fn direct_socket(origin: SocketAddrV6) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0))?;
    socket.connect(SocketAddr::V6(origin))?;
    Ok(socket)
}

/// Relays at most one reply per mapping. A reply that cannot be authorized
/// retires only its own mapping; the worker and every other flow keep running.
fn collect_udp(
    plan: &Arc<Plan>,
    ipv6: &Ipv6Plan,
    ingress: &UdpSocket,
    shared: &Arc<Shared>,
    policy: Option<&crate::managed::Runtime>,
    flows: &mut BTreeMap<SocketAddrV6, UdpFlow>,
) -> bool {
    let now = Instant::now();
    let mut buffer = [0; 65_535];
    let mut progressed = false;
    let peers: Vec<_> = flows.keys().copied().collect();
    for peer in peers {
        let Some(flow) = flows.get_mut(&peer) else {
            continue;
        };
        let mut retire = false;
        match flow.socket.recv(&mut buffer) {
            Ok(size) => {
                progressed = true;
                let verified = match destination_v6(
                    plan,
                    "udp",
                    SocketAddrV6::new(ipv6.guest, peer.port(), 0, peer.scope_id()),
                    shared,
                ) {
                    Ok(verified) => verified,
                    Err(error) => {
                        if shared.is_stopping() {
                            flow.stats.stopped();
                        } else {
                            flow.stats.stage("metadata");
                            flow.stats.failed();
                            shared.record_error("udp", error);
                        }
                        flows.remove(&peer);
                        continue;
                    }
                };
                let route_valid = policy.is_some_and(|runtime| {
                    route_v6(runtime, verified)
                        .map(|chained| chained == flow.chained)
                        .unwrap_or(false)
                });
                if verified != flow.origin || !route_valid {
                    flow.stats.failed();
                    retire = true;
                } else {
                    match ingress.send_to(&buffer[..size], flow.peer) {
                        Ok(sent) if sent == size => {
                            flow.stats.rx(sent);
                            flow.touched = now;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        result => {
                            flow.stats.failed();
                            shared.record_error(
                                "udp",
                                format!("send IPv6 UDP reply failed: {result:?}"),
                            );
                            retire = true;
                        }
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => {
                progressed = true;
                flow.stats.failed();
                shared.record_error("udp", format!("IPv6 origin receive failed: {error}"));
                retire = true;
            }
        }
        if retire {
            flows.remove(&peer);
        }
    }
    // An idle mapping ended normally: count it like an IPv4 one and let the
    // dropped flow record itself as completed.
    flows.retain(|_, flow| {
        let live = now.duration_since(flow.touched) <= UDP_IDLE_TIMEOUT;
        if !live {
            let mut counters = lock(&shared.counters);
            counters.udp_idle_expirations = counters.udp_idle_expirations.saturating_add(1);
        }
        live
    });
    progressed
}

#[cfg(windows)]
fn wait(
    listener: &TcpListener,
    ingress: &UdpSocket,
    flows: &mut BTreeMap<SocketAddrV6, UdpFlow>,
    shared: &Shared,
) -> Result<(), String> {
    let mut failed = [false; super::MAX_UDP];
    super::udp_pump::wait_ready(
        listener,
        ingress,
        flows.values().map(|flow| flow.socket.as_raw_socket()),
        |index| failed[index] = true,
    )?;
    // A connected origin socket can report an ICMP error here. Retire just that
    // mapping so a persistent error cannot turn the wait into a busy loop.
    let retired: Vec<SocketAddrV6> = flows
        .keys()
        .zip(failed)
        .filter_map(|(peer, failed)| failed.then_some(*peer))
        .collect();
    for peer in retired {
        if let Some(flow) = flows.remove(&peer) {
            flow.stats.failed();
            shared.record_error("udp", "IPv6 origin socket readiness failed".into());
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn wait(
    _listener: &TcpListener,
    _ingress: &UdpSocket,
    _flows: &mut BTreeMap<SocketAddrV6, UdpFlow>,
    _shared: &Shared,
) -> Result<(), String> {
    thread::sleep(POLL_INTERVAL);
    Ok(())
}

fn destination_v6(
    plan: &Plan,
    protocol: &'static str,
    peer: SocketAddrV6,
    shared: &Shared,
) -> Result<SocketAddrV6, String> {
    if shared.is_stopping() {
        return Err("IPv6 ingress is stopping".into());
    }
    let rx = lock(&shared.bridge)
        .as_ref()
        .ok_or("query_transport_closed: metadata bridge is closed")?
        .submit(Lookup {
            protocol,
            peer: SocketAddr::V6(peer),
        })?;
    super::finish_observation_v6(
        plan,
        protocol,
        Instant::now(),
        rx.recv_timeout(super::METADATA_WAIT_TIMEOUT)
            .map_err(|_| "query_transport_timeout".to_string()),
        shared,
    )
}

fn route_v6(runtime: &crate::managed::Runtime, origin: SocketAddrV6) -> Result<bool, String> {
    let direct = runtime.policy.allows_ipv6(*origin.ip());
    route_v6_decision(origin, direct)
}

fn route_v6_decision(origin: SocketAddrV6, direct: bool) -> Result<bool, String> {
    if origin.port() == 53 {
        Err("alternate plaintext IPv6 DNS destination rejected".into())
    } else {
        Ok(!direct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};

    // Every lookup fails here: the test owner has no metadata bridge.
    fn plan() -> Arc<Plan> {
        Arc::new(Plan {
            target: crate::host::Distro {
                id: "test-id".into(),
                name: "test-distro".into(),
                base_path: "test-path".into(),
                version: 2,
            },
            cgroup_ns: "test-cgroup-ns".into(),
            cgroup_root: "/test-cgroup".into(),
            boot_id: "test-boot".into(),
            guest: Ipv4Addr::LOCALHOST,
            ingress: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18080),
            origins: Vec::new(),
            system_dns: None,
            cookie: 1,
            ipv6: Some(Ipv6Plan {
                guest: Ipv6Addr::LOCALHOST,
                ingress: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 18080, 0, 0),
            }),
        })
    }

    fn v6(socket: &UdpSocket) -> SocketAddrV6 {
        let SocketAddr::V6(address) = socket.local_addr().unwrap() else {
            unreachable!()
        };
        address
    }

    fn direct_flow(shared: &Shared, peer: SocketAddrV6, origin: &UdpSocket) -> UdpFlow {
        let socket = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        socket.connect(origin.local_addr().unwrap()).unwrap();
        UdpFlow {
            peer,
            origin: v6(origin),
            socket: UdpTransport::Direct(socket),
            chained: false,
            stats: shared.flows.begin("udp"),
            touched: Instant::now(),
        }
    }

    #[test]
    fn a_reset_for_an_earlier_reply_does_not_stop_the_ipv6_listener() {
        let shared = Arc::new(Shared::new());
        let plan = plan();
        let ipv6 = plan.ipv6.clone().unwrap();
        let ingress = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        // A reply to a guest socket that has already closed provokes an ICMP
        // port-unreachable; Windows reports it on this socket's next receive.
        let closed = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let closed_address = closed.local_addr().unwrap();
        drop(closed);
        ingress.send_to(b"late reply", closed_address).unwrap();
        thread::sleep(Duration::from_millis(100));
        ingress.set_nonblocking(true).unwrap();
        let mut flows = BTreeMap::new();
        let mut setups = ChainSetups::new();
        assert!(
            receive_udp(
                &plan,
                &ipv6,
                &ingress,
                &shared,
                None,
                &mut flows,
                &mut setups
            )
            .is_ok()
        );
        assert!(flows.is_empty());
        // The error was consumed: the next round finds an empty queue.
        assert_eq!(
            receive_udp(
                &plan,
                &ipv6,
                &ingress,
                &shared,
                None,
                &mut flows,
                &mut setups
            ),
            Ok(false)
        );
    }

    #[test]
    fn an_unauthorized_reply_retires_only_its_mapping_without_stopping_the_worker() {
        let shared = Arc::new(Shared::new());
        let plan = plan();
        let ipv6 = plan.ipv6.clone().unwrap();
        let ingress = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let origin = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let replying = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 45_000, 0, 0);
        let quiet = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 45_001, 0, 0);
        let mut flows = BTreeMap::new();
        flows.insert(replying, direct_flow(&shared, replying, &origin));
        flows.insert(quiet, direct_flow(&shared, quiet, &origin));
        let UdpTransport::Direct(socket) = &flows[&replying].socket else {
            unreachable!()
        };
        origin
            .send_to(b"reply", socket.local_addr().unwrap())
            .unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket.peek(&mut [0; 8]).unwrap();
        for flow in flows.values() {
            flow.socket.set_nonblocking(true).unwrap();
        }

        assert!(collect_udp(
            &plan, &ipv6, &ingress, &shared, None, &mut flows
        ));
        assert!(!flows.contains_key(&replying));
        assert!(flows.contains_key(&quiet));
        assert!(!shared.is_stopping());
        assert!(lock(&shared.failure).is_none());
        let counters = lock(&shared.counters);
        assert_eq!(counters.udp_failures, 1);
        assert!(
            counters
                .last_error
                .as_deref()
                .is_some_and(|error| error.starts_with("query_transport_closed"))
        );
    }

    #[test]
    fn an_idle_ipv6_worker_waits_instead_of_spinning() {
        let shared = Arc::new(Shared::new());
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let ingress = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let origin = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let peer = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 45_002, 0, 0);
        let mut flows = BTreeMap::new();
        flows.insert(peer, direct_flow(&shared, peer, &origin));
        let started = Instant::now();
        wait(&listener, &ingress, &mut flows, &shared).unwrap();
        // Nothing is readable, so the wait lasts (about) one poll interval.
        assert!(started.elapsed() >= Duration::from_millis(2));
        assert!(flows.contains_key(&peer));
        assert_eq!(lock(&shared.counters).udp_failures, 0);
    }

    #[test]
    fn dropped_tcp_workers_shut_their_relays_down_and_join_them() {
        use std::io::Read;
        let shared = Arc::new(Shared::new());
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (relay, SocketAddr::V6(peer)) = listener.accept().unwrap() else {
            unreachable!("an IPv6 listener accepts IPv6 peers");
        };
        let mut workers = TcpWorkers {
            shared: Arc::clone(&shared),
            active: Arc::new(Mutex::new(BTreeMap::new())),
            handles: Vec::new(),
        };
        lock(&workers.active).insert(peer, relay.try_clone().unwrap());
        let active = Arc::clone(&workers.active);
        // Like `forward_tcp`: wait on the client in short steps until it is
        // shut down, then deregister. Left alone it would run for 30 seconds.
        workers.handles.push(thread::spawn(move || {
            let mut relay = relay;
            relay
                .set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut byte = [0];
            while Instant::now() < deadline {
                match relay.read(&mut byte) {
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    _ => break,
                }
            }
            lock(&active).remove(&peer);
        }));
        let active = Arc::clone(&workers.active);
        let started = Instant::now();
        drop(workers);
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(lock(&active).is_empty());
        assert!(lock(&shared.failure).is_none());
    }

    #[test]
    fn an_idle_ipv6_mapping_completes_and_is_counted() {
        let shared = Arc::new(Shared::new());
        let plan = plan();
        let ipv6 = plan.ipv6.clone().unwrap();
        let ingress = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let origin = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let peer = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 45_003, 0, 0);
        let mut flow = direct_flow(&shared, peer, &origin);
        flow.socket.set_nonblocking(true).unwrap();
        flow.touched = Instant::now() - UDP_IDLE_TIMEOUT - Duration::from_secs(1);
        let mut flows = BTreeMap::from([(peer, flow)]);
        collect_udp(&plan, &ipv6, &ingress, &shared, None, &mut flows);
        assert!(flows.is_empty());
        assert_eq!(lock(&shared.counters).udp_idle_expirations, 1);
        let (connections, _) = shared.flows.snapshot();
        assert_eq!(connections["recent"][0]["status"], "completed");
        assert_eq!(lock(&shared.counters).udp_failures, 0);
    }

    #[test]
    fn rejects_ipv6_plaintext_dns_even_when_the_address_is_allowlisted() {
        let address = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0);
        assert!(route_v6_decision(address, true).is_err());
        assert_eq!(
            route_v6_decision(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0), true),
            Ok(false)
        );
    }
}
