//! IPv6 ingress worker. It shares the authenticated metadata lane with the
//! IPv4 worker and keeps the transport-specific state local to this module.

use super::{
    Flow, Plan, Shared, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpSocket, lock,
};
use crate::plan::Ipv6Plan;
use crate::query_bridge::Lookup;
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_TCP: usize = 64;

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
    Chain(crate::policy::UdpChain),
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
    let mut tcp_workers = Vec::new();
    let active = Arc::new(Mutex::new(BTreeMap::<SocketAddrV6, TcpStream>::new()));
    let mut udp_flows = BTreeMap::new();
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("configure IPv6 listener: {e}"))?;
    ingress
        .set_nonblocking(true)
        .map_err(|e| format!("configure IPv6 UDP ingress: {e}"))?;
    while !shared.is_stopping() {
        reap_tcp(&mut tcp_workers)?;
        accept_tcp(
            &plan,
            &ipv6,
            &listener,
            &shared,
            runtime.clone(),
            &mut tcp_workers,
            &active,
        )?;
        receive_udp(
            &plan,
            &ipv6,
            &ingress,
            &shared,
            runtime.as_deref(),
            &mut udp_flows,
        )?;
        collect_udp(
            &plan,
            &ipv6,
            &ingress,
            &shared,
            runtime.as_deref(),
            &mut udp_flows,
        )?;
        if tcp_workers.is_empty() && udp_flows.is_empty() {
            thread::sleep(POLL_INTERVAL);
        }
    }
    for flow in udp_flows.into_values() {
        flow.stats.stopped();
    }
    for client in lock(&active).values() {
        let _ = client.shutdown(std::net::Shutdown::Both);
    }
    for worker in tcp_workers {
        let _ = worker.join();
    }
    Ok(())
}

fn reap_tcp(workers: &mut Vec<thread::JoinHandle<()>>) -> Result<(), String> {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            if workers.swap_remove(index).join().is_err() {
                return Err("IPv6 TCP forwarding worker panicked".into());
            }
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn accept_tcp(
    plan: &Arc<Plan>,
    ipv6: &Ipv6Plan,
    listener: &TcpListener,
    shared: &Arc<Shared>,
    runtime: Option<Arc<crate::managed::Runtime>>,
    workers: &mut Vec<thread::JoinHandle<()>>,
    active: &Arc<Mutex<BTreeMap<SocketAddrV6, TcpStream>>>,
) -> Result<(), String> {
    for _ in 0..super::ACCEPT_BATCH {
        let (client, peer) = match listener.accept() {
            Ok((client, SocketAddr::V6(peer))) if peer.ip() == &ipv6.guest => (client, peer),
            Ok((_, _)) => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if super::tcp::transient(&error) => continue,
            Err(error) => return Err(format!("IPv6 TCP ingress accept failed: {error}")),
        };
        if workers.len() >= MAX_TCP {
            continue;
        }
        let retained = client
            .try_clone()
            .map_err(|e| format!("retain IPv6 TCP shutdown handle: {e}"))?;
        lock(active).insert(peer, retained);
        let plan = Arc::clone(plan);
        let shared = Arc::clone(shared);
        let active = Arc::clone(active);
        let runtime = runtime.clone();
        workers.push(
            thread::Builder::new()
                .name("m1-tcp-ipv6".into())
                .spawn(move || {
                    let result = forward_tcp(plan, client, peer, shared.clone(), runtime);
                    lock(&active).remove(&peer);
                    if let Err(error) = result
                        && !shared.is_stopping()
                    {
                        shared.record_error("tcp", error);
                    }
                })
                .map_err(|e| format!("start IPv6 TCP forwarding worker: {e}"))?,
        );
    }
    Ok(())
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
    super::tcp::relay(client, upstream, &shared, &flow).map_err(|e| format!("IPv6 relay: {e}"))
}

fn receive_udp(
    plan: &Arc<Plan>,
    ipv6: &Ipv6Plan,
    ingress: &UdpSocket,
    shared: &Arc<Shared>,
    policy: Option<&crate::managed::Runtime>,
    flows: &mut BTreeMap<SocketAddrV6, UdpFlow>,
) -> Result<(), String> {
    let mut buffer = [0; 65_535];
    loop {
        let (size, peer) = match ingress.recv_from(&mut buffer) {
            Ok((size, SocketAddr::V6(peer))) if peer.ip() == &ipv6.guest => (size, peer),
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(format!("IPv6 UDP ingress receive failed: {error}")),
        };
        let origin = match destination_v6(plan, "udp", peer, shared) {
            Ok(origin) => origin,
            Err(error) => {
                shared.record_error("udp", error);
                continue;
            }
        };
        let Some(runtime) = policy else {
            shared.record_error("udp", "IPv6 UDP runtime missing".into());
            continue;
        };
        let chained = match route_v6(runtime, origin) {
            Ok(chained) => chained,
            Err(error) => {
                shared.record_error("udp", error);
                continue;
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
            if flows.len() >= super::MAX_UDP {
                shared.record_error("udp", "IPv6 UDP flow capacity reached".into());
                continue;
            }
            let socket = if chained {
                match runtime.policy.chain_udp(SocketAddr::V6(origin)) {
                    Ok(socket) => UdpTransport::Chain(socket),
                    Err(error) => {
                        shared.record_error("udp", format!("IPv6 UDP chain setup failed: {error}"));
                        continue;
                    }
                }
            } else {
                let socket =
                    UdpSocket::bind(SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0))
                        .map_err(|e| format!("bind IPv6 origin UDP socket: {e}"))?;
                socket
                    .connect(SocketAddr::V6(origin))
                    .map_err(|e| format!("connect IPv6 origin UDP socket: {e}"))?;
                UdpTransport::Direct(socket)
            };
            socket
                .set_nonblocking(true)
                .map_err(|e| format!("configure IPv6 origin UDP socket: {e}"))?;
            let stats = shared.flows.begin("udp");
            stats.selected(
                if chained { "chain" } else { "direct" },
                if chained {
                    "default_chain"
                } else {
                    "ip_or_cidr"
                },
            );
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
            match flow.socket.send(&buffer[..size]) {
                Ok(sent) if sent == size => {
                    flow.stats.tx(sent);
                    flow.touched = Instant::now();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => {
                    flow.stats.failed();
                    shared
                        .record_error("udp", format!("send IPv6 origin packet failed: {result:?}"));
                    flows.remove(&peer);
                }
            }
        }
    }
    Ok(())
}

fn collect_udp(
    plan: &Arc<Plan>,
    ipv6: &Ipv6Plan,
    ingress: &UdpSocket,
    shared: &Arc<Shared>,
    policy: Option<&crate::managed::Runtime>,
    flows: &mut BTreeMap<SocketAddrV6, UdpFlow>,
) -> Result<(), String> {
    let now = Instant::now();
    let mut buffer = [0; 65_535];
    let peers: Vec<_> = flows.keys().copied().collect();
    for peer in peers {
        let Some(flow) = flows.get_mut(&peer) else {
            continue;
        };
        let mut retire = false;
        match flow.socket.recv(&mut buffer) {
            Ok(size) => {
                let verified = destination_v6(
                    plan,
                    "udp",
                    SocketAddrV6::new(ipv6.guest, peer.port(), 0, peer.scope_id()),
                    shared,
                )?;
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
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => {
                flow.stats.failed();
                shared.record_error("udp", format!("IPv6 origin receive failed: {error}"));
                retire = true;
            }
        }
        if retire {
            flows.remove(&peer);
        }
    }
    flows.retain(|_, flow| {
        if now.duration_since(flow.touched) > super::TCP_IDLE_TIMEOUT {
            flow.stats.stopped();
            false
        } else {
            true
        }
    });
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
    use super::route_v6_decision;
    use std::net::{Ipv6Addr, SocketAddrV6};

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
