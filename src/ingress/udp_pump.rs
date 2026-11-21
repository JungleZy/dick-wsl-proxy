use super::{
    BTreeMap, DestinationGroup, Ipv4Addr, Lookup, MAX_UDP, POLL_INTERVAL, Plan, Route, Shared,
    SocketAddrV4, TcpListener, UDP_BATCH, UdpFlow, UdpSocket, record_udp_retirement, route,
};
use std::{
    io,
    ops::Bound::{Excluded, Unbounded},
    time::Instant,
};

struct PendingReply {
    peer: SocketAddrV4,
    generation: u64,
    size: usize,
}

pub(super) struct UdpPump {
    // Ingress and reply groups never overlap: both reuse this fixed 1 MiB pool.
    pub(super) buffers: [Vec<u8>; UDP_BATCH],
    pending: Vec<PendingReply>,
    cursor: SocketAddrV4,
}

impl UdpPump {
    pub(super) fn new() -> Self {
        Self {
            buffers: std::array::from_fn(|_| vec![0; 65_535]),
            pending: Vec::with_capacity(UDP_BATCH),
            cursor: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub(super) fn keys(&self) -> impl Iterator<Item = Lookup> + '_ {
        self.pending.iter().map(|reply| Lookup {
            protocol: "udp",
            peer: reply.peer,
        })
    }

    pub(super) fn collect(
        &mut self,
        flows: &mut BTreeMap<SocketAddrV4, UdpFlow>,
        shared: &Shared,
    ) -> bool {
        debug_assert!(self.pending.is_empty());
        debug_assert!(flows.len() <= MAX_UDP);
        let mut progressed = false;
        let now = Instant::now();
        flows.retain(|_, flow| {
            if shared.is_stopping() {
                flow.stats.stopped();
            } else if let Some(reason) = flow.activity.expired(now) {
                record_udp_retirement(flow, reason, shared);
            } else {
                return true;
            }
            progressed = true;
            false
        });
        let start = self.cursor;
        let mut retired = [None; MAX_UDP];
        let mut retired_count = 0;
        // Stable endpoint order makes the cursor independent of table rehashes
        // and removals. One packet per flow per round bounds a noisy flow's share;
        // a full window resumes after its final inspected peer next turn.
        for (peer, flow) in flows
            .range((Excluded(start), Unbounded))
            .chain(flows.range(..=start))
        {
            if shared.is_stopping() {
                break;
            }
            self.cursor = *peer;
            let size = match flow.socket.recv(&mut self.buffers[self.pending.len()]) {
                Ok(size) => size,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::Interrupted =>
                {
                    continue;
                }
                Err(error) => {
                    flow.stats.failed();
                    shared.record_error("udp", format!("origin receive failed: {error}"));
                    retired[retired_count] = Some(*peer);
                    retired_count += 1;
                    progressed = true;
                    continue;
                }
            };
            progressed = true;
            flow.stats.stage("metadata");
            self.pending.push(PendingReply {
                peer: *peer,
                generation: flow.generation,
                size,
            });
            if self.pending.len() == UDP_BATCH {
                break;
            }
        }
        for peer in retired[..retired_count].iter().flatten() {
            flows.remove(peer);
        }
        progressed
    }

    pub(super) fn forward(
        &mut self,
        plan: &Plan,
        runtime: Option<&crate::managed::Runtime>,
        ingress: &UdpSocket,
        flows: &mut BTreeMap<SocketAddrV4, UdpFlow>,
        mut observations: DestinationGroup,
        shared: &Shared,
    ) {
        for (slot, pending) in self.pending.drain(..).enumerate() {
            // Consume exactly one fresh result even if this socket was retired.
            // Never retain a socket/flow borrow while the metadata lane runs.
            let original = observations.next(plan, shared);
            let Some(flow) = flows.get_mut(&pending.peer) else {
                continue;
            };
            if flow.generation != pending.generation {
                continue;
            }
            if shared.is_stopping() {
                flow.stats.stopped();
                continue;
            }
            let authorized = original.and_then(|original| {
                if original != flow.origin {
                    return Err("UDP mapping changed before reply".into());
                }
                flow.stats.stage("policy");
                match route(plan, runtime, "udp", original) {
                    Ok(Route::Direct(target)) if flow.target == Some(target) => Ok(()),
                    Ok(Route::Chain) if flow.target.is_none() => Ok(()),
                    _ => Err("UDP route expired before reply".into()),
                }
            });
            if let Err(error) = authorized {
                flow.stats.failed();
                shared.record_error("udp", error);
                flows.remove(&pending.peer);
                continue;
            }
            if shared.is_stopping() {
                flow.stats.stopped();
                continue;
            }
            flow.stats.stage("relay");
            match ingress.send_to(&self.buffers[slot][..pending.size], pending.peer) {
                Ok(sent) if sent == pending.size => {
                    flow.stats.rx(sent);
                    flow.activity.replied(Instant::now());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => {
                    flow.stats.failed();
                    shared.record_error("udp", format!("guest send failed: {result:?}"));
                    flows.remove(&pending.peer);
                }
            }
        }
    }
}

#[cfg(windows)]
pub(super) fn wait(
    listener: &TcpListener,
    ingress: &UdpSocket,
    flows: &mut BTreeMap<SocketAddrV4, UdpFlow>,
    shared: &Shared,
) -> Result<(), String> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        POLLERR, POLLHUP, POLLNVAL, POLLRDNORM, SOCKET_ERROR, WSAGetLastError, WSAPOLLFD, WSAPoll,
    };

    let mut descriptors = [WSAPOLLFD::default(); MAX_UDP + 2];
    let mut peers = [None; MAX_UDP];
    descriptors[0].fd = listener.as_raw_socket() as _;
    descriptors[1].fd = ingress.as_raw_socket() as _;
    for (index, (peer, flow)) in flows.iter().enumerate() {
        descriptors[index + 2].fd = flow.socket.as_raw_socket() as _;
        peers[index] = Some(*peer);
    }
    let count = flows.len() + 2;
    for descriptor in &mut descriptors[..count] {
        descriptor.events = POLLRDNORM;
    }
    // Every handle is owned by this ingress thread throughout the call. The
    // finite timeout also bounds stop latency without another wakeup socket.
    let result = unsafe {
        WSAPoll(
            descriptors.as_mut_ptr(),
            count as u32,
            POLL_INTERVAL.as_millis() as i32,
        )
    };
    if result == SOCKET_ERROR {
        let error = io::Error::from_raw_os_error(unsafe { WSAGetLastError() });
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(());
        }
        return Err(format!("ingress readiness wait failed: {error}"));
    }
    for (index, descriptor) in descriptors[..count].iter().enumerate() {
        if descriptor.revents & POLLNVAL != 0 {
            return Err("ingress readiness wait found an invalid socket".into());
        }
        if descriptor.revents & (POLLERR | POLLHUP) == 0 {
            continue;
        }
        if index < 2 {
            return Err("ingress readiness wait found a failed listener".into());
        }
        // Connected UDP can report an origin ICMP error here. Retire just that
        // flow so a persistent error cannot turn the idle poll into a busy loop.
        let peer = peers[index - 2].expect("polled UDP flow has a peer");
        if let Some(flow) = flows.remove(&peer) {
            flow.stats.failed();
            shared.record_error("udp", "origin socket readiness failed".into());
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub(super) fn wait(
    _listener: &TcpListener,
    _ingress: &UdpSocket,
    _flows: &mut BTreeMap<SocketAddrV4, UdpFlow>,
    _shared: &Shared,
) -> Result<(), String> {
    std::thread::sleep(POLL_INTERVAL);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{Observation, lock};
    use super::*;
    use std::{net::SocketAddr, time::Duration};

    fn socket() -> UdpSocket {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
    }

    fn address(socket: &UdpSocket) -> SocketAddrV4 {
        let SocketAddr::V4(address) = socket.local_addr().unwrap() else {
            unreachable!()
        };
        address
    }

    fn plan(origins: Vec<SocketAddrV4>) -> Plan {
        Plan {
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
            origins,
            system_dns: None,
            cookie: 1,
            ipv6: None,
        }
    }

    fn group(origins: Vec<Result<SocketAddrV4, String>>) -> DestinationGroup {
        let started = Instant::now();
        let count = origins.len();
        let observations = origins
            .into_iter()
            .enumerate()
            .map(|(index, origin)| Observation {
                origin,
                started,
                elapsed: Duration::ZERO,
                batch: if index == 0 { count } else { 0 },
                guest_us: None,
            })
            .collect::<Vec<_>>()
            .into_iter();
        DestinationGroup {
            started,
            observations: Ok(observations),
        }
    }

    fn flow(shared: &Shared, original: SocketAddrV4, target: SocketAddrV4) -> UdpFlow {
        let stats = shared.flows.begin("udp");
        stats.destination(original);
        stats.selected("direct", "enumerated_origin");
        UdpFlow::connect(original, target, stats).unwrap()
    }

    fn queue_reply(flow: &mut UdpFlow, origin: &UdpSocket, payload: &[u8]) {
        assert_eq!(flow.socket.send(payload).unwrap(), payload.len());
        flow.activity.sent(Instant::now());
        let mut request = [0; 64];
        let (size, peer) = origin.recv_from(&mut request).unwrap();
        assert_eq!(&request[..size], payload);
        assert_eq!(origin.send_to(payload, peer).unwrap(), payload.len());
        // Peeking does not consume or reorder the datagram. It also ensures
        // the test's collection window begins with a genuinely ready socket.
        flow.socket.set_nonblocking(false).unwrap();
        flow.socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        assert_eq!(flow.socket.peek(&mut request).unwrap(), payload.len());
        flow.socket.set_nonblocking(true).unwrap();
    }

    fn assert_no_reply(guest: &UdpSocket) {
        guest.set_nonblocking(true).unwrap();
        assert_eq!(
            guest.recv(&mut [0; 64]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        guest.set_nonblocking(false).unwrap();
    }

    #[test]
    fn saturated_table_visits_every_flow_before_repeating_and_keeps_socket_order() {
        let shared = Shared::new();
        let origin = socket();
        let target = address(&origin);
        let mut flows = BTreeMap::new();
        for index in 0..MAX_UDP {
            let peer = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 20_000 + index as u16);
            let mut flow = flow(&shared, target, target);
            queue_reply(&mut flow, &origin, &[index as u8, 0]);
            queue_reply(&mut flow, &origin, &[index as u8, 1]);
            flows.insert(peer, flow);
        }
        let mut pump = UdpPump::new();
        let mut seen = [0; MAX_UDP];
        for packet in 0..2 {
            for _ in 0..MAX_UDP / UDP_BATCH {
                assert!(pump.collect(&mut flows, &shared));
                assert_eq!(pump.pending.len(), UDP_BATCH);
                for (slot, pending) in pump.pending.iter().enumerate() {
                    let index = usize::from(pending.peer.port() - 20_000);
                    assert_eq!(seen[index], packet);
                    assert_eq!(&pump.buffers[slot][..pending.size], &[index as u8, packet]);
                    seen[index] += 1;
                }
                // Inspect collection without sending to synthetic guest peers.
                pump.pending.clear();
            }
            assert!(seen.iter().all(|&count| count == packet + 1));
        }
        assert!(!pump.collect(&mut flows, &shared));
        assert!(pump.is_empty());
        assert_eq!(flows.len(), MAX_UDP);
    }

    #[test]
    fn failed_and_remapped_group_members_do_not_poison_a_valid_reply() {
        let shared = Shared::new();
        let origin = socket();
        let other_origin = socket();
        let target = address(&origin);
        let changed = address(&other_origin);
        let plan = plan(vec![target, changed]);
        let ingress = socket();
        let guests = [socket(), socket(), socket()];
        let mut flows = BTreeMap::new();
        for guest in &guests {
            let mut flow = flow(&shared, target, target);
            queue_reply(&mut flow, &origin, b"reply");
            flows.insert(address(guest), flow);
        }
        let mut pump = UdpPump::new();
        assert!(pump.collect(&mut flows, &shared));
        let peers = pump
            .pending
            .iter()
            .map(|pending| pending.peer)
            .collect::<Vec<_>>();
        let observations = group(vec![
            Err("query_lookup_missing".into()),
            Ok(changed),
            Ok(target),
        ]);
        pump.forward(&plan, None, &ingress, &mut flows, observations, &shared);
        for guest in &guests {
            if address(guest) == peers[2] {
                let mut reply = [0; 64];
                assert_eq!(guest.recv(&mut reply).unwrap(), 5);
                assert_eq!(&reply[..5], b"reply");
            } else {
                assert_no_reply(guest);
            }
        }
        assert_eq!(flows.len(), 1);
        assert!(!flows[&peers[2]].activity.has_response_debt());
        let counters = lock(&shared.counters);
        assert_eq!(counters.metadata_queries, 3);
        assert_eq!(counters.metadata_successes, 2);
        assert_eq!(counters.metadata_udp_failures, 1);
        assert_eq!(counters.udp_failures, 2);
    }

    #[test]
    fn collected_reply_cannot_attach_to_a_replacement_with_identical_endpoints() {
        let shared = Shared::new();
        let origin = socket();
        let target = address(&origin);
        let plan = plan(vec![target]);
        let ingress = socket();
        let guest = socket();
        let peer = address(&guest);
        let mut old = flow(&shared, target, target);
        queue_reply(&mut old, &origin, b"old");
        let mut flows = BTreeMap::from([(peer, old)]);
        let mut pump = UdpPump::new();
        assert!(pump.collect(&mut flows, &shared));
        let old_generation = pump.pending[0].generation;
        flows.remove(&peer);
        let replacement = flow(&shared, target, target);
        assert_ne!(replacement.generation, old_generation);
        flows.insert(peer, replacement);
        pump.forward(
            &plan,
            None,
            &ingress,
            &mut flows,
            group(vec![Ok(target)]),
            &shared,
        );
        assert_no_reply(&guest);
        assert_eq!(flows.len(), 1);
        assert_eq!(lock(&shared.counters).udp_failures, 0);
        queue_reply(flows.get_mut(&peer).unwrap(), &origin, b"new");
        assert!(pump.collect(&mut flows, &shared));
        pump.forward(
            &plan,
            None,
            &ingress,
            &mut flows,
            group(vec![Ok(target)]),
            &shared,
        );
        let mut reply = [0; 64];
        assert_eq!(guest.recv(&mut reply).unwrap(), 3);
        assert_eq!(&reply[..3], b"new");
        assert_no_reply(&guest);
    }

    #[test]
    fn collected_reply_is_dropped_after_eviction_or_stop_without_clearing_debt() {
        for stopped in [false, true] {
            let shared = Shared::new();
            let origin = socket();
            let target = address(&origin);
            let plan = plan(vec![target]);
            let ingress = socket();
            let guest = socket();
            let peer = address(&guest);
            let mut flow = flow(&shared, target, target);
            queue_reply(&mut flow, &origin, b"late");
            let mut flows = BTreeMap::from([(peer, flow)]);
            let mut pump = UdpPump::new();
            assert!(pump.collect(&mut flows, &shared));
            if stopped {
                shared.request_stop()
            } else {
                flows.remove(&peer);
            }
            pump.forward(
                &plan,
                None,
                &ingress,
                &mut flows,
                group(vec![Ok(target)]),
                &shared,
            );
            assert_no_reply(&guest);
            assert!(pump.is_empty());
            if stopped {
                assert!(flows[&peer].activity.has_response_debt());
                assert!(pump.collect(&mut flows, &shared));
            }
            assert!(flows.is_empty());
            assert_eq!(lock(&shared.counters).udp_failures, 0);
        }
    }

    #[test]
    fn route_mismatch_and_transport_failure_never_send_or_clear_response_debt() {
        for transport_failed in [false, true] {
            let shared = Shared::new();
            let original = socket();
            let target_socket = socket();
            let original_address = address(&original);
            let target = address(&target_socket);
            let plan = plan(vec![original_address, target]);
            let ingress = socket();
            let guest = socket();
            let peer = address(&guest);
            let mut flow = flow(&shared, original_address, target);
            queue_reply(&mut flow, &target_socket, b"unauthorized");
            let mut flows = BTreeMap::from([(peer, flow)]);
            let mut pump = UdpPump::new();
            assert!(pump.collect(&mut flows, &shared));
            let observations = if transport_failed {
                DestinationGroup {
                    started: Instant::now(),
                    observations: Err("query_transport_closed".into()),
                }
            } else {
                group(vec![Ok(original_address)])
            };
            pump.forward(&plan, None, &ingress, &mut flows, observations, &shared);
            assert_no_reply(&guest);
            assert!(flows.is_empty());
            let counters = lock(&shared.counters);
            assert_eq!(counters.metadata_queries, 1);
            assert_eq!(counters.udp_failures, 1);
            assert_eq!(
                counters.metadata_transport_failures,
                u64::from(transport_failed)
            );
        }
    }
    #[test]
    fn reply_windows_keep_empty_datagrams_and_reuse_the_live_socket() {
        let shared = Shared::new();
        let origin = socket();
        let target = address(&origin);
        let plan = plan(vec![target]);
        let ingress = socket();
        let guest = socket();
        let peer = address(&guest);
        let mut flows = BTreeMap::from([(peer, flow(&shared, target, target))]);
        let generation = flows[&peer].generation;
        let mut pump = UdpPump::new();
        for payload in [b"first".as_slice(), b"".as_slice(), b"third".as_slice()] {
            queue_reply(flows.get_mut(&peer).unwrap(), &origin, payload);
            assert!(pump.collect(&mut flows, &shared));
            pump.forward(
                &plan,
                None,
                &ingress,
                &mut flows,
                group(vec![Ok(target)]),
                &shared,
            );
            let mut reply = [0; 64];
            let size = guest.recv(&mut reply).unwrap();
            assert_eq!(&reply[..size], payload);
            assert_eq!(flows[&peer].generation, generation);
            assert!(!flows[&peer].activity.has_response_debt());
            assert_no_reply(&guest);
        }
    }
}
