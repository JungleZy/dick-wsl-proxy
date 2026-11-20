// Ingress integration and flow behavior tests.
use super::*;
use super::tcp::relay;

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
    let worker = thread::spawn(move || relay(ingress, upstream, &relay_shared, &registration.flow));
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
    let mut replacement = UdpFlow::connect(address, address, shared.flows.begin("udp")).unwrap();
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
    let mut flow = UdpFlow::connect(plan.origins[0], target, shared.flows.begin("udp")).unwrap();
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
