// Managed DNS wire, alias, ledger, and transport tests.
use super::ledger::read_alias_highwater;
use super::wire::{a_address, put_name, word};
use super::*;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::thread;

fn query(host: &str) -> Vec<u8> {
    let mut wire = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    put_name(&mut wire, host);
    wire.extend_from_slice(&[0, 1, 0, 1]);
    wire
}

fn response(query_wire: &[u8], ip: Ipv4Addr) -> Vec<u8> {
    let mut wire = query_wire.to_vec();
    wire[2..4].copy_from_slice(&0x81a0u16.to_be_bytes());
    wire[6..8].copy_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    wire.extend_from_slice(&ip.octets());
    wire
}

fn resolve(
    query_wire: &[u8],
    upstream: Result<Vec<u8>, String>,
    direct: bool,
    aliases: &Mutex<Aliases>,
) -> Result<Vec<u8>, String> {
    let query = Message::query(query_wire)?;
    let upstream = upstream?;
    let answer = Message::response(&upstream, &query)?;
    finish_answer(&query, &upstream, &answer, direct, aliases, MAX_DNS)
}

#[test]
fn shared_true_ip_does_not_grant_other_names() {
    let aliases = Mutex::new(Aliases::default());
    let true_ip = Ipv4Addr::new(93, 184, 216, 34);
    let white = query("allowed.example");
    let other = query("other.example");
    let rewritten = resolve(&white, Ok(response(&white, true_ip)), true, &aliases).unwrap();
    let parsed = Message::parse(&rewritten).unwrap();
    let alias = a_address(&rewritten, &parsed.answers[0]).unwrap();
    assert!(reserved(alias));
    assert_eq!(parsed.flags & 0x20, 0);
    let ordinary = resolve(&other, Ok(response(&other, true_ip)), false, &aliases).unwrap();
    let parsed = Message::parse(&ordinary).unwrap();
    assert_eq!(a_address(&ordinary, &parsed.answers[0]).unwrap(), true_ip);
    let table = aliases.lock().unwrap();
    assert_eq!(table.lookup(true_ip, Instant::now()).unwrap(), None);
    assert_eq!(table.lookup(alias, Instant::now()).unwrap(), Some(true_ip));
    assert!(table.live.contains_key("allowed.example"));
}

#[test]
fn compressed_cname_is_flattened_without_lending_alias_to_shared_owner() {
    let wire = query("allowed.example");
    let mut upstream = wire.clone();
    upstream[2..4].copy_from_slice(&0x81a0u16.to_be_bytes());
    upstream[6..8].copy_from_slice(&2u16.to_be_bytes());
    upstream.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 20]);
    let mut canonical = Vec::new();
    put_name(&mut canonical, "shared.cdn.example");
    upstream.extend_from_slice(&(canonical.len() as u16).to_be_bytes());
    let canonical_at = upstream.len() as u16;
    upstream.extend_from_slice(&canonical);
    upstream.extend_from_slice(&(0xc000 | canonical_at).to_be_bytes());
    upstream.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 1, 1, 1]);
    let aliases = Mutex::new(Aliases::default());
    let result = resolve(&wire, Ok(upstream), true, &aliases).unwrap();
    let parsed = Message::parse(&result).unwrap();
    assert_eq!(parsed.answers.len(), 1);
    assert_eq!(parsed.answers[0].name, "allowed.example");
    assert_eq!(parsed.answers[0].kind, 1);
    assert_eq!(parsed.answers[0].ttl, 0);
    assert!(reserved(a_address(&result, &parsed.answers[0]).unwrap()));
    assert!(
        !aliases
            .lock()
            .unwrap()
            .live
            .contains_key("shared.cdn.example")
    );
}

#[test]
fn additional_records_cannot_create_or_borrow_alias_grants() {
    let aliases = Mutex::new(Aliases::default());
    let wire = query("allowed.example");
    let mut upstream = response(&wire, Ipv4Addr::new(1, 1, 1, 1));
    upstream[11] = 1;
    put_name(&mut upstream, "unrelated.example");
    upstream.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 8, 8, 8, 8]);
    let result = resolve(&wire, Ok(upstream.clone()), true, &aliases).unwrap();
    assert_eq!(word(&result, 10).unwrap(), 0);
    assert_eq!(aliases.lock().unwrap().entries.len(), 1);
    let length = upstream.len();
    upstream[length - 4..].copy_from_slice(&[198, 18, 0, 1]);
    assert!(resolve(&wire, Ok(upstream), false, &aliases).is_err());
}

#[test]
fn alias_capacity_is_atomic_and_aaaa_never_gets_an_alias() {
    let mut table = Aliases::default();
    let now = Instant::now();
    for offset in 0..MAX_ALIASES {
        table.entries.insert(
            Ipv4Addr::from(ALIAS_START + offset as u32),
            Alias {
                real: Ipv4Addr::new(1, 1, 1, 1),
                expires: now + Duration::from_secs(60),
            },
        );
    }
    assert!(
        table
            .assign("full.example", &[Ipv4Addr::new(8, 8, 8, 8)], 60, now)
            .is_err()
    );
    assert!(table.live.is_empty());
    let mut wire = query("ipv6.example");
    let length = wire.len();
    wire[length - 4..length - 2].copy_from_slice(&28u16.to_be_bytes());
    assert_eq!(Message::query(&wire).unwrap().question.kind, 28);
}

#[test]
fn ordinary_in_questions_and_dnssec_pass_through_without_aliases() {
    let aliases = Mutex::new(Aliases::default());
    for kind in [2u16, 15, 16, 28, 33, 65] {
        let mut wire = query("_service.example");
        let length = wire.len();
        wire[length - 4..length - 2].copy_from_slice(&kind.to_be_bytes());
        let mut upstream = wire.clone();
        upstream[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        assert_eq!(
            resolve(&wire, Ok(upstream.clone()), false, &aliases).unwrap(),
            upstream
        );
    }
    let mut wire = query("allowed.example");
    wire[11] = 1;
    wire.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0x80, 0, 0, 0]);
    assert!(Message::query(&wire).unwrap().dnssec);
    assert!(aliases.lock().unwrap().entries.is_empty());
    let table = aliases.lock().unwrap();
    assert!(!table.ledger.path.as_ref().unwrap().exists());
    assert!(
        !table
            .ledger
            .path
            .as_ref()
            .unwrap()
            .parent()
            .unwrap()
            .exists()
    );
}

#[test]
fn udp_truncation_can_retry_full_answer_over_tcp_without_grant_leaks() {
    let aliases = Mutex::new(Aliases::default());
    let wire = query("many.example");
    let query = Message::query(&wire).unwrap();
    let mut upstream = wire.clone();
    upstream[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    upstream[6..8].copy_from_slice(&32u16.to_be_bytes());
    for last in 1..=32u8 {
        upstream.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 1, 1, last]);
    }
    let response = Message::response(&upstream, &query).unwrap();
    let udp = finish_answer(&query, &upstream, &response, true, &aliases, query.udp_size).unwrap();
    assert_ne!(word(&udp, 2).unwrap() & 0x0200, 0);
    assert!(aliases.lock().unwrap().entries.is_empty());
    let tcp = finish_answer(&query, &upstream, &response, true, &aliases, MAX_DNS).unwrap();
    assert_eq!(word(&tcp, 2).unwrap() & 0x0200, 0);
    assert_eq!(word(&tcp, 6).unwrap(), 32);
    assert_eq!(aliases.lock().unwrap().entries.len(), 32);
}

#[test]
fn https_ipv4_hints_cannot_borrow_a_reserved_alias() {
    let mut wire = query("other.example");
    let length = wire.len();
    wire[length - 4..length - 2].copy_from_slice(&65u16.to_be_bytes());
    let mut upstream = wire.clone();
    upstream[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    upstream[7] = 1;
    upstream.extend_from_slice(&[0xc0, 12, 0, 65, 0, 1, 0, 0, 0, 60, 0, 11]);
    upstream.extend_from_slice(&[0, 1, 0, 0, 4, 0, 4, 198, 18, 0, 1]);
    let parsed = Message::query(&wire).unwrap();
    assert!(Message::response(&upstream, &parsed).is_err());
}

#[test]
fn mapped_aaaa_cannot_borrow_a_reserved_alias() {
    let mut wire = query("other.example");
    let length = wire.len();
    wire[length - 4..length - 2].copy_from_slice(&28u16.to_be_bytes());
    let mut upstream = wire.clone();
    upstream[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    upstream[7] = 1;
    upstream.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
    upstream.extend_from_slice(&Ipv4Addr::new(198, 18, 0, 1).to_ipv6_mapped().octets());
    let parsed = Message::query(&wire).unwrap();
    assert!(Message::response(&upstream, &parsed).is_err());
}

#[test]
fn https_ipv6_hints_cannot_borrow_a_reserved_alias() {
    let mut wire = query("other.example");
    let length = wire.len();
    wire[length - 4..length - 2].copy_from_slice(&65u16.to_be_bytes());
    let mut upstream = wire.clone();
    upstream[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    upstream[7] = 1;
    upstream.extend_from_slice(&[0xc0, 12, 0, 65, 0, 1, 0, 0, 0, 60, 0, 23]);
    upstream.extend_from_slice(&[0, 1, 0, 0, 6, 0, 16]);
    upstream.extend_from_slice(&Ipv4Addr::new(198, 18, 0, 1).to_ipv6_mapped().octets());
    let parsed = Message::query(&wire).unwrap();
    assert!(Message::response(&upstream, &parsed).is_err());
}

#[test]
fn aliases_never_cross_names_and_reclaim_same_pair_after_expiry() {
    let mut table = Aliases::default();
    let now = Instant::now();
    let ip = Ipv4Addr::new(1, 1, 1, 1);
    let first = table.assign("first.example", &[ip], 1, now).unwrap()[0];
    let second = table.assign("second.example", &[ip], 60, now).unwrap()[0];
    assert_ne!(first, second);
    assert!(table.lookup(first, now + Duration::from_secs(2)).is_err());
    let renewed = table
        .assign("first.example", &[ip], 60, now + Duration::from_secs(2))
        .unwrap()[0];
    assert_eq!(first, renewed);
    assert_eq!(
        table.lookup(first, now + Duration::from_secs(2)).unwrap(),
        Some(ip)
    );
    assert!(table.lookup(Ipv4Addr::new(198, 19, 255, 254), now).is_err());
}

#[test]
fn upstream_errors_and_reserved_injections_fail_closed() {
    let aliases = Mutex::new(Aliases::default());
    let wire = query("other.example");
    assert!(resolve(&wire, Err("upstream unavailable".into()), false, &aliases).is_err());
    assert!(
        resolve(
            &wire,
            Ok(response(&wire, Ipv4Addr::new(198, 18, 0, 1))),
            false,
            &aliases
        )
        .is_err()
    );
    assert!(aliases.lock().unwrap().entries.is_empty());
}

#[test]
fn malformed_question_response_edns_and_compression_are_rejected() {
    let wire = query("allowed.example");
    let parsed = Message::query(&wire).unwrap();
    let mut answer = response(&wire, Ipv4Addr::new(1, 1, 1, 1));
    answer[1] ^= 1;
    assert!(Message::response(&answer, &parsed).is_err());
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(Message::query(&trailing).is_err());
    let mut edns = wire.clone();
    edns[11] = 1;
    edns.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 8]);
    assert!(Message::query(&edns).is_err());
    let mut loop_wire = wire;
    loop_wire[12..14].copy_from_slice(&[0xc0, 12]);
    assert!(Message::query(&loop_wire).is_err());
}

#[test]
fn https_requires_dns_content_type_and_unambiguous_bounded_framing() {
    let body = query("test.example");
    let mut http = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    http.extend_from_slice(&body);
    assert_eq!(read_http(&mut io::Cursor::new(http)).unwrap().body, body);
    assert!(read_http(&mut io::Cursor::new(b"HTTP/1.1 503 Error\r\n\r\n")).is_err());
    assert!(
        read_http(&mut io::Cursor::new(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 12\r\n\r\n012345678901"
        ))
        .is_err()
    );
    assert!(read_http(&mut io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 999999\r\n\r\n")).is_err());
}

#[test]
fn chunked_https_bodies_join_and_stop_at_their_own_end() {
    let body = query("test.example");
    let (head, tail) = body.split_at(5);
    let response = |headers: &str, chunks: &[u8]| {
        let mut http =
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n{headers}\r\n")
                .into_bytes();
        http.extend_from_slice(chunks);
        http
    };
    let chunks = |end: &[u8]| {
        let mut bytes = format!("{:x}\r\n", head.len()).into_bytes();
        bytes.extend_from_slice(head);
        bytes.extend_from_slice(format!("\r\n{:X}\r\n", tail.len()).as_bytes());
        bytes.extend_from_slice(tail);
        bytes.extend_from_slice(end);
        bytes
    };

    // Two chunks make one body; the next response on a kept-alive connection
    // is left unread.
    let mut next = chunks(b"\r\n0\r\n\r\n");
    next.extend_from_slice(b"HTTP/1.1 200 OK");
    let mut reader = io::Cursor::new(response("Transfer-Encoding: chunked\r\n", &next));
    let reply = read_http(&mut reader).unwrap();
    assert_eq!(reply.body, body);
    assert!(reply.keep_alive);
    let mut rest = String::new();
    reader.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "HTTP/1.1 200 OK");

    let complete = chunks(b"\r\n0\r\n\r\n");
    for (headers, chunks) in [
        // Two framings for one body.
        (
            "Transfer-Encoding: chunked\r\nContent-Length: 12\r\n",
            complete.clone(),
        ),
        ("Transfer-Encoding: gzip, chunked\r\n", complete.clone()),
        (
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            complete.clone(),
        ),
        // No framing at all.
        ("", complete.clone()),
        // A trailer could restate the content type or length.
        (
            "Transfer-Encoding: chunked\r\n",
            chunks(b"\r\n0\r\nContent-Type: text/html\r\n\r\n"),
        ),
        // The chunk data must end with CRLF.
        ("Transfer-Encoding: chunked\r\n", chunks(b"XX0\r\n\r\n")),
        // Chunk sizes are bare hex: no extensions, no sign, at most 8 digits.
        (
            "Transfer-Encoding: chunked\r\n",
            b"5;ext=1\r\nhello\r\n0\r\n\r\n".to_vec(),
        ),
        ("Transfer-Encoding: chunked\r\n", b"\r\n".to_vec()),
        (
            "Transfer-Encoding: chunked\r\n",
            b"000000001\r\nx\r\n0\r\n\r\n".to_vec(),
        ),
        // Larger than one DNS message.
        ("Transfer-Encoding: chunked\r\n", b"10000\r\n".to_vec()),
        // A complete but too short body.
        (
            "Transfer-Encoding: chunked\r\n",
            b"3\r\nabc\r\n0\r\n\r\n".to_vec(),
        ),
        // Cut off before the last chunk.
        ("Transfer-Encoding: chunked\r\n", chunks(b"\r\n")),
    ] {
        assert!(
            read_http(&mut io::Cursor::new(response(headers, &chunks))).is_err(),
            "{headers:?} {:?}",
            String::from_utf8_lossy(&chunks)
        );
    }
}

#[test]
fn only_an_http11_response_without_close_keeps_the_connection() {
    let body = query("test.example");
    let reply = |status: &str, extra: &str| {
        let mut http = format!(
            "{status}\r\nContent-Type: application/dns-message\r\n{extra}Content-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        http.extend_from_slice(&body);
        read_http(&mut io::Cursor::new(http)).unwrap().keep_alive
    };
    assert!(reply("HTTP/1.1 200 OK", ""));
    assert!(reply("HTTP/1.1 200 OK", "Connection: keep-alive\r\n"));
    assert!(!reply("HTTP/1.1 200 OK", "Connection: close\r\n"));
    assert!(!reply(
        "HTTP/1.1 200 OK",
        "Connection: Keep-Alive, Close\r\n"
    ));
    assert!(!reply("HTTP/1.0 200 OK", ""));
}

#[test]
fn one_connection_carries_consecutive_queries_with_exact_framing() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let first = query("one.example");
    let second = query("two.example");
    let answers = [first.clone(), second.clone()];
    let server = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reader = io::BufReader::new(socket);
        for answer in answers {
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.strip_prefix("Content-Length: ") {
                    length = value.trim().parse().unwrap();
                }
                assert!(!line.to_ascii_lowercase().starts_with("connection: close"));
            }
            let mut request = vec![0; length];
            reader.read_exact(&mut request).unwrap();
            let mut reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                answer.len()
            )
            .into_bytes();
            reply.extend_from_slice(&answer);
            reader.get_mut().write_all(&reply).unwrap();
        }
    });
    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut reader = io::BufReader::new(socket);
    for expected in [first, second] {
        let response = super::http::post_query(&mut reader, "dns.example", &expected).unwrap();
        assert_eq!(response.body, expected);
        assert!(response.keep_alive);
        assert!(reader.buffer().is_empty());
    }
    server.join().unwrap();
}

#[test]
fn idle_upstreams_expire_and_stay_bounded() {
    let pool = IdlePool::new();
    let start = Instant::now();
    assert_eq!(pool.take(start), None);
    for index in 0..MAX_IDLE_UPSTREAMS + 2 {
        pool.put(index, start);
    }
    // The newest kept connection comes back first; extras beyond the cap were dropped.
    assert_eq!(
        pool.take(start),
        Some((MAX_IDLE_UPSTREAMS - 1, Duration::ZERO))
    );
    // It reports how long it was idle.
    assert_eq!(
        pool.take(start + Duration::from_secs(3)),
        Some((MAX_IDLE_UPSTREAMS - 2, Duration::from_secs(3)))
    );
    pool.put(99, start);
    assert_eq!(pool.take(start + UPSTREAM_IDLE), None);
}

#[test]
fn actual_tls_boundary_rejects_a_plaintext_dns_https_impostor() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut hello = [0; 4096];
        let received = socket.read(&mut hello).unwrap();
        assert!(
            received > 0 && hello[0] == 22,
            "client must send a TLS handshake, not HTTP/DNS plaintext"
        );
        let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n012345678901");
    });
    let connector = TlsConnector::builder().build().unwrap();
    let socket = TcpStream::connect(address).unwrap();
    let stream = DeadlineStream {
        socket,
        deadline: Instant::now() + Duration::from_secs(2),
    };
    assert!(connector.connect("dns.google", stream).is_err());
    server.join().unwrap();
}

fn write_highwater(path: &Path, high: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut bytes = *b"WDA1\0\0\0\0";
    bytes[4..].copy_from_slice(&high.to_be_bytes());
    fs::write(path, bytes).unwrap();
}

#[test]
fn durable_aliases_do_not_reuse_old_session_or_crash_reserved_numbers() {
    let owner = AliasLedger::default();
    let path = owner.path.as_ref().unwrap().clone();
    let now = Instant::now();
    let mut first = Aliases {
        ledger: AliasLedger::at(path.clone()),
        ..Aliases::default()
    };
    let old = first
        .assign("first.example", &[Ipv4Addr::new(1, 1, 1, 1)], 60, now)
        .unwrap()[0];
    assert_eq!(read_alias_highwater(&path).unwrap(), ALIAS_BLOCK);
    assert_eq!(
        first
            .assign("first.example", &[Ipv4Addr::new(1, 1, 1, 1)], 60, now)
            .unwrap()[0],
        old
    );
    assert_eq!(read_alias_highwater(&path).unwrap(), ALIAS_BLOCK);
    assert_eq!(
        first.lookup(old, now).unwrap(),
        Some(Ipv4Addr::new(1, 1, 1, 1))
    );
    drop(first);
    let mut second = Aliases {
        ledger: AliasLedger::at(path.clone()),
        ..Aliases::default()
    };
    let new = second
        .assign("second.example", &[Ipv4Addr::new(8, 8, 8, 8)], 60, now)
        .unwrap()[0];
    assert_eq!(u32::from(new), u32::from(old) + ALIAS_BLOCK);
    assert!(second.lookup(old, now).is_err());
    assert_eq!(
        second.lookup(new, now).unwrap(),
        Some(Ipv4Addr::new(8, 8, 8, 8))
    );
    assert_eq!(read_alias_highwater(&path).unwrap(), 2 * ALIAS_BLOCK);
}

#[test]
fn durable_aliases_reuse_the_same_name_and_ip_after_a_new_session() {
    let owner = AliasLedger::default();
    let path = owner.path.as_ref().unwrap().clone();
    let now = Instant::now();
    let ip = Ipv4Addr::new(1, 1, 1, 1);
    let mut first = Aliases {
        ledger: AliasLedger::at(path.clone()),
        ..Aliases::default()
    };
    let old = first.assign("same.example", &[ip], 1, now).unwrap()[0];
    assert_eq!(read_alias_highwater(&path).unwrap(), ALIAS_BLOCK);
    drop(first);

    let mut second = Aliases {
        ledger: AliasLedger::at(path.clone()),
        ..Aliases::default()
    };
    let reused = second
        .assign("same.example", &[ip], 60, now + Duration::from_secs(2))
        .unwrap()[0];
    assert_eq!(reused, old);
    assert_eq!(read_alias_highwater(&path).unwrap(), ALIAS_BLOCK);
}

#[test]
fn durable_alias_exhaustion_is_atomic_and_never_resets() {
    let owner = AliasLedger::default();
    let path = owner.path.as_ref().unwrap().clone();
    write_highwater(&path, ALIAS_SPACE - 1);
    let mut ledger = AliasLedger::at(path.clone());
    assert!(ledger.allocate(2).is_err());
    assert_eq!(read_alias_highwater(&path).unwrap(), ALIAS_SPACE - 1);
    assert_eq!(
        ledger.allocate(1).unwrap(),
        vec![Ipv4Addr::new(198, 19, 255, 254)]
    );
    assert_eq!(read_alias_highwater(&path).unwrap(), ALIAS_SPACE);
    assert!(AliasLedger::at(path.clone()).allocate(1).is_err());
    assert_eq!(read_alias_highwater(&path).unwrap(), ALIAS_SPACE);
}

#[test]
fn explicit_idle_reset_removes_the_ledger_including_an_uncertain_commit() {
    let owner = AliasLedger::default();
    let path = owner.path.as_ref().unwrap().clone();
    write_highwater(&path, ALIAS_BLOCK);
    fs::write(path.with_extension("map"), b"WDM1").unwrap();
    AliasLedger::reset_at(&path).unwrap();
    assert!(!path.exists());
    assert!(!path.with_extension("map").exists());

    // An uncertain commit still blocks allocation; the confirmed reset clears it.
    write_highwater(&path, ALIAS_BLOCK);
    fs::write(path.with_extension("pending"), b"uncertain").unwrap();
    assert!(AliasLedger::at(path.clone()).allocate(1).is_err());
    AliasLedger::reset_at(&path).unwrap();
    assert!(!path.exists());
    assert!(!path.with_extension("pending").exists());
    assert!(AliasLedger::at(path.clone()).allocate(1).is_ok());

    // A pending commit that is not a regular file is never deleted.
    write_highwater(&path, ALIAS_BLOCK);
    fs::create_dir(path.with_extension("pending")).unwrap();
    assert!(AliasLedger::reset_at(&path).is_err());
    assert!(path.with_extension("pending").is_dir());
    assert!(
        path.exists(),
        "nothing is deleted when one entry is foreign"
    );
    fs::remove_dir(path.with_extension("pending")).unwrap();
}

#[test]
fn corrupt_or_uncertain_ledger_and_file_errors_fail_closed() {
    let owner = AliasLedger::default();
    let path = owner.path.as_ref().unwrap().clone();
    write_highwater(&path, 32);
    fs::write(&path, b"corrupt").unwrap();
    assert!(AliasLedger::at(path.clone()).allocate(1).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"corrupt");
    write_highwater(&path, 32);
    fs::write(path.with_extension("pending"), b"uncertain").unwrap();
    assert!(AliasLedger::at(path.clone()).allocate(1).is_err());
    assert_eq!(read_alias_highwater(&path).unwrap(), 32);
    let invalid_parent = path.parent().unwrap().join("not-a-directory");
    fs::write(&invalid_parent, b"file").unwrap();
    let mut table = Aliases {
        ledger: AliasLedger::at(invalid_parent.join("dns-alias.highwater")),
        ..Aliases::default()
    };
    assert!(
        table
            .assign(
                "blocked.example",
                &[Ipv4Addr::new(1, 1, 1, 1)],
                60,
                Instant::now()
            )
            .is_err()
    );
    assert!(table.entries.is_empty());
    assert!(table.live.is_empty());
}

#[test]
fn synthetic_wire_ttl_zero_does_not_shorten_authenticated_session_grant() {
    let aliases = Mutex::new(Aliases::default());
    let wire = query("allowed.example");
    let real = Ipv4Addr::new(1, 1, 1, 1);
    let result = resolve(&wire, Ok(response(&wire, real)), true, &aliases).unwrap();
    let parsed = Message::parse(&result).unwrap();
    assert_eq!(parsed.answers[0].ttl, 0);
    let alias = a_address(&result, &parsed.answers[0]).unwrap();
    let now = Instant::now();
    let table = aliases.lock().unwrap();
    assert_eq!(
        table.lookup(alias, now + Duration::from_secs(30)).unwrap(),
        Some(real)
    );
    assert!(table.lookup(alias, now + Duration::from_secs(61)).is_err());
}

fn ttl_of_first_answer(wire: &[u8]) -> u32 {
    let parsed = Message::parse(wire).unwrap();
    parsed.answers[0].ttl
}

fn negative(query_wire: &[u8], rcode: u16, soa_ttl: u32, minimum: u32) -> Vec<u8> {
    let mut wire = query_wire.to_vec();
    wire[2..4].copy_from_slice(&(0x8180u16 | rcode).to_be_bytes());
    wire[8..10].copy_from_slice(&1u16.to_be_bytes());
    let mut rdata = Vec::new();
    put_name(&mut rdata, "ns.example");
    put_name(&mut rdata, "admin.example");
    for value in [1u32, 7200, 900, 1_209_600, minimum] {
        rdata.extend_from_slice(&value.to_be_bytes());
    }
    put_name(&mut wire, "example");
    wire.extend_from_slice(&[0, 6, 0, 1]);
    wire.extend_from_slice(&soa_ttl.to_be_bytes());
    wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    wire.extend_from_slice(&rdata);
    wire
}

fn key_for(query_wire: &[u8]) -> cache::Key {
    let query = Message::query(query_wire).unwrap();
    cache::Key::new(
        &query.question.name,
        query.question.kind,
        query.question.class,
        query.flags,
        query.dnssec,
    )
}

#[test]
fn a_cached_answer_counts_its_ttl_down_and_answers_the_new_query() {
    let cache = Cache::default();
    let first = query("cached.example");
    let now = Instant::now();
    cache.put(
        key_for(&first),
        &response(&first, Ipv4Addr::new(93, 184, 216, 34)),
        now,
    );
    // A later query with another ID and letter case.
    let mut second = query("CaChEd.example");
    second[..2].copy_from_slice(&0x4242u16.to_be_bytes());
    let hit = cache
        .get(&key_for(&second), &second, now + Duration::from_secs(25))
        .unwrap();
    assert_eq!(&hit[..2], &0x4242u16.to_be_bytes());
    assert_eq!(&hit[12..12 + 16], &second[12..12 + 16]);
    assert_eq!(ttl_of_first_answer(&hit), 35);
    let query = Message::query(&second).unwrap();
    assert!(Message::response(&hit, &query).is_ok());
    // Gone once the shortest TTL has run out.
    assert!(
        cache
            .get(&key_for(&second), &second, now + Duration::from_secs(60))
            .is_none()
    );
    assert!(
        cache
            .get(&key_for(&second), &second, now + Duration::from_secs(59))
            .is_some()
    );
}

#[test]
fn unusable_answers_are_never_cached() {
    let cache = Cache::default();
    let now = Instant::now();
    let q = query("nope.example");
    let mut zero = response(&q, Ipv4Addr::new(93, 184, 216, 34));
    let at = zero.len() - 10;
    zero[at..at + 4].copy_from_slice(&0u32.to_be_bytes());
    cache.put(key_for(&q), &zero, now);
    let mut truncated = response(&q, Ipv4Addr::new(93, 184, 216, 34));
    truncated[2..4].copy_from_slice(&0x83a0u16.to_be_bytes());
    cache.put(key_for(&q), &truncated, now);
    let mut servfail = response(&q, Ipv4Addr::new(93, 184, 216, 34));
    servfail[2..4].copy_from_slice(&0x81a2u16.to_be_bytes());
    cache.put(key_for(&q), &servfail, now);
    // An empty answer without an SOA has no negative lifetime.
    let mut empty = q.clone();
    empty[2..4].copy_from_slice(&0x8183u16.to_be_bytes());
    cache.put(key_for(&q), &empty, now);
    assert_eq!(cache.len(), 0);
}

#[test]
fn negative_answers_live_as_long_as_their_soa_allows() {
    let cache = Cache::default();
    let now = Instant::now();
    let q = query("missing.example");
    cache.put(key_for(&q), &negative(&q, 3, 600, 45), now);
    assert!(
        cache
            .get(&key_for(&q), &q, now + Duration::from_secs(44))
            .is_some()
    );
    assert!(
        cache
            .get(&key_for(&q), &q, now + Duration::from_secs(45))
            .is_none()
    );
    // NODATA (NOERROR, no answer) is cached the same way, e.g. a missing AAAA.
    let mut aaaa = query("v4only.example");
    let len = aaaa.len();
    aaaa[len - 4..len - 2].copy_from_slice(&28u16.to_be_bytes());
    cache.put(key_for(&aaaa), &negative(&aaaa, 0, 30, 300), now);
    let hit = cache
        .get(&key_for(&aaaa), &aaaa, now + Duration::from_secs(10))
        .unwrap();
    let parsed = Message::response(&hit, &Message::query(&aaaa).unwrap()).unwrap();
    assert!(parsed.answers.is_empty());
}

#[test]
fn query_bits_that_change_the_answer_are_part_of_the_key() {
    let plain = query("keyed.example");
    let mut checking_disabled = plain.clone();
    checking_disabled[2..4].copy_from_slice(&0x0110u16.to_be_bytes());
    assert_ne!(key_for(&plain), key_for(&checking_disabled));
    let mut case = query("KEYED.example");
    case[..2].copy_from_slice(&[9, 9]);
    assert_eq!(key_for(&plain), key_for(&case));
}

#[test]
fn a_cached_whitelisted_answer_still_gets_its_alias() {
    let aliases = Mutex::new(Aliases::default());
    let cache = Cache::default();
    let now = Instant::now();
    let white = query("allowed.example");
    let true_ip = Ipv4Addr::new(93, 184, 216, 34);
    let upstream = response(&white, true_ip);
    let first = resolve(&white, Ok(upstream.clone()), true, &aliases).unwrap();
    cache.put(key_for(&white), &upstream, now);
    let hit = cache
        .get(&key_for(&white), &white, now + Duration::from_secs(5))
        .unwrap();
    let second = resolve(&white, Ok(hit), true, &aliases).unwrap();
    let alias = |wire: &[u8]| a_address(wire, &Message::parse(wire).unwrap().answers[0]).unwrap();
    assert!(reserved(alias(&first)));
    assert_eq!(alias(&first), alias(&second));
    assert_eq!(
        aliases
            .lock()
            .unwrap()
            .lookup(alias(&second), Instant::now())
            .unwrap(),
        Some(true_ip)
    );
}

#[test]
fn an_expired_answer_is_served_stale_for_a_while_with_a_short_ttl() {
    let cache = Cache::default();
    let q = query("stale.example");
    let now = Instant::now();
    cache.put(
        key_for(&q),
        &response(&q, Ipv4Addr::new(93, 184, 216, 34)),
        now,
    );
    // Still fresh: counted down, not stale.
    let fresh = cache
        .lookup(&key_for(&q), &q, now + Duration::from_secs(50))
        .unwrap();
    assert!(!fresh.stale);
    assert_eq!(ttl_of_first_answer(&fresh.wire), 10);
    // Past its 60 s TTL: a plain get misses, a lookup serves it stale.
    let later = now + Duration::from_secs(61);
    assert!(cache.get(&key_for(&q), &q, later).is_none());
    let stale = cache.lookup(&key_for(&q), &q, later).unwrap();
    assert!(stale.stale);
    assert_eq!(ttl_of_first_answer(&stale.wire), 30);
    assert!(Message::response(&stale.wire, &Message::query(&q).unwrap()).is_ok());
    // A stale whitelisted answer still gets an alias.
    let aliases = Mutex::new(Aliases::default());
    let rewritten = resolve(&q, Ok(stale.wire), true, &aliases).unwrap();
    assert!(reserved(
        a_address(&rewritten, &Message::parse(&rewritten).unwrap().answers[0]).unwrap()
    ));
    // An hour after expiry it is gone.
    assert!(
        cache
            .lookup(&key_for(&q), &q, now + Duration::from_secs(60 + 3600))
            .is_none()
    );
    assert!(
        cache
            .lookup(&key_for(&q), &q, now + Duration::from_secs(60 + 3599))
            .is_some()
    );
}
