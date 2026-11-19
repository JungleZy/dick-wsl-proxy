use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use native_tls::{Protocol, TlsConnector};

const MAX_DNS: usize = 65_535;
const MAX_RECORDS: usize = 128;
const MAX_ALIASES: usize = 16_384;
const MAX_TTL: u32 = 300;
const IO_DEADLINE: Duration = Duration::from_secs(10);
const ALIAS_START: u32 = u32::from_be_bytes([198, 18, 0, 1]);
const ALIAS_SPACE: u32 = 131_070;
const ALIAS_BLOCK: u32 = 32;

/// Session-local DNS through the authenticated proxy chain. Ordinary IN queries,
/// including AAAA, pass through; IPv6 blocking belongs to the Target kernel rules.
/// Only proven whitelisted A answers with DO=0 get aliases; these carry no AD or
/// DNSSEC records. A durable high-water ledger prevents alias reuse across runs.
pub struct ManagedDns {
    policy: Arc<crate::policy::Policy>,
    tls: TlsConnector,
    aliases: Mutex<Aliases>,
    probe: Mutex<Probe>,
}

#[derive(Default)]
struct Probe {
    name: Option<String>,
    seen: bool,
}

#[derive(Default)]
struct Aliases {
    entries: HashMap<Ipv4Addr, Alias>,
    live: HashMap<String, HashMap<Ipv4Addr, Ipv4Addr>>,
    ledger: AliasLedger,
}

struct Alias {
    real: Ipv4Addr,
    expires: Instant,
}

impl ManagedDns {
    pub fn new(policy: Arc<crate::policy::Policy>) -> Result<Self, String> {
        let mut builder = TlsConnector::builder();
        builder.min_protocol_version(Some(Protocol::Tlsv12));
        let tls = builder
            .build()
            .map_err(|e| format!("build DNS TLS connector: {e}"))?;
        Ok(Self {
            policy,
            tls,
            aliases: Mutex::new(Aliases::default()),
            probe: Mutex::new(Probe::default()),
        })
    }

    pub fn arm_probe(&self, name: &str) -> Result<(), String> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty()
            || name.len() > 253
            || name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
        {
            return Err("invalid DNS readiness probe name".into());
        }
        let mut probe = self.probe.lock().map_err(|_| "DNS probe lock poisoned")?;
        probe.name = Some(name);
        probe.seen = false;
        Ok(())
    }

    pub fn probe_seen(&self) -> bool {
        self.probe.lock().map(|probe| probe.seen).unwrap_or(false)
    }

    pub fn answer(&self, wire: &[u8]) -> Result<Vec<u8>, String> {
        self.answer_for(wire, true)
    }

    pub fn answer_tcp(&self, wire: &[u8]) -> Result<Vec<u8>, String> {
        self.answer_for(wire, false)
    }

    fn answer_for(&self, wire: &[u8], udp: bool) -> Result<Vec<u8>, String> {
        let query = Message::query(wire)?;
        let direct = query.question.kind == 1
            && !query.dnssec
            && self.policy.allows_domain(&query.question.name);
        let limit = if udp { query.udp_size } else { MAX_DNS };
        let response_wire = self.exchange(wire)?;
        let response = Message::response(&response_wire, &query)?;
        let answer = finish_answer(
            &query,
            &response_wire,
            &response,
            direct,
            &self.aliases,
            limit,
        )?;
        if !direct
            && query.question.kind == 1
            && matches!(response.flags & 15, 0 | 3)
            && response.flags & 0x0200 == 0
        {
            let mut probe = self.probe.lock().map_err(|_| "DNS probe lock poisoned")?;
            if probe.name.as_deref() == Some(&query.question.name) {
                probe.seen = true;
            }
        }
        Ok(answer)
    }

    pub fn direct_alias(&self, ip: Ipv4Addr) -> Result<Option<Ipv4Addr>, String> {
        self.aliases
            .lock()
            .map_err(|_| "DNS alias table lock poisoned".to_string())?
            .lookup(ip, Instant::now())
    }

    fn exchange(&self, wire: &[u8]) -> Result<Vec<u8>, String> {
        let socket = self.policy.chain(self.policy.dns_upstream())?;
        let stream = DeadlineStream {
            socket,
            deadline: Instant::now() + IO_DEADLINE,
        };
        // This is a preconnected literal-address chain stream. The DNS hostname
        // is used only for SNI, certificate verification, and the HTTP Host field.
        let mut tls = self
            .tls
            .connect(self.policy.dns_tls_name(), stream)
            .map_err(|_| "DNS TLS verification/handshake failed".to_string())?;
        let request = format!(
            "POST /dns-query HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.policy.dns_tls_name(),
            wire.len()
        );
        tls.write_all(request.as_bytes())
            .and_then(|_| tls.write_all(wire))
            .and_then(|_| tls.flush())
            .map_err(|e| format!("write DNS HTTPS request: {e}"))?;
        read_http(&mut BufReader::new(tls))
    }
}

struct DeadlineStream {
    socket: TcpStream,
    deadline: Instant,
}

impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "DNS upstream deadline"))
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

fn http_line(reader: &mut impl BufRead, budget: &mut usize) -> Result<String, String> {
    let mut line = Vec::new();
    loop {
        if *budget == 0 || line.len() >= 8192 {
            return Err("DNS HTTPS headers exceed limit".into());
        }
        let mut byte = [0];
        reader
            .read_exact(&mut byte)
            .map_err(|e| format!("read DNS HTTPS header: {e}"))?;
        *budget -= 1;
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if !line.ends_with(b"\r\n") {
        return Err("invalid DNS HTTPS header line".into());
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line).map_err(|_| "non-ASCII DNS HTTPS header".into())
}

fn read_http(reader: &mut impl BufRead) -> Result<Vec<u8>, String> {
    let mut budget = 16_384;
    let status = http_line(reader, &mut budget)?;
    if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.0 200 ") {
        return Err("DNS HTTPS upstream did not return HTTP 200".into());
    }
    let mut length = None;
    let mut chunked = false;
    let mut content_type = false;
    loop {
        let line = http_line(reader, &mut budget)?;
        if line.is_empty() {
            break;
        }
        let (key, value) = line.split_once(':').ok_or("malformed DNS HTTPS header")?;
        let value = value.trim();
        match key.to_ascii_lowercase().as_str() {
            "content-length" => {
                if length.is_some() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("ambiguous DNS HTTPS Content-Length".into());
                }
                let size = value
                    .parse::<usize>()
                    .map_err(|_| "invalid DNS HTTPS length")?;
                if !(12..=MAX_DNS).contains(&size) {
                    return Err("DNS HTTPS body size outside limits".into());
                }
                length = Some(size);
            }
            "transfer-encoding" => {
                if chunked || !value.eq_ignore_ascii_case("chunked") {
                    return Err("unsupported DNS HTTPS transfer encoding".into());
                }
                chunked = true;
            }
            "content-type" => {
                if content_type || !value.eq_ignore_ascii_case("application/dns-message") {
                    return Err("invalid DNS HTTPS content type".into());
                }
                content_type = true;
            }
            "content-encoding" if !value.eq_ignore_ascii_case("identity") => {
                return Err("compressed DNS HTTPS body is unsupported".into());
            }
            _ => {}
        }
    }
    if !content_type || (chunked && length.is_some()) {
        return Err("ambiguous DNS HTTPS response framing".into());
    }
    let mut body = Vec::new();
    if let Some(length) = length {
        body.resize(length, 0);
        reader
            .read_exact(&mut body)
            .map_err(|e| format!("read DNS HTTPS body: {e}"))?;
    } else if chunked {
        loop {
            let line = http_line(reader, &mut budget)?;
            if line.is_empty() || line.len() > 8 || !line.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid DNS HTTPS chunk size".into());
            }
            let size = usize::from_str_radix(&line, 16).map_err(|_| "invalid DNS HTTPS chunk")?;
            if size == 0 {
                // Reject trailers rather than allow a second interpretation of
                // content type, length, or the authenticated message boundary.
                if !http_line(reader, &mut budget)?.is_empty() {
                    return Err("DNS HTTPS trailers are unsupported".into());
                }
                break;
            }
            if size > MAX_DNS - body.len() {
                return Err("DNS HTTPS body exceeds limit".into());
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader
                .read_exact(&mut body[start..])
                .map_err(|e| format!("read DNS HTTPS chunk: {e}"))?;
            let mut end = [0; 2];
            reader
                .read_exact(&mut end)
                .map_err(|e| format!("read DNS HTTPS chunk end: {e}"))?;
            if end != *b"\r\n" {
                return Err("invalid DNS HTTPS chunk end".into());
            }
        }
    } else {
        return Err("DNS HTTPS response requires explicit body framing".into());
    }
    if body.len() < 12 {
        return Err("short DNS HTTPS body".into());
    }
    Ok(body)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Question {
    name: String,
    kind: u16,
    class: u16,
}

struct Record {
    name: String,
    kind: u16,
    class: u16,
    ttl: u32,
    start: usize,
    end: usize,
    cname: Option<String>,
}

struct Message {
    id: u16,
    flags: u16,
    question: Question,
    answers: Vec<Record>,
    dnssec: bool,
    udp_size: usize,
    has_reserved_a: bool,
}

fn word(wire: &[u8], at: usize) -> Result<u16, String> {
    let bytes = wire.get(at..at + 2).ok_or("truncated DNS integer")?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn name(wire: &[u8], cursor: &mut usize) -> Result<String, String> {
    let mut at = *cursor;
    let mut jumped = false;
    let mut labels = Vec::new();
    let mut size = 1;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(at) || visited.len() > 128 {
            return Err("DNS compression loop or excessive depth".into());
        }
        let length = *wire.get(at).ok_or("truncated DNS name")?;
        if length & 0xc0 == 0xc0 {
            let target = usize::from(word(wire, at)? & 0x3fff);
            if target < 12 || target >= at {
                return Err("invalid DNS compression pointer".into());
            }
            if !jumped {
                *cursor = at + 2;
            }
            jumped = true;
            at = target;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err("unsupported DNS label encoding".into());
        }
        at += 1;
        if length == 0 {
            if !jumped {
                *cursor = at;
            }
            break;
        }
        size += usize::from(length) + 1;
        if size > 255 {
            return Err("DNS name exceeds 255 bytes".into());
        }
        let label = wire
            .get(at..at + usize::from(length))
            .ok_or("truncated DNS label")?;
        // Fail closed on non-hostname labels instead of letting an escaped dot,
        // NUL, or IDNA interpretation broaden a configured domain whitelist.
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        {
            return Err("unsupported non-hostname DNS label".into());
        }
        labels
            .push(String::from_utf8(label.to_ascii_lowercase()).map_err(|_| "invalid DNS label")?);
        at += usize::from(length);
    }
    Ok(labels.join("."))
}

impl Message {
    fn query(wire: &[u8]) -> Result<Self, String> {
        let message = Self::parse(wire)?;
        if message.flags & !0x0130 != 0 || word(wire, 6)? != 0 || word(wire, 8)? != 0 {
            return Err("unsupported DNS query flags or sections".into());
        }
        if message.question.class != 1 || matches!(message.question.kind, 0 | 41 | 249..=252) {
            return Err("managed DNS requires an ordinary IN question (no zone transfers or message authentication)".into());
        }
        Ok(message)
    }

    fn response(wire: &[u8], query: &Self) -> Result<Self, String> {
        let message = Self::parse(wire)?;
        if message.id != query.id
            || message.question != query.question
            || message.flags & 0x8000 == 0
            || message.flags & 0x7840 != 0
            || message.flags & 0x0100 != query.flags & 0x0100
        {
            return Err("DNS upstream response does not match the question".into());
        }
        if message.has_reserved_a {
            return Err("upstream DNS returned a reserved session alias".into());
        }
        Ok(message)
    }

    fn parse(wire: &[u8]) -> Result<Self, String> {
        if !(12..=MAX_DNS).contains(&wire.len()) || word(wire, 4)? != 1 {
            return Err("DNS requires exactly one bounded question".into());
        }
        let flags = word(wire, 2)?;
        let counts = [word(wire, 6)?, word(wire, 8)?, word(wire, 10)?];
        if counts.iter().map(|n| usize::from(*n)).sum::<usize>() > MAX_RECORDS {
            return Err("too many DNS records".into());
        }
        let mut cursor = 12;
        let question_name = name(wire, &mut cursor)?;
        let question = Question {
            name: question_name,
            kind: word(wire, cursor)?,
            class: word(wire, cursor + 2)?,
        };
        cursor += 4;
        let mut answers = Vec::new();
        let mut seen_opt = false;
        let mut dnssec = false;
        let mut udp_size = 512;
        let mut has_reserved_a = false;
        for (section, count) in counts.into_iter().enumerate() {
            for _ in 0..count {
                let owner = name(wire, &mut cursor)?;
                let kind = word(wire, cursor)?;
                let class = word(wire, cursor + 2)?;
                let ttl =
                    (u32::from(word(wire, cursor + 4)?) << 16) | u32::from(word(wire, cursor + 6)?);
                let length = usize::from(word(wire, cursor + 8)?);
                cursor += 10;
                let start = cursor;
                let end = cursor
                    .checked_add(length)
                    .filter(|end| *end <= wire.len())
                    .ok_or("truncated DNS RDATA")?;
                let cname = match kind {
                    1 if length != 4 => return Err("invalid DNS A length".into()),
                    28 if length != 16 => return Err("invalid DNS AAAA length".into()),
                    5 => {
                        let target = name(wire, &mut cursor)?;
                        if cursor != end || target.is_empty() {
                            return Err("invalid DNS CNAME data".into());
                        }
                        Some(target)
                    }
                    41 => {
                        if section != 2 || seen_opt || !owner.is_empty() || ttl & !0x8000 != 0 {
                            return Err("unsupported DNS EDNS version, flags, or placement".into());
                        }
                        seen_opt = true;
                        dnssec = ttl & 0x8000 != 0;
                        udp_size = usize::from(class).clamp(512, 4096);
                        let mut option = start;
                        while option < end {
                            let size = usize::from(word(wire, option + 2)?);
                            option = option
                                .checked_add(4 + size)
                                .filter(|at| *at <= end)
                                .ok_or("invalid DNS EDNS option")?;
                        }
                        None
                    }
                    _ => None,
                };
                if kind == 1 {
                    let octets: [u8; 4] = wire[start..end]
                        .try_into()
                        .map_err(|_| "invalid DNS A data")?;
                    has_reserved_a |= reserved(Ipv4Addr::from(octets));
                }
                validate_rdata(wire, kind, start, end, &mut has_reserved_a)?;
                if section == 0 {
                    answers.push(Record {
                        name: owner,
                        kind,
                        class,
                        ttl,
                        start,
                        end,
                        cname,
                    });
                } else if flags & 0x8000 == 0 && kind != 41 {
                    return Err("DNS query has unsupported additional data".into());
                }
                cursor = end;
            }
        }
        if cursor != wire.len() {
            return Err("trailing bytes after DNS message".into());
        }
        Ok(Self {
            id: word(wire, 0)?,
            flags,
            question,
            answers,
            dnssec,
            udp_size,
            has_reserved_a,
        })
    }
}

fn validate_rdata(
    wire: &[u8],
    kind: u16,
    start: usize,
    end: usize,
    reserved_ip: &mut bool,
) -> Result<(), String> {
    let mut at = start;
    match kind {
        2 | 12 | 39 => {
            name(wire, &mut at)?;
        }
        15 => {
            word(wire, at)?;
            at += 2;
            name(wire, &mut at)?;
        }
        33 => {
            if end - start < 7 {
                return Err("short DNS SRV data".into());
            }
            at += 6;
            name(wire, &mut at)?;
        }
        6 => {
            name(wire, &mut at)?;
            name(wire, &mut at)?;
            at += 20;
        }
        16 => {
            if at == end {
                return Err("empty DNS TXT data".into());
            }
            while at < end {
                let size = usize::from(wire[at]);
                at += size + 1;
            }
        }
        64 | 65 => {
            if end - start < 3 {
                return Err("short DNS service binding".into());
            }
            at += 2;
            let target_at = at;
            name(wire, &mut at)?;
            if at > end || wire[target_at..at].iter().any(|byte| byte & 0xc0 == 0xc0) {
                return Err("invalid compressed DNS service target".into());
            }
            let mut previous = None;
            while at < end {
                if end - at < 4 {
                    return Err("short DNS service parameter".into());
                }
                let key = word(wire, at)?;
                let size = usize::from(word(wire, at + 2)?);
                if previous.is_some_and(|old| old >= key) {
                    return Err("unordered DNS service parameters".into());
                }
                previous = Some(key);
                at += 4;
                let next = at
                    .checked_add(size)
                    .filter(|next| *next <= end)
                    .ok_or("invalid DNS service parameter length")?;
                if key == 4 {
                    if size == 0 || size % 4 != 0 {
                        return Err("invalid DNS IPv4 hint".into());
                    }
                    for address in wire[at..next].as_chunks::<4>().0 {
                        *reserved_ip |= reserved(Ipv4Addr::new(
                            address[0], address[1], address[2], address[3],
                        ));
                    }
                }
                at = next;
            }
        }
        _ => return Ok(()),
    }
    if at != end {
        return Err("DNS RDATA length does not match record semantics".into());
    }
    Ok(())
}

fn put_name(wire: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|label| !label.is_empty()) {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
}

fn header(query: &Message, flags: u16, answers: u16) -> Vec<u8> {
    let mut wire = Vec::with_capacity(512);
    for value in [query.id, flags, 1, answers, 0, 0] {
        wire.extend_from_slice(&value.to_be_bytes());
    }
    put_name(&mut wire, &query.question.name);
    wire.extend_from_slice(&query.question.kind.to_be_bytes());
    wire.extend_from_slice(&query.question.class.to_be_bytes());
    wire
}

fn finish_answer(
    query: &Message,
    response_wire: &[u8],
    response: &Message,
    direct: bool,
    aliases: &Mutex<Aliases>,
    limit: usize,
) -> Result<Vec<u8>, String> {
    if response.flags & 0x0200 != 0 || response_wire.len() > limit {
        return Ok(header(query, (response.flags | 0x0200) & !0x0020, 0));
    }
    if !direct || response.flags & 15 != 0 || response.answers.is_empty() {
        return Ok(response_wire.to_vec());
    }
    let mut current = query.question.name.clone();
    let mut visited = HashSet::new();
    let mut selected = Vec::new();
    let mut ttl = MAX_TTL;
    loop {
        if !visited.insert(current.clone()) {
            return Err("DNS CNAME cycle".into());
        }
        let records: Vec<_> = response
            .answers
            .iter()
            .filter(|r| r.name == current)
            .collect();
        if records.is_empty() {
            return Err("incomplete DNS CNAME chain".into());
        }
        if records
            .iter()
            .any(|r| r.class != 1 || !matches!(r.kind, 1 | 5))
        {
            return Err("unsupported whitelisted DNS answer shape".into());
        }
        let cnames: Vec<_> = records.iter().filter(|r| r.kind == 5).collect();
        if !cnames.is_empty() {
            if records.len() != 1 {
                return Err("ambiguous DNS CNAME answer".into());
            }
            let record = *cnames[0];
            ttl = ttl.min(record.ttl);
            selected.push(record);
            current = record.cname.clone().ok_or("missing DNS CNAME target")?;
        } else {
            for record in records {
                ttl = ttl.min(record.ttl);
                selected.push(record);
            }
            break;
        }
    }
    if selected.len() != response.answers.len() || ttl == 0 {
        return Err("unrelated records or zero TTL in whitelisted DNS answer".into());
    }
    // Flatten the authenticated CNAME chain onto the original whitelisted name.
    // Publishing an alias under a shared canonical owner would let the guest's
    // DNS cache lend that alias to unrelated names using the same CDN target.
    let addresses: Vec<_> = selected
        .into_iter()
        .filter(|record| record.kind == 1)
        .collect();
    let mut wire = header(query, response.flags & !0x0420, addresses.len() as u16);
    let mut destinations = Vec::with_capacity(addresses.len());
    let mut patches = Vec::with_capacity(addresses.len());
    for record in addresses {
        let ip = a_address(response_wire, record)?;
        if !public_destination(ip) {
            return Err("whitelisted DNS resolved to an unsafe IPv4 destination".into());
        }
        put_name(&mut wire, &query.question.name);
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&0u32.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        patches.push(wire.len());
        destinations.push(ip);
        wire.extend_from_slice(&[0; 4]);
    }
    if wire.len() > limit {
        return Ok(header(query, (response.flags | 0x0200) & !0x0020, 0));
    }
    let mut table = aliases
        .lock()
        .map_err(|_| "DNS alias table lock poisoned")?;
    let assigned = table.assign(&query.question.name, &destinations, ttl, Instant::now())?;
    for (at, alias) in patches.into_iter().zip(assigned) {
        wire[at..at + 4].copy_from_slice(&alias.octets());
    }
    Ok(wire)
}

fn a_address(wire: &[u8], record: &Record) -> Result<Ipv4Addr, String> {
    let bytes: [u8; 4] = wire[record.start..record.end]
        .try_into()
        .map_err(|_| "invalid DNS A data")?;
    Ok(Ipv4Addr::from(bytes))
}

fn reserved(ip: Ipv4Addr) -> bool {
    u32::from(ip) & 0xfffe_0000 == 0xc612_0000
}

fn public_destination(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b))
        || reserved(ip))
}

impl Aliases {
    fn lookup(&self, ip: Ipv4Addr, now: Instant) -> Result<Option<Ipv4Addr>, String> {
        if !reserved(ip) {
            return Ok(None);
        }
        let entry = self.entries.get(&ip).ok_or("unknown DNS session alias")?;
        if entry.expires <= now {
            return Err("expired DNS session alias".into());
        }
        Ok(Some(entry.real))
    }

    fn assign(
        &mut self,
        name: &str,
        ips: &[Ipv4Addr],
        ttl: u32,
        now: Instant,
    ) -> Result<Vec<Ipv4Addr>, String> {
        let missing: HashSet<_> = ips
            .iter()
            .filter(|ip| {
                self.live
                    .get(name)
                    .and_then(|addresses| addresses.get(*ip))
                    .and_then(|alias| self.entries.get(alias))
                    .is_none_or(|entry| entry.expires <= now)
            })
            .copied()
            .collect();
        if missing.len() > MAX_ALIASES - self.entries.len() {
            return Err("DNS session alias capacity exhausted; restart session explicitly".into());
        }
        // Reserve every new number durably before changing the session table.
        // Expired numbers remain burned both in this session and on disk.
        let mut fresh = self.ledger.allocate(missing.len())?.into_iter();
        let expires = now + Duration::from_secs(u64::from(ttl));
        let mut result = Vec::with_capacity(ips.len());
        for ip in ips {
            let previous = self
                .live
                .get(name)
                .and_then(|addresses| addresses.get(ip))
                .copied();
            let alias = match previous {
                Some(alias)
                    if self
                        .entries
                        .get(&alias)
                        .is_some_and(|entry| entry.expires > now) =>
                {
                    alias
                }
                _ => {
                    let alias = fresh
                        .next()
                        .expect("reserved every distinct missing DNS alias");
                    self.entries.insert(alias, Alias { real: *ip, expires });
                    self.live
                        .entry(name.to_string())
                        .or_default()
                        .insert(*ip, alias);
                    alias
                }
            };
            self.entries
                .get_mut(&alias)
                .expect("assigned DNS alias exists")
                .expires = expires;
            result.push(alias);
        }
        Ok(result)
    }
}

/// Serialized by the controller's existing current-user exclusive lock. The
/// ledger contains only a version marker and an allocated-address count. A
/// leftover pending file is an uncertain commit, never permission to reset.
#[cfg_attr(not(test), derive(Default))]
struct AliasLedger {
    path: Option<PathBuf>,
    next: u32,
    end: u32,
    #[cfg(test)]
    cleanup: Option<PathBuf>,
}

#[cfg(test)]
impl Default for AliasLedger {
    fn default() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "wsl-proxyctl-dns-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        Self {
            path: Some(root.join("dns-alias.highwater")),
            next: 0,
            end: 0,
            cleanup: Some(root),
        }
    }
}

impl AliasLedger {
    #[cfg(test)]
    fn at(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            next: 0,
            end: 0,
            cleanup: None,
        }
    }

    fn allocate(&mut self, count: usize) -> Result<Vec<Ipv4Addr>, String> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let count = u32::try_from(count).map_err(|_| "DNS alias allocation exceeds range")?;
        if self.end - self.next < count {
            if self.path.is_none() {
                self.path = Some(crate::host::state_dir()?.join("dns-alias.highwater"));
            }
            let path = self
                .path
                .as_deref()
                .ok_or("DNS alias ledger path unavailable")?;
            let parent = path.parent().ok_or("DNS alias ledger has no parent")?;
            fs::create_dir_all(parent)
                .map_err(|e| format!("create DNS alias ledger directory: {e}"))?;
            let pending = path.with_extension("pending");
            match fs::symlink_metadata(&pending) {
                Ok(_) => return Err(
                    "DNS alias ledger has an uncertain pending commit; manual recovery required"
                        .into(),
                ),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("inspect DNS alias ledger pending commit: {e}")),
            }
            let high = read_alias_highwater(path)?;
            if count > ALIAS_SPACE - high {
                return Err(
                    "durable DNS alias range exhausted; automatic reset is forbidden".into(),
                );
            }
            let end = high
                + count
                    .div_ceil(ALIAS_BLOCK)
                    .saturating_mul(ALIAS_BLOCK)
                    .min(ALIAS_SPACE - high);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&pending)
                .map_err(|e| format!("create DNS alias ledger pending commit: {e}"))?;
            let mut bytes = *b"WDA1\0\0\0\0";
            bytes[4..].copy_from_slice(&end.to_be_bytes());
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|e| format!("sync DNS alias ledger commit: {e}"))?;
            drop(file);
            replace_alias_ledger(&pending, path)
                .map_err(|e| format!("commit DNS alias high-water ledger: {e}"))?;
            self.next = high;
            self.end = end;
        }
        let result = (self.next..self.next + count)
            .map(|offset| Ipv4Addr::from(ALIAS_START + offset))
            .collect();
        self.next += count;
        Ok(result)
    }
}

fn read_alias_highwater(path: &Path) -> Result<u32, String> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(format!("open DNS alias ledger: {e}")),
    };
    let mut bytes = [0u8; 9];
    let mut read = 0;
    while read < bytes.len() {
        let count = file
            .read(&mut bytes[read..])
            .map_err(|e| format!("read DNS alias ledger: {e}"))?;
        if count == 0 {
            break;
        }
        read += count;
    }
    if read != 8 || &bytes[..4] != b"WDA1" {
        return Err("corrupt DNS alias ledger; automatic reset is forbidden".into());
    }
    let high = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if high == 0 || high > ALIAS_SPACE {
        return Err(
            "DNS alias ledger high-water outside range; automatic reset is forbidden".into(),
        );
    }
    Ok(high)
}

#[cfg(windows)]
fn replace_alias_ledger(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let source: Vec<_> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<_> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_alias_ledger(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)?;
    File::open(
        destination
            .parent()
            .ok_or_else(|| io::Error::other("DNS ledger parent missing"))?,
    )?
    .sync_all()
}

#[cfg(test)]
impl Drop for AliasLedger {
    fn drop(&mut self) {
        if let Some(root) = &self.cleanup {
            let _ = fs::remove_dir_all(root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
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
                    expires: now,
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
        let udp =
            finish_answer(&query, &upstream, &response, true, &aliases, query.udp_size).unwrap();
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
    fn aliases_never_cross_names_or_revive_after_expiry() {
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
        assert_ne!(first, renewed);
        assert!(table.lookup(first, now + Duration::from_secs(2)).is_err());
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
        let mut http = format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        http.extend_from_slice(&body);
        assert_eq!(read_http(&mut io::Cursor::new(http)).unwrap(), body);
        assert!(read_http(&mut io::Cursor::new(b"HTTP/1.1 503 Error\r\n\r\n")).is_err());
        assert!(read_http(&mut io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 12\r\n\r\n012345678901")).is_err());
        assert!(read_http(&mut io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 999999\r\n\r\n")).is_err());
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
}
