use super::{Aliases, MAX_DNS, MAX_RECORDS, MAX_TTL};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Question {
    pub(super) name: String,
    pub(super) kind: u16,
    pub(super) class: u16,
}

pub(super) struct Record {
    pub(super) name: String,
    pub(super) kind: u16,
    pub(super) class: u16,
    pub(super) ttl: u32,
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) cname: Option<String>,
}

pub(super) struct Message {
    pub(super) id: u16,
    pub(super) flags: u16,
    pub(super) question: Question,
    pub(super) answers: Vec<Record>,
    pub(super) dnssec: bool,
    pub(super) udp_size: usize,
    pub(super) has_reserved_alias: bool,
}

pub(super) fn word(wire: &[u8], at: usize) -> Result<u16, String> {
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
    pub(super) fn query(wire: &[u8]) -> Result<Self, String> {
        let message = Self::parse(wire)?;
        if message.flags & !0x0130 != 0 || word(wire, 6)? != 0 || word(wire, 8)? != 0 {
            return Err("unsupported DNS query flags or sections".into());
        }
        if message.question.class != 1 || matches!(message.question.kind, 0 | 41 | 249..=252) {
            return Err("managed DNS requires an ordinary IN question (no zone transfers or message authentication)".into());
        }
        Ok(message)
    }

    pub(super) fn response(wire: &[u8], query: &Self) -> Result<Self, String> {
        let message = Self::parse(wire)?;
        if message.id != query.id
            || message.question != query.question
            || message.flags & 0x8000 == 0
            || message.flags & 0x7840 != 0
            || message.flags & 0x0100 != query.flags & 0x0100
        {
            return Err("DNS upstream response does not match the question".into());
        }
        if message.has_reserved_alias {
            return Err("upstream DNS returned a reserved session alias".into());
        }
        Ok(message)
    }

    pub(super) fn parse(wire: &[u8]) -> Result<Self, String> {
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
        let mut has_reserved_alias = false;
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
                    has_reserved_alias |= reserved(Ipv4Addr::from(octets));
                } else if kind == 28 {
                    let octets: [u8; 16] = wire[start..end]
                        .try_into()
                        .map_err(|_| "invalid DNS AAAA data")?;
                    has_reserved_alias |= Ipv6Addr::from(octets)
                        .to_ipv4_mapped()
                        .is_some_and(reserved);
                }
                validate_rdata(wire, kind, start, end, &mut has_reserved_alias)?;
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
            has_reserved_alias,
        })
    }
}

fn validate_rdata(
    wire: &[u8],
    kind: u16,
    start: usize,
    end: usize,
    reserved_alias: &mut bool,
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
                        *reserved_alias |= reserved(Ipv4Addr::new(
                            address[0], address[1], address[2], address[3],
                        ));
                    }
                } else if key == 6 {
                    if size == 0 || size % 16 != 0 {
                        return Err("invalid DNS IPv6 hint".into());
                    }
                    for address in wire[at..next].as_chunks::<16>().0 {
                        *reserved_alias |= Ipv6Addr::from(*address)
                            .to_ipv4_mapped()
                            .is_some_and(reserved);
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

pub(super) fn put_name(wire: &mut Vec<u8>, name: &str) {
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

pub(super) fn finish_answer(
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
    let (destinations, ttl) = whitelisted_destinations(query, response_wire, response)?;
    // Flatten the authenticated CNAME chain onto the original whitelisted name.
    // Publishing an alias under a shared canonical owner would let the guest's
    // DNS cache lend that alias to unrelated names using the same CDN target.
    let mut wire = header(query, response.flags & !0x0420, destinations.len() as u16);
    let mut patches = Vec::with_capacity(destinations.len());
    for _ in &destinations {
        put_name(&mut wire, &query.question.name);
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&0u32.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        patches.push(wire.len());
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

/// Whether a direct (domestic) upstream's answer can be handed on as is
/// (decision 18). One that does not match the question, SERVFAIL or REFUSED
/// (the upstream failing or rate limiting, much like not answering), or a
/// whitelisted A answer that `finish_answer` would refuse, is asked again
/// through the chain instead. NXDOMAIN is an authoritative answer and passes.
pub(super) fn direct_answer_usable(query: &Message, answer: &[u8]) -> bool {
    let Ok(response) = Message::response(answer, query) else {
        return false;
    };
    if matches!(response.flags & 15, 2 | 5) {
        return false;
    }
    if query.question.kind != 1
        || query.dnssec
        || response.flags & 0x0200 != 0
        || response.flags & 15 != 0
        || response.answers.is_empty()
    {
        return true;
    }
    whitelisted_destinations(query, answer, &response).is_ok()
}

/// The addresses a whitelisted A answer resolves to and its shortest TTL,
/// after checking the CNAME chain from the question name, the record types,
/// the TTLs and that every address is a public destination. Assigns nothing.
fn whitelisted_destinations(
    query: &Message,
    response_wire: &[u8],
    response: &Message,
) -> Result<(Vec<Ipv4Addr>, u32), String> {
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
    let mut destinations = Vec::new();
    for record in selected.into_iter().filter(|record| record.kind == 1) {
        let ip = a_address(response_wire, record)?;
        if !public_destination(ip) {
            return Err("whitelisted DNS resolved to an unsafe IPv4 destination".into());
        }
        destinations.push(ip);
    }
    Ok((destinations, ttl))
}

pub(super) fn a_address(wire: &[u8], record: &Record) -> Result<Ipv4Addr, String> {
    let bytes: [u8; 4] = wire[record.start..record.end]
        .try_into()
        .map_err(|_| "invalid DNS A data")?;
    Ok(Ipv4Addr::from(bytes))
}

pub(super) fn reserved(ip: Ipv4Addr) -> bool {
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

/// Where a validated upstream response keeps its TTLs, and how long it may be
/// reused. Every record except EDNS OPT is listed, so a cached copy can count
/// all of them down together. A positive answer lives as long as its shortest
/// TTL. An empty answer (NXDOMAIN or no data) lives as long as the SOA in its
/// authority section allows (RFC 2308), and is not reused without one.
pub(super) struct Lifetime {
    pub(super) ttl_offsets: Vec<usize>,
    pub(super) seconds: u32,
}

pub(super) fn lifetime(wire: &[u8]) -> Result<Option<Lifetime>, String> {
    let counts = [word(wire, 6)?, word(wire, 8)?, word(wire, 10)?];
    let mut cursor = 12;
    name(wire, &mut cursor)?;
    cursor += 4;
    let mut ttl_offsets = Vec::new();
    let mut shortest = u32::MAX;
    let mut negative = None::<u32>;
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            name(wire, &mut cursor)?;
            let kind = word(wire, cursor)?;
            let ttl =
                (u32::from(word(wire, cursor + 4)?) << 16) | u32::from(word(wire, cursor + 6)?);
            let length = usize::from(word(wire, cursor + 8)?);
            let start = cursor + 10;
            let end = start
                .checked_add(length)
                .filter(|end| *end <= wire.len())
                .ok_or("truncated DNS RDATA")?;
            if kind != 41 {
                ttl_offsets.push(cursor + 4);
                shortest = shortest.min(ttl);
                if section == 1 && kind == 6 && length >= 20 {
                    let minimum =
                        (u32::from(word(wire, end - 4)?) << 16) | u32::from(word(wire, end - 2)?);
                    negative = Some(negative.unwrap_or(u32::MAX).min(ttl.min(minimum)));
                }
            }
            cursor = end;
        }
    }
    let seconds = if counts[0] > 0 {
        shortest
    } else {
        match negative {
            Some(seconds) => seconds.min(shortest),
            None => return Ok(None),
        }
    };
    Ok((seconds > 0).then_some(Lifetime {
        ttl_offsets,
        seconds,
    }))
}
