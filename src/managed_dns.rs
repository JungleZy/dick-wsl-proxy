use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Write};
use std::net::Ipv4Addr;
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
mod http;
use http::{DeadlineStream, read_http};
mod wire;
use wire::{Message, finish_answer, reserved};
mod ledger;
use ledger::AliasLedger;

/// Session-local DNS through the authenticated proxy chain. Ordinary IN queries,
/// including AAAA, pass through; IPv6 blocking belongs to the Target kernel rules.
/// Only proven whitelisted A answers with DO=0 get aliases; these carry no AD or
/// DNSSEC records. A durable digest ledger prevents alias reuse across different
/// name/IP pairs while allowing the same pair to reclaim its prior alias.
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
    // A session-local history lets the same name/IP pair reclaim its own
    // expired alias without lending that alias to another name. The durable
    // ledger still prevents reuse across controller sessions.
    history: HashMap<(String, Ipv4Addr), Ipv4Addr>,
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

impl Aliases {
    fn reap_expired(&mut self, now: Instant) {
        let expired: HashSet<_> = self
            .entries
            .iter()
            .filter_map(|(alias, entry)| (entry.expires <= now).then_some(*alias))
            .collect();
        for alias in &expired {
            self.entries.remove(alias);
        }
        self.live.retain(|_, addresses| {
            addresses.retain(|_, alias| !expired.contains(alias));
            !addresses.is_empty()
        });
    }

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
        self.reap_expired(now);
        let name = name.to_owned();
        let missing: HashSet<_> = ips
            .iter()
            .filter(|ip| {
                self.live
                    .get(&name)
                    .and_then(|addresses| addresses.get(*ip))
                    .and_then(|alias| self.entries.get(alias))
                    .is_none_or(|entry| entry.expires <= now)
            })
            .copied()
            .collect();
        let mut new_pairs = Vec::new();
        for ip in &missing {
            if self.history.contains_key(&(name.clone(), *ip)) {
                continue;
            }
            let key = AliasLedger::key(&name, *ip);
            if self.ledger.lookup(key)?.is_none() {
                new_pairs.push((*ip, key));
            }
        }
        if new_pairs.len() > MAX_ALIASES.saturating_sub(self.entries.len()) {
            return Err("DNS session alias capacity exhausted; restart session explicitly".into());
        }
        // Reserve every new number durably before changing the session table.
        // Expired aliases are reclaimed only for the same name/IP pair.
        let allocated = self.ledger.allocate(new_pairs.len())?;
        self.ledger.record(
            new_pairs
                .iter()
                .zip(allocated)
                .map(|((_, key), alias)| (*key, alias)),
        )?;
        let expires = now + Duration::from_secs(u64::from(ttl));
        let mut result = Vec::with_capacity(ips.len());
        for ip in ips {
            let previous = self
                .live
                .get(&name)
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
                _ => match self.history.get(&(name.clone(), *ip)).copied() {
                    Some(alias) => alias,
                    None => {
                        let alias = self
                            .ledger
                            .lookup(AliasLedger::key(&name, *ip))?
                            .ok_or("DNS alias mapping missing after durable reservation")?;
                        self.history.insert((name.clone(), *ip), alias);
                        self.live
                            .entry(name.clone())
                            .or_default()
                            .insert(*ip, alias);
                        alias
                    }
                },
            };
            if !self.entries.contains_key(&alias) {
                self.entries.insert(alias, Alias { real: *ip, expires });
                self.live
                    .entry(name.clone())
                    .or_default()
                    .insert(*ip, alias);
            }
            self.entries
                .get_mut(&alias)
                .expect("assigned DNS alias exists")
                .expires = expires;
            result.push(alias);
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests;
