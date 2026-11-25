//! fake-ip: non-allowlisted A queries are answered at once with an address
//! from the top of the reserved range, and the residential proxy resolves the
//! name when a connection to that address is chained. See
//! docs/discussions/2026-11-24-fake-ip-非白名单域名交给住宅代理解析.md.
use super::cache::question_length;
use super::wire::Message;
use super::{ALIAS_SPACE, ALIAS_START};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// The alias ledger's offsets below the fake range: the lower half.
pub(super) const LEDGER_FLOOR: u32 = 65_535;
/// Fewer free fake addresses than this and fake-ip is not used.
const MIN_FAKE_ADDRESSES: u32 = 4_096;
/// A fake address is handed to another name only after this long unused.
const COOLDOWN: Duration = Duration::from_secs(600);
/// TTL of a fake answer, so resolvers ask again rather than keep it.
const FAKE_TTL: u32 = 1;
/// Names under these never get a fake address.
const SPECIAL_SUFFIXES: [&str; 9] = [
    "local",
    "localhost",
    "internal",
    "lan",
    "home.arpa",
    "arpa",
    "invalid",
    "test",
    "onion",
];

struct Entry {
    name: String,
    last_used: Instant,
    /// Relayed connections still using this address.
    leases: usize,
    /// Whether any connection has used this address in this takeover. Such
    /// an address is never given to another name: a program that kept it
    /// would reach that other name instead (decision 19).
    connected: bool,
}

/// Session-only name and fake-address mapping, allocated downwards between
/// `low` and the top of the reserved range. Each session starts at a random
/// point and wraps at `low`, so an address an application kept from an
/// earlier session is unlikely to name another host so soon.
pub(super) struct FakePool {
    low: u32,
    high: u32,
    next: u32,
    /// Addresses never handed out yet in this session.
    unused: u32,
    by_name: HashMap<String, u32>,
    by_address: HashMap<u32, Entry>,
    reclaimed: u64,
}

impl FakePool {
    /// A pool above `boundary`, the alias ledger's upper offset, starting at
    /// a random point. `None` when that leaves fewer than
    /// `MIN_FAKE_ADDRESSES`.
    pub(super) fn above(boundary: u32) -> Option<Self> {
        use std::hash::{BuildHasher, Hasher};
        let mut seed = std::collections::hash_map::RandomState::new().build_hasher();
        if let Ok(since) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            seed.write_u128(since.as_nanos());
        }
        Self::starting(boundary, seed.finish())
    }

    /// `above`, starting `offset` (modulo the size) below the top.
    pub(super) fn starting(boundary: u32, offset: u64) -> Option<Self> {
        let high = ALIAS_START + ALIAS_SPACE - 1;
        let low = ALIAS_START.checked_add(boundary)?;
        if low > high || high - low + 1 < MIN_FAKE_ADDRESSES {
            return None;
        }
        let size = high - low + 1;
        let offset = u32::try_from(offset % u64::from(size)).ok()?;
        Some(Self {
            low,
            high,
            next: high - offset,
            unused: size,
            by_name: HashMap::new(),
            by_address: HashMap::new(),
            reclaimed: 0,
        })
    }

    pub(super) fn contains(&self, address: Ipv4Addr) -> bool {
        (self.low..=self.high).contains(&u32::from(address))
    }

    pub(super) fn capacity(&self) -> u32 {
        self.high - self.low + 1
    }

    pub(super) fn in_use(&self) -> usize {
        self.by_address.len()
    }

    pub(super) fn reclaimed(&self) -> u64 {
        self.reclaimed
    }

    /// The fake address for `name`, the same one for as long as it stays
    /// mapped. `None` when the range is full and nothing can be reclaimed.
    pub(super) fn assign(&mut self, name: &str, now: Instant) -> Option<Ipv4Addr> {
        if let Some(address) = self.by_name.get(name).copied() {
            if let Some(entry) = self.by_address.get_mut(&address) {
                entry.last_used = now;
            }
            return Some(Ipv4Addr::from(address));
        }
        let address = if self.unused > 0 {
            let address = self.next;
            self.unused -= 1;
            self.next = if address == self.low {
                self.high
            } else {
                address - 1
            };
            address
        } else {
            self.reclaim(now)?
        };
        self.by_name.insert(name.to_owned(), address);
        self.by_address.insert(
            address,
            Entry {
                name: name.to_owned(),
                last_used: now,
                leases: 0,
                connected: false,
            },
        );
        Some(Ipv4Addr::from(address))
    }

    /// Frees the least recently used address that has been idle past the
    /// cooldown and has never carried a connection. Only resolved-but-unused
    /// names give theirs up, so a flood of new names cannot steer an address
    /// a program still remembers to another name.
    fn reclaim(&mut self, now: Instant) -> Option<u32> {
        let (&address, _) = self
            .by_address
            .iter()
            .filter(|(_, entry)| {
                !entry.connected
                    && entry.leases == 0
                    && now.saturating_duration_since(entry.last_used) >= COOLDOWN
            })
            .min_by_key(|(_, entry)| entry.last_used)?;
        let entry = self.by_address.remove(&address)?;
        self.by_name.remove(&entry.name);
        self.reclaimed += 1;
        Some(address)
    }

    /// The name behind `address`, marking it used.
    pub(super) fn name(&mut self, address: Ipv4Addr, now: Instant) -> Option<String> {
        let entry = self.by_address.get_mut(&u32::from(address))?;
        entry.last_used = now;
        Some(entry.name.clone())
    }

    /// Like `name`, and keeps the address from being reclaimed until `release`.
    pub(super) fn lease(&mut self, address: Ipv4Addr, now: Instant) -> Option<String> {
        let entry = self.by_address.get_mut(&u32::from(address))?;
        entry.last_used = now;
        entry.leases += 1;
        entry.connected = true;
        Some(entry.name.clone())
    }

    pub(super) fn release(&mut self, address: Ipv4Addr, now: Instant) {
        if let Some(entry) = self.by_address.get_mut(&u32::from(address)) {
            entry.leases = entry.leases.saturating_sub(1);
            entry.last_used = now;
        }
    }
}

/// Names that keep real resolution: single labels, names under the
/// resolver's search suffixes, and special-use suffixes.
pub(super) fn excluded(name: &str, search: &[String]) -> bool {
    let under = |suffix: &str| {
        name == suffix
            || (name.len() > suffix.len()
                && name.ends_with(suffix)
                && name.as_bytes()[name.len() - suffix.len() - 1] == b'.')
    };
    !name.contains('.')
        || SPECIAL_SUFFIXES.iter().any(|suffix| under(suffix))
        || search.iter().any(|suffix| under(suffix))
}

/// A response header and the query's own question bytes.
fn header(query_wire: &[u8], query: &Message, answers: u16) -> Option<Vec<u8>> {
    let question_end = 12 + question_length(query_wire)?;
    let mut wire = Vec::with_capacity(question_end + 16);
    // QR and RA, with the query's RD and CD; NOERROR.
    let flags = 0x8080 | (query.flags & 0x0110);
    for value in [query.id, flags, 1, answers, 0, 0] {
        wire.extend_from_slice(&value.to_be_bytes());
    }
    wire.extend_from_slice(&query_wire[12..question_end]);
    Some(wire)
}

/// One A record for the question name, pointing at `address`.
pub(super) fn address_answer(
    query_wire: &[u8],
    query: &Message,
    address: Ipv4Addr,
) -> Option<Vec<u8>> {
    let mut wire = header(query_wire, query, 1)?;
    wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
    wire.extend_from_slice(&FAKE_TTL.to_be_bytes());
    wire.extend_from_slice(&[0, 4]);
    wire.extend_from_slice(&address.octets());
    Some(wire)
}

/// NOERROR with no records: the name has no data of this type.
pub(super) fn empty_answer(query_wire: &[u8], query: &Message) -> Option<Vec<u8>> {
    header(query_wire, query, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_dns::wire::{a_address, put_name};

    fn query(name: &str, kind: u16, flags: u16) -> Vec<u8> {
        let mut wire = vec![0x12, 0x34];
        wire.extend_from_slice(&flags.to_be_bytes());
        wire.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        put_name(&mut wire, name);
        wire.extend_from_slice(&kind.to_be_bytes());
        wire.extend_from_slice(&[0, 1]);
        wire
    }

    #[test]
    fn addresses_go_down_from_the_start_and_stay_with_their_name() {
        let mut pool = FakePool::starting(LEDGER_FLOOR, 0).unwrap();
        assert_eq!(pool.capacity(), 65_535);
        let now = Instant::now();
        let first = pool.assign("one.example", now).unwrap();
        let second = pool.assign("two.example", now).unwrap();
        assert_eq!(first, Ipv4Addr::new(198, 19, 255, 254));
        assert_eq!(second, Ipv4Addr::new(198, 19, 255, 253));
        assert_eq!(pool.assign("one.example", now), Some(first));
        assert_eq!(pool.name(second, now).as_deref(), Some("two.example"));
        assert!(pool.contains(first));
        assert!(pool.contains(Ipv4Addr::new(198, 19, 0, 0)));
        // The lower half belongs to the alias ledger.
        assert!(!pool.contains(Ipv4Addr::new(198, 18, 255, 255)));
        assert_eq!(pool.name(Ipv4Addr::new(198, 19, 0, 9), now), None);
        // Too little room above the ledger: no pool at all.
        assert!(FakePool::above(ALIAS_SPACE - MIN_FAKE_ADDRESSES + 1).is_none());
    }

    #[test]
    fn a_full_pool_reclaims_only_idle_never_connected_addresses() {
        let mut pool = FakePool::starting(ALIAS_SPACE - MIN_FAKE_ADDRESSES, 0).unwrap();
        assert_eq!(pool.capacity(), MIN_FAKE_ADDRESSES);
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let mut addresses = Vec::new();
        for index in 0..u64::from(MIN_FAKE_ADDRESSES) {
            addresses.push(
                pool.assign(&format!("n{index}.example"), at(index))
                    .unwrap(),
            );
        }
        // The oldest is in use by a connection.
        assert_eq!(
            pool.lease(addresses[0], at(5_000)).as_deref(),
            Some("n0.example")
        );
        // Full, and nothing has cooled down yet.
        assert_eq!(pool.assign("new.example", at(10_000)), None);
        // After the cooldown the least recently used unleased one goes.
        let later = at(5_000) + COOLDOWN;
        let reused = pool.assign("new.example", later).unwrap();
        assert_eq!(reused, addresses[1]);
        assert_eq!(pool.reclaimed(), 1);
        assert_eq!(pool.name(reused, later).as_deref(), Some("new.example"));
        assert_eq!(
            pool.name(addresses[0], later).as_deref(),
            Some("n0.example")
        );
        assert_eq!(pool.in_use(), MIN_FAKE_ADDRESSES as usize);
        // Released and cooled down, it still stays with its name: it has
        // carried a connection, and a program that kept the address must not
        // reach another name. Only the never-connected ones are reclaimed.
        pool.release(addresses[0], later);
        let much_later = later + COOLDOWN;
        let taken: Vec<_> = (0..MIN_FAKE_ADDRESSES)
            .filter_map(|index| pool.assign(&format!("m{index}.example"), much_later))
            .collect();
        assert!(!taken.contains(&addresses[0]));
        assert_eq!(taken.len(), MIN_FAKE_ADDRESSES as usize - 1);
        assert_eq!(
            pool.name(addresses[0], much_later).as_deref(),
            Some("n0.example")
        );
    }

    #[test]
    fn a_session_starts_anywhere_and_wraps_at_the_bottom_of_the_range() {
        let now = Instant::now();
        // Two addresses above the bottom: the third wraps to the top.
        let size = u64::from(MIN_FAKE_ADDRESSES);
        let mut pool = FakePool::starting(ALIAS_SPACE - MIN_FAKE_ADDRESSES, size - 2).unwrap();
        let bottom = ALIAS_START + ALIAS_SPACE - MIN_FAKE_ADDRESSES;
        let got: Vec<u32> = (0..3)
            .map(|i| u32::from(pool.assign(&format!("w{i}.example"), now).unwrap()))
            .collect();
        assert_eq!(got, [bottom + 1, bottom, ALIAS_START + ALIAS_SPACE - 1]);
        // Every address is handed out once before any reclaim is needed.
        for i in 3..MIN_FAKE_ADDRESSES {
            pool.assign(&format!("w{i}.example"), now).unwrap();
        }
        assert_eq!(pool.in_use(), MIN_FAKE_ADDRESSES as usize);
        assert_eq!(pool.assign("one-more.example", now), None);
        // Separate sessions rarely start at the same point.
        let starts: std::collections::HashSet<_> = (0..8)
            .map(|_| {
                FakePool::above(LEDGER_FLOOR)
                    .unwrap()
                    .assign("same.example", now)
                    .unwrap()
            })
            .collect();
        assert!(starts.len() > 1);
    }

    #[test]
    fn local_and_special_names_keep_real_resolution() {
        let search = ["corp.example".to_owned()];
        for name in [
            "localhost",
            "printer",
            "nas.local",
            "router.lan",
            "box.home.arpa",
            "4.3.2.1.in-addr.arpa",
            "db.internal",
            "x.test",
            "corp.example",
            "git.corp.example",
        ] {
            assert!(excluded(name, &search), "{name}");
        }
        for name in ["example.com", "notcorp.example", "local.example.com"] {
            assert!(!excluded(name, &search), "{name}");
        }
        // Names a chain cannot carry are left to real resolution by the
        // resolver as well.
        assert!(!crate::policy::valid_chain_name("bad name.example"));
        assert!(crate::policy::valid_chain_name("_dmarc.example.com"));
    }

    /// A made answer read back as the guest would: same ID and question,
    /// QR set, RD and CD as asked, NOERROR. (`Message::response` is the
    /// upstream check, which refuses reserved addresses on purpose.)
    fn read_back(answer: &[u8], query: &Message) -> Message {
        let parsed = Message::parse(answer).unwrap();
        assert_eq!(parsed.id, query.id);
        assert!(parsed.question == query.question);
        assert_eq!(parsed.flags & 0x8000, 0x8000);
        assert_eq!(parsed.flags & 0x0110, query.flags & 0x0110);
        assert_eq!(parsed.flags & 0x000f, 0);
        parsed
    }

    #[test]
    fn made_answers_match_their_query() {
        // RD and CD come back; the address carries a one-second TTL.
        let wire = query("Media.Example.com", 1, 0x0110);
        let message = Message::query(&wire).unwrap();
        let address = Ipv4Addr::new(198, 19, 255, 254);
        let answer = address_answer(&wire, &message, address).unwrap();
        let parsed = read_back(&answer, &message);
        assert_eq!(parsed.flags & 0x0110, 0x0110);
        assert_eq!(parsed.flags & 0x000f, 0);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].ttl, FAKE_TTL);
        assert_eq!(a_address(&answer, &parsed.answers[0]).unwrap(), address);
        // The question's letter case is the query's own.
        assert_eq!(&answer[12..answer.len() - 16], &wire[12..]);

        let wire = query("media.example.com", 28, 0x0100);
        let message = Message::query(&wire).unwrap();
        let empty = empty_answer(&wire, &message).unwrap();
        // No address in it, so the upstream check passes too.
        assert!(Message::response(&empty, &message).is_ok());
        assert!(read_back(&empty, &message).answers.is_empty());
    }
}
