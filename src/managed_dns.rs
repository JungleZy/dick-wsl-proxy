use std::collections::{HashMap, HashSet, VecDeque, hash_map::Entry};
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use native_tls::{Protocol, TlsConnector};

const MAX_DNS: usize = 65_535;
const MAX_RECORDS: usize = 128;
const MAX_ALIASES: usize = 16_384;
const MAX_TTL: u32 = 300;
const IO_DEADLINE: Duration = Duration::from_secs(10);
/// A kept connection that a hop dropped without closing it would otherwise
/// hold the query for the whole I/O deadline before the fresh retry; guest
/// resolvers give up after about five seconds.
const REUSED_IO_DEADLINE: Duration = Duration::from_secs(4);
/// A direct upstream that does not accept quickly is treated as failed, and
/// the query goes through the chain instead.
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// An idle DoH connection is reused only this long; upstreams and proxy hops
/// close quiet keep-alives on their own schedule. Connections idle for 21-26 s
/// were measured to still work over the real chain; one that a hop has closed
/// fails on reuse and the query goes out once more on a fresh connection.
const UPSTREAM_IDLE: Duration = Duration::from_secs(120);
/// As many as one route runs exchanges at once, so a burst's connections
/// stay ready for the next one.
const MAX_IDLE_UPSTREAMS: usize = flights::MAX_ACTIVE;
/// Queries per connection before a fresh chain is built.
const MAX_UPSTREAM_USES: u32 = 100;
/// Background refreshes of stale answers running at once. Each is a thread
/// that may wait on the chain; past this many a stale answer is served
/// without starting another.
const MAX_REFRESHES: usize = 32;
const ALIAS_START: u32 = u32::from_be_bytes([198, 18, 0, 1]);
const ALIAS_SPACE: u32 = 131_070;
const ALIAS_BLOCK: u32 = 32;
mod http;
#[cfg(test)]
use http::read_http;
use http::{DeadlineStream, post_query};
mod wire;
use wire::{Message, direct_answer_usable, finish_answer, reserved};
mod ledger;
use ledger::AliasLedger;
mod cache;
use cache::{Cache, Key};
mod flights;
use flights::{Flights, Slots};
mod fake;
use fake::FakePool;

pub fn reset_aliases() -> Result<(), String> {
    AliasLedger::reset()
}

/// Session-local DNS through the authenticated proxy chain. Ordinary IN queries,
/// including AAAA, pass through; IPv6 blocking belongs to the Target kernel rules.
/// With fake-ip on, non-whitelisted A queries are answered here with a fake
/// address that the ingress chains by name, and their AAAA, SVCB and HTTPS
/// queries with no data; excluded names, probes and DO queries still pass
/// through. Only proven whitelisted A answers with DO=0 get aliases; these
/// carry no AD or DNSSEC records. A durable digest ledger prevents alias reuse across different
/// name/IP pairs while allowing the same pair to reclaim its prior alias.
pub struct ManagedDns {
    resolver: Arc<Resolver>,
}

impl ManagedDns {
    pub fn new(policy: Arc<crate::policy::Policy>) -> Result<Self, String> {
        Ok(Self {
            resolver: Arc::new(Resolver::new(policy)?),
        })
    }

    pub fn arm_probe(&self, name: &str) -> Result<(), String> {
        self.resolver.arm_probe(name)
    }

    pub fn probe_seen(&self) -> bool {
        self.resolver.probe_seen()
    }

    pub fn answer(&self, wire: &[u8]) -> Result<Vec<u8>, String> {
        self.resolver.answer_for(wire, true)
    }

    pub fn answer_tcp(&self, wire: &[u8]) -> Result<Vec<u8>, String> {
        self.resolver.answer_for(wire, false)
    }

    pub fn direct_alias(&self, ip: Ipv4Addr) -> Result<Option<Ipv4Addr>, String> {
        self.resolver.direct_alias(ip)
    }

    /// What managed DNS did since this takeover started.
    pub fn report(&self) -> serde_json::Value {
        self.resolver.report()
    }

    /// Search suffixes from the target's resolver configuration: names under
    /// them keep real resolution.
    pub(crate) fn set_search_suffixes(&self, suffixes: Vec<String>) {
        *lock(&self.resolver.search) = suffixes;
    }

    /// Starts or stops answering with fake addresses. Starting fails, with
    /// the reason, when the alias ledger leaves too little room.
    pub(crate) fn set_fake_ip(&self, enabled: bool) -> Result<(), String> {
        if enabled && lock(&self.resolver.fake).is_none() {
            return Err(lock(&self.resolver.fake_unavailable)
                .clone()
                .unwrap_or_else(|| "fake-ip unavailable".into()));
        }
        self.resolver.fake_enabled.store(enabled, Ordering::Release);
        Ok(())
    }

    /// Why fake-ip cannot start in this session, if it cannot.
    pub(crate) fn fake_pool_unavailable(&self) -> Option<String> {
        if lock(&self.resolver.fake).is_some() {
            return None;
        }
        Some(
            lock(&self.resolver.fake_unavailable)
                .clone()
                .unwrap_or_else(|| "fake-ip unavailable".into()),
        )
    }

    /// The fake address `name` gets, as an A query for it would.
    #[cfg(test)]
    pub(crate) fn assign_fake(&self, name: &str) -> Option<Ipv4Addr> {
        lock(&self.resolver.fake)
            .as_mut()?
            .assign(name, Instant::now())
    }

    #[cfg(test)]
    pub(crate) fn fake_ip_active(&self) -> bool {
        self.resolver.fake_enabled.load(Ordering::Acquire)
    }

    /// Whether `address` is in this session's fake range.
    pub(crate) fn is_fake(&self, address: Ipv4Addr) -> bool {
        self.resolver.is_fake(address)
    }

    /// The name behind a fake address, marking it used.
    pub(crate) fn fake_name(&self, address: Ipv4Addr) -> Option<String> {
        lock(&self.resolver.fake)
            .as_mut()?
            .name(address, Instant::now())
    }

    /// The name behind a fake address, kept from reclamation while the
    /// returned lease lives.
    pub(crate) fn fake_lease(&self, address: Ipv4Addr) -> Option<(String, FakeLease)> {
        let name = lock(&self.resolver.fake)
            .as_mut()?
            .lease(address, Instant::now())?;
        Some((
            name,
            FakeLease {
                resolver: Arc::clone(&self.resolver),
                address,
            },
        ))
    }

    /// Diagnostic only: the A records the managed path returns for `name`,
    /// session aliases left out.
    pub(crate) fn resolve_ipv4(&self, name: &str) -> Result<Vec<Ipv4Addr>, String> {
        let mut query = vec![0x51, 0x70, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        wire::put_name(&mut query, name);
        query.extend_from_slice(&[0, 1, 0, 1]);
        Message::query(&query)?;
        let response = self.answer_tcp(&query)?;
        let parsed = Message::parse(&response)?;
        Ok(parsed
            .answers
            .iter()
            .filter(|record| record.kind == 1)
            .filter_map(|record| wire::a_address(&response, record).ok())
            .filter(|address| !reserved(*address))
            .collect())
    }
}

/// Keeps a fake address from being handed to another name while a relayed
/// connection uses it.
pub(crate) struct FakeLease {
    resolver: Arc<Resolver>,
    address: Ipv4Addr,
}

impl Drop for FakeLease {
    fn drop(&mut self) {
        if let Some(pool) = lock(&self.resolver.fake).as_mut() {
            pool.release(self.address, Instant::now());
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// The state behind `ManagedDns`, shared with background refreshes.
struct Resolver {
    policy: Arc<crate::policy::Policy>,
    tls: TlsConnector,
    aliases: Mutex<Aliases>,
    probe: Mutex<Probe>,
    upstreams: IdlePool<Upstream>,
    /// Connections to the direct DoH upstream for whitelisted names.
    direct_upstreams: IdlePool<Upstream>,
    /// Validated upstream answers, reused until their TTL runs out.
    answers: Cache,
    /// Identical queries in flight share one exchange.
    flights: Flights,
    /// Exchanges at once on the chain and on the direct upstream.
    chain_slots: Slots,
    direct_slots: Slots,
    stats: Stats,
    /// Questions whose stale answer is being refreshed in the background.
    refreshing: Mutex<HashSet<Key>>,
    /// fake-ip: the address pool, whether answers use it now, and why it is
    /// unavailable when it is.
    fake: Mutex<Option<FakePool>>,
    fake_enabled: AtomicBool,
    fake_unavailable: Mutex<Option<String>>,
    search: Mutex<Vec<String>>,
}

/// What managed DNS did, for the status report.
#[derive(Default)]
struct Stats {
    cache_hits: AtomicU64,
    /// Expired answers served while a refresh ran.
    stale_served: AtomicU64,
    refreshes: AtomicU64,
    refresh_failures: AtomicU64,
    /// Refreshes not started because `MAX_REFRESHES` were already running.
    refresh_skips: AtomicU64,
    upstream_asks: AtomicU64,
    reused: AtomicU64,
    /// Idle connections that failed when reused; a fresh one followed.
    stale_reuses: AtomicU64,
    fresh_connections: AtomicU64,
    connect_failures: AtomicU64,
    fake_answers: AtomicU64,
    fake_empty: AtomicU64,
    fake_excluded: AtomicU64,
    fake_exhausted: AtomicU64,
    /// The latest upstream exchanges, newest last.
    recent: Mutex<VecDeque<serde_json::Value>>,
}

impl Stats {
    fn record(&self, entry: serde_json::Value) {
        let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        if recent.len() == 32 {
            recent.pop_front();
        }
        recent.push_back(entry);
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Where a query is sent. Whitelisted names go to the direct DoH upstream so
/// they resolve to the addresses the direct path should use; everything else,
/// and a whitelisted name whose direct upstream fails, goes through the chain.
#[derive(Clone, Copy)]
enum Route<'a> {
    Chain,
    Direct(std::net::SocketAddrV4, &'a str),
}

/// One verified DoH connection over the proxy chain, kept for the next query.
struct Upstream {
    reader: BufReader<native_tls::TlsStream<DeadlineStream>>,
    uses: u32,
}

/// Idle connections, most recent last. Expired ones are dropped on every use.
struct IdlePool<T> {
    idle: Mutex<Vec<(T, Instant)>>,
}

impl<T> IdlePool<T> {
    fn new() -> Self {
        Self {
            idle: Mutex::new(Vec::new()),
        }
    }

    /// The most recent idle item and how long it was idle.
    fn take(&self, now: Instant) -> Option<(T, Duration)> {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        idle.retain(|(_, since)| now.saturating_duration_since(*since) < UPSTREAM_IDLE);
        idle.pop()
            .map(|(item, since)| (item, now.saturating_duration_since(since)))
    }

    fn put(&self, item: T, now: Instant) {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        idle.retain(|(_, since)| now.saturating_duration_since(*since) < UPSTREAM_IDLE);
        if idle.len() < MAX_IDLE_UPSTREAMS {
            idle.push((item, now));
        }
    }
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

impl Resolver {
    fn new(policy: Arc<crate::policy::Policy>) -> Result<Self, String> {
        let mut builder = TlsConnector::builder();
        builder.min_protocol_version(Some(Protocol::Tlsv12));
        let tls = builder
            .build()
            .map_err(|e| format!("build DNS TLS connector: {e}"))?;
        // Fake addresses take the upper half of the reserved range, and the
        // durable alias ledger stays in the lower half for this session.
        // Only when fake-ip may be used: otherwise, or when the ledger has
        // already gone past the lower half, the ledger keeps the whole range.
        let mut aliases = Aliases::default();
        let (fake, fake_unavailable) = if !policy.fake_ip() {
            (None, Some("fake_ip_off_in_policy".to_owned()))
        } else {
            match ledger::current_high() {
                Ok(high) if high <= fake::LEDGER_FLOOR => {
                    match FakePool::above(fake::LEDGER_FLOOR) {
                        Some(pool) => {
                            aliases.ledger.limit = Some(fake::LEDGER_FLOOR);
                            (Some(pool), None)
                        }
                        None => (None, Some("fake_ip_range_unavailable".to_owned())),
                    }
                }
                Ok(_) => (
                    None,
                    Some(
                        "fake_ip_range_in_use: the DNS alias ledger already uses the upper half"
                            .to_owned(),
                    ),
                ),
                Err(error) => (None, Some(format!("fake_ip_ledger_unreadable: {error}"))),
            }
        };
        Ok(Self {
            policy,
            tls,
            aliases: Mutex::new(aliases),
            probe: Mutex::new(Probe::default()),
            upstreams: IdlePool::new(),
            direct_upstreams: IdlePool::new(),
            answers: Cache::default(),
            flights: Flights::default(),
            chain_slots: Slots::default(),
            direct_slots: Slots::default(),
            stats: Stats::default(),
            refreshing: Mutex::new(HashSet::new()),
            fake: Mutex::new(fake),
            fake_enabled: AtomicBool::new(false),
            fake_unavailable: Mutex::new(fake_unavailable),
            search: Mutex::new(Vec::new()),
        })
    }

    fn is_fake(&self, address: Ipv4Addr) -> bool {
        lock(&self.fake)
            .as_ref()
            .is_some_and(|pool| pool.contains(address))
    }

    /// An answer made here instead of upstream: a fake address for a
    /// non-allowlisted A query, or no data for its AAAA, SVCB and HTTPS
    /// queries. `None` leaves the query to the upstream path.
    fn fake_answer(&self, query: &Message, wire: &[u8]) -> Option<Vec<u8>> {
        if !self.fake_enabled.load(Ordering::Acquire)
            || query.question.class != 1
            || query.dnssec
            || !matches!(query.question.kind, 1 | 28 | 64 | 65)
            || self.policy.allows_domain(&query.question.name)
        {
            return None;
        }
        // Names the chain could not carry keep real resolution too.
        if fake::excluded(&query.question.name, &lock(&self.search))
            || !crate::policy::valid_chain_name(&query.question.name)
        {
            self.stats.fake_excluded.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if query.question.kind != 1 {
            self.stats.fake_empty.fetch_add(1, Ordering::Relaxed);
            return fake::empty_answer(wire, query);
        }
        let address = lock(&self.fake)
            .as_mut()?
            .assign(&query.question.name, Instant::now());
        match address {
            Some(address) => {
                self.stats.fake_answers.fetch_add(1, Ordering::Relaxed);
                fake::address_answer(wire, query, address)
            }
            None => {
                self.stats.fake_exhausted.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    fn arm_probe(&self, name: &str) -> Result<(), String> {
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

    fn probe_seen(&self) -> bool {
        self.probe.lock().map(|probe| probe.seen).unwrap_or(false)
    }

    fn answer_for(self: &Arc<Self>, wire: &[u8], udp: bool) -> Result<Vec<u8>, String> {
        let query = Message::query(wire)?;
        let direct = query.question.kind == 1
            && !query.dnssec
            && self.policy.allows_domain(&query.question.name);
        let limit = if udp { query.udp_size } else { MAX_DNS };
        // The readiness probe must reach the upstream through the chain, so
        // its name never comes from the cache.
        let probing = self
            .probe
            .lock()
            .map_err(|_| "DNS probe lock poisoned")?
            .name
            .as_deref()
            == Some(query.question.name.as_str());
        if !probing && let Some(answer) = self.fake_answer(&query, wire) {
            return Ok(answer);
        }
        let key = Key::new(
            &query.question.name,
            query.question.kind,
            query.question.class,
            query.flags,
            query.dnssec,
        );
        let now = Instant::now();
        let cached = if probing {
            None
        } else {
            self.answers.lookup(&key, wire, now)
        };
        let fresh = cached.is_none();
        let cached = cached.map(|hit| {
            if hit.stale {
                // Answer now with the expired record and refresh it once in
                // the background, rather than make this query wait for it.
                self.stats.stale_served.fetch_add(1, Ordering::Relaxed);
                self.refresh(key.clone(), wire.to_vec());
            } else {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            }
            hit.wire
        });
        let response_wire = match cached {
            Some(response_wire) => response_wire,
            // The probe must make its own trip through the chain.
            None if probing => self.ask_upstream(&query, wire)?,
            None => self
                .flights
                .run(&key, wire, || self.ask_upstream(&query, wire))?,
        };
        let response = Message::response(&response_wire, &query)?;
        let answer = finish_answer(
            &query,
            &response_wire,
            &response,
            direct,
            &self.aliases,
            limit,
        )?;
        if fresh {
            self.answers.put(key, &response_wire, now);
        }
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

    /// Asks the upstream again for a question whose cached answer has
    /// expired, at most once at a time, and caches what comes back.
    fn refresh(self: &Arc<Self>, key: Key, wire: Vec<u8>) {
        if !self.claim_refresh(&key) {
            return;
        }
        let resolver = Arc::clone(self);
        let refreshed = key.clone();
        let spawned = std::thread::Builder::new()
            .name("dns-refresh".into())
            .spawn(move || {
                let key = refreshed;
                let outcome = (|| {
                    let query = Message::query(&wire)?;
                    let answer = resolver
                        .flights
                        .run(&key, &wire, || resolver.ask_upstream(&query, &wire))?;
                    Message::response(&answer, &query)?;
                    resolver
                        .answers
                        .refresh(key.clone(), &answer, Instant::now());
                    Ok::<(), String>(())
                })();
                let counter = if outcome.is_ok() {
                    &resolver.stats.refreshes
                } else {
                    &resolver.stats.refresh_failures
                };
                counter.fetch_add(1, Ordering::Relaxed);
                resolver
                    .refreshing
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&key);
            });
        if spawned.is_err() {
            self.stats.refresh_failures.fetch_add(1, Ordering::Relaxed);
            self.refreshing
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
        }
    }

    /// Marks `key` as being refreshed. False when it already is, or when
    /// `MAX_REFRESHES` refreshes already run: that one is skipped, the stale
    /// answer is still served, and the next query for it tries again.
    fn claim_refresh(&self, key: &Key) -> bool {
        let mut refreshing = self.refreshing.lock().unwrap_or_else(|e| e.into_inner());
        if refreshing.contains(key) {
            return false;
        }
        if refreshing.len() >= MAX_REFRESHES {
            self.stats.refresh_skips.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        refreshing.insert(key.clone())
    }

    fn direct_alias(&self, ip: Ipv4Addr) -> Result<Option<Ipv4Addr>, String> {
        // A fake address is not an alias: it is chained by name, never direct.
        if self.is_fake(ip) {
            return Ok(None);
        }
        self.aliases
            .lock()
            .map_err(|_| "DNS alias table lock poisoned".to_string())?
            .lookup(ip, Instant::now())
    }

    fn ask_upstream(&self, query: &Message, wire: &[u8]) -> Result<Vec<u8>, String> {
        self.stats.upstream_asks.fetch_add(1, Ordering::Relaxed);
        match self
            .policy
            .direct_dns()
            .filter(|_| self.policy.allows_domain(&query.question.name))
        {
            // A direct upstream that fails or answers something unusable
            // falls back to the chain, never to a local resolver.
            Some((upstream, name)) => self
                .exchange_via(Route::Direct(upstream, name), wire)
                .ok()
                .filter(|answer| direct_answer_usable(query, answer))
                .map_or_else(|| self.exchange_via(Route::Chain, wire), Ok),
            None => self.exchange_via(Route::Chain, wire),
        }
    }

    fn pool(&self, route: Route) -> &IdlePool<Upstream> {
        match route {
            Route::Chain => &self.upstreams,
            Route::Direct(..) => &self.direct_upstreams,
        }
    }

    fn tls_name<'a>(&'a self, route: Route<'a>) -> &'a str {
        match route {
            Route::Chain => self.policy.dns_tls_name(),
            Route::Direct(_, name) => name,
        }
    }

    fn exchange_via(&self, route: Route, wire: &[u8]) -> Result<Vec<u8>, String> {
        // A bounded number of exchanges per route: a later query takes the
        // connection an earlier one hands back instead of opening its own.
        let waiting = Instant::now();
        let _slot = match route {
            Route::Chain => self.chain_slots.acquire(),
            Route::Direct(..) => self.direct_slots.acquire(),
        };
        let started = Instant::now();
        let slot_wait = started.saturating_duration_since(waiting);
        let name = match route {
            Route::Chain => "chain",
            Route::Direct(..) => "direct",
        };
        let mut stale = None;
        if let Some((upstream, idle)) = self.pool(route).take(started) {
            match self.exchange_on(route, upstream, wire, REUSED_IO_DEADLINE) {
                Ok(answer) => {
                    self.stats.reused.fetch_add(1, Ordering::Relaxed);
                    self.stats.record(serde_json::json!({
                        "route": name, "kind": "reused", "ms": millis(started.elapsed()),
                        "idle_ms": millis(idle), "slot_wait_ms": millis(slot_wait),
                    }));
                    return Ok(answer);
                }
                Err(_) => {
                    self.stats.stale_reuses.fetch_add(1, Ordering::Relaxed);
                    stale = Some((idle, started.elapsed()));
                }
            }
        }
        // No idle connection, or the upstream or a proxy hop closed it while it
        // was idle. A DNS query is idempotent: send it once more on a fresh connection.
        self.stats.fresh_connections.fetch_add(1, Ordering::Relaxed);
        let result = self
            .connect_upstream(route)
            .inspect_err(|_| {
                self.stats.connect_failures.fetch_add(1, Ordering::Relaxed);
            })
            .and_then(|upstream| self.exchange_on(route, upstream, wire, IO_DEADLINE));
        self.stats.record(serde_json::json!({
            "route": name,
            "kind": if stale.is_some() { "stale_then_fresh" } else { "fresh" },
            "ms": millis(started.elapsed()),
            "stale_idle_ms": stale.map(|(idle, _)| millis(idle)),
            "stale_wasted_ms": stale.map(|(_, wasted)| millis(wasted)),
            "slot_wait_ms": millis(slot_wait),
            "ok": result.is_ok(),
        }));
        result
    }

    fn report(&self) -> serde_json::Value {
        let count = |value: &AtomicU64| value.load(Ordering::Relaxed);
        let idle =
            |pool: &IdlePool<Upstream>| pool.idle.lock().unwrap_or_else(|e| e.into_inner()).len();
        serde_json::json!({
            "cache_hits": count(&self.stats.cache_hits),
            "stale_served": count(&self.stats.stale_served),
            "refreshes": count(&self.stats.refreshes),
            "refresh_failures": count(&self.stats.refresh_failures),
            "refresh_skips": count(&self.stats.refresh_skips),
            "shared_waits": self.flights.joined(),
            "upstream_asks": count(&self.stats.upstream_asks),
            "reused": count(&self.stats.reused),
            "stale_reuses": count(&self.stats.stale_reuses),
            "fresh_connections": count(&self.stats.fresh_connections),
            "connect_failures": count(&self.stats.connect_failures),
            "fake_ip": {
                "active": self.fake_enabled.load(Ordering::Acquire),
                "unavailable": lock(&self.fake_unavailable).clone(),
                "capacity": lock(&self.fake).as_ref().map(FakePool::capacity),
                "in_use": lock(&self.fake).as_ref().map(FakePool::in_use),
                "reclaimed": lock(&self.fake).as_ref().map(FakePool::reclaimed),
                "answers": count(&self.stats.fake_answers),
                "empty_answers": count(&self.stats.fake_empty),
                "excluded": count(&self.stats.fake_excluded),
                "exhausted": count(&self.stats.fake_exhausted),
            },
            "idle_chain": idle(&self.upstreams),
            "idle_direct": idle(&self.direct_upstreams),
            "recent": self.stats.recent.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect::<Vec<_>>(),
        })
    }

    fn connect_upstream(&self, route: Route) -> Result<Upstream, String> {
        let deadline = Instant::now() + IO_DEADLINE;
        let socket = match route {
            Route::Chain => self.policy.chain(self.policy.dns_upstream())?,
            Route::Direct(upstream, _) => {
                let socket = std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::V4(upstream),
                    DIRECT_CONNECT_TIMEOUT,
                )
                .map_err(|_| "cannot connect to the direct DNS upstream".to_string())?;
                socket
                    .set_nodelay(true)
                    .map_err(|_| "cannot configure the direct DNS socket".to_string())?;
                socket
            }
        };
        let stream = DeadlineStream { socket, deadline };
        // This is a preconnected literal-address stream. The DNS hostname is
        // used only for SNI, certificate verification, and the HTTP Host field.
        let tls = self
            .tls
            .connect(self.tls_name(route), stream)
            .map_err(|_| "DNS TLS verification/handshake failed".to_string())?;
        Ok(Upstream {
            reader: BufReader::new(tls),
            uses: 0,
        })
    }

    fn exchange_on(
        &self,
        route: Route,
        mut upstream: Upstream,
        wire: &[u8],
        budget: Duration,
    ) -> Result<Vec<u8>, String> {
        // Each query gets its own I/O budget, also on a connection kept from earlier.
        upstream.reader.get_mut().get_mut().deadline = Instant::now() + budget;
        let response = post_query(&mut upstream.reader, self.tls_name(route), wire)?;
        upstream.uses += 1;
        // Reuse only an exactly framed HTTP/1.1 exchange with nothing left over.
        if response.keep_alive
            && upstream.reader.buffer().is_empty()
            && upstream.uses < MAX_UPSTREAM_USES
        {
            self.pool(route).put(upstream, Instant::now());
        }
        Ok(response.body)
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
            if let Entry::Vacant(entry) = self.entries.entry(alias) {
                entry.insert(Alias { real: *ip, expires });
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
