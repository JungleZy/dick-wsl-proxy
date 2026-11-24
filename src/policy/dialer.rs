//! First hop -> authenticated residential SOCKS5 -> destination, with a small
//! pool of tunnels already authenticated at the residential proxy. A pooled
//! tunnel only needs its CONNECT, which saves the first-hop CONNECT and the
//! residential method and authentication round trips of a fresh chain.
use super::{
    AuthPacket, SETUP_TIMEOUT, WipedBytes, connect, connect_addr, connect_reply, connect_request,
    expect, receive, remaining, send,
};
use crate::credential::Residential;
use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Pool settings. A policy's pool is always adaptive: the ceiling follows
/// the largest recent burst of chain requests up to `AUTO_MAX`, and the
/// demand window follows how far apart episodes of activity usually are.
/// Tests fix either value (a `max` of 0 turns the pool off).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PoolSettings {
    pub(super) max: Option<usize>,
    pub(super) demand_window: Option<Duration>,
}

impl PoolSettings {
    pub(super) const ADAPTIVE: Self = Self {
        max: None,
        demand_window: None,
    };
}

/// The settings a policy's dialer runs with. Unit tests that build a policy
/// exercise exact handshake sequences, so the pool stays off for them; the
/// pool's own tests build a dialer directly.
pub(super) fn effective(settings: PoolSettings) -> PoolSettings {
    if cfg!(test) {
        PoolSettings {
            max: Some(0),
            ..settings
        }
    } else {
        settings
    }
}

/// Hard ceiling of an adaptive pool, a guard against runaway growth.
pub(super) const AUTO_MAX: usize = 64;
/// An adaptive demand window stays between these.
const AUTO_DEMAND_MIN: Duration = Duration::from_secs(60);
const AUTO_DEMAND_MAX: Duration = Duration::from_secs(900);
/// A quiet spell longer than this separates two episodes of activity; the
/// lengths of those spells set an adaptive demand window.
const EPISODE_GAP: Duration = Duration::from_secs(5);
/// Episode gaps remembered for the adaptive demand window.
const GAP_HISTORY: usize = 16;

const POOL_MIN: usize = 2;
/// Chain requests this close together count as one burst.
const BURST_WINDOW: Duration = Duration::from_secs(3);
/// A pooled tunnel is closed after at most this long unused. Proxies drop
/// sessions that stay quiet after authentication on their own schedule, so
/// the limit shrinks to 80% of the shortest idle time at which the chain
/// was seen to close one, but never below `MIN_POOL_IDLE`.
const POOL_IDLE: Duration = Duration::from_secs(20);
const MIN_POOL_IDLE: Duration = Duration::from_secs(2);

/// How a residential handshake failed: refused or broken for real, or in a
/// way that only shows the proxy could not take pipelined requests.
pub(super) enum Setup {
    Failed(String),
    Incompatible(String),
}

impl Setup {
    fn into_message(self) -> String {
        match self {
            Self::Failed(message) | Self::Incompatible(message) => message,
        }
    }
}

struct Pooled {
    id: u64,
    stream: TcpStream,
    since: Instant,
}

pub(super) struct Dialer {
    first_hop: SocketAddrV4,
    residential: Residential,
    /// Whether residential handshakes still send authentication and CONNECT
    /// in one write. Cleared for the rest of this takeover the first time the
    /// proxy cannot follow that.
    pub(super) pipeline: AtomicBool,
    /// Upper bound on the pool; 0 disables it.
    max: usize,
    adaptive_max: bool,
    /// A fixed demand window, or `None` to learn it from `gaps`.
    fixed_demand: Option<Duration>,
    /// Recent quiet spells between episodes of activity, newest last.
    gaps: Mutex<VecDeque<Duration>>,
    pool: Mutex<Vec<Pooled>>,
    next_id: AtomicUsize,
    in_flight: AtomicUsize,
    /// When chains were asked for recently, oldest first.
    demand: Mutex<VecDeque<Instant>>,
    closed: AtomicBool,
    /// The current idle limit in milliseconds; see `POOL_IDLE`.
    idle_limit_ms: AtomicU64,
    stats: Stats,
}

/// What the pool did, for the status report.
#[derive(Default)]
struct Stats {
    hits: AtomicU64,
    fresh: AtomicU64,
    /// Pooled tunnels found closed, talking or too old when taken.
    discarded: AtomicU64,
    /// Pooled tunnels that broke on their CONNECT.
    stale_on_connect: AtomicU64,
    prepared: AtomicU64,
    prepare_failures: AtomicU64,
    last_prepare_error: Mutex<Option<String>>,
    /// How long recently used and discarded tunnels had been idle, newest last.
    hit_ages_ms: Mutex<VecDeque<u64>>,
    discard_ages_ms: Mutex<VecDeque<u64>>,
}

fn remember(ages: &Mutex<VecDeque<u64>>, age: Duration) {
    let mut ages = ages.lock().unwrap_or_else(|e| e.into_inner());
    if ages.len() == 16 {
        ages.pop_front();
    }
    ages.push_back(u64::try_from(age.as_millis()).unwrap_or(u64::MAX));
}

impl Dialer {
    pub(super) fn new(
        first_hop: SocketAddrV4,
        residential: Residential,
        settings: PoolSettings,
    ) -> Self {
        Self {
            first_hop,
            residential,
            pipeline: AtomicBool::new(true),
            max: settings.max.unwrap_or(AUTO_MAX),
            adaptive_max: settings.max.is_none(),
            fixed_demand: settings.demand_window,
            gaps: Mutex::new(VecDeque::new()),
            pool: Mutex::new(Vec::new()),
            next_id: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            demand: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            idle_limit_ms: AtomicU64::new(POOL_IDLE.as_millis() as u64),
            stats: Stats::default(),
        }
    }

    pub(super) fn report(&self) -> serde_json::Value {
        let ages = |ages: &Mutex<VecDeque<u64>>| {
            ages.lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .copied()
                .collect::<Vec<_>>()
        };
        let count = |value: &AtomicU64| value.load(Ordering::Relaxed);
        serde_json::json!({
            "pooled": self.pool.lock().unwrap_or_else(|e| e.into_inner()).len(),
            "target": self.target(Instant::now()),
            "max": self.max,
            "max_adaptive": self.adaptive_max,
            "demand_window_seconds": self.demand_window().as_secs(),
            "demand_window_adaptive": self.fixed_demand.is_none(),
            "episode_gaps_s": self
                .gaps
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .map(|gap| gap.as_secs())
                .collect::<Vec<_>>(),
            "pipelined": self.pipeline.load(Ordering::Relaxed),
            "idle_limit_ms": self.idle_limit_ms.load(Ordering::Relaxed),
            "hits": count(&self.stats.hits),
            "fresh": count(&self.stats.fresh),
            "discarded": count(&self.stats.discarded),
            "stale_on_connect": count(&self.stats.stale_on_connect),
            "prepared": count(&self.stats.prepared),
            "prepare_failures": count(&self.stats.prepare_failures),
            "last_prepare_error": *self.stats.last_prepare_error.lock().unwrap_or_else(|e| e.into_inner()),
            "hit_idle_ms": ages(&self.stats.hit_ages_ms),
            "discard_idle_ms": ages(&self.stats.discard_ages_ms),
        })
    }

    /// Drops every pooled tunnel; tunnels still being built are dropped when
    /// they finish. Called when the policy is dropped.
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.pool.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// A chain to `dest`: on a pooled tunnel when one is alive, otherwise a
    /// fresh one. The single deadline covers every handshake.
    pub(super) fn chain(self: &Arc<Self>, dest: SocketAddr) -> Result<TcpStream, String> {
        let deadline = Instant::now() + SETUP_TIMEOUT;
        self.record_demand(Instant::now());
        let pooled = self.take();
        self.refill();
        if let Some((mut stream, idle)) = pooled {
            match pooled_connect(&mut stream, dest, deadline) {
                Ok(()) => {
                    self.stats.hits.fetch_add(1, Ordering::Relaxed);
                    return finish(stream);
                }
                Err(Setup::Failed(message)) => return Err(message),
                // The tunnel went stale while pooled: build a fresh chain.
                Err(Setup::Incompatible(_)) => {
                    self.stats.stale_on_connect.fetch_add(1, Ordering::Relaxed);
                    self.closed_after(idle);
                }
            }
        }
        self.stats.fresh.fetch_add(1, Ordering::Relaxed);
        self.fresh(dest, deadline).and_then(finish)
    }

    fn fresh(&self, dest: SocketAddr, deadline: Instant) -> Result<TcpStream, String> {
        let pipelined = self.pipeline.load(Ordering::Relaxed);
        let mut stream = self.open_residential(deadline)?;
        match self.residential_connect(&mut stream, dest, deadline, pipelined) {
            Ok(()) => Ok(stream),
            Err(Setup::Incompatible(_)) if pipelined => {
                self.pipeline.store(false, Ordering::Relaxed);
                let mut stream = self.open_residential(deadline)?;
                self.residential_connect(&mut stream, dest, deadline, false)
                    .map_err(Setup::into_message)?;
                Ok(stream)
            }
            Err(error) => Err(error.into_message()),
        }
    }

    /// The newest pooled tunnel that is still open and not past its idle
    /// limit, with how long it had been idle.
    fn take(&self) -> Option<(TcpStream, Duration)> {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(entry) = pool.pop() {
            let idle = entry.since.elapsed();
            if idle >= self.idle_limit() {
                self.stats.discarded.fetch_add(1, Ordering::Relaxed);
                remember(&self.stats.discard_ages_ms, idle);
                continue;
            }
            if alive(&entry.stream) {
                remember(&self.stats.hit_ages_ms, idle);
                return Some((entry.stream, idle));
            }
            self.stats.discarded.fetch_add(1, Ordering::Relaxed);
            remember(&self.stats.discard_ages_ms, idle);
            self.closed_after(idle);
        }
        None
    }

    fn idle_limit(&self) -> Duration {
        Duration::from_millis(self.idle_limit_ms.load(Ordering::Relaxed))
    }

    /// The chain closed a tunnel that had been idle for `idle`: keep later
    /// tunnels well inside that.
    fn closed_after(&self, idle: Duration) {
        let limit = (idle.mul_f64(0.8)).max(MIN_POOL_IDLE);
        self.idle_limit_ms.fetch_min(
            u64::try_from(limit.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Starts background dials until pooled plus in-flight tunnels reach the
    /// target, while chains are still being asked for.
    fn refill(self: &Arc<Self>) {
        let target = self.target(Instant::now());
        if target == 0 || self.closed.load(Ordering::Acquire) {
            return;
        }
        let pooled = self.pool.lock().unwrap_or_else(|e| e.into_inner()).len();
        loop {
            let in_flight = self.in_flight.load(Ordering::Acquire);
            if pooled + in_flight >= target {
                return;
            }
            if self
                .in_flight
                .compare_exchange(
                    in_flight,
                    in_flight + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }
            let dialer = Arc::clone(self);
            let spawned = thread::Builder::new()
                .name("chain-pool".into())
                .spawn(move || dialer.prepare());
            if spawned.is_err() {
                self.in_flight.fetch_sub(1, Ordering::AcqRel);
                return;
            }
        }
    }

    fn record_demand(&self, now: Instant) {
        let keep = self.fixed_demand.unwrap_or(AUTO_DEMAND_MAX);
        let mut demand = self.demand.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(previous) = demand.back() {
            let gap = now.saturating_duration_since(*previous);
            if gap >= EPISODE_GAP {
                let mut gaps = self.gaps.lock().unwrap_or_else(|e| e.into_inner());
                if gaps.len() == GAP_HISTORY {
                    gaps.pop_front();
                }
                gaps.push_back(gap);
            }
        }
        while demand
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= keep)
        {
            demand.pop_front();
        }
        // Enough history to see the largest burst the pool can follow.
        if demand.len() >= 1024 {
            demand.pop_front();
        }
        demand.push_back(now);
    }

    /// How long tunnels stay ready after the last chain request: fixed by
    /// the policy, or 1.2 times the 75th percentile of recent quiet spells
    /// between episodes of activity, so the next episode usually still finds
    /// the pool ready. Between `AUTO_DEMAND_MIN` and `AUTO_DEMAND_MAX`.
    fn demand_window(&self) -> Duration {
        if let Some(fixed) = self.fixed_demand {
            return fixed;
        }
        let mut gaps: Vec<Duration> = self
            .gaps
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .copied()
            .collect();
        if gaps.is_empty() {
            return AUTO_DEMAND_MIN;
        }
        gaps.sort();
        let p75 = gaps[(gaps.len() * 3).div_ceil(4) - 1];
        p75.mul_f64(1.2).clamp(AUTO_DEMAND_MIN, AUTO_DEMAND_MAX)
    }

    /// How many tunnels to keep ready: the largest burst of chain requests
    /// within `BURST_WINDOW` during the demand window, between `POOL_MIN`
    /// and the maximum. None at all without requests in that window.
    fn target(&self, now: Instant) -> usize {
        if self.max == 0 {
            return 0;
        }
        let window = self.demand_window();
        let demand = self.demand.lock().unwrap_or_else(|e| e.into_inner());
        let recent: Vec<Instant> = demand
            .iter()
            .copied()
            .filter(|at| now.saturating_duration_since(*at) < window)
            .collect();
        if recent.is_empty() {
            return 0;
        }
        let mut largest = 0;
        let mut start = 0;
        for end in 0..recent.len() {
            while recent[end].saturating_duration_since(recent[start]) >= BURST_WINDOW {
                start += 1;
            }
            largest = largest.max(end - start + 1);
        }
        largest.clamp(POOL_MIN.min(self.max), self.max)
    }

    /// Background: builds one authenticated tunnel, pools it, and closes it
    /// again if it is still unused when its idle limit passes.
    fn prepare(self: Arc<Self>) {
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let built = self.open_residential(deadline).and_then(|mut stream| {
            authenticate(&mut stream, &self.residential, deadline)
                .map_err(Setup::into_message)
                .map(|()| stream)
        });
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as u64;
        match &built {
            Ok(_) => {
                self.stats.prepared.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                self.stats.prepare_failures.fetch_add(1, Ordering::Relaxed);
                *self
                    .stats
                    .last_prepare_error
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(error.clone());
            }
        }
        let pooled = match built {
            Ok(stream) if !self.closed.load(Ordering::Acquire) => {
                let target = self.target(Instant::now());
                let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
                if pool.len() < target {
                    pool.push(Pooled {
                        id,
                        stream,
                        since: Instant::now(),
                    });
                    true
                } else {
                    false
                }
            }
            _ => false,
        };
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
        if !pooled {
            return;
        }
        // Re-read after each wake: the limit may have shrunk meanwhile.
        let since = Instant::now();
        loop {
            let left = self.idle_limit().saturating_sub(since.elapsed());
            if left.is_zero() || self.closed.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(left.min(Duration::from_millis(500)));
        }
        let expired = {
            let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            let before = pool.len();
            pool.retain(|entry| entry.id != id);
            pool.len() != before
        };
        if expired {
            self.refill();
        }
    }

    /// A first-hop tunnel to the residential proxy. No residential bytes,
    /// least of all credentials, are sent before this outer CONNECT succeeds.
    fn open_residential(&self, deadline: Instant) -> Result<TcpStream, String> {
        let mut stream =
            TcpStream::connect_timeout(&SocketAddr::V4(self.first_hop), remaining(deadline)?)
                .map_err(|_| "cannot connect to first-hop SOCKS5 endpoint")?;
        stream
            .set_nodelay(true)
            .map_err(|_| "cannot configure chain socket")?;
        send(&mut stream, &[5, 1, 0], deadline)?;
        expect(
            &mut stream,
            &[5, 0],
            deadline,
            "first-hop SOCKS5 method rejected",
        )?;
        connect(&mut stream, self.residential.endpoint(), deadline)?;
        Ok(stream)
    }

    /// Residential method selection, username/password authentication and
    /// CONNECT. Pipelined, authentication and CONNECT go out in one write
    /// once the proxy has selected authentication, saving one residential
    /// round trip.
    fn residential_connect(
        &self,
        stream: &mut TcpStream,
        dest: SocketAddr,
        deadline: Instant,
        pipelined: bool,
    ) -> Result<(), Setup> {
        if !pipelined {
            authenticate(stream, &self.residential, deadline)?;
            return connect_addr(stream, dest, deadline).map_err(Setup::Failed);
        }
        select_authentication(stream, deadline)?;
        let mut packet = AuthPacket([0; 513]);
        let auth = self.residential.auth_packet(&mut packet.0);
        let request = connect_request(dest);
        let mut batch = WipedBytes(Vec::with_capacity(auth + request.len()));
        batch.0.extend_from_slice(&packet.0[..auth]);
        batch.0.extend_from_slice(&request);
        send(stream, &batch.0, deadline).map_err(Setup::Failed)?;
        // A connection that breaks before the authentication reply means the
        // proxy could not take CONNECT behind the credentials, not that either
        // was refused.
        let mut status = [0; 2];
        receive(stream, &mut status, deadline).map_err(Setup::Incompatible)?;
        if status != [1, 0] {
            return Err(Setup::Failed(
                "residential SOCKS5 authentication rejected".into(),
            ));
        }
        connect_reply(stream, deadline).map_err(Setup::Failed)
    }
}

/// Credentials go out only after the proxy has selected username/password
/// authentication.
fn select_authentication(stream: &mut TcpStream, deadline: Instant) -> Result<(), Setup> {
    send(stream, &[5, 1, 2], deadline).map_err(Setup::Failed)?;
    expect(
        stream,
        &[5, 2],
        deadline,
        "residential SOCKS5 authentication method rejected",
    )
    .map_err(Setup::Failed)
}

fn authenticate(
    stream: &mut TcpStream,
    residential: &Residential,
    deadline: Instant,
) -> Result<(), Setup> {
    select_authentication(stream, deadline)?;
    let mut packet = AuthPacket([0; 513]);
    let auth = residential.auth_packet(&mut packet.0);
    send(stream, &packet.0[..auth], deadline).map_err(Setup::Failed)?;
    expect(
        stream,
        &[1, 0],
        deadline,
        "residential SOCKS5 authentication rejected",
    )
    .map_err(Setup::Failed)
}

/// CONNECT on a pooled, already authenticated tunnel. A tunnel that closes
/// before any reply went stale while pooled; a reply that refuses is final.
fn pooled_connect(
    stream: &mut TcpStream,
    dest: SocketAddr,
    deadline: Instant,
) -> Result<(), Setup> {
    if send(stream, &connect_request(dest), deadline).is_err() {
        return Err(Setup::Incompatible("pooled tunnel closed".into()));
    }
    let mut first = [0; 1];
    receive(stream, &mut first, deadline).map_err(Setup::Incompatible)?;
    if first[0] != 5 {
        return Err(Setup::Failed("SOCKS5 CONNECT rejected or malformed".into()));
    }
    connect_reply_rest(stream, deadline).map_err(Setup::Failed)
}

/// The rest of a CONNECT reply whose version byte was already read.
fn connect_reply_rest(stream: &mut TcpStream, deadline: Instant) -> Result<(), String> {
    let mut header = [0; 3];
    receive(stream, &mut header, deadline)?;
    if header[0] != 0 || header[1] != 0 {
        return Err("SOCKS5 CONNECT rejected or malformed".into());
    }
    let length = match header[2] {
        1 => 6,
        4 => 18,
        3 => {
            let mut length = [0];
            receive(stream, &mut length, deadline)?;
            if length[0] == 0 {
                return Err("SOCKS5 CONNECT returned an invalid bound address".into());
            }
            usize::from(length[0]) + 2
        }
        _ => return Err("SOCKS5 CONNECT returned an unsupported address type".into()),
    };
    let mut bound = [0; 257];
    receive(stream, &mut bound[..length], deadline)
}

/// An idle tunnel that has neither closed nor sent anything since it was
/// authenticated.
fn alive(stream: &TcpStream) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return false;
    }
    let mut byte = [0];
    let quiet =
        matches!(stream.peek(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock);
    quiet && stream.set_nonblocking(false).is_ok()
}

fn finish(stream: TcpStream) -> Result<TcpStream, String> {
    stream
        .set_read_timeout(None)
        .map_err(|_| "cannot configure chain socket")?;
    stream
        .set_write_timeout(None)
        .map_err(|_| "cannot configure chain socket")?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, Shutdown, TcpListener};

    fn local(listener: &TcpListener) -> SocketAddrV4 {
        match listener.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!(),
        }
    }

    fn read_exact<const N: usize>(stream: &mut TcpStream) -> [u8; N] {
        let mut bytes = [0; N];
        stream.read_exact(&mut bytes).unwrap();
        bytes
    }

    fn relay(mut left: TcpStream, mut right: TcpStream) {
        let mut reader = left.try_clone().unwrap();
        let mut writer = right.try_clone().unwrap();
        let forward = thread::spawn(move || {
            let _ = std::io::copy(&mut reader, &mut writer);
            let _ = writer.shutdown(Shutdown::Write);
        });
        let _ = std::io::copy(&mut right, &mut left);
        let _ = left.shutdown(Shutdown::Write);
        let _ = forward.join();
    }

    /// A first hop that tunnels every connection to `residential`, and a
    /// residential proxy that records whether each CONNECT arrived together
    /// with the credentials ("fresh") or later on an idle tunnel ("pooled").
    fn proxies() -> (SocketAddrV4, Arc<Mutex<Vec<&'static str>>>) {
        let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let residential = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let first_endpoint = local(&first);
        let residential_endpoint = local(&residential);
        thread::spawn(move || {
            for stream in first.incoming() {
                let mut stream = stream.unwrap();
                thread::spawn(move || {
                    assert_eq!(read_exact::<3>(&mut stream), [5, 1, 0]);
                    stream.write_all(&[5, 0]).unwrap();
                    read_exact::<10>(&mut stream);
                    let target = TcpStream::connect(residential_endpoint).unwrap();
                    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                    relay(stream, target);
                });
            }
        });
        let log = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&log);
        thread::spawn(move || {
            for stream in residential.incoming() {
                let mut stream = stream.unwrap();
                let record = Arc::clone(&record);
                thread::spawn(move || {
                    assert_eq!(read_exact::<3>(&mut stream), [5, 1, 2]);
                    stream.write_all(&[5, 2]).unwrap();
                    read_exact::<31>(&mut stream);
                    stream.set_nonblocking(true).unwrap();
                    thread::sleep(Duration::from_millis(50));
                    let mut peek = [0];
                    let together = stream.peek(&mut peek).is_ok_and(|n| n > 0);
                    stream.set_nonblocking(false).unwrap();
                    stream.write_all(&[1, 0]).unwrap();
                    let mut request = [0; 10];
                    if stream.read_exact(&mut request).is_err() {
                        return; // A pooled tunnel closed unused.
                    }
                    record
                        .lock()
                        .unwrap()
                        .push(if together { "fresh" } else { "pooled" });
                    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                    let mut rest = Vec::new();
                    let _ = stream.read_to_end(&mut rest);
                });
            }
        });
        (first_endpoint, log)
    }

    fn settings(max: usize) -> PoolSettings {
        PoolSettings {
            max: Some(max),
            demand_window: Some(Duration::from_secs(60)),
        }
    }

    fn dialer(first_hop: SocketAddrV4) -> Arc<Dialer> {
        let residential = crate::credential::fixture(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        Arc::new(Dialer::new(first_hop, residential, settings(2)))
    }

    fn wait_for_pool(dialer: &Dialer, size: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while dialer.pool.lock().unwrap().len() < size {
            assert!(Instant::now() < deadline, "pool never filled");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_later_chain_only_sends_connect_on_a_pooled_tunnel() {
        let (first_hop, log) = proxies();
        // The fixture points the credential at port 1; route the first hop's
        // CONNECT to the fake residential proxy whatever it names.
        let dialer = dialer(first_hop);
        let destination = SocketAddr::V4("192.0.2.1:443".parse().unwrap());
        drop(dialer.chain(destination).unwrap());
        wait_for_pool(&dialer, 2);
        drop(dialer.chain(destination).unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        while log.lock().unwrap().len() < 2 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(*log.lock().unwrap(), ["fresh", "pooled"]);
        dialer.close();
        assert!(dialer.pool.lock().unwrap().is_empty());
    }

    #[test]
    fn closed_or_expired_tunnels_are_never_handed_out() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let dialer = dialer(local(&listener));
        let pair = || {
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            (client, server)
        };
        let (closed, server) = pair();
        drop(server);
        thread::sleep(Duration::from_millis(50));
        let (talking, mut server_talking) = pair();
        server_talking.write_all(b"x").unwrap();
        thread::sleep(Duration::from_millis(50));
        let (old, _server_old) = pair();
        let (good, _server_good) = pair();
        let good_port = good.local_addr().unwrap().port();
        {
            let mut pool = dialer.pool.lock().unwrap();
            let now = Instant::now();
            pool.push(Pooled {
                id: 1,
                stream: good,
                since: now,
            });
            pool.push(Pooled {
                id: 2,
                stream: old,
                since: now - POOL_IDLE,
            });
            pool.push(Pooled {
                id: 3,
                stream: talking,
                since: now,
            });
            pool.push(Pooled {
                id: 4,
                stream: closed,
                since: now,
            });
        }
        let (taken, _) = dialer.take().unwrap();
        assert_eq!(taken.local_addr().unwrap().port(), good_port);
        assert!(dialer.take().is_none());
    }

    #[test]
    fn a_closed_dialer_neither_refills_nor_keeps_tunnels() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let dialer = dialer(local(&listener));
        dialer.record_demand(Instant::now());
        dialer.close();
        dialer.refill();
        assert_eq!(dialer.in_flight.load(Ordering::Acquire), 0);
        // No demand at all: nothing is kept ready either.
        let idle = dialer_with_target(local(&listener), 2);
        idle.refill();
        assert_eq!(idle.in_flight.load(Ordering::Acquire), 0);
    }

    #[test]
    fn the_idle_limit_shrinks_below_the_shortest_observed_close() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let dialer = dialer_with_target(local(&listener), 8);
        assert_eq!(dialer.idle_limit(), POOL_IDLE);
        dialer.closed_after(Duration::from_millis(9_500));
        assert_eq!(dialer.idle_limit(), Duration::from_millis(7_600));
        // A later, longer close never raises it again.
        dialer.closed_after(Duration::from_secs(30));
        assert_eq!(dialer.idle_limit(), Duration::from_millis(7_600));
        // A very short close stops at the floor.
        dialer.closed_after(Duration::from_millis(500));
        assert_eq!(dialer.idle_limit(), MIN_POOL_IDLE);
        // A pooled tunnel past the learned limit is not handed out.
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _server = listener.accept().unwrap();
        dialer.pool.lock().unwrap().push(Pooled {
            id: 9,
            stream: client,
            since: Instant::now() - MIN_POOL_IDLE,
        });
        assert!(dialer.take().is_none());
        assert_eq!(dialer.report()["discarded"], 1);
    }

    #[test]
    fn the_pool_follows_the_largest_recent_burst() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let dialer = dialer_with_target(local(&listener), 8);
        let start = Instant::now();
        assert_eq!(dialer.target(start), 0, "nothing kept ready without demand");
        dialer.record_demand(start);
        assert_eq!(
            dialer.target(start),
            2,
            "at least the minimum once in demand"
        );
        // Five requests within the burst window, then a lone one later.
        for millis in [100, 300, 600, 900] {
            dialer.record_demand(start + Duration::from_millis(millis));
        }
        dialer.record_demand(start + Duration::from_secs(10));
        assert_eq!(dialer.target(start + Duration::from_secs(10)), 5);
        // Spread over more than the burst window, requests do not add up.
        for second in 20..26 {
            dialer.record_demand(start + Duration::from_secs(second));
        }
        assert_eq!(dialer.target(start + Duration::from_secs(26)), 5);
        // A burst larger than the maximum is capped.
        for millis in 0..20 {
            dialer.record_demand(start + Duration::from_secs(30) + Duration::from_millis(millis));
        }
        assert_eq!(dialer.target(start + Duration::from_secs(31)), 8);
        // Once the demand window has passed, nothing is kept ready.
        assert_eq!(dialer.target(start + Duration::from_secs(100)), 0);
    }

    #[test]
    fn an_adaptive_pool_follows_large_bursts_and_learns_the_gap_between_them() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let residential = crate::credential::fixture(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        let dialer = Dialer::new(local(&listener), residential, PoolSettings::ADAPTIVE);
        let start = Instant::now();
        // A page load of 20 connections: the pool follows it past the old 8.
        for millis in 0..20 {
            dialer.record_demand(start + Duration::from_millis(millis * 50));
        }
        assert_eq!(dialer.target(start + Duration::from_secs(2)), 20);
        assert_eq!(dialer.demand_window(), AUTO_DEMAND_MIN);
        // A burst larger than the hard ceiling is capped.
        let later = start + Duration::from_secs(10);
        for millis in 0..100 {
            dialer.record_demand(later + Duration::from_millis(millis * 10));
        }
        assert_eq!(dialer.target(later + Duration::from_secs(1)), AUTO_MAX);
        // Episodes every 150 s: the window stretches to keep the pool ready
        // across the quiet spell instead of emptying after 60 s.
        let mut at = later + Duration::from_secs(1);
        for _ in 0..4 {
            at += Duration::from_secs(150);
            dialer.record_demand(at);
        }
        let window = dialer.demand_window();
        assert_eq!(window, Duration::from_secs(150).mul_f64(1.2));
        assert!(dialer.target(at + Duration::from_secs(170)) > 0);
        assert_eq!(dialer.target(at + window), 0);
        // Very long gaps stop at the ceiling of the window.
        for _ in 0..GAP_HISTORY {
            at += Duration::from_secs(3_600);
            dialer.record_demand(at);
        }
        assert_eq!(dialer.demand_window(), AUTO_DEMAND_MAX);
        let report = dialer.report();
        assert_eq!(report["max_adaptive"], true);
        assert_eq!(report["demand_window_adaptive"], true);
    }

    #[test]
    fn fixed_settings_override_the_adaptive_ones() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let residential = crate::credential::fixture(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        let dialer = Dialer::new(
            local(&listener),
            residential,
            PoolSettings {
                max: Some(4),
                demand_window: Some(Duration::from_secs(10)),
            },
        );
        let start = Instant::now();
        dialer.record_demand(start);
        assert_eq!(dialer.target(start + Duration::from_secs(9)), 2);
        assert_eq!(dialer.target(start + Duration::from_secs(10)), 0);
        assert_eq!(dialer.report()["max"], 4);
        assert_eq!(dialer.report()["demand_window_seconds"], 10);
    }

    fn dialer_with_target(first_hop: SocketAddrV4, target: usize) -> Arc<Dialer> {
        let residential = crate::credential::fixture(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        Arc::new(Dialer::new(first_hop, residential, settings(target)))
    }
}
