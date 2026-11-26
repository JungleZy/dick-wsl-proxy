//! First hop -> authenticated residential SOCKS5 -> destination, with a small
//! pool of tunnels already authenticated at the residential proxy. A pooled
//! tunnel only needs its CONNECT, which saves the first-hop CONNECT and the
//! residential method and authentication round trips of a fresh chain.
use super::{
    AuthPacket, SETUP_TIMEOUT, WipedBytes, connect, connect_reply, connect_request, expect,
    receive, remaining, send,
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
/// was seen to close one, but never below `MIN_POOL_IDLE`. Only a tunnel
/// found closed while it sat in the pool counts (decision 30).
const POOL_IDLE: Duration = Duration::from_secs(20);
const MIN_POOL_IDLE: Duration = Duration::from_secs(2);
/// A learned idle limit returns to `POOL_IDLE` once this long has passed
/// without another tunnel closing while pooled: a one-off batch close (the
/// first hop restarting) must not shorten every later tunnel's life for the
/// rest of the takeover (decision 30).
const IDLE_RECOVERY: Duration = Duration::from_secs(600);
/// How long a pipelined CONNECT waits for its first reply byte while
/// pipelining has not yet worked on this takeover (decision 22). A proxy
/// that drops the CONNECT read with the credentials and hangs would
/// otherwise hold the first chain for the full setup deadline, longer than
/// the readiness DNS probe waits. A slow target misjudged here only turns
/// pipelining off for this takeover.
const UNPROVEN_REPLY_WAIT: Duration = Duration::from_secs(4);

/// How a residential handshake failed: refused or broken for real, or in a
/// way that only shows the proxy could not take pipelined requests.
pub(super) enum Setup {
    Failed(String),
    Incompatible(String),
    /// Pipelined: authentication was accepted, but not one byte came back
    /// for the CONNECT sent behind it. Either the target cannot be reached,
    /// or the proxy dropped the CONNECT it read together with the credentials.
    Unanswered(String),
    /// Pipelined: the authentication reply refused the credentials. Either
    /// they are wrong, or the proxy cannot parse credentials that arrive
    /// together with the CONNECT behind them.
    Rejected(String),
}

impl Setup {
    fn into_message(self) -> String {
        match self {
            Self::Failed(message)
            | Self::Incompatible(message)
            | Self::Unanswered(message)
            | Self::Rejected(message) => message,
        }
    }
}

/// How a CONNECT on a pooled tunnel failed.
enum PooledFailure {
    /// The tunnel could not even take the request: it closed while pooled.
    Closed,
    /// Sent, then no reply byte before the deadline, or the tunnel closed
    /// first. A slow or unreachable target, or a proxy that closes on a
    /// CONNECT it cannot complete, looks the same as a tunnel the chain had
    /// closed, so this teaches the idle limit nothing (decision 30).
    Unanswered,
    /// The proxy answered: refused, or with a malformed reply.
    Failed(String),
}

struct Pooled {
    id: u64,
    stream: TcpStream,
    since: Instant,
}

/// The idle limit and when a tunnel last closed while pooled.
struct IdleLimit {
    limit: Duration,
    last_close: Option<Instant>,
}

impl IdleLimit {
    /// Back to `POOL_IDLE` once `IDLE_RECOVERY` passed without a close.
    fn recover(&mut self, now: Instant) {
        if self
            .last_close
            .is_some_and(|at| now.saturating_duration_since(at) >= IDLE_RECOVERY)
        {
            self.limit = POOL_IDLE;
            self.last_close = None;
        }
    }
}

pub(super) struct Dialer {
    first_hop: SocketAddrV4,
    residential: Residential,
    /// Whether residential handshakes still send authentication and CONNECT
    /// in one write. Cleared for the rest of this takeover the first time the
    /// proxy cannot follow that.
    pub(super) pipeline: AtomicBool,
    /// Set once a pipelined CONNECT has been answered on this takeover. From
    /// then on an unanswered one is the target's failure, not the proxy's.
    pipeline_proven: AtomicBool,
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
    /// The current idle limit; see `POOL_IDLE`.
    idle_limit: Mutex<IdleLimit>,
    stats: Stats,
}

/// What the pool did, for the status report.
#[derive(Default)]
struct Stats {
    hits: AtomicU64,
    fresh: AtomicU64,
    /// Chains asked for by name (fake-ip) rather than by address.
    by_name: AtomicU64,
    /// Pooled tunnels found closed, talking or too old when taken.
    discarded: AtomicU64,
    /// Pooled tunnels found closed when their CONNECT was sent.
    stale_on_connect: AtomicU64,
    /// Pooled tunnels whose CONNECT went unanswered; a fresh chain followed.
    unanswered_on_connect: AtomicU64,
    /// Fresh chains asked again step by step because a pipelined CONNECT
    /// went unanswered before pipelining had ever worked.
    unanswered_retries: AtomicU64,
    /// Fresh chains asked again step by step because the proxy refused the
    /// credentials sent together with their CONNECT.
    rejected_retries: AtomicU64,
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
            pipeline_proven: AtomicBool::new(false),
            max: settings.max.unwrap_or(AUTO_MAX),
            adaptive_max: settings.max.is_none(),
            fixed_demand: settings.demand_window,
            gaps: Mutex::new(VecDeque::new()),
            pool: Mutex::new(Vec::new()),
            next_id: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            demand: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            idle_limit: Mutex::new(IdleLimit {
                limit: POOL_IDLE,
                last_close: None,
            }),
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
            "idle_limit_ms": u64::try_from(self.idle_limit().as_millis()).unwrap_or(u64::MAX),
            "hits": count(&self.stats.hits),
            "fresh": count(&self.stats.fresh),
            "by_name": count(&self.stats.by_name),
            "discarded": count(&self.stats.discarded),
            "stale_on_connect": count(&self.stats.stale_on_connect),
            "unanswered_on_connect": count(&self.stats.unanswered_on_connect),
            "unanswered_retries": count(&self.stats.unanswered_retries),
            "rejected_retries": count(&self.stats.rejected_retries),
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
    pub(super) fn chain(self: &Arc<Self>, target: &ChainTarget) -> Result<TcpStream, String> {
        let deadline = Instant::now() + SETUP_TIMEOUT;
        self.record_demand(Instant::now());
        if matches!(target, ChainTarget::Name(..)) {
            self.stats.by_name.fetch_add(1, Ordering::Relaxed);
        }
        let pooled = self.take();
        self.refill();
        if let Some((mut stream, idle)) = pooled {
            match pooled_connect(&mut stream, target, deadline) {
                Ok(()) => {
                    self.stats.hits.fetch_add(1, Ordering::Relaxed);
                    return finish(stream);
                }
                Err(PooledFailure::Failed(message)) => return Err(message),
                // The tunnel went stale while pooled: build a fresh chain.
                Err(PooledFailure::Closed) => {
                    self.stats.stale_on_connect.fetch_add(1, Ordering::Relaxed);
                    self.closed_after(idle);
                }
                // Maybe the target, maybe the tunnel: try a fresh chain, but
                // learn nothing from it.
                Err(PooledFailure::Unanswered) => {
                    self.stats
                        .unanswered_on_connect
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        self.stats.fresh.fetch_add(1, Ordering::Relaxed);
        self.fresh(target, deadline).and_then(finish)
    }

    fn fresh(&self, target: &ChainTarget, deadline: Instant) -> Result<TcpStream, String> {
        let pipelined = self.pipeline.load(Ordering::Relaxed);
        let mut stream = self.open_residential(deadline)?;
        match self.residential_connect(&mut stream, target, deadline, pipelined) {
            Ok(()) => {
                if pipelined {
                    self.pipeline_proven.store(true, Ordering::Relaxed);
                }
                Ok(stream)
            }
            Err(Setup::Incompatible(_)) if pipelined => {
                self.pipeline.store(false, Ordering::Relaxed);
                let mut stream = self.open_residential(deadline)?;
                self.residential_connect(&mut stream, target, deadline, false)
                    .map_err(Setup::into_message)?;
                Ok(stream)
            }
            // Until a pipelined CONNECT has worked, an unanswered one may be
            // a proxy that drops what follows the credentials; then every
            // pipelined chain would hang until its deadline. Ask once more
            // step by step, with a deadline of its own since the first one
            // may be spent, and stop pipelining only if that is answered: a
            // target that cannot be reached fails both ways and changes
            // nothing.
            Err(Setup::Unanswered(message))
                if pipelined && !self.pipeline_proven.load(Ordering::Relaxed) =>
            {
                self.stats
                    .unanswered_retries
                    .fetch_add(1, Ordering::Relaxed);
                let deadline = Instant::now() + SETUP_TIMEOUT;
                let mut stream = self
                    .open_residential(deadline)
                    .map_err(|_| message.clone())?;
                self.residential_connect(&mut stream, target, deadline, false)
                    .map_err(|_| message)?;
                self.pipeline.store(false, Ordering::Relaxed);
                Ok(stream)
            }
            // Some proxies refuse credentials that arrive in the same read as
            // the CONNECT behind them, and accept the same ones step by step.
            // Whether both land in one read depends on how the first hop
            // relays them, so this is asked again even after pipelining has
            // worked. The refusal comes back within one round trip, so the
            // same deadline covers the retry. Pipelining stops only if the
            // retry is accepted: wrong credentials fail both ways and change
            // nothing.
            Err(Setup::Rejected(_)) if pipelined => {
                self.stats.rejected_retries.fetch_add(1, Ordering::Relaxed);
                let mut stream = self.open_residential(deadline)?;
                self.residential_connect(&mut stream, target, deadline, false)
                    .map_err(Setup::into_message)?;
                self.pipeline.store(false, Ordering::Relaxed);
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
        self.idle_limit_at(Instant::now())
    }

    fn idle_limit_at(&self, now: Instant) -> Duration {
        let mut idle = self.idle_limit.lock().unwrap_or_else(|e| e.into_inner());
        idle.recover(now);
        idle.limit
    }

    /// The chain closed a tunnel that had been idle for `idle` while it sat
    /// in the pool: keep later tunnels well inside that.
    fn closed_after(&self, idle: Duration) {
        self.closed_after_at(idle, Instant::now());
    }

    fn closed_after_at(&self, idle: Duration, now: Instant) {
        let mut learned = self.idle_limit.lock().unwrap_or_else(|e| e.into_inner());
        learned.recover(now);
        learned.limit = learned.limit.min(idle.mul_f64(0.8).max(MIN_POOL_IDLE));
        learned.last_close = Some(now);
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
    /// round trip. A pipelined refusal is `Setup::Rejected`, for the caller
    /// to ask again step by step.
    fn residential_connect(
        &self,
        stream: &mut TcpStream,
        target: &ChainTarget,
        deadline: Instant,
        pipelined: bool,
    ) -> Result<(), Setup> {
        let request = target_request(target).map_err(Setup::Failed)?;
        if !pipelined {
            authenticate(stream, &self.residential, deadline)?;
            send(stream, &request, deadline).map_err(Setup::Failed)?;
            return connect_reply(stream, deadline).map_err(Setup::Failed);
        }
        select_authentication(stream, deadline)?;
        let mut packet = AuthPacket([0; 513]);
        let auth = self.residential.auth_packet(&mut packet.0);
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
            return Err(Setup::Rejected(
                "residential SOCKS5 authentication rejected".into(),
            ));
        }
        let first_deadline = if self.pipeline_proven.load(Ordering::Relaxed) {
            deadline
        } else {
            deadline.min(Instant::now() + UNPROVEN_REPLY_WAIT)
        };
        let mut first = [0; 1];
        receive(stream, &mut first, first_deadline).map_err(Setup::Unanswered)?;
        if first[0] != 5 {
            return Err(Setup::Failed("SOCKS5 CONNECT rejected or malformed".into()));
        }
        connect_reply_rest(stream, deadline).map_err(Setup::Failed)
    }
}

/// Where a chain goes: a literal address, or a name the residential proxy
/// resolves itself (SOCKS5 address type 3).
pub(crate) enum ChainTarget {
    Address(SocketAddr),
    Name(String, u16),
}

/// The CONNECT request for `target`.
pub(super) fn target_request(target: &ChainTarget) -> Result<Vec<u8>, String> {
    match target {
        ChainTarget::Address(address) => Ok(connect_request(*address)),
        ChainTarget::Name(name, port) => {
            let bytes = name.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 || !name.is_ascii() {
                return Err("chain name must be 1-255 ASCII bytes".into());
            }
            let mut request = vec![5, 1, 0, 3, bytes.len() as u8];
            request.extend_from_slice(bytes);
            request.extend_from_slice(&port.to_be_bytes());
            Ok(request)
        }
    }
}

impl Dialer {
    /// Diagnostic only: builds an authenticated tunnel without timing it,
    /// then times one CONNECT to `target` from request to reply. The tunnel
    /// is closed without sending anything through it.
    pub(super) fn probe_connect(&self, target: &ChainTarget) -> Result<Duration, String> {
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let mut stream = self.open_residential(deadline)?;
        authenticate(&mut stream, &self.residential, deadline).map_err(Setup::into_message)?;
        let request = target_request(target)?;
        let started = Instant::now();
        send(&mut stream, &request, deadline)?;
        let mut header = [0; 4];
        receive(&mut stream, &mut header, deadline)?;
        if header[0] != 5 {
            return Err("probe CONNECT reply is not SOCKS5".into());
        }
        if header[1] != 0 {
            return Err(format!(
                "probe CONNECT refused with reply code {}",
                header[1]
            ));
        }
        let elapsed = started.elapsed();
        Ok(elapsed)
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

/// CONNECT on a pooled, already authenticated tunnel. A tunnel that cannot
/// take the request closed while pooled; one that takes it and then gives
/// no reply is unanswered; a reply that refuses is final.
fn pooled_connect(
    stream: &mut TcpStream,
    target: &ChainTarget,
    deadline: Instant,
) -> Result<(), PooledFailure> {
    let request = target_request(target).map_err(PooledFailure::Failed)?;
    if send(stream, &request, deadline).is_err() {
        return Err(PooledFailure::Closed);
    }
    let mut first = [0; 1];
    receive(stream, &mut first, deadline).map_err(|_| PooledFailure::Unanswered)?;
    if first[0] != 5 {
        return Err(PooledFailure::Failed(
            "SOCKS5 CONNECT rejected or malformed".into(),
        ));
    }
    connect_reply_rest(stream, deadline).map_err(PooledFailure::Failed)
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

    /// A CONNECT request after its first four bytes, by address type.
    fn read_target(stream: &mut TcpStream, header: [u8; 4]) -> Option<Vec<u8>> {
        let rest = match header[3] {
            1 => 6,
            4 => 18,
            3 => {
                let mut length = [0];
                stream.read_exact(&mut length).ok()?;
                let mut name = vec![0; usize::from(length[0]) + 2];
                stream.read_exact(&mut name).ok()?;
                return Some([&header[..], &length, &name].concat());
            }
            _ => return None,
        };
        let mut bytes = vec![0; rest];
        stream.read_exact(&mut bytes).ok()?;
        Some([&header[..], &bytes].concat())
    }

    /// A first hop that tunnels every connection to `residential`, and a
    /// residential proxy that records whether each CONNECT arrived together
    /// with the credentials ("fresh") or later on an idle tunnel ("pooled").
    fn proxies() -> (SocketAddrV4, Arc<Mutex<Vec<&'static str>>>) {
        let (first, log, _) = proxies_with_requests();
        (first, log)
    }

    /// `proxies`, also keeping each CONNECT request the residential side read.
    #[allow(clippy::type_complexity)]
    fn proxies_with_requests() -> (
        SocketAddrV4,
        Arc<Mutex<Vec<&'static str>>>,
        Arc<Mutex<Vec<Vec<u8>>>>,
    ) {
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
        let requests = Arc::new(Mutex::new(Vec::new()));
        let keep = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in residential.incoming() {
                let mut stream = stream.unwrap();
                let record = Arc::clone(&record);
                let keep = Arc::clone(&keep);
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
                    let mut header = [0; 4];
                    if stream.read_exact(&mut header).is_err() {
                        return; // A pooled tunnel closed unused.
                    }
                    let Some(request) = read_target(&mut stream, header) else {
                        return;
                    };
                    keep.lock().unwrap().push(request);
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
        (first_endpoint, log, requests)
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
        drop(dialer.chain(&ChainTarget::Address(destination)).unwrap());
        wait_for_pool(&dialer, 2);
        drop(dialer.chain(&ChainTarget::Address(destination)).unwrap());
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
    fn a_name_target_is_sent_as_a_domain_connect_fresh_and_pooled() {
        let (first_hop, log, requests) = proxies_with_requests();
        let dialer = dialer(first_hop);
        let target = ChainTarget::Name("media.example.com".into(), 443);
        drop(dialer.chain(&target).unwrap());
        wait_for_pool(&dialer, 2);
        drop(dialer.chain(&target).unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        while log.lock().unwrap().len() < 2 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(*log.lock().unwrap(), ["fresh", "pooled"]);
        let expected = [&[5, 1, 0, 3, 17][..], b"media.example.com", &[1, 187]].concat();
        assert_eq!(*requests.lock().unwrap(), [expected.clone(), expected]);
        dialer.close();
    }

    #[test]
    fn name_requests_carry_the_name_and_reject_unusable_ones() {
        assert_eq!(
            target_request(&ChainTarget::Name("a.example".into(), 80)).unwrap(),
            [&[5, 1, 0, 3, 9][..], b"a.example", &[0, 80]].concat()
        );
        assert!(target_request(&ChainTarget::Name(String::new(), 80)).is_err());
        assert!(target_request(&ChainTarget::Name("a".repeat(256), 80)).is_err());
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
    fn a_learned_idle_limit_recovers_after_ten_quiet_minutes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let dialer = dialer_with_target(local(&listener), 8);
        let start = Instant::now();
        dialer.closed_after_at(Duration::from_millis(9_500), start);
        assert_eq!(
            dialer.idle_limit_at(start + Duration::from_secs(540)),
            Duration::from_millis(7_600)
        );
        // Another close while pooled restarts the ten minutes.
        dialer.closed_after_at(Duration::from_secs(9), start + Duration::from_secs(300));
        assert_eq!(
            dialer.idle_limit_at(start + IDLE_RECOVERY),
            Duration::from_millis(7_200)
        );
        assert_eq!(
            dialer.idle_limit_at(start + Duration::from_secs(300) + IDLE_RECOVERY),
            POOL_IDLE
        );
        // Learning starts over from the initial limit.
        dialer.closed_after_at(Duration::from_secs(15), start + Duration::from_secs(1_000));
        assert_eq!(
            dialer.idle_limit_at(start + Duration::from_secs(1_000)),
            Duration::from_secs(12)
        );
    }

    #[test]
    fn only_a_tunnel_closed_while_pooled_teaches_the_idle_limit() {
        // No pool refills, and no first hop: a fresh chain fails at once.
        let unused = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let first_hop = local(&unused);
        drop(unused);
        let residential = crate::credential::fixture(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        let dialer = Arc::new(Dialer::new(
            first_hop,
            residential,
            PoolSettings {
                max: Some(0),
                demand_window: Some(Duration::from_secs(60)),
            },
        ));
        let pair = || {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            (client, listener.accept().unwrap().0)
        };
        let target = ChainTarget::Address(SocketAddr::from(([192, 0, 2, 1], 443)));

        // The proxy reads the CONNECT and closes without a reply, as some do
        // when the target cannot be reached: a fresh chain is tried, and the
        // idle limit stays where it was.
        let (client, mut server) = pair();
        let reader = thread::spawn(move || {
            let mut request = [0; 10];
            server.read_exact(&mut request).unwrap();
        });
        dialer.pool.lock().unwrap().push(Pooled {
            id: 1,
            stream: client,
            since: Instant::now() - Duration::from_secs(1),
        });
        assert!(dialer.chain(&target).is_err());
        reader.join().unwrap();
        assert_eq!(dialer.idle_limit(), POOL_IDLE);
        assert_eq!(dialer.report()["unanswered_on_connect"], 1);
        assert_eq!(dialer.report()["stale_on_connect"], 0);

        // A tunnel found closed while it sat in the pool does teach it.
        let (client, server) = pair();
        drop(server);
        thread::sleep(Duration::from_millis(100));
        dialer.pool.lock().unwrap().push(Pooled {
            id: 2,
            stream: client,
            since: Instant::now() - Duration::from_secs(5),
        });
        assert!(dialer.take().is_none());
        assert!(dialer.idle_limit() <= Duration::from_secs(4) + Duration::from_millis(100));
        assert!(dialer.idle_limit() >= Duration::from_secs(4));
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
