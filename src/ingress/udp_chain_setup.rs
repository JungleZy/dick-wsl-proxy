//! Two-hop UDP associations take several proxy round trips and may wait for the
//! full setup deadline. Build them off the ingress thread so one slow hop cannot
//! freeze TCP accepts, the other UDP mappings or DNS intake.
//!
//! A mapping's first datagram waits for its setup and is authorized against the
//! kernel again before it is sent; later datagrams are dropped meanwhile (UDP
//! senders retransmit). A failed setup refuses the same mapping for a short
//! backoff instead of rebuilding the chain for every retransmission.
use super::Flow;
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Setups running at once; further new chained mappings are refused.
pub(super) const MAX_SETUPS: usize = 16;
/// How long a mapping whose setup failed is refused before the next attempt.
pub(super) const FAILURE_BACKOFF: Duration = Duration::from_secs(3);

/// Why a datagram from a mapping without a flow must not be processed now.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Hold {
    /// No setup is running or recently failed for this mapping.
    No,
    /// Its setup is running; the first datagram is already held.
    Pending,
    /// Its setup failed moments ago.
    BackedOff,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Refused {
    /// Another setup is already running for this guest socket.
    Busy,
    /// `MAX_SETUPS` setups are running.
    Full,
    Spawn(String),
}

impl Refused {
    pub(super) fn message(&self) -> String {
        match self {
            Self::Busy => "UDP chain setup already running for this guest socket".into(),
            Self::Full => {
                format!("UDP chain setup capacity reached: {MAX_SETUPS} setups in progress")
            }
            Self::Spawn(error) => format!("start UDP chain setup: {error}"),
        }
    }
}

/// A finished setup and the mapping's held first datagram.
pub(super) struct Ready<K, T> {
    pub(super) peer: K,
    pub(super) origin: SocketAddr,
    pub(super) stats: Flow,
    pub(super) datagram: Vec<u8>,
    pub(super) result: Result<T, String>,
}

struct Pending {
    token: u64,
    origin: SocketAddr,
    stats: Flow,
    datagram: Vec<u8>,
    worker: JoinHandle<()>,
}

type Message<K, T> = (u64, K, Result<T, String>);

pub(super) struct ChainSetups<K, T> {
    pending: BTreeMap<K, Pending>,
    backoff: BTreeMap<K, (SocketAddr, Instant)>,
    ready: VecDeque<Ready<K, T>>,
    sender: Sender<Message<K, T>>,
    results: Receiver<Message<K, T>>,
    next_token: u64,
}

impl<K: Ord + Copy + Send + 'static, T: Send + 'static> ChainSetups<K, T> {
    pub(super) fn new() -> Self {
        let (sender, results) = mpsc::channel();
        Self {
            pending: BTreeMap::new(),
            backoff: BTreeMap::new(),
            ready: VecDeque::new(),
            sender,
            results,
            next_token: 0,
        }
    }

    /// Checked before a datagram opens a connection record for `peer`.
    pub(super) fn hold(&mut self, peer: K, origin: SocketAddr, now: Instant) -> Hold {
        if self
            .pending
            .get(&peer)
            .is_some_and(|pending| pending.origin == origin)
        {
            return Hold::Pending;
        }
        match self.backoff.get(&peer) {
            Some((failed, until)) if *failed == origin && now < *until => Hold::BackedOff,
            Some(_) => {
                self.backoff.remove(&peer);
                Hold::No
            }
            None => Hold::No,
        }
    }

    /// Starts `connect` on its own thread and holds `datagram` until it
    /// finishes. A refusal hands the accounting record back to the caller.
    pub(super) fn start(
        &mut self,
        peer: K,
        origin: SocketAddr,
        datagram: &[u8],
        stats: Flow,
        connect: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Result<(), (Flow, Refused)> {
        if self.pending.contains_key(&peer) {
            return Err((stats, Refused::Busy));
        }
        if self.pending.len() >= MAX_SETUPS {
            return Err((stats, Refused::Full));
        }
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        let sender = self.sender.clone();
        let worker = thread::Builder::new()
            .name("m2-udp-chain".into())
            .spawn(move || {
                let result = connect();
                let _ = sender.send((token, peer, result));
            });
        match worker {
            Ok(worker) => {
                self.pending.insert(
                    peer,
                    Pending {
                        token,
                        origin,
                        stats,
                        datagram: datagram.to_vec(),
                        worker,
                    },
                );
                Ok(())
            }
            Err(error) => Err((stats, Refused::Spawn(error.to_string()))),
        }
    }

    /// Up to `limit` finished setups, oldest first. A failure starts the backoff.
    pub(super) fn finished(&mut self, now: Instant, limit: usize) -> Vec<Ready<K, T>> {
        self.backoff.retain(|_, (_, until)| now < *until);
        // A worker sends its result before it exits. Look at the exited ones
        // first, then drain: an exited worker without a result has panicked.
        let exited: Vec<K> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.worker.is_finished())
            .map(|(peer, _)| *peer)
            .collect();
        while let Ok((token, peer, result)) = self.results.try_recv() {
            if self
                .pending
                .get(&peer)
                .is_some_and(|pending| pending.token == token)
            {
                self.complete(peer, result, now);
            }
        }
        for peer in exited {
            if self.pending.contains_key(&peer) {
                self.complete(peer, Err("UDP chain setup worker panicked".into()), now);
            }
        }
        let count = limit.min(self.ready.len());
        self.ready.drain(..count).collect()
    }

    fn complete(&mut self, peer: K, result: Result<T, String>, now: Instant) {
        let Some(pending) = self.pending.remove(&peer) else {
            return;
        };
        let _ = pending.worker.join();
        if result.is_err() {
            self.backoff
                .insert(peer, (pending.origin, now + FAILURE_BACKOFF));
        }
        self.ready.push_back(Ready {
            peer,
            origin: pending.origin,
            stats: pending.stats,
            datagram: pending.datagram,
            result,
        });
    }
}

impl<K, T> Drop for ChainSetups<K, T> {
    fn drop(&mut self) {
        // Every setup ends within its own deadline. Join them so none outlives
        // the ingress, and close their records as stopped, not completed.
        for (_, pending) in std::mem::take(&mut self.pending) {
            let _ = pending.worker.join();
            pending.stats.stopped();
        }
        for ready in self.ready.drain(..) {
            ready.stats.stopped();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::flow_stats::FlowStats;
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;

    fn address(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), port))
    }

    fn wait_ready(setups: &mut ChainSetups<u16, u8>, now: Instant) -> Ready<u16, u8> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(ready) = setups.finished(now, 1).pop() {
                return ready;
            }
            assert!(Instant::now() < deadline, "setup did not finish");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_slow_setup_does_not_block_and_holds_only_its_own_mapping() {
        let stats = Arc::new(FlowStats::new());
        let mut setups: ChainSetups<u16, u8> = ChainSetups::new();
        let (release, gate) = mpsc::channel::<()>();
        let started = Instant::now();
        setups
            .start(1, address(443), b"first", stats.begin("udp"), move || {
                gate.recv().unwrap();
                Ok(7)
            })
            .map_err(|(_, refused)| refused)
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        let now = Instant::now();
        assert_eq!(setups.hold(1, address(443), now), Hold::Pending);
        assert_eq!(setups.hold(1, address(444), now), Hold::No);
        assert_eq!(setups.hold(2, address(443), now), Hold::No);
        let (stats_back, refused) = setups
            .start(1, address(444), b"x", stats.begin("udp"), || Ok(0))
            .unwrap_err();
        assert_eq!(refused, Refused::Busy);
        stats_back.failed();
        assert!(setups.finished(now, 16).is_empty());

        release.send(()).unwrap();
        let ready = wait_ready(&mut setups, now);
        assert_eq!(ready.peer, 1);
        assert_eq!(ready.datagram, b"first");
        assert_eq!(ready.result, Ok(7));
        assert_eq!(setups.hold(1, address(443), now), Hold::No);
        drop(ready);
    }

    #[test]
    fn a_failed_setup_backs_off_its_mapping_then_allows_a_retry() {
        let stats = Arc::new(FlowStats::new());
        let mut setups: ChainSetups<u16, u8> = ChainSetups::new();
        setups
            .start(1, address(443), b"q", stats.begin("udp"), || {
                Err("residential UDP authentication rejected".into())
            })
            .map_err(|(_, refused)| refused)
            .unwrap();
        let now = Instant::now();
        let ready = wait_ready(&mut setups, now);
        assert!(ready.result.is_err());
        ready.stats.failed();
        assert_eq!(setups.hold(1, address(443), now), Hold::BackedOff);
        // A different destination from the same socket is a different mapping.
        assert_eq!(setups.hold(1, address(53), now), Hold::No);
        assert_eq!(
            setups.hold(1, address(443), now + FAILURE_BACKOFF),
            Hold::No
        );
    }

    #[test]
    fn running_setups_are_bounded() {
        let stats = Arc::new(FlowStats::new());
        let mut setups: ChainSetups<u16, u8> = ChainSetups::new();
        let (release, gate) = mpsc::channel::<()>();
        let gate = Arc::new(std::sync::Mutex::new(gate));
        for peer in 0..MAX_SETUPS as u16 {
            let gate = Arc::clone(&gate);
            setups
                .start(peer, address(443), b"q", stats.begin("udp"), move || {
                    let _ = gate.lock().unwrap().recv();
                    Ok(0)
                })
                .map_err(|(_, refused)| refused)
                .unwrap();
        }
        let (stats_back, refused) = setups
            .start(999, address(443), b"q", stats.begin("udp"), || Ok(0))
            .unwrap_err();
        assert_eq!(refused, Refused::Full);
        stats_back.failed();
        drop(stats_back);
        drop(release); // Unblocks every worker; drop joins them.
        drop(setups);
        let (connections, _) = stats.snapshot();
        let recent = connections["recent"].as_array().unwrap();
        assert_eq!(recent.len(), MAX_SETUPS + 1);
        let stopped = recent
            .iter()
            .filter(|row| row["status"] == "stopped")
            .count();
        assert_eq!(stopped, MAX_SETUPS);
        assert!(connections["active"].as_array().unwrap().is_empty());
    }

    #[test]
    fn a_panicking_setup_is_reported_as_a_failure() {
        let stats = Arc::new(FlowStats::new());
        let mut setups: ChainSetups<u16, u8> = ChainSetups::new();
        setups
            .start(1, address(443), b"q", stats.begin("udp"), || {
                panic!("setup bug")
            })
            .map_err(|(_, refused)| refused)
            .unwrap();
        let ready = wait_ready(&mut setups, Instant::now());
        assert_eq!(
            ready.result,
            Err("UDP chain setup worker panicked".to_string())
        );
        ready.stats.failed();
    }
}
