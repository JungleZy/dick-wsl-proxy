//! Combine only queries already waiting for a fresh conntrack observation. No cache,
//! collection delay, retries or shared results between observations.
use crate::{
    plan::Plan,
    query_bridge::{BatchOrigins, Lookup, MAX_LOOKUPS, QueryBridge},
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

type Origin = Result<SocketAddr, String>;

/// Every caller waits for its own reply, so this many lookups can be queued at
/// once while the lane keeps up: one per IPv4 and IPv6 TCP worker, one per DNS
/// UDP worker, plus one group from the IPv4 loop and one lookup from the IPv6
/// loop. A smaller queue refuses valid lookups under load. Callers that gave up
/// after their timeout still hold a slot until dispatched; then the lane is
/// stalled anyway and a full queue fails new lookups fast.
pub(super) fn queue_capacity(max_tcp: usize) -> usize {
    2 * max_tcp + super::MAX_DNS_UDP + 2
}
pub(super) struct Observation {
    pub origin: Origin,
    pub started: Instant,
    pub elapsed: Duration,
    // Count each physical query once, separately from per-lookup timings.
    pub batch: usize,
    pub guest_us: Option<(u64, u64)>,
}
enum Job {
    One(Lookup, SyncSender<Observation>),
    Group(Vec<Lookup>, SyncSender<Vec<Observation>>),
}

pub(super) struct MetadataLane {
    jobs: Option<SyncSender<Job>>,
    worker: Option<JoinHandle<Result<(), String>>>,
}

impl MetadataLane {
    pub fn start(plan: &Plan, stopping: Arc<AtomicBool>, queue: usize) -> Result<Self, String> {
        let mut bridge = QueryBridge::open(plan)?;
        let (jobs, receiver) = mpsc::sync_channel(queue);
        let worker = thread::Builder::new()
            .name("wsl-metadata".into())
            .spawn(move || {
                let shared = std::cell::RefCell::new(&mut bridge);
                dispatch(
                    receiver,
                    &stopping,
                    KEEPALIVE_IDLE,
                    |keys| shared.borrow_mut().query_batch(keys),
                    || {
                        // A failed keepalive closes the helper; the next
                        // lookup starts a fresh one, as after an idle exit.
                        let _ = shared.borrow_mut().keepalive();
                    },
                );
                bridge.close()
            })
            .map_err(|e| format!("query_transport_dispatch: {e}"))?;
        Ok(Self {
            jobs: Some(jobs),
            worker: Some(worker),
        })
    }
    pub fn submit(&self, key: Lookup) -> Result<Receiver<Observation>, String> {
        let (send, reply) = mpsc::sync_channel(1);
        self.enqueue(Job::One(key, send))?;
        Ok(reply)
    }

    pub fn submit_group(&self, keys: &[Lookup]) -> Result<Receiver<Vec<Observation>>, String> {
        if !(1..=MAX_LOOKUPS).contains(&keys.len()) {
            return Err("query_transport_invalid_group_size".into());
        }
        let (send, reply) = mpsc::sync_channel(1);
        self.enqueue(Job::Group(keys.to_vec(), send))?;
        Ok(reply)
    }

    fn enqueue(&self, job: Job) -> Result<(), String> {
        self.jobs
            .as_ref()
            .ok_or("query_transport_closed")?
            .try_send(job)
            .map_err(|e| match e {
                mpsc::TrySendError::Full(_) => "query_transport_queue_full".into(),
                mpsc::TrySendError::Disconnected(_) => "query_transport_closed".into(),
            })
    }
    pub fn close(&mut self) -> Result<(), String> {
        self.jobs.take();
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .map_err(|_| "query_transport_dispatch_panicked")?,
            None => Ok(()),
        }
    }
}
impl Drop for MetadataLane {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// With no lookup for this long, the lane sends the helper an empty
/// keepalive request. It is well inside the host's 40-second reuse window and
/// the helper's own 45- and 60-second idle deadlines.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(20);

fn dispatch(
    receiver: Receiver<Job>,
    stopping: &AtomicBool,
    idle: Duration,
    mut query: impl FnMut(Vec<Lookup>) -> Result<BatchOrigins, String>,
    mut keepalive: impl FnMut(),
) {
    let mut next = None;
    let mut senders = Vec::with_capacity(MAX_LOOKUPS);
    loop {
        let job = match next.take() {
            Some(job) => job,
            None => match receiver.recv_timeout(idle) {
                Ok(job) => job,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if !stopping.load(Ordering::Acquire) {
                        keepalive();
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            },
        };
        match job {
            Job::Group(keys, send) => {
                // The whole group was received before enqueue. No timer or split/replay.
                let _ = send.send(observe(keys, stopping, &mut query).collect());
            }
            Job::One(first, send) => {
                let mut keys = Vec::with_capacity(MAX_LOOKUPS);
                keys.push(first);
                senders.push(send);
                while keys.len() < MAX_LOOKUPS {
                    match receiver.try_recv() {
                        Ok(Job::One(key, send)) => {
                            keys.push(key);
                            senders.push(send);
                        }
                        Ok(group) => {
                            next = Some(group);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                for (send, obs) in senders.drain(..).zip(observe(keys, stopping, &mut query)) {
                    let _ = send.send(obs);
                }
            }
        }
    }
}

fn observe(
    keys: Vec<Lookup>,
    stopping: &AtomicBool,
    query: &mut impl FnMut(Vec<Lookup>) -> Result<BatchOrigins, String>,
) -> impl Iterator<Item = Observation> {
    let count = keys.len();
    let started = Instant::now();
    let results = if stopping.load(Ordering::Acquire) {
        Err("ingress is stopping".into())
    } else {
        query(keys).and_then(|v| {
            if v.origins.len() == count {
                Ok(v)
            } else {
                Err("query_transport_result_count_mismatch".into())
            }
        })
    };
    let elapsed = started.elapsed();
    (0..count).map(move |i| {
        let origin = match &results {
            Ok(batch) => match batch.origins[i] {
                Some(origin) => Ok(origin),
                None => Err("query_lookup_mapping_missing_ambiguous_or_unowned".to_owned()),
            },
            Err(e) => Err(e.clone()),
        };
        Observation {
            origin,
            started,
            elapsed,
            batch: if i == 0 { count } else { 0 },
            guest_us: results
                .as_ref()
                .ok()
                .filter(|_| i == 0)
                .map(|b| (b.kernel_read_us, b.decode_lookup_us)),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dispatch_now(
        receiver: Receiver<Job>,
        query: impl FnMut(Vec<Lookup>) -> Result<BatchOrigins, String>,
    ) {
        dispatch(
            receiver,
            &AtomicBool::new(false),
            KEEPALIVE_IDLE,
            query,
            || {},
        );
    }

    #[test]
    fn an_idle_lane_keeps_its_helper_alive_without_a_lookup() {
        let (send, recv) = mpsc::sync_channel(4);
        let keepalives = std::cell::Cell::new(0);
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(120));
            drop(send);
        });
        dispatch(
            recv,
            &AtomicBool::new(false),
            Duration::from_millis(20),
            |_| panic!("no lookup was submitted"),
            || keepalives.set(keepalives.get() + 1),
        );
        worker.join().unwrap();
        // Several idle periods passed before the lane closed.
        assert!(keepalives.get() >= 2, "{}", keepalives.get());
    }

    #[test]
    fn a_stopping_lane_sends_no_keepalive() {
        let (send, recv) = mpsc::sync_channel::<Job>(1);
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(80));
            drop(send);
        });
        dispatch(
            recv,
            &AtomicBool::new(true),
            Duration::from_millis(10),
            |_| panic!("no lookup was submitted"),
            || panic!("keepalive while stopping"),
        );
        worker.join().unwrap();
    }
    use std::net::SocketAddrV4;
    #[test]
    fn queued_queries_share_a_fresh_observation_but_not_each_others_result() {
        let (send, recv) = mpsc::sync_channel(32);
        let mut replies = Vec::new();
        for i in 0..MAX_LOOKUPS + 1 {
            let (tx, rx) = mpsc::sync_channel(1);
            send.send(Job::One(
                Lookup {
                    protocol: "tcp",
                    peer: SocketAddr::V4(SocketAddrV4::new([127, 0, 0, 1].into(), 9000 + i as u16)),
                },
                tx,
            ))
            .unwrap();
            replies.push(rx);
        }
        drop(send);
        let mut batches = 0;
        dispatch_now(recv, |keys| {
            batches += 1;
            Ok(BatchOrigins {
                origins: keys
                    .iter()
                    .map(|k| (k.peer.port() % 2 == 0).then_some(k.peer))
                    .collect(),
                kernel_read_us: 1,
                decode_lookup_us: 2,
            })
        });
        assert_eq!(batches, 2);
        for (i, r) in replies.into_iter().enumerate() {
            let observation = r.recv().unwrap();
            if i % 2 == 0 {
                assert_eq!(observation.origin.unwrap().port(), 9000 + i as u16)
            } else {
                assert!(observation.origin.is_err())
            }
        }
    }
    #[test]
    fn a_group_is_not_split_or_paired_with_the_next_request() {
        let (send, recv) = mpsc::sync_channel(3);
        let (first, r1) = mpsc::sync_channel(1);
        let (group, rg) = mpsc::sync_channel(1);
        let (last, r2) = mpsc::sync_channel(1);
        let key = |p| Lookup {
            protocol: "udp",
            peer: SocketAddr::V4(SocketAddrV4::new([127, 0, 0, 1].into(), p)),
        };
        send.send(Job::One(key(1), first)).unwrap();
        send.send(Job::Group(vec![key(2), key(3)], group)).unwrap();
        send.send(Job::One(key(4), last)).unwrap();
        drop(send);
        dispatch_now(recv, |keys| {
            Ok(BatchOrigins {
                origins: keys
                    .iter()
                    .map(|k| (k.peer.port() != 3).then_some(k.peer))
                    .collect(),
                kernel_read_us: 1,
                decode_lookup_us: 2,
            })
        });
        assert_eq!(r1.recv().unwrap().origin.unwrap().port(), 1);
        let mut group = rg.recv().unwrap().into_iter();
        let obs = group.next().unwrap();
        assert_eq!(obs.origin.unwrap().port(), 2);
        assert_eq!(obs.batch, 2);
        let miss = group.next().unwrap();
        assert!(miss.origin.is_err());
        assert_eq!(miss.guest_us, None);
        assert_eq!(r2.recv().unwrap().origin.unwrap().port(), 4);
    }

    #[test]
    fn the_queue_holds_every_concurrent_caller_at_the_worker_limits() {
        // The dispatcher has not started: every possible waiter is still queued.
        let max_tcp = crate::policy::Limits::default().max_tcp;
        let (jobs, _receiver) = mpsc::sync_channel(queue_capacity(max_tcp));
        let lane = MetadataLane {
            jobs: Some(jobs),
            worker: None,
        };
        let key = |port| Lookup {
            protocol: "tcp",
            peer: SocketAddr::V4(SocketAddrV4::new([127, 0, 0, 1].into(), port)),
        };
        let mut replies = Vec::new();
        let waiters = 2 * max_tcp + crate::ingress::MAX_DNS_UDP + 1;
        for index in 0..waiters {
            replies.push(lane.submit(key(10_000 + index as u16)).unwrap());
        }
        assert!(lane.submit_group(&[key(1), key(2)]).is_ok());
        assert_eq!(
            lane.submit(key(3)).err().as_deref(),
            Some("query_transport_queue_full")
        );
    }
}
