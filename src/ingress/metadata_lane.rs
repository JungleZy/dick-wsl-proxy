//! Combine only queries already waiting for a fresh conntrack observation. No cache,
//! collection delay, retries or shared results between observations.
use crate::{
    plan::Plan,
    query_bridge::{BatchOrigins, Lookup, MAX_LOOKUPS, QueryBridge},
};
use std::{
    net::{SocketAddr, SocketAddrV4},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

type Origin = Result<SocketAddrV4, String>;
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
    pub fn start(plan: &Plan, stopping: Arc<AtomicBool>) -> Result<Self, String> {
        let mut bridge = QueryBridge::open(plan)?;
        // 64 TCP workers, eight DNS workers and one bounded datagram group can wait.
        let (jobs, receiver) = mpsc::sync_channel(80);
        let worker = thread::Builder::new()
            .name("wsl-metadata".into())
            .spawn(move || {
                dispatch(receiver, &stopping, |keys| bridge.query_batch(keys));
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

fn dispatch(
    receiver: Receiver<Job>,
    stopping: &AtomicBool,
    mut query: impl FnMut(Vec<Lookup>) -> Result<BatchOrigins, String>,
) {
    let mut next = None;
    let mut senders = Vec::with_capacity(MAX_LOOKUPS);
    while let Some(job) = next.take().or_else(|| receiver.recv().ok()) {
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
                Some(SocketAddr::V4(origin)) => Ok(origin),
                Some(SocketAddr::V6(_)) => {
                    Err("query_lookup_ipv6_origin_requires_ipv6_ingress".to_owned())
                }
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
        dispatch(recv, &AtomicBool::new(false), |keys| {
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
        dispatch(recv, &AtomicBool::new(false), |keys| {
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
}
