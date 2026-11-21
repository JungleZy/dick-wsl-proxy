use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::lock;

const ACTIVE_LIMIT: usize = 256;
const RECENT_LIMIT: usize = 128;
const RECENT_TTL: Duration = Duration::from_secs(300);

/// Byte counts are application transport bytes, excluding proxy handshakes and
/// kernel/IP headers. No payload, DNS question, credential, or peer identity is retained.
pub(super) struct FlowStats {
    next_id: AtomicU64,
    tx: AtomicU64,
    rx: AtomicU64,
    records: Mutex<Records>,
    sample: Mutex<Sample>,
}

struct Records {
    active: VecDeque<Arc<Record>>,
    recent: VecDeque<(Instant, Arc<Record>)>,
}

struct Sample {
    at: Instant,
    tx: u64,
    rx: u64,
}

struct Record {
    id: u64,
    protocol: &'static str,
    started: Instant,
    tx: AtomicU64,
    rx: AtomicU64,
    details: Mutex<Details>,
}

struct Details {
    destination: Option<SocketAddr>,
    route: Option<&'static str>,
    reason: Option<&'static str>,
    status: &'static str,
    stage: &'static str,
    failure_stage: Option<&'static str>,
}

pub(super) struct Flow {
    stats: Arc<FlowStats>,
    record: Arc<Record>,
}

impl FlowStats {
    pub(super) fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
            records: Mutex::new(Records {
                active: VecDeque::new(),
                recent: VecDeque::new(),
            }),
            sample: Mutex::new(Sample {
                at: Instant::now(),
                tx: 0,
                rx: 0,
            }),
        }
    }

    pub(super) fn begin(self: &Arc<Self>, protocol: &'static str) -> Flow {
        let record = Arc::new(Record {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            protocol,
            started: Instant::now(),
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
            details: Mutex::new(Details {
                destination: None,
                route: None,
                reason: None,
                status: "active",
                stage: "metadata",
                failure_stage: None,
            }),
        });
        let mut records = lock(&self.records);
        records.prune();
        // The transport limits currently permit at most 201 simultaneous rows.
        // Retain a hard bound even if a future caller raises those limits.
        if records.active.len() == ACTIVE_LIMIT {
            records.active.pop_front();
        }
        records.active.push_back(Arc::clone(&record));
        Flow {
            stats: Arc::clone(self),
            record,
        }
    }

    pub(super) fn snapshot(&self) -> (serde_json::Value, serde_json::Value) {
        let mut records = lock(&self.records);
        records.prune();
        let rows = |record: &Arc<Record>| {
            let details = lock(&record.details);
            serde_json::json!({
                "id": record.id,
                "protocol": record.protocol,
                "destination": details.destination.map(|value| value.to_string()),
                "route": details.route,
                "reason": details.reason,
                "status": details.status,
                "stage": details.stage,
                "failure_stage": details.failure_stage,
                "active": details.status == "active",
                "tx_bytes": record.tx.load(Ordering::Relaxed),
                "rx_bytes": record.rx.load(Ordering::Relaxed),
                "age_ms": record.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            })
        };
        let connections = serde_json::json!({
            "active_limit": ACTIVE_LIMIT,
            "recent_limit": RECENT_LIMIT,
            "recent_ttl_seconds": RECENT_TTL.as_secs(),
            "active": records.active.iter().map(rows).collect::<Vec<_>>(),
            "recent": records.recent.iter().rev().map(|(_, record)| rows(record)).collect::<Vec<_>>(),
        });
        drop(records);
        let mut sample = lock(&self.sample);
        let now = Instant::now();
        let tx = self.tx.load(Ordering::Relaxed);
        let rx = self.rx.load(Ordering::Relaxed);
        let seconds = now.duration_since(sample.at).as_secs_f64();
        let rate = |value: u64, previous: u64| {
            if seconds > 0.0 {
                value.saturating_sub(previous) as f64 / seconds
            } else {
                0.0
            }
        };
        let traffic = serde_json::json!({
            "tx_bytes": tx,
            "rx_bytes": rx,
            "tx_bytes_per_sec": rate(tx, sample.tx),
            "rx_bytes_per_sec": rate(rx, sample.rx),
            "sample_seconds": seconds,
        });
        *sample = Sample { at: now, tx, rx };
        (connections, traffic)
    }
}

impl Records {
    fn prune(&mut self) {
        while self
            .recent
            .front()
            .is_some_and(|(at, _)| at.elapsed() >= RECENT_TTL)
        {
            self.recent.pop_front();
        }
    }
}

pub(super) struct FailureMarker(Arc<Record>);

impl FailureMarker {
    pub(super) fn failed(self) {
        self.0.failed();
    }
}

impl Record {
    fn failed(&self) {
        let mut details = lock(&self.details);
        details.failure_stage = Some(details.stage);
        details.status = "failed";
        if details.route.is_none() {
            details.route = Some("reject");
            details.reason = Some(if details.destination.is_none() {
                "metadata_unavailable"
            } else {
                "policy_reject"
            });
        }
    }
}

impl Flow {
    pub(super) fn destination(&self, destination: impl Into<SocketAddr>) {
        let mut details = lock(&self.record.details);
        details.destination = Some(destination.into());
        details.stage = "policy";
    }

    pub(super) fn selected(&self, route: &'static str, reason: &'static str) {
        let mut details = lock(&self.record.details);
        details.route = Some(route);
        details.reason = Some(reason);
    }

    pub(super) fn stage(&self, stage: &'static str) {
        lock(&self.record.details).stage = stage;
    }

    pub(super) fn failed(&self) {
        self.record.failed();
    }

    // spawn consumes its closure even on failure, so retain only the existing
    // record (not another flow owner) to report that failure after closure drop.
    pub(super) fn failure_marker(&self) -> FailureMarker {
        FailureMarker(Arc::clone(&self.record))
    }

    pub(super) fn stopped(&self) {
        let mut details = lock(&self.record.details);
        if details.status == "active" {
            details.status = "stopped";
        }
    }

    pub(super) fn tx(&self, size: usize) {
        if size == 0 {
            return;
        }
        self.record.tx.fetch_add(size as u64, Ordering::Relaxed);
        self.stats.tx.fetch_add(size as u64, Ordering::Relaxed);
    }

    pub(super) fn rx(&self, size: usize) {
        if size == 0 {
            return;
        }
        self.record.rx.fetch_add(size as u64, Ordering::Relaxed);
        self.stats.rx.fetch_add(size as u64, Ordering::Relaxed);
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.failed();
        }
        {
            let mut details = lock(&self.record.details);
            if details.status == "active" {
                details.status = "completed";
            }
        }
        let mut records = lock(&self.stats.records);
        records.active.retain(|record| record.id != self.record.id);
        records.prune();
        if records.recent.len() == RECENT_LIMIT {
            records.recent.pop_front();
        }
        records
            .recent
            .push_back((Instant::now(), Arc::clone(&self.record)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_rows_have_a_hard_cap_and_completed_rows_remain_bounded() {
        let stats = Arc::new(FlowStats::new());
        let flows: Vec<_> = (0..ACTIVE_LIMIT + 7).map(|_| stats.begin("tcp")).collect();
        let (rows, _) = stats.snapshot();
        assert_eq!(rows["active"].as_array().unwrap().len(), ACTIVE_LIMIT);
        assert_eq!(rows["active"][0]["id"], 8);
        drop(flows);
        let (rows, _) = stats.snapshot();
        assert!(rows["active"].as_array().unwrap().is_empty());
        assert_eq!(rows["recent"].as_array().unwrap().len(), RECENT_LIMIT);
    }

    #[test]
    fn worker_start_failure_updates_the_consumed_closures_recent_row() {
        let stats = Arc::new(FlowStats::new());
        let flow = stats.begin("tcp");
        let marker = flow.failure_marker();
        drop(flow);
        marker.failed();
        let (rows, _) = stats.snapshot();
        assert_eq!(rows["recent"][0]["status"], "failed");
        assert_eq!(rows["recent"][0]["failure_stage"], "metadata");
    }

    #[test]
    fn rows_transition_and_preserve_logical_destination_without_payloads() {
        let stats = Arc::new(FlowStats::new());
        let flow = stats.begin("tcp");
        flow.destination("198.18.0.1:443".parse::<SocketAddr>().unwrap());
        flow.selected("direct", "domain_alias");
        flow.stage("connect");
        let (active, _) = stats.snapshot();
        assert_eq!(active["active"][0]["active"], true);
        let id = active["active"][0]["id"].clone();
        flow.failed();
        drop(flow);
        let (rows, _) = stats.snapshot();
        assert_eq!(rows["active"].as_array().unwrap().len(), 0);
        let row = &rows["recent"][0];
        assert_eq!(row["id"], id);
        assert_eq!(row["destination"], "198.18.0.1:443");
        assert_eq!(row["reason"], "domain_alias");
        assert_eq!(row["status"], "failed");
        assert_eq!(row["failure_stage"], "connect");
        assert_eq!(row.as_object().unwrap().len(), 12);
    }

    #[test]
    fn aggregate_rate_uses_byte_deltas_and_recent_rows_are_bounded() {
        let stats = Arc::new(FlowStats::new());
        for _ in 0..RECENT_LIMIT + 7 {
            let flow = stats.begin("udp");
            flow.tx(3);
            flow.rx(5);
        }
        let (rows, traffic) = stats.snapshot();
        assert_eq!(rows["recent"].as_array().unwrap().len(), RECENT_LIMIT);
        assert_eq!(traffic["tx_bytes"], ((RECENT_LIMIT + 7) * 3) as u64);
        assert_eq!(traffic["rx_bytes"], ((RECENT_LIMIT + 7) * 5) as u64);
        assert!(traffic["tx_bytes_per_sec"].as_f64().unwrap() > 0.0);
        let (_, idle) = stats.snapshot();
        assert_eq!(idle["tx_bytes_per_sec"], 0.0);
        assert_eq!(idle["rx_bytes_per_sec"], 0.0);
    }

    #[test]
    fn metadata_failure_has_no_invented_destination_and_recent_rows_expire() {
        let stats = Arc::new(FlowStats::new());
        let flow = stats.begin("udp");
        flow.failed();
        drop(flow);
        let (rows, _) = stats.snapshot();
        assert!(rows["recent"][0]["destination"].is_null());
        assert_eq!(rows["recent"][0]["route"], "reject");
        assert_eq!(rows["recent"][0]["failure_stage"], "metadata");
        lock(&stats.records).recent[0].0 = Instant::now() - RECENT_TTL;
        assert!(stats.snapshot().0["recent"].as_array().unwrap().is_empty());
    }
}
