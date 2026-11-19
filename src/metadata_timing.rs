//! Constant-space, per-controller measurements for fresh WSL metadata observations.
use serde_json::{Value, json};
use std::time::Duration;

// Finite buckets contain values <= 2^index microseconds. Report the bucket upper bound,
// not an invented exact percentile. Nanosecond totals keep sub-microsecond waits visible.
#[derive(Default)]
struct Series {
    bins: [u64; 32],
    count: u64,
    total_ns: u128,
    max_us: u64,
}
impl Series {
    fn record(&mut self, elapsed: Duration) {
        let us = u64::try_from(elapsed.as_nanos().div_ceil(1000)).unwrap_or(u64::MAX);
        let index = (u64::BITS - (us.saturating_sub(1)).leading_zeros()).min(31) as usize;
        self.bins[index] = self.bins[index].saturating_add(1);
        self.count = self.count.saturating_add(1);
        self.total_ns = self.total_ns.saturating_add(elapsed.as_nanos());
        self.max_us = self.max_us.max(us);
    }
    fn percentile_upper(&self, percent: u64) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let rank = (u128::from(self.count) * u128::from(percent)).div_ceil(100);
        let mut prefix = 0u128;
        for (i, &n) in self.bins.iter().enumerate() {
            prefix += u128::from(n);
            if prefix >= rank {
                return Some(if i == 31 {
                    self.max_us
                } else {
                    self.max_us.min(1 << i)
                });
            }
        }
        None
    }
    fn snapshot(&self) -> Value {
        json!({"count":self.count,"total_us": self.total_ns as f64 / 1000., "max_us":self.max_us,"p50_upper_us":self.percentile_upper(50),"p95_upper_us":self.percentile_upper(95),"buckets":self.bins})
    }
}
#[derive(Default)]
pub(super) struct MetadataTiming {
    queue: Series,
    command: Series,
    batches: u64,
    largest_batch: usize,
    wall: Series,
    kernel_read: Series,
    decode_lookup: Series,
    residual: Series,
}
impl MetadataTiming {
    pub(super) fn observe(
        &mut self,
        queue: Duration,
        command: Duration,
        batch: usize,
        guest_us: Option<(u64, u64)>,
    ) {
        if batch != 0 {
            self.batches = self.batches.saturating_add(1);
            self.largest_batch = self.largest_batch.max(batch);
            // Guest durations are from its monotonic clock, not wall-clock timestamps.
            // Only the first member of a successfully measured physical batch contributes.
            if let Some((read, decode)) = guest_us {
                let read = Duration::from_micros(read);
                let decode = Duration::from_micros(decode);
                self.wall.record(command);
                self.kernel_read.record(read);
                self.decode_lookup.record(decode);
                self.residual.record(command.saturating_sub(read + decode));
            }
        }
        self.queue.record(queue);
        self.command.record(command);
    }
    pub(super) fn snapshot(&self) -> Value {
        json!({"queue":self.queue.snapshot(),"query":self.command.snapshot(),"batches":self.batches,"largest_batch":self.largest_batch,
            "physical":{"wall":self.wall.snapshot(), "kernel_read":self.kernel_read.snapshot(),"decode_lookup":self.decode_lookup.snapshot(),"residual":self.residual.snapshot()}})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boundaries_preserve_upper_bounds_and_empty_samples() {
        let mut s = Series::default();
        assert_eq!(s.percentile_upper(95), None);
        for us in [0, 1, 2, 3, 5, 8, 9] {
            s.record(Duration::from_micros(us));
        }
        assert_eq!(s.bins[..5], [2, 1, 1, 2, 1]);
        assert_eq!(s.percentile_upper(50), Some(4));
        assert_eq!(s.percentile_upper(95), Some(9));
        assert_eq!(s.total_ns, 28000);
    }
    #[test]
    fn logical_timings_do_not_multiply_physical_stage_totals() {
        let mut t = MetadataTiming::default();
        let command = Duration::from_micros(11);
        t.observe(Duration::ZERO, command, 2, Some((3, 5)));
        t.observe(Duration::ZERO, command, 0, None);
        assert_eq!(t.command.count, 2);
        assert_eq!(t.wall.count, 1);
        assert_eq!(t.residual.total_ns, 3000);
    }
}
