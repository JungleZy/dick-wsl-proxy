use std::time::{Duration, Instant};

const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const PRESSURE_QUIET: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Retirement {
    Idle,
    Quiet,
}

impl Retirement {
    pub(super) fn priority(self) -> u8 {
        match self {
            Self::Idle => 0,
            Self::Quiet => 1,
        }
    }
}

pub(super) struct UdpActivity {
    touched: Instant,
    response_debt: u32,
    debt_overflowed: bool,
}

impl UdpActivity {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            touched: now,
            response_debt: 0,
            debt_overflowed: false,
        }
    }

    pub(super) fn touched(&self) -> Instant {
        self.touched
    }

    pub(super) fn has_response_debt(&self) -> bool {
        self.response_debt != 0 || self.debt_overflowed
    }

    pub(super) fn sent(&mut self, now: Instant) {
        if let Some(debt) = self.response_debt.checked_add(1) {
            self.response_debt = debt;
        } else {
            // Once saturated, replies cannot prove that the debt reached zero.
            self.debt_overflowed = true;
        }
        self.touched = now;
    }

    pub(super) fn replied(&mut self, now: Instant) {
        self.response_debt = self.response_debt.saturating_sub(1);
        self.touched = now;
    }

    pub(super) fn expired(&self, now: Instant) -> Option<Retirement> {
        (now.duration_since(self.touched) >= IDLE_TIMEOUT).then_some(Retirement::Idle)
    }

    pub(super) fn reclaimable(&self, now: Instant) -> Option<Retirement> {
        self.expired(now).or_else(|| {
            // This is a pressure-only inactivity lease, not proof of protocol
            // completion: opaque UDP cannot correlate requests, duplicate or
            // multi-part replies. Sends add debt; only validated, delivered
            // replies retire it. Extra replies restart the quiet interval.
            // Never infer quiescence from recv WouldBlock. Lost/unanswered
            // traffic waits for ordinary idle expiry; ongoing traffic is busy.
            (!self.has_response_debt() && now.duration_since(self.touched) >= PRESSURE_QUIET)
                .then_some(Retirement::Quiet)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unanswered_send_is_busy_even_when_no_reply_is_queued() {
        let now = Instant::now();
        let mut activity = UdpActivity::new(now);
        activity.sent(now);
        assert_eq!(activity.reclaimable(now + PRESSURE_QUIET), None);
        assert_eq!(
            activity.reclaimable(now + IDLE_TIMEOUT),
            Some(Retirement::Idle)
        );
        assert!(activity.has_response_debt());
    }

    #[test]
    fn several_send_reply_cycles_must_be_quiet_before_pressure_reclaim() {
        let now = Instant::now();
        let mut activity = UdpActivity::new(now);
        for cycle in 0..3 {
            let at = now + Duration::from_millis(cycle);
            activity.sent(at);
            activity.replied(at);
        }
        assert_eq!(activity.reclaimable(now + PRESSURE_QUIET), None);
        assert_eq!(
            activity.reclaimable(now + PRESSURE_QUIET + Duration::from_millis(2)),
            Some(Retirement::Quiet)
        );
        activity.sent(now + PRESSURE_QUIET + Duration::from_millis(3));
        assert_eq!(activity.reclaimable(now + PRESSURE_QUIET * 2), None);
    }

    #[test]
    fn pipelined_sends_and_lost_responses_keep_their_debt() {
        let now = Instant::now();
        let mut activity = UdpActivity::new(now);
        activity.sent(now);
        activity.sent(now);
        activity.replied(now);
        assert_eq!(activity.reclaimable(now + PRESSURE_QUIET), None);
        activity.replied(now + PRESSURE_QUIET);
        assert_eq!(activity.reclaimable(now + PRESSURE_QUIET), None);
        assert_eq!(
            activity.reclaimable(now + PRESSURE_QUIET * 2),
            Some(Retirement::Quiet)
        );
    }

    #[test]
    fn extra_replies_restart_the_pressure_lease_without_creating_credit() {
        let now = Instant::now();
        let mut activity = UdpActivity::new(now);
        activity.sent(now);
        activity.replied(now);
        activity.replied(now + PRESSURE_QUIET);
        assert_eq!(activity.reclaimable(now + PRESSURE_QUIET), None);
        activity.sent(now + PRESSURE_QUIET);
        assert_eq!(activity.reclaimable(now + PRESSURE_QUIET * 2), None);
    }

    #[test]
    fn frequent_unanswered_traffic_is_not_expired_just_to_admit_new_peers() {
        let now = Instant::now();
        let mut activity = UdpActivity::new(now);
        for second in 0..90 {
            let at = now + Duration::from_secs(second);
            activity.sent(at);
            assert_eq!(activity.expired(at), None);
            assert_eq!(activity.reclaimable(at + PRESSURE_QUIET), None);
        }
        assert_eq!(
            activity.reclaimable(now + Duration::from_secs(119)),
            Some(Retirement::Idle)
        );
    }

    #[test]
    fn debt_overflow_is_bounded_and_never_becomes_a_false_completion() {
        let now = Instant::now();
        let mut activity = UdpActivity::new(now);
        activity.response_debt = u32::MAX;
        activity.sent(now);
        activity.response_debt = 1;
        activity.replied(now);
        assert_eq!(activity.reclaimable(now + PRESSURE_QUIET), None);
        assert_eq!(
            activity.reclaimable(now + IDLE_TIMEOUT),
            Some(Retirement::Idle)
        );
    }
}
