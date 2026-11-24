//! Keeps a burst of DNS queries from fanning out into one proxy chain each.
//! Identical queries in flight share one upstream exchange, and each route
//! runs a bounded number of exchanges at once, so later queries reuse the
//! connections those finish with instead of opening their own.
use super::cache::{Key, with_query_identity};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// How long a query waits for an identical one already in flight. Longer
/// than any single exchange, including a chain fallback.
const FLIGHT_WAIT: Duration = Duration::from_secs(30);
/// Exchanges one route runs at once.
pub(super) const MAX_ACTIVE: usize = 8;
/// How long an exchange waits for a free slot before going ahead anyway, so
/// a stalled upstream cannot hold every later query back.
const SLOT_WAIT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Flight {
    result: Mutex<Option<Result<Vec<u8>, String>>>,
    done: Condvar,
}

#[derive(Default)]
pub(super) struct Flights {
    running: Mutex<HashMap<Key, Arc<Flight>>>,
    joined: AtomicU64,
}

/// Ends a flight however its exchange ended, a panic included, so waiting
/// queries are never left until their deadline.
struct Finish<'a> {
    flights: &'a Flights,
    key: &'a Key,
    flight: Arc<Flight>,
}

impl Drop for Finish<'_> {
    fn drop(&mut self) {
        {
            let mut result = lock(&self.flight.result);
            if result.is_none() {
                *result = Some(Err("DNS upstream exchange ended without an answer".into()));
            }
        }
        self.flight.done.notify_all();
        lock(&self.flights.running).remove(self.key);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Flights {
    /// Queries that waited for an identical one instead of asking.
    pub(super) fn joined(&self) -> u64 {
        self.joined.load(Ordering::Relaxed)
    }

    /// The upstream response for `query`: from `ask` when no identical query
    /// is in flight, otherwise the one that query gets, re-addressed to this
    /// query's ID and question. An error is shared the same way.
    pub(super) fn run(
        &self,
        key: &Key,
        query: &[u8],
        ask: impl FnOnce() -> Result<Vec<u8>, String>,
    ) -> Result<Vec<u8>, String> {
        let joined = {
            let mut running = lock(&self.running);
            match running.get(key) {
                Some(flight) => Some(Arc::clone(flight)),
                None => {
                    running.insert(key.clone(), Arc::new(Flight::default()));
                    None
                }
            }
        };
        if let Some(flight) = joined {
            self.joined.fetch_add(1, Ordering::Relaxed);
            let deadline = Instant::now() + FLIGHT_WAIT;
            let mut result = lock(&flight.result);
            while result.is_none() {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err("DNS query timed out waiting for an identical query".into());
                }
                result = flight
                    .done
                    .wait_timeout(result, left)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
            return match result.as_ref().expect("checked above") {
                Ok(response) => with_query_identity(response, query)
                    .ok_or_else(|| "DNS response does not fit the waiting query".into()),
                Err(error) => Err(error.clone()),
            };
        }
        let flight = Arc::clone(lock(&self.running).get(key).expect("inserted above"));
        let finish = Finish {
            flights: self,
            key,
            flight,
        };
        let outcome = ask();
        *lock(&finish.flight.result) = Some(outcome.clone());
        drop(finish);
        outcome
    }
}

/// A bound on the exchanges one route runs at once.
#[derive(Default)]
pub(super) struct Slots {
    busy: Mutex<usize>,
    freed: Condvar,
}

pub(super) struct Slot<'a>(&'a Slots);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut busy = lock(&self.0.busy);
        *busy = busy.saturating_sub(1);
        drop(busy);
        self.0.freed.notify_one();
    }
}

impl Slots {
    /// Waits for one of `MAX_ACTIVE` slots, or `SLOT_WAIT` at most.
    pub(super) fn acquire(&self) -> Slot<'_> {
        self.acquire_within(SLOT_WAIT)
    }

    fn acquire_within(&self, wait: Duration) -> Slot<'_> {
        let deadline = Instant::now() + wait;
        let mut busy = lock(&self.busy);
        while *busy >= MAX_ACTIVE {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            busy = self
                .freed
                .wait_timeout(busy, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        *busy += 1;
        Slot(self)
    }

    #[cfg(test)]
    pub(super) fn busy(&self) -> usize {
        *lock(&self.busy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::thread;

    fn key(name: &str) -> Key {
        Key::new(name, 1, 1, 0x0100, false)
    }

    fn query(id: u16, name: &str) -> Vec<u8> {
        let mut wire = id.to_be_bytes().to_vec();
        wire.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        super::super::wire::put_name(&mut wire, name);
        wire.extend_from_slice(&[0, 1, 0, 1]);
        wire
    }

    fn response(query: &[u8]) -> Vec<u8> {
        let mut wire = query.to_vec();
        wire[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        wire[6..8].copy_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        wire
    }

    #[test]
    fn identical_queries_in_flight_share_one_exchange() {
        let flights = Arc::new(Flights::default());
        let asked = Arc::new(AtomicUsize::new(0));
        let leader_query = query(1, "shared.example");
        let leader = {
            let (flights, asked, leader_query) = (
                Arc::clone(&flights),
                Arc::clone(&asked),
                leader_query.clone(),
            );
            thread::spawn(move || {
                flights.run(&key("shared.example"), &leader_query, || {
                    asked.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(300));
                    Ok(response(&leader_query))
                })
            })
        };
        thread::sleep(Duration::from_millis(50));
        let followers: Vec<_> = (2..6u16)
            .map(|id| {
                let (flights, asked) = (Arc::clone(&flights), Arc::clone(&asked));
                thread::spawn(move || {
                    // Another letter case, as some resolvers send.
                    let own = query(id, "SHARED.example");
                    let answer = flights
                        .run(&key("shared.example"), &own, || {
                            asked.fetch_add(1, Ordering::SeqCst);
                            Ok(response(&own))
                        })
                        .unwrap();
                    (own, answer)
                })
            })
            .collect();
        assert_eq!(leader.join().unwrap().unwrap()[..2], [0, 1]);
        for follower in followers {
            let (own, answer) = follower.join().unwrap();
            assert_eq!(answer[..2], own[..2], "the follower's own ID");
            assert_eq!(
                answer[12..12 + 16],
                own[12..12 + 16],
                "its own question bytes"
            );
        }
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // Once it has finished, the next identical query asks again.
        let again = query(9, "shared.example");
        flights
            .run(&key("shared.example"), &again, || {
                asked.fetch_add(1, Ordering::SeqCst);
                Ok(response(&again))
            })
            .unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn errors_are_shared_and_different_questions_do_not_wait() {
        let flights = Arc::new(Flights::default());
        let leader = {
            let flights = Arc::clone(&flights);
            thread::spawn(move || {
                flights.run(
                    &key("failing.example"),
                    &query(1, "failing.example"),
                    || {
                        thread::sleep(Duration::from_millis(300));
                        Err("upstream failed".into())
                    },
                )
            })
        };
        thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        let other = query(2, "other.example");
        flights
            .run(&key("other.example"), &other, || Ok(response(&other)))
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(200));
        let follower = flights.run(
            &key("failing.example"),
            &query(3, "failing.example"),
            || Ok(Vec::new()),
        );
        assert_eq!(follower.unwrap_err(), "upstream failed");
        assert_eq!(leader.join().unwrap().unwrap_err(), "upstream failed");
        assert!(lock(&flights.running).is_empty());
    }

    #[test]
    fn a_route_runs_a_bounded_number_of_exchanges_then_waits_briefly() {
        let slots = Slots::default();
        let held: Vec<_> = (0..MAX_ACTIVE).map(|_| slots.acquire()).collect();
        assert_eq!(slots.busy(), MAX_ACTIVE);
        // Full: the next waits, then goes ahead once its wait runs out.
        let started = Instant::now();
        let extra = slots.acquire_within(Duration::from_millis(150));
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert_eq!(slots.busy(), MAX_ACTIVE + 1);
        drop(extra);
        drop(held);
        assert_eq!(slots.busy(), 0);
        // A slot freed while waiting is taken at once.
        let slots = Arc::new(slots);
        let held: Vec<_> = (0..MAX_ACTIVE).map(|_| slots.acquire()).collect();
        let waiter = {
            let slots = Arc::clone(&slots);
            thread::spawn(move || {
                let started = Instant::now();
                let _slot = slots.acquire_within(Duration::from_secs(5));
                started.elapsed()
            })
        };
        thread::sleep(Duration::from_millis(100));
        drop(held);
        assert!(waiter.join().unwrap() < Duration::from_secs(1));
    }
}
