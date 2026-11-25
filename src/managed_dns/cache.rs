//! Validated upstream answers, reused until their TTL runs out, and for a while
//! after that as stale answers while a refresh runs (RFC 8767). A hit stands in
//! for the upstream exchange only: the caller still matches, validates and
//! rewrites it like a fresh response, so whitelist aliases are granted the same
//! way. Nothing is cached across controller sessions.
use super::wire::{Lifetime, lifetime, word};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Whether a validated response may be cached.
enum Usable {
    Keep(Lifetime),
    /// A normal answer the upstream says not to reuse.
    DoNotKeep,
    /// Not a normal answer: a server error, a truncated or unreadable one.
    Failure,
}

fn usable(response: &[u8]) -> Usable {
    let Ok(flags) = word(response, 2) else {
        return Usable::Failure;
    };
    if flags & 0x0200 != 0 || !matches!(flags & 15, 0 | 3) {
        return Usable::Failure;
    }
    match lifetime(response) {
        Ok(Some(lifetime)) => Usable::Keep(lifetime),
        Ok(None) => Usable::DoNotKeep,
        Err(_) => Usable::Failure,
    }
}

/// Upper bound on how long any answer is reused, whatever its TTL.
const MAX_CACHE_SECONDS: u32 = 3600;
const MAX_ENTRIES: usize = 4096;
/// How long after expiry an answer may still be served stale.
const STALE_WINDOW: u32 = 3600;
/// The TTL a stale answer carries, as RFC 8767 recommends.
const STALE_TTL: u32 = 30;

/// A cached answer for a query, and whether it had already expired.
pub(super) struct Hit {
    pub(super) wire: Vec<u8>,
    pub(super) stale: bool,
}

/// Question plus the query bits that change what an upstream returns:
/// recursion desired, checking disabled and DNSSEC OK.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct Key {
    name: String,
    kind: u16,
    class: u16,
    flags: u16,
    dnssec: bool,
}

impl Key {
    pub(super) fn new(name: &str, kind: u16, class: u16, flags: u16, dnssec: bool) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            class,
            flags: flags & 0x0110,
            dnssec,
        }
    }
}

struct Entry {
    wire: Vec<u8>,
    ttl_offsets: Vec<usize>,
    stored: Instant,
    seconds: u32,
}

#[derive(Default)]
pub(super) struct Cache {
    entries: Mutex<HashMap<Key, Entry>>,
}

impl Cache {
    /// `lookup` without stale answers.
    #[cfg(test)]
    pub(super) fn get(&self, key: &Key, query: &[u8], now: Instant) -> Option<Vec<u8>> {
        self.lookup(key, query, now)
            .filter(|hit| !hit.stale)
            .map(|hit| hit.wire)
    }

    /// A copy of the cached response for `query`: its ID and question bytes
    /// (including letter case) taken from the query, every TTL reduced by the
    /// whole seconds it has been cached. An answer that expired less than
    /// `STALE_WINDOW` ago comes back marked stale, every TTL then set to
    /// `STALE_TTL`; the caller refreshes it.
    pub(super) fn lookup(&self, key: &Key, query: &[u8], now: Instant) -> Option<Hit> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.get(key)?;
        let elapsed = u32::try_from(now.saturating_duration_since(entry.stored).as_secs()).ok()?;
        let stale = elapsed >= entry.seconds;
        if stale && elapsed - entry.seconds >= STALE_WINDOW {
            return None;
        }
        let mut wire = with_query_identity(&entry.wire, query)?;
        for &at in &entry.ttl_offsets {
            let ttl =
                (u32::from(word(&wire, at).ok()?) << 16) | u32::from(word(&wire, at + 2).ok()?);
            let left = if stale {
                STALE_TTL
            } else {
                ttl.saturating_sub(elapsed)
            };
            wire[at..at + 4].copy_from_slice(&left.to_be_bytes());
        }
        Some(Hit { wire, stale })
    }

    /// Keeps a response that already passed validation for its query. Answers
    /// without a usable lifetime (zero TTL, truncated, server errors, empty
    /// answers without an SOA) are not kept.
    pub(super) fn put(&self, key: Key, response: &[u8], now: Instant) {
        if let Usable::Keep(lifetime) = usable(response) {
            self.insert(key, response, lifetime, now);
        }
    }

    /// Stores what a refresh of an expired answer brought back. Like `put`,
    /// and when the upstream answered normally (NOERROR or NXDOMAIN, not
    /// truncated) but said not to keep the answer (zero TTL, an empty answer
    /// without SOA), the expired copy goes too: it must not be served stale
    /// again. A failure (SERVFAIL, REFUSED, truncated, unreadable) leaves the
    /// expired copy to be served stale until its window ends (decision 04).
    pub(super) fn refresh(&self, key: Key, response: &[u8], now: Instant) {
        match usable(response) {
            Usable::Keep(lifetime) => self.insert(key, response, lifetime, now),
            Usable::DoNotKeep => {
                self.entries
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&key);
            }
            Usable::Failure => {}
        }
    }

    fn insert(&self, key: Key, response: &[u8], lifetime: Lifetime, now: Instant) {
        let Lifetime {
            ttl_offsets,
            seconds,
        } = lifetime;
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= MAX_ENTRIES && !entries.contains_key(&key) {
            entries.retain(|_, entry| {
                now.saturating_duration_since(entry.stored)
                    < Duration::from_secs(u64::from(entry.seconds) + u64::from(STALE_WINDOW))
            });
            if entries.len() >= MAX_ENTRIES {
                let oldest = entries
                    .iter()
                    .min_by_key(|(_, entry)| {
                        entry.stored + Duration::from_secs(u64::from(entry.seconds))
                    })
                    .map(|(key, _)| key.clone());
                if let Some(oldest) = oldest {
                    entries.remove(&oldest);
                }
            }
        }
        entries.insert(
            key,
            Entry {
                wire: response.to_vec(),
                ttl_offsets,
                stored: now,
                seconds: seconds.min(MAX_CACHE_SECONDS),
            },
        );
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

/// `response` re-addressed to `query`: its ID and question bytes, letter
/// case included. `None` unless both carry the same-length question.
pub(super) fn with_query_identity(response: &[u8], query: &[u8]) -> Option<Vec<u8>> {
    // Same question, so the same uncompressed length right after the header.
    let question_end = 12 + question_length(query)?;
    if response.len() < question_end || query.len() < question_end {
        return None;
    }
    let mut wire = response.to_vec();
    wire[..2].copy_from_slice(&query[..2]);
    wire[12..question_end].copy_from_slice(&query[12..question_end]);
    Some(wire)
}

/// Bytes of the question name plus type and class in an uncompressed query.
pub(super) fn question_length(wire: &[u8]) -> Option<usize> {
    let mut at = 12;
    loop {
        let length = usize::from(*wire.get(at)?);
        if length & 0xc0 != 0 {
            return None;
        }
        at += 1 + length;
        if length == 0 {
            break;
        }
    }
    (at + 4 <= wire.len()).then_some(at + 4 - 12)
}
