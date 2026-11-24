//! Validated upstream answers, reused until their TTL runs out. A hit stands in
//! for the upstream exchange only: the caller still matches, validates and
//! rewrites it like a fresh response, so whitelist aliases are granted the same
//! way. Nothing is cached across controller sessions.
use super::wire::{Lifetime, lifetime, word};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Upper bound on how long any answer is reused, whatever its TTL.
const MAX_CACHE_SECONDS: u32 = 3600;
const MAX_ENTRIES: usize = 4096;

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
    /// A copy of the cached response for `query`: its ID and question bytes
    /// (including letter case) taken from the query, every TTL reduced by the
    /// whole seconds it has been cached. `None` once fewer than one second of
    /// its lifetime is left.
    pub(super) fn get(&self, key: &Key, query: &[u8], now: Instant) -> Option<Vec<u8>> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.get(key)?;
        let elapsed = u32::try_from(now.saturating_duration_since(entry.stored).as_secs()).ok()?;
        if elapsed >= entry.seconds {
            return None;
        }
        let mut wire = entry.wire.clone();
        // Same question, so the same uncompressed length right after the header.
        let question_end = 12 + question_length(query)?;
        if wire.len() < question_end || query.len() < question_end {
            return None;
        }
        wire[..2].copy_from_slice(&query[..2]);
        wire[12..question_end].copy_from_slice(&query[12..question_end]);
        for &at in &entry.ttl_offsets {
            let ttl =
                (u32::from(word(&wire, at).ok()?) << 16) | u32::from(word(&wire, at + 2).ok()?);
            wire[at..at + 4].copy_from_slice(&ttl.saturating_sub(elapsed).to_be_bytes());
        }
        Some(wire)
    }

    /// Keeps a response that already passed validation for its query. Answers
    /// without a usable lifetime (zero TTL, truncated, server errors, empty
    /// answers without an SOA) are not kept.
    pub(super) fn put(&self, key: Key, response: &[u8], now: Instant) {
        let flags = match word(response, 2) {
            Ok(flags) => flags,
            Err(_) => return,
        };
        if flags & 0x0200 != 0 || !matches!(flags & 15, 0 | 3) {
            return;
        }
        let Ok(Some(Lifetime {
            ttl_offsets,
            seconds,
        })) = lifetime(response)
        else {
            return;
        };
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= MAX_ENTRIES && !entries.contains_key(&key) {
            entries.retain(|_, entry| {
                now.saturating_duration_since(entry.stored)
                    < Duration::from_secs(u64::from(entry.seconds))
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

/// Bytes of the question name plus type and class in an uncompressed query.
fn question_length(wire: &[u8]) -> Option<usize> {
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
