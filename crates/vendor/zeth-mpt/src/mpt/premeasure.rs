//! Feature-gated (`premeasure`) resolver counters — native runs only, never
//! enabled in guest builds.
//!
//! Counts: digest probes and resolver hits during `resolve_with` (witness-entry
//! consumption) and the hits that decoded into a node.

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

pub static PROBES: AtomicU64 = AtomicU64::new(0);
pub static HITS: AtomicU64 = AtomicU64::new(0);
pub static DECODES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default)]
pub struct Snapshot {
    pub probes: u64,
    pub hits: u64,
    pub decodes: u64,
}

pub fn snapshot() -> Snapshot {
    Snapshot {
        probes: PROBES.load(Relaxed),
        hits: HITS.load(Relaxed),
        decodes: DECODES.load(Relaxed),
    }
}

#[inline]
pub(super) fn count(counter: &AtomicU64) {
    counter.fetch_add(1, Relaxed);
}
