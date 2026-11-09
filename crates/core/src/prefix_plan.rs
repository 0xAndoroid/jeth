//! Choose which already-computed trie prefixes the guest should retain.
//!
//! The planner changes untrusted hints only. Borrowed map keys avoid making
//! more copies of the recorded prefixes. After the visit cap, hints stay zero
//! and the guest hashes normally; the cap never rejects an execution.

use alloc::{collections::BTreeMap, vec::Vec};

use crate::keccak_prefix_params::{MAX_DEPTH, MAX_ENTRIES, RATE};

const MAX_VISITS: usize = 131_072;

struct Visit {
    prefix: Vec<u8>,
    offset: usize,
}

pub(crate) struct PrefixPlan {
    visits: Vec<Visit>,
    limit: usize,
}

impl PrefixPlan {
    pub(crate) const fn new() -> Self {
        Self {
            visits: Vec::new(),
            limit: MAX_VISITS,
        }
    }

    /// The caller has appended a zero hint at `offset`; input length satisfies
    /// the guest cache's eligibility check. Addresses do not affect the plan.
    pub(crate) fn record(&mut self, input: &[u8], offset: usize) {
        if self.visits.len() < self.limit {
            let len = (input.len() / RATE).min(MAX_DEPTH) * RATE;
            self.visits.push(Visit {
                prefix: input[..len].to_vec(),
                offset,
            });
        }
    }

    pub(crate) fn finish(&self, tape: &mut [u8]) {
        self.finish_with_capacity(tape, MAX_ENTRIES);
    }

    fn finish_with_capacity(&self, tape: &mut [u8], capacity: usize) {
        let mut counts = BTreeMap::<&[u8], usize>::new();
        for visit in &self.visits {
            for depth in 1..=visit.prefix.len() / RATE {
                *counts.entry(&visit.prefix[..depth * RATE]).or_default() += 1;
            }
        }
        let mut entries = BTreeMap::<&[u8], usize>::new();
        for visit in &self.visits {
            let mut depth = 0;
            let mut id = 0;
            for d in 1..=visit.prefix.len() / RATE {
                if let Some(&entry) = entries.get(&visit.prefix[..d * RATE]) {
                    depth = d;
                    id = entry;
                } else {
                    break;
                }
            }
            let mut parent = id;
            let mut mask = 0u64;
            for d in depth + 1..=visit.prefix.len() / RATE {
                let prefix = &visit.prefix[..d * RATE];
                if counts[prefix] > 1 && entries.len() < capacity && (d == 1 || parent != 0) {
                    parent = entries.len() + 1;
                    entries.insert(prefix, parent);
                    mask |= 1 << (d - 1);
                } else {
                    parent = 0;
                }
            }
            let hint = id as u64 | (mask << 32);
            tape[visit.offset..visit.offset + 8].copy_from_slice(&hint.to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn append(plan: &mut PrefixPlan, tape: &mut Vec<u8>, bytes: &[u8]) {
        let offset = tape.len();
        tape.extend_from_slice(&0u64.to_le_bytes());
        plan.record(bytes, offset);
    }

    fn word(tape: &[u8], offset: usize) -> u64 {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&tape[offset..offset + 8]);
        u64::from_le_bytes(bytes)
    }

    #[test]
    fn shared_parents_get_ids_in_guest_insertion_order() {
        let mut plan = PrefixPlan::new();
        let mut tape = vec![0x91; 8];
        let mut input = vec![7; 2 * RATE];
        input[RATE..].fill(19);
        append(&mut plan, &mut tape, &input[..RATE]);
        append(&mut plan, &mut tape, &input);
        append(&mut plan, &mut tape, &input);
        tape.extend_from_slice(&[0x58; 8]);
        plan.finish(&mut tape);
        assert_eq!(word(&tape, 8), 1 << 32);
        assert_eq!(word(&tape, 16), 1 | (2 << 32));
        assert_eq!(word(&tape, 24), 2);
        assert_eq!(&tape[..8], &[0x91; 8]);
        assert_eq!(&tape[32..], &[0x58; 8]);
    }

    #[test]
    fn singleton_children_are_not_stored() {
        let mut plan = PrefixPlan::new();
        let mut tape = Vec::new();
        for byte in [1, 2] {
            let mut input = vec![7; 2 * RATE];
            input[RATE..].fill(byte);
            append(&mut plan, &mut tape, &input);
        }
        plan.finish(&mut tape);
        assert_eq!(word(&tape, 0), 1 << 32);
        assert_eq!(word(&tape, 8), 1);
    }

    #[test]
    fn visit_limit_leaves_later_hints_as_plain_hashes() {
        let mut plan = PrefixPlan {
            visits: Vec::new(),
            limit: 2,
        };
        let mut tape = Vec::new();
        for _ in 0..4 {
            append(&mut plan, &mut tape, &[7; RATE]);
        }
        plan.finish(&mut tape);
        assert_eq!(plan.visits.len(), 2);
        assert_eq!(word(&tape, 0), 1 << 32);
        assert_eq!(word(&tape, 8), 1);
        assert_eq!(&tape[16..], &[0; 16]);
    }

    #[test]
    fn full_cache_reuses_existing_entries_without_admitting_children() {
        for capacity in 0..=3 {
            let mut plan = PrefixPlan::new();
            let mut tape = Vec::new();
            for _ in 0..2 {
                append(&mut plan, &mut tape, &[7; 3 * RATE]);
            }
            plan.finish_with_capacity(&mut tape, capacity);
            assert_eq!(word(&tape, 0), ((1 << capacity) - 1) << 32);
            assert_eq!(word(&tape, 8), capacity as u64);
        }
    }
}
