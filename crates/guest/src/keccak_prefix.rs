//! Bounded Keccak prefix cache. Advice selects an earlier guest-computed state;
//! the guest checks every byte of its prefix before using it. No state or digest
//! supplied by the prover is trusted. A full cache simply stops admitting entries.

use super::{absorb_permute, copy_words, merge_final_block, permute, store_digest};
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};

use super::prefix_params::{MAX_DEPTH, MAX_ENTRIES, MAX_INPUT_LEN, RATE};
const ENTRY_CHUNK_LEN: usize = 1024;

#[repr(C)]
struct Entry {
    state: [u64; 25],
    block: [u64; 17],
    parent: usize,
    depth: usize,
}

// Fixed chunks keep existing states in place and allocate only as entries arrive.
struct Entries {
    chunks: Vec<Vec<Entry>>,
    len: usize,
}
impl Entries {
    fn new(limit: usize) -> Self {
        Self {
            chunks: Vec::with_capacity(limit.div_ceil(ENTRY_CHUNK_LEN)),
            len: 0,
        }
    }
    fn len(&self) -> usize {
        self.len
    }
    fn get(&self, i: usize) -> Option<&Entry> {
        self.chunks
            .get(i / ENTRY_CHUNK_LEN)?
            .get(i % ENTRY_CHUNK_LEN)
    }
    /// The caller supplies separate readable state/block buffers and len < limit.
    unsafe fn append(
        &mut self,
        limit: usize,
        state: *const u64,
        block: *const u8,
        parent: usize,
        depth: usize,
    ) {
        if self.len.is_multiple_of(ENTRY_CHUNK_LEN) {
            self.chunks
                .push(Vec::with_capacity(ENTRY_CHUNK_LEN.min(limit - self.len)));
        }
        let chunk = self.chunks.last_mut().expect("entry chunk exists");
        let len = chunk.len();
        // SAFETY: the chunk reserves all slots it can receive. Initialize every
        // field before publishing; neither input points into this private store.
        let entry: *mut Entry = chunk.as_mut_ptr().add(len);
        copy_words::<false>(core::ptr::addr_of_mut!((*entry).state).cast(), state, 25);
        copy_words::<false>(
            core::ptr::addr_of_mut!((*entry).block).cast(),
            block.cast(),
            17,
        );
        core::ptr::addr_of_mut!((*entry).parent).write(parent);
        core::ptr::addr_of_mut!((*entry).depth).write(depth);
        chunk.set_len(len + 1);
        self.len += 1;
    }
}
impl core::ops::Index<usize> for Entries {
    type Output = Entry;
    fn index(&self, i: usize) -> &Entry {
        self.get(i).expect("entry index in bounds")
    }
}

struct PrefixCache {
    entries: Entries,
    limit: usize,
}

impl PrefixCache {
    fn new(limit: usize) -> Self {
        Self {
            entries: Entries::new(limit),
            limit,
        }
    }

    // Tests choose valid hints by comparing the complete stored prefix. The
    // production native planner is exercised separately against this cache.
    #[cfg(test)]
    unsafe fn find(&self, bytes: *const u8, len: usize) -> usize {
        let mut best = 0;
        let mut best_depth = 0;
        for id in 1..=self.entries.len() {
            let depth = self.entries[id - 1].depth;
            if depth <= best_depth || depth > len / RATE {
                continue;
            }
            let mut current = id;
            let mut matches = true;
            for d in (1..=depth).rev() {
                let entry = &self.entries[current - 1];
                let block = bytes.add((d - 1) * RATE);
                for i in 0..17 {
                    if core::ptr::read_unaligned(block.add(i * 8).cast::<u64>()) != entry.block[i] {
                        matches = false;
                        break;
                    }
                }
                if !matches {
                    break;
                }
                current = entry.parent;
            }
            if matches {
                best = id;
                best_depth = depth;
            }
        }
        best
    }

    /// Copies a verified earlier sponge state into `state`. Input is aligned,
    /// readable for `len` bytes; output is a separate initialized 25-word array.
    unsafe fn restore(&self, id: usize, bytes: *const u8, len: usize, state: *mut u64) -> usize {
        if id == 0 {
            return 0;
        }
        let entry = self
            .entries
            .get(id - 1)
            .expect("Keccak prefix ID out of bounds");
        let depth = entry.depth;
        assert!(depth > 0 && depth <= MAX_DEPTH && depth <= len / RATE);
        let mut current = id;
        for d in (1..=depth).rev() {
            let e = self
                .entries
                .get(
                    current
                        .checked_sub(1)
                        .expect("Keccak prefix parent missing"),
                )
                .expect("Keccak prefix parent out of bounds");
            assert_eq!(e.depth, d);
            let block = bytes.add((d - 1) * RATE).cast::<u64>();
            for i in 0..17 {
                let word = read_volatile(block.add(i));
                #[cfg(feature = "guest")]
                jolt::check_advice_eq!(word, e.block[i]);
                #[cfg(not(feature = "guest"))]
                assert_eq!(word, e.block[i], "Keccak prefix bytes differ");
            }
            current = e.parent;
        }
        assert_eq!(
            current, 0,
            "Keccak prefix chain did not reach the initial state"
        );
        copy_words::<false>(state, entry.state.as_ptr(), 25);
        depth
    }

    unsafe fn save(
        &mut self,
        state: *const u64,
        block: *const u8,
        parent: usize,
        depth: usize,
    ) -> usize {
        if depth > MAX_DEPTH || self.entries.len() == self.limit || (depth > 1 && parent == 0) {
            return 0;
        }
        let len = self.entries.len();
        self.entries.append(self.limit, state, block, parent, depth);
        let id = len + 1;
        id
    }

    /// Same input/output contract as keccak256_into, with RATE <= len <=
    /// MAX_INPUT_LEN. Hint consumption never depends on buffer alignment.
    #[inline(always)]
    unsafe fn hash_with_hint(
        &mut self,
        bytes: *const u8,
        len: usize,
        out: *mut u8,
        hint: usize,
    ) -> usize {
        assert!((RATE..=MAX_INPUT_LEN).contains(&len));
        // Initialize this bounded scratch only when the input needs alignment.
        // Aligned inputs keep their original address and require no copying.
        let mut scratch = core::mem::MaybeUninit::<[u64; MAX_INPUT_LEN / 8]>::uninit();
        let bytes = if bytes as usize & 7 == 0 {
            bytes
        } else {
            let aligned = scratch.write([0; MAX_INPUT_LEN / 8]);
            super::super::mem::memcpy_impl(aligned.as_mut_ptr().cast(), bytes, len);
            aligned.as_ptr().cast()
        };
        let mut state = core::mem::MaybeUninit::<[u64; 25]>::uninit();
        let state = state.as_mut_ptr().cast::<u64>();
        // Lower 32 bits name a checked earlier prefix; upper bits only request
        // storage of states computed below. They cannot supply a hash or state.
        let save_mask = (hint >> 32) & 7;
        let hint = hint & 0xffff_ffff;
        let reused = self.restore(hint, bytes, len, state);
        let mut depth = reused;
        let mut parent = hint;
        if depth == 0 {
            for i in 17..25 {
                write_volatile(state.add(i), 0);
            }
            copy_words::<false>(state, bytes.cast(), 17);
            permute(state);
            depth = 1;
            parent = if save_mask & 1 != 0 {
                self.save(state, bytes, 0, depth)
            } else {
                0
            };
        }
        while depth < len / RATE {
            let block = bytes.add(depth * RATE);
            absorb_permute(state, block.cast());
            depth += 1;
            parent = if save_mask & (1 << (depth - 1)) != 0 {
                self.save(state, block, parent, depth)
            } else {
                0
            };
        }
        merge_final_block::<true>(state, bytes.add(depth * RATE), len % RATE);
        permute(state);
        store_digest(state, out);
        reused
    }
}

/// The guest is single-hart and the shim never calls itself. Cache ownership is
/// confined to this function; pointers into the cache never escape it.
#[cfg(all(feature = "guest", target_arch = "riscv64"))]
pub(super) unsafe fn hash_global(bytes: *const u8, len: usize, out: *mut u8) -> usize {
    #[cfg(feature = "compute_advice")]
    let hint = {
        // The interpreted fallback needs no cache search or future knowledge.
        jolt::AdviceWriter::get().write_u64(0);
        0usize
    };
    #[cfg(not(feature = "compute_advice"))]
    let hint = jolt::AdviceReader::get().read_u64() as usize;
    if hint == 0 {
        super::keccak256_into(bytes, len, out);
        return 0;
    }
    static mut CACHE: Option<PrefixCache> = None;
    let slot = &mut *core::ptr::addr_of_mut!(CACHE);
    let cache = slot.get_or_insert_with(|| PrefixCache::new(MAX_ENTRIES));
    cache.hash_with_hint(bytes, len, out, hint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};

    #[test]
    fn native_planner_hints_replay_against_guest_cache_and_independent_hash() {
        let mut plan = crate::prefix_plan::PrefixPlan::new();
        let mut tape = Vec::new();
        let mut messages = Vec::new();
        for n in 0..512usize {
            let len = RATE + (n * 53) % (MAX_INPUT_LEN - RATE + 1);
            let mut message = vec![0u8; len];
            for (i, byte) in message.iter_mut().enumerate() {
                *byte = (i.wrapping_mul(37) + (n % (3 + i / RATE))) as u8;
            }
            let offset = tape.len();
            tape.extend_from_slice(&0u64.to_le_bytes());
            plan.record(&message, offset);
            messages.push(message);
        }
        plan.finish(&mut tape);
        let mut cache = PrefixCache::new(MAX_ENTRIES);
        let mut reused = 0;
        for (n, message) in messages.iter().enumerate() {
            let hint = u64::from_le_bytes(tape[n * 8..n * 8 + 8].try_into().unwrap()) as usize;
            let mut words = vec![0u64; message.len().div_ceil(8) + 2];
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), words.len() * 8)
            };
            let bytes = &mut bytes[n % 8..];
            bytes[..message.len()].copy_from_slice(message);
            let mut output = [0u64; 4];
            reused += unsafe {
                cache.hash_with_hint(
                    bytes.as_ptr(),
                    message.len(),
                    output.as_mut_ptr().cast(),
                    hint,
                )
            };
            let actual: Vec<_> = output.iter().flat_map(|x| x.to_le_bytes()).collect();
            assert_eq!(actual.as_slice(), Keccak256::digest(message).as_slice());
        }
        assert!(reused > 512);
    }

    fn run(cache: &mut PrefixCache, msg: &[u8], hint: Option<usize>) -> ([u8; 32], usize) {
        let mut words = vec![0u64; msg.len().div_ceil(8) + 1];
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), words.len() * 8)
        };
        bytes[..msg.len()].copy_from_slice(msg);
        let mut out = [0u64; 4];
        let reused = unsafe {
            let id = hint.unwrap_or_else(|| cache.find(bytes.as_ptr(), msg.len()));
            cache.hash_with_hint(
                bytes.as_ptr(),
                msg.len(),
                out.as_mut_ptr().cast(),
                id | (7usize << 32),
            )
        };
        let result: [u8; 32] = core::array::from_fn(|i| out[i / 8].to_le_bytes()[i % 8]);
        assert_eq!(result.as_slice(), Keccak256::digest(msg).as_slice());
        (result, reused)
    }

    #[test]
    fn arbitrary_save_masks_preserve_hashes_and_valid_prefix_chains() {
        for mask in 0..8usize {
            for len in [136usize, 137, 272, 408, MAX_INPUT_LEN] {
                let mut cache = PrefixCache::new(8);
                for changed in 0..5 {
                    let mut words = vec![0x1357_2468_1357_2468u64; len.div_ceil(8) + 1];
                    // Retain long common prefixes, but also change a prefix byte.
                    if changed != 0 {
                        words[if changed == 4 { 0 } else { len / 8 - 1 }] ^= changed;
                    }
                    let bytes = words.as_ptr().cast::<u8>();
                    let msg = unsafe { core::slice::from_raw_parts(bytes, len) };
                    let hint = unsafe { cache.find(bytes, len) } | (mask << 32);
                    let mut out = [0u64; 4];
                    unsafe {
                        cache.hash_with_hint(bytes, len, out.as_mut_ptr().cast(), hint);
                    }
                    let digest: Vec<_> = out.iter().flat_map(|x| x.to_le_bytes()).collect();
                    assert_eq!(digest.as_slice(), Keccak256::digest(msg).as_slice());
                    for i in 0..cache.entries.len() {
                        let e = &cache.entries[i];
                        if e.depth == 1 {
                            assert_eq!(e.parent, 0);
                        } else {
                            assert!(e.parent > 0 && e.parent <= i);
                            assert_eq!(cache.entries[e.parent - 1].depth + 1, e.depth);
                        }
                    }
                    if mask == 0 {
                        assert_eq!(cache.entries.len(), 0);
                    }
                }
            }
        }
    }

    #[test]
    fn saved_states_survive_chunk_boundaries_and_capacity_exhaustion() {
        let mut cache = PrefixCache::new(ENTRY_CHUNK_LEN + 1);
        let message = |n: usize| {
            let mut msg = vec![0x39; RATE];
            msg[..8].copy_from_slice(&(n as u64).to_le_bytes());
            msg
        };
        for n in 0..=ENTRY_CHUNK_LEN {
            assert_eq!(run(&mut cache, &message(n), Some(0)).1, 0);
        }
        for n in [0, ENTRY_CHUNK_LEN - 1, ENTRY_CHUNK_LEN] {
            assert_eq!(run(&mut cache, &message(n), Some(n + 1)).1, 1);
        }
        run(&mut cache, &message(ENTRY_CHUNK_LEN + 1), Some(0));
        assert_eq!(cache.entries.len(), ENTRY_CHUNK_LEN + 1);
        assert_eq!(run(&mut cache, &message(0), Some(1)).1, 1);
    }

    #[test]
    fn prefix_changes_and_padding_match_independent_hash() {
        let mut cache = PrefixCache::new(65_536);
        let mut rng = 0x123456789abcdefu64;
        for len in RATE..=MAX_INPUT_LEN {
            let mut msg = vec![0u8; len];
            for b in &mut msg {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                *b = rng as u8;
            }
            assert_eq!(run(&mut cache, &msg, None).1, 0);
            assert_eq!(run(&mut cache, &msg, None).1, (len / RATE).min(3));
            for offset in [0, 135, RATE, 271, 272, 407, 408, len - 1] {
                if offset >= len {
                    continue;
                }
                let mut changed = msg.clone();
                changed[offset] ^= 0x80;
                run(&mut cache, &changed, None);
            }
            // Same full prefix but a different message length/padding position.
            if len < MAX_INPUT_LEN {
                let mut extended = msg.clone();
                extended.push(1);
                run(&mut cache, &extended, None);
            }
        }
    }

    #[test]
    fn capacity_exhaustion_and_forced_misses_preserve_hash() {
        for limit in [0, 1, 2, 3, 4, 7] {
            let mut cache = PrefixCache::new(limit);
            for n in 0..80 {
                let mut msg = vec![0x39; RATE + n * 5];
                msg[135] ^= (n % 4) as u8;
                run(&mut cache, &msg, None);
                run(&mut cache, &msg, Some(0));
                assert!(cache.entries.len() <= limit);
            }
        }
    }

    #[test]
    fn rejects_wrong_prefix_out_of_range_and_too_long_hints() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        let mut cache = PrefixCache::new(32);
        let msg = vec![0x39; MAX_INPUT_LEN];
        run(&mut cache, &msg, None);
        for (len, offset, hint) in [
            (MAX_INPUT_LEN, 0, 1),
            (MAX_INPUT_LEN, 135, 3),
            (MAX_INPUT_LEN, 271, 3),
            (MAX_INPUT_LEN, 407, 3),
            (RATE, 0, 3),
            (MAX_INPUT_LEN, 0, usize::MAX),
        ] {
            let mut changed = msg[..len].to_vec();
            changed[offset] ^= 1;
            assert!(
                catch_unwind(AssertUnwindSafe(|| run(&mut cache, &changed, Some(hint)))).is_err()
            );
        }
        assert_eq!(core::mem::size_of::<Entry>(), 352);
    }
}
