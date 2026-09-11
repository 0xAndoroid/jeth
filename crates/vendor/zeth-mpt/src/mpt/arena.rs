// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Arena node encoder: dirty nodes encode post-order into one 8-aligned
//! scratch buffer through a word writer (no sub-word stores); each node's
//! payload length is untrusted advice, sealed against the bytes written.
use super::{
    advice::{advice_assert_eq, advice_u64},
    children::Slot,
    memoize::Memoization,
    node::Node,
    rlp::{NodeRef, RlpNode, DIGEST_ITEM_PREFIX, DIGEST_RLP_LENGTH},
};
use alloy_primitives::B256;
use alloy_rlp::{Encodable, EMPTY_STRING_CODE};
use alloy_trie::nodes::encode_path_leaf;
use core::ptr::{read_volatile, write_volatile};

/// Scratch capacity for the arena encoder — a branch is ≤ 3 + 17×33 = 564 B,
/// leaves ≤ path 34 + value item ≈ 150 B; 1 KiB leaves ample margin. The
/// capacity assert turns a (dishonest) oversized claim into a refusal.
pub(super) const MAX_NODE_ENCODING: usize = 1024;

/// Arena encoder scratch: `MAX_NODE_ENCODING` usable bytes, 8-aligned so the
/// word writer's `ld`/`sd` addresses are provably aligned (Jolt traps on
/// misaligned word access), plus a 7-byte tail that absorbs the writer's
/// clobber past the cursor ([`put_window`]).
#[repr(C, align(8))]
pub(super) struct Scratch([u8; MAX_NODE_ENCODING + 8]);

impl Scratch {
    #[inline]
    pub(super) fn new() -> Self {
        Self([0; MAX_NODE_ENCODING + 8])
    }
}

/// Write an RLP list header for `payload_len` at `buf[0..]`; returns its size.
/// Mirrors `alloy_rlp::Header::encode` for lists (payloads here ≤ 1 KiB).
#[inline(always)]
fn write_list_header(buf: &mut [u8], payload_len: usize) -> usize {
    if payload_len < 56 {
        buf[0] = 0xc0 + payload_len as u8;
        1
    } else if payload_len < 256 {
        buf[0] = 0xf8;
        buf[1] = payload_len as u8;
        2
    } else {
        buf[0] = 0xf9;
        buf[1] = (payload_len >> 8) as u8;
        buf[2] = payload_len as u8;
        3
    }
}

/// Longest string item the arena encoder writes: the long form carries a
/// one-byte length (`0xb8 len`), which covers every trie value (an account
/// leaf is ~110 bytes, a storage value at most 33). Longer items are refused,
/// never encoded with a wrong length.
const MAX_STR_ITEM_LEN: usize = 256;

/// Append `bytes` as an RLP string item (canonical: single bytes < 0x80 are
/// their own encoding). Mirrors `alloy_rlp`'s `[u8]` Encodable.
#[inline(always)]
fn write_str_item(buf: &mut Scratch, cursor: &mut usize, bytes: &[u8]) {
    let len = bytes.len();
    if len == 1 && bytes[0] < 0x80 {
        buf.0[*cursor] = bytes[0];
        *cursor += 1;
        return;
    }
    let prefix = if len < 56 {
        0x80 + len as u8
    } else {
        assert!(
            len < MAX_STR_ITEM_LEN,
            "MPT: string item too long for the one-byte length form"
        );
        buf.0[*cursor] = 0xb8;
        *cursor += 1;
        len as u8
    };
    if len == 0 {
        buf.0[*cursor] = prefix;
        *cursor += 1;
        return;
    }
    assert!(
        *cursor + 1 + len <= MAX_NODE_ENCODING,
        "MPT: node encoding too large"
    );
    // SAFETY: `bytes` is a live slice of `len ≥ 1` bytes; the bound above is
    // the writer's capacity contract.
    unsafe { put_prefixed(buf, cursor, prefix, bytes.as_ptr(), len) }
}

/// Word-granular scratch writer. Every sub-word memory access is a multi-row
/// virtual sequence in Jolt (`sb` 8, `lbu` 4, `lw` 5 rows), and the generic
/// `memcpy` pays ~60 rows of head/tail alignment work per call, so the
/// encoder assembles child references and string items from whole `ld`
/// words and stores whole `sd` words: the first destination word is
/// read-modify-written (bytes below the cursor are preserved), the last one
/// clobbers up to 7 bytes past the item — the scratch is fully owned and
/// [`Scratch`] carries that slack. Sources are read as the aligned words that
/// contain them (same argument as the guest `mem.rs` overrides: Jolt guest
/// RAM is flat and word-granular, and a word holding a live byte is
/// addressable; natively the containing word lies in the same page).
///
/// A "window" is the stream of `len` bytes starting at byte `so` (0..8) of a
/// sequence of 8-byte little-endian words: word 0 is `w0` — a register value,
/// loaded or synthesized (that is how a one-byte RLP prefix is folded in for
/// free) — and words 1.. are the aligned memory words at `rest`. Exactly the
/// words holding live stream bytes are read from `rest`.
///
/// `dst` is the aligned scratch word containing the cursor, `d = cursor & 7`.
///
/// # Safety
/// `dst` must be 8-aligned with `(d + len + 7) / 8` writable words behind it;
/// `rest` must be 8-aligned with `(so + len + 7) / 8 - 1` readable words.
#[inline(always)]
unsafe fn put_window(dst: *mut u64, d: usize, w0: u64, rest: *const u64, so: usize, len: usize) {
    debug_assert!(d < 8 && so < 8 && len >= 1);
    let n_dst = (d + len + 7) >> 3;
    let n_src = (so + len + 7) >> 3;
    // bytes below the cursor in the first destination word
    let keep = !(u64::MAX << (8 * d));
    let merge = |v: u64| (read_volatile(dst) & keep) | (v & !keep);
    // Relative byte shift between the source window and the destination
    // words: destination word j is the funnel of virtual words U_j, U_{j+1}
    // where U_k = V_k when `so >= d`, else U_k = V_{k-1} (V_{-1} = 0); words
    // past the window are dead bytes and read as 0.
    let s = so.wrapping_sub(d) & 7;
    if s == 0 {
        write_volatile(dst, merge(w0));
        let mut j = 1;
        while j < n_dst {
            write_volatile(dst.add(j), read_volatile(rest.add(j - 1)));
            j += 1;
        }
        return;
    }
    let sr = (8 * s) as u32;
    let sl = 64 - sr;
    if so > d {
        // n_dst <= n_src; destination word j needs V_{j+1}, which exists
        // for j < full.
        let full = if n_dst < n_src { n_dst } else { n_dst - 1 };
        let mut cur = w0;
        if full == 0 {
            write_volatile(dst, merge(cur >> sr));
            return;
        }
        let nxt = read_volatile(rest);
        write_volatile(dst, merge((cur >> sr) | (nxt << sl)));
        cur = nxt;
        let mut j = 1;
        while j < full {
            let nxt = read_volatile(rest.add(j));
            write_volatile(dst.add(j), (cur >> sr) | (nxt << sl));
            cur = nxt;
            j += 1;
        }
        if full < n_dst {
            write_volatile(dst.add(full), cur >> sr);
        }
    } else {
        // n_dst ∈ {n_src, n_src + 1}; destination word j ≥ 1 needs V_j =
        // rest[j - 1], which exists for j < full.
        write_volatile(dst, merge(w0 << sl));
        let full = if n_dst == n_src { n_dst } else { n_dst - 1 };
        let mut cur = w0;
        let mut j = 1;
        while j < full {
            let nxt = read_volatile(rest.add(j - 1));
            write_volatile(dst.add(j), (cur >> sr) | (nxt << sl));
            cur = nxt;
            j += 1;
        }
        if full < n_dst {
            write_volatile(dst.add(full), cur >> sr);
        }
    }
}

/// [`put_window`] unrolled for a 33-byte stream (the RLP of a digest: the
/// dominant child reference) held in the 5-word window `v` at byte `so`: for
/// every `so`, `d` the window is exactly 5 words and so is the destination.
///
/// # Safety
/// `dst` 8-aligned with 5 writable words behind it.
#[inline(always)]
unsafe fn put_window33(dst: *mut u64, d: usize, v: [u64; 5], so: usize) {
    debug_assert!(d < 8 && so < 8);
    let keep = !(u64::MAX << (8 * d));
    let merge = |x: u64| (read_volatile(dst) & keep) | (x & !keep);
    let s = so.wrapping_sub(d) & 7;
    if s == 0 {
        write_volatile(dst, merge(v[0]));
        write_volatile(dst.add(1), v[1]);
        write_volatile(dst.add(2), v[2]);
        write_volatile(dst.add(3), v[3]);
        write_volatile(dst.add(4), v[4]);
        return;
    }
    let sr = (8 * s) as u32;
    let sl = 64 - sr;
    if so > d {
        write_volatile(dst, merge((v[0] >> sr) | (v[1] << sl)));
        write_volatile(dst.add(1), (v[1] >> sr) | (v[2] << sl));
        write_volatile(dst.add(2), (v[2] >> sr) | (v[3] << sl));
        write_volatile(dst.add(3), (v[3] >> sr) | (v[4] << sl));
        write_volatile(dst.add(4), v[4] >> sr);
    } else {
        write_volatile(dst, merge(v[0] << sl));
        write_volatile(dst.add(1), (v[0] >> sr) | (v[1] << sl));
        write_volatile(dst.add(2), (v[1] >> sr) | (v[2] << sl));
        write_volatile(dst.add(3), (v[2] >> sr) | (v[3] << sl));
        write_volatile(dst.add(4), (v[3] >> sr) | (v[4] << sl));
    }
}

/// Destination word containing the cursor and the cursor's byte offset in it.
#[inline(always)]
fn dst_word(buf: &mut Scratch, cursor: usize) -> (*mut u64, usize) {
    // SAFETY (alignment): `Scratch` is `align(8)`, `cursor & !7` is a multiple of 8.
    (
        unsafe { buf.0.as_mut_ptr().add(cursor & !7) as *mut u64 },
        cursor & 7,
    )
}

/// Append the `len ≥ 1` bytes at `src` (any alignment) — used for cached
/// child encodings, which carry their own RLP header.
///
/// # Safety
/// `src..src + len` readable; `*cursor + len <= MAX_NODE_ENCODING`.
#[inline(always)]
unsafe fn put_raw(buf: &mut Scratch, cursor: &mut usize, src: *const u8, len: usize) {
    debug_assert!(*cursor + len <= MAX_NODE_ENCODING);
    let (dst, d) = dst_word(buf, *cursor);
    let so = src as usize & 7;
    let base = (src as usize & !7) as *const u64;
    let w0 = read_volatile(base);
    let rest = base.add(1);
    if len == DIGEST_RLP_LENGTH {
        let v = [
            w0,
            read_volatile(rest),
            read_volatile(rest.add(1)),
            read_volatile(rest.add(2)),
            read_volatile(rest.add(3)),
        ];
        put_window33(dst, d, v, so);
    } else {
        put_window(dst, d, w0, rest, so, len);
    }
    *cursor += len;
}

/// Append `prefix` followed by the `len ≥ 1` bytes at `src` (any alignment):
/// the one-byte RLP header of a string item, folded into the source window
/// instead of a separate byte store. With an 8-aligned `src` the prefix
/// becomes the top byte of a synthesized word 0 (nothing before `src` is
/// read); otherwise it replaces the dead byte preceding `src` in word 0.
///
/// # Safety
/// `src..src + len` readable; `*cursor + 1 + len <= MAX_NODE_ENCODING`.
#[inline(always)]
unsafe fn put_prefixed(
    buf: &mut Scratch,
    cursor: &mut usize,
    prefix: u8,
    src: *const u8,
    len: usize,
) {
    debug_assert!(*cursor + 1 + len <= MAX_NODE_ENCODING);
    let (dst, d) = dst_word(buf, *cursor);
    let base = (src as usize & !7) as *const u64;
    let (w0, rest, so) = match src as usize & 7 {
        0 => ((prefix as u64) << 56, base, 7),
        so => {
            let shift = 8 * (so - 1);
            let w0 = (read_volatile(base) & !(0xff << shift)) | ((prefix as u64) << shift);
            (w0, base.add(1), so - 1)
        }
    };
    if len + 1 == DIGEST_RLP_LENGTH {
        let v = [
            w0,
            read_volatile(rest),
            read_volatile(rest.add(1)),
            read_volatile(rest.add(2)),
            read_volatile(rest.add(3)),
        ];
        put_window33(dst, d, v, so);
    } else {
        put_window(dst, d, w0, rest, so, len + 1);
    }
    *cursor += len + 1;
}

impl<M: Memoization> Node<M> {
    /// Memoize the hash of every dirty sub-trie: dirty nodes are encoded into
    /// one reused scratch buffer — single pass, no per-node `Vec`, no
    /// dyn-`BufMut` dispatch, child references and string items assembled by
    /// the whole-word writer ([`put_window`]) instead of `memcpy`. The payload
    /// length is UNTRUSTED ADVICE written ahead of the header and sealed by
    /// `cursor_delta == claimed` right after the parts are written, BEFORE the
    /// bytes are hashed / consumed by the parent. The capacity assert closes
    /// the overstated-length gap; the writer's capacity asserts and slice
    /// indexing bounds-panics close the understated one (both = refusal, no
    /// proof).
    pub(super) fn memoize_arena(&mut self, scratch: &mut Scratch) {
        if self.needs_memo() {
            self.encode_dirty(scratch);
        }
    }

    /// Whether this node still needs an encoding — an unmemoized Leaf,
    /// Extension or Branch. Parents test this before descending, so clean and
    /// digest children cost a tag/cache test instead of a call.
    #[inline(always)]
    pub(super) fn needs_memo(&self) -> bool {
        match self {
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache) => {
                cache.get().is_none()
            }
            Node::Null | Node::Digest(_) => false,
        }
    }

    /// [`Self::memoize_arena`] for a node that [`Self::needs_memo`]: memoize
    /// the dirty children, then encode this node into the scratch.
    pub(super) fn encode_dirty(&mut self, scratch: &mut Scratch) {
        debug_assert!(self.needs_memo());
        match self {
            Node::Extension(_, child, _) => {
                if child.needs_memo() {
                    child.encode_dirty(scratch);
                }
            }
            Node::Branch(children, _) => children.memoize_arena(scratch),
            _ => {}
        }

        let claimed = advice_u64!(self.encoded_payload_length() as u64) as usize;
        assert!(
            claimed + 3 <= MAX_NODE_ENCODING,
            "MPT: node encoding too large"
        );
        let header_len = write_list_header(&mut scratch.0, claimed);
        let mut cursor = header_len;
        match &*self {
            Node::Leaf(prefix, value, _) => {
                let path = encode_path_leaf(prefix, true);
                write_str_item(scratch, &mut cursor, &path);
                write_str_item(scratch, &mut cursor, value);
            }
            Node::Extension(prefix, child, _) => {
                let path = encode_path_leaf(prefix, false);
                write_str_item(scratch, &mut cursor, &path);
                write_child_ref(scratch, &mut cursor, child);
            }
            Node::Branch(children, _) => {
                for slot in children.iter() {
                    write_slot_ref(scratch, &mut cursor, slot);
                }
                // EMPTY_STRING_CODE for the missing branch value
                scratch.0[cursor] = EMPTY_STRING_CODE;
                cursor += 1;
            }
            _ => unreachable!(),
        }
        // seal the claimed length before the bytes are consumed
        advice_assert_eq!((cursor - header_len) as u64, claimed as u64);
        let rlp_node = RlpNode::from_rlp(&scratch.0[..cursor]);
        self.cache_set(rlp_node);
    }

    /// Exact RLP payload length of this node (children must be memoized —
    /// guaranteed by the post-order arena walk). Pass-1 / native only: the
    /// proven pass reads this value from the advice tape.
    #[allow(dead_code)] // proven riscv64 ELF reads the tape instead
    fn encoded_payload_length(&self) -> usize {
        match self {
            Node::Leaf(prefix, value, _) => {
                let path = encode_path_leaf(prefix, true);
                str_item_length(&path) + str_item_length(value)
            }
            Node::Extension(prefix, child, _) => {
                let path = encode_path_leaf(prefix, false);
                str_item_length(&path) + NodeRef::from_node(child).length()
            }
            Node::Branch(children, _) => {
                let mut payload_length = 1; // EMPTY_STRING_CODE value slot
                for slot in children.iter() {
                    payload_length += NodeRef::from_slot(slot).length();
                }
                payload_length
            }
            _ => unreachable!(),
        }
    }
}

/// Append a child reference (post-order-memoized: cached / digest / null).
/// Mirrors `NodeRef::encode` without the dyn-`BufMut` dispatch.
///
/// The word writer's capacity contract (`cursor + 33 <= MAX_NODE_ENCODING`)
/// holds structurally: the cursor is at most 3 (list header) + 35 (extension
/// path item) or 3 + 15 × 33 (sixteenth branch child) when a reference is
/// written, so no per-call bound check is paid.
#[inline(always)]
fn write_child_ref<M: Memoization>(buf: &mut Scratch, cursor: &mut usize, node: &Node<M>) {
    debug_assert!(*cursor + DIGEST_RLP_LENGTH <= MAX_NODE_ENCODING);
    match node {
        Node::Null => {
            buf.0[*cursor] = EMPTY_STRING_CODE;
            *cursor += 1;
        }
        // SAFETY: `digest` is a live 32-byte `B256`; cursor bound above.
        Node::Digest(digest) => unsafe {
            put_prefixed(buf, cursor, 0xa0, digest.0.as_ptr(), B256::len_bytes())
        },
        Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache) => {
            let rlp_node = cache.get().expect("MPT: child encoded before its parent");
            // SAFETY: `rlp_node` holds `len() >= 1` initialized bytes at
            // `as_ptr()` (every encoding is non-empty); cursor bound above.
            unsafe { put_raw(buf, cursor, rlp_node.as_ptr(), rlp_node.len()) }
        }
    }
}

/// [`write_child_ref`] for a branch slot: the inline digest of an unresolved
/// child is written from its 8-aligned words.
#[inline(always)]
fn write_slot_ref<M: Memoization>(buf: &mut Scratch, cursor: &mut usize, slot: &Slot<M>) {
    debug_assert!(*cursor + DIGEST_RLP_LENGTH <= MAX_NODE_ENCODING);
    match slot {
        Slot::Empty => {
            buf.0[*cursor] = EMPTY_STRING_CODE;
            *cursor += 1;
        }
        // SAFETY: `digest` is a live 32-byte `Digest`; cursor bound as in
        // `write_child_ref`.
        Slot::Digest(digest) => unsafe {
            put_prefixed(
                buf,
                cursor,
                DIGEST_ITEM_PREFIX,
                digest.as_ptr(),
                B256::len_bytes(),
            )
        },
        Slot::Node(child) => write_child_ref(buf, cursor, child),
    }
}

/// RLP string-item length of `bytes` (mirrors alloy's `[u8]::length`).
#[inline(always)]
fn str_item_length(bytes: &[u8]) -> usize {
    let len = bytes.len();
    if len == 1 && bytes[0] < 0x80 {
        1
    } else if len < 56 {
        1 + len
    } else {
        assert!(
            len < MAX_STR_ITEM_LEN,
            "MPT: string item too long for the one-byte length form"
        );
        2 + len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// The word writer is byte-exact for every source offset, cursor offset
    /// and length, preserves everything below the cursor and clobbers at most
    /// 7 bytes past the item.
    #[test]
    fn word_writer_matches_byte_copy() {
        let mut src_words = [0u64; 16];
        for (i, w) in src_words.iter_mut().enumerate() {
            *w = 0x0101_0101_0101_0101u64.wrapping_mul(i as u64 + 1) ^ 0x8040_2010_0804_0201;
        }
        let src_bytes: Vec<u8> = src_words.iter().flat_map(|w| w.to_le_bytes()).collect();
        for so in 0..8 {
            for d in 0..8 {
                for len in 1..=90 {
                    for prefixed in [false, true] {
                        let src = &src_bytes[so..so + len];
                        let cursor0 = 16 + d;
                        let mut scratch = Scratch::new();
                        for (i, b) in scratch.0.iter_mut().enumerate() {
                            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
                        }
                        let mut expect = scratch.0;
                        let mut cursor = cursor0;
                        let total = if prefixed {
                            unsafe {
                                put_prefixed(&mut scratch, &mut cursor, 0xa0, src.as_ptr(), len)
                            };
                            expect[cursor0] = 0xa0;
                            expect[cursor0 + 1..cursor0 + 1 + len].copy_from_slice(src);
                            len + 1
                        } else {
                            unsafe { put_raw(&mut scratch, &mut cursor, src.as_ptr(), len) };
                            expect[cursor0..cursor0 + len].copy_from_slice(src);
                            len
                        };
                        assert_eq!(cursor, cursor0 + total);
                        let end = cursor0 + total;
                        assert_eq!(
                            &scratch.0[..end],
                            &expect[..end],
                            "so={so} d={d} len={len} prefixed={prefixed}"
                        );
                        assert_eq!(
                            &scratch.0[end + 7..],
                            &expect[end + 7..],
                            "clobber past slack: so={so} d={d} len={len} prefixed={prefixed}"
                        );
                    }
                }
            }
        }
    }
}
