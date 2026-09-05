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

use super::{
    advice::{advice_assert_eq, advice_u64},
    children::{Children, Slot},
    memoize::Memoization,
    node::{Child, Digest, Node},
};
use alloc::{boxed::Box, vec, vec::Vec};
use alloy_primitives::{hex, keccak256, map::B256IndexMap, Bytes, B256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header, PayloadView, EMPTY_STRING_CODE};
use alloy_trie::{nodes::encode_path_leaf, Nibbles, EMPTY_ROOT_HASH};
use core::{
    fmt,
    mem::MaybeUninit,
    num::NonZeroUsize,
    ptr::{read_volatile, write_volatile},
};

/// The length in bytes of an RLP-encoded digest, i.e. hash length + 1 byte for the RLP header.
const DIGEST_RLP_LENGTH: usize = 1 + B256::len_bytes();

/// RLP header byte of a digest item (32-byte string).
const DIGEST_ITEM_PREFIX: u8 = EMPTY_STRING_CODE + B256::len_bytes() as u8;

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
        debug_assert!(len < 256);
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
/// virtual sequence in Jolt (`sb` 6, `lbu` 3, `lw` 4 rows), and the generic
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

/// jeth (advice-trie): digest→bytes resolution callback for trie hydration.
///
/// Contract: a `Some(bytes)` return MUST be authenticated by the implementor —
/// `keccak256(bytes) == *digest` — before the bytes are handed out (the trie
/// decodes them as the node with that digest). `None` = "not available":
/// the node stays an unresolved [`Node::Digest`] stub.
pub trait DigestResolver {
    fn resolve(&mut self, digest: &B256) -> Option<&Bytes>;
}

impl<M: Memoization> Node<M> {
    /// Returns the hash of the node.
    #[inline]
    pub(super) fn hash(&self) -> B256 {
        NodeRef::from_node(self).hash()
    }

    /// Returns the RLP encoding of the node.
    pub(super) fn rlp_encoded(&self) -> Vec<u8> {
        match self {
            Node::Null => vec![EMPTY_STRING_CODE],
            Node::Leaf(prefix, value, _) => {
                let path = encode_path_leaf(prefix, true);
                let mut out = encode_list_header(path.length() + value.length());
                path.encode(&mut out);
                value.encode(&mut out);

                out
            }
            Node::Extension(prefix, child, _) => {
                let path = encode_path_leaf(prefix, false);
                let node_ref = NodeRef::from_node(child);
                let mut out = encode_list_header(path.length() + node_ref.length());
                path.encode(&mut out);
                node_ref.encode(&mut out);

                out
            }
            Node::Branch(children, _) => {
                let mut child_refs: [NodeRef<'_>; 16] = Default::default();
                let mut payload_length = 1; // start with 1 for the EMPTY_STRING_CODE at the end

                for (i, slot) in children.iter().enumerate() {
                    let node_ref = NodeRef::from_slot(slot);
                    payload_length += node_ref.length();
                    child_refs[i] = node_ref;
                }

                let mut out = encode_list_header(payload_length);
                child_refs.iter().for_each(|child| child.encode(&mut out));
                // add an EMPTY_STRING_CODE for the missing value
                out.push(EMPTY_STRING_CODE);

                out
            }
            Node::Digest(digest) => alloy_rlp::encode(&digest.0),
        }
    }

    /// Memoize the hash of every sub-trie.
    #[allow(dead_code)] // superseded by memoize_arena (kept for upstream parity)
    pub(super) fn memoize(&mut self) {
        // early termination for already memoized nodes or Null/Digest
        match self {
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache)
                if cache.get().is_some() =>
            {
                return;
            }
            Node::Null | Node::Digest(_) => return,
            _ => {} // proceed to memoization for other variants
        }
        match self {
            Node::Extension(_, child, _) => child.memoize(),
            Node::Branch(children, _) => children.memoize(),
            _ => {} // no children to memoize for Leaf, Null, or Digest
        }
        #[cfg(feature = "premeasure")]
        super::premeasure::count(&super::premeasure::MEMO_ENCODES);
        let rlp = self.rlp_encoded();
        match self {
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache) => {
                cache.set(RlpNode::from_rlp(rlp));
            }
            _ => unreachable!(),
        }
    }

    /// jeth (advice-trie Phase 3a): [`Self::memoize`] with dirty nodes encoded
    /// into one reused scratch buffer — single pass, no per-node `Vec`, no
    /// dyn-`BufMut` dispatch, child references and string items assembled by
    /// the whole-word writer ([`put_window`]) instead of `memcpy`. The payload
    /// length is UNTRUSTED ADVICE written ahead of the header and sealed by
    /// `cursor_delta == claimed` right after the parts are written, BEFORE the
    /// bytes are hashed / consumed by the parent (L2: every advice value is
    /// locally verified). The capacity assert closes the overstated-length gap;
    /// the writer's capacity asserts and slice indexing bounds-panics close the
    /// understated one (both = refusal, no proof).
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

    /// Returns the RLP-encoded nodes of the trie in preorder.
    pub(super) fn rlp_nodes(&self) -> Vec<Bytes> {
        fn rec<'a, M: Memoization>(node: &'a Node<M>, nodes: &mut Vec<Bytes>) -> NodeRef<'a> {
            let node_ref = match node {
                Node::Extension(prefix, child, _) => {
                    let (path, child) = (encode_path_leaf(prefix, false), rec(child, nodes));
                    let mut out = encode_list_header(path.length() + child.length());
                    path.encode(&mut out);
                    child.encode(&mut out);
                    NodeRef::Rlp(out)
                }
                Node::Branch(children, _) => {
                    let mut list = Vec::with_capacity(17);
                    for slot in children.iter() {
                        list.push(match slot {
                            Slot::Empty => NodeRef::Empty,
                            Slot::Digest(digest) => NodeRef::Digest(digest),
                            Slot::Node(child) => rec(child, nodes),
                        });
                    }
                    list.push(NodeRef::Empty);
                    NodeRef::Rlp(encode_list(&list))
                }
                Node::Leaf(..) => NodeRef::Rlp(node.rlp_encoded()), // do not use the cached value
                Node::Digest(digest) => NodeRef::Digest(digest),
                Node::Null => NodeRef::Empty,
            };
            match &node_ref {
                NodeRef::Rlp(rlp) if rlp.len() >= 32 => nodes.push(rlp.clone().into()),
                NodeRef::Cached(..) => unreachable!(),
                _ => {}
            }
            node_ref
        }

        if matches!(self, Node::Null) {
            return vec![];
        }

        let mut vec = Vec::new();
        match rec(self, &mut vec) {
            NodeRef::Rlp(rlp) if rlp.len() >= 32 => {}
            NodeRef::Cached(..) => unreachable!(),
            node_ref => vec.push(alloy_rlp::encode(node_ref).into()),
        }
        vec.reverse();

        vec
    }

    /// Creates a new trie from the given RLP encoded nodes.
    pub(super) fn from_rlp<T: AsRef<[u8]>>(
        nodes: impl IntoIterator<Item = T>,
    ) -> alloy_rlp::Result<Self> {
        let mut iterator = nodes.into_iter();

        // the first node must be the root
        let mut root = match iterator.next() {
            None => return Ok(Self::default()),
            Some(rlp) => {
                let mut node: Node<M> = alloy_rlp::decode_exact(rlp.as_ref())?;
                node.cache_set(RlpNode::from_rlp(rlp));
                node
            }
        };

        // compute the references of all the remaining nodes
        let (lower, _) = iterator.size_hint();
        let mut rlp_by_digest = B256IndexMap::with_capacity_and_hasher(lower, Default::default());
        for rlp in iterator {
            rlp_by_digest.insert(keccak256(&rlp), rlp);
        }

        // return the resolved trie
        root.resolve_digests(&rlp_by_digest)?;
        Ok(root)
    }

    /// Resolves all applicable digest nodes with the node corresponding to the RLP encoding.
    pub(super) fn resolve_digests(
        &mut self,
        rlp_by_digest: &B256IndexMap<impl AsRef<[u8]>>,
    ) -> alloy_rlp::Result<()> {
        match self {
            Node::Null | Node::Leaf(..) => {}
            Node::Extension(_, child, _) => {
                child.resolve_digests(rlp_by_digest)?;
                if !matches!(**child, Node::Branch(..) | Node::Digest(..)) {
                    return Err(alloy_rlp::Error::Custom(
                        "extension node with invalid child",
                    ));
                }
            }
            Node::Branch(children, _) => {
                for slot in children.iter_mut() {
                    if let Slot::Digest(digest) = slot {
                        // resolve the stub as a node, then take it into the
                        // slot unless it stayed a digest
                        let mut node = Node::Digest(*digest);
                        node.resolve_digests(rlp_by_digest)?;
                        match node {
                            Node::Digest(_) => {}
                            Node::Null => *slot = Slot::Empty,
                            node => *slot = Slot::from_child(node.into()),
                        }
                    } else if let Slot::Node(child) = slot {
                        child.resolve_digests(rlp_by_digest)?;
                        slot.clear_null();
                    }
                }
            }
            Node::Digest(digest) => {
                #[cfg(feature = "premeasure")]
                super::premeasure::count(&super::premeasure::PROBES);
                if let Some(bytes) = rlp_by_digest.get(&digest.0) {
                    #[cfg(feature = "premeasure")]
                    super::premeasure::count(&super::premeasure::HITS);
                    let mut node: Node<M> = alloy_rlp::decode_exact(bytes.as_ref())?;
                    // do not try to replace a node by a digest
                    if !matches!(node, Node::Digest(_)) {
                        #[cfg(feature = "premeasure")]
                        super::premeasure::count(&super::premeasure::DECODES);
                        node.cache_set(RlpNode::from_digest(digest));
                        *self = node;
                        self.resolve_digests(rlp_by_digest)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// jeth (advice-trie): like [`Self::resolve_digests`], but digest→bytes
    /// resolution goes through a [`DigestResolver`] callback instead of a
    /// prebuilt map. The resolver must return AUTHENTICATED bytes
    /// (`keccak(bytes) == digest`) or `None` to leave the digest stub in
    /// place (L3: an untouched stub contributes its parent-sourced digest to
    /// encodes bit-identically; content access panics).
    ///
    /// Decoding is the zero-copy variant: leaf values become
    /// [`Bytes::slice_ref`] views into the resolved node bytes.
    pub(super) fn resolve_with<R: DigestResolver>(&mut self, r: &mut R) -> alloy_rlp::Result<()> {
        match self {
            Node::Null | Node::Leaf(..) => {}
            Node::Extension(_, child, _) => {
                child.resolve_with(r)?;
                if !matches!(**child, Node::Branch(..) | Node::Digest(..)) {
                    return Err(alloy_rlp::Error::Custom(
                        "extension node with invalid child",
                    ));
                }
            }
            Node::Branch(children, _) => {
                for slot in children.iter_mut() {
                    // Digest stubs are the bulk of the slots and most of them
                    // miss (boundary siblings): they are probed here, without
                    // a call per stub, and a hit decodes into a fresh heap
                    // node that takes the slot.
                    if let Slot::Digest(digest) = slot {
                        #[cfg(feature = "premeasure")]
                        super::premeasure::count(&super::premeasure::PROBES);
                        let Some(bytes) = r.resolve(digest) else { continue };
                        match Node::decode_child(digest, bytes)? {
                            Some(child) => *slot = Slot::Node(child),
                            None => continue, // digest for digest: the stub stays
                        }
                    }
                    let Slot::Node(child) = slot else { continue };
                    child.resolve_with(r)?;
                    slot.clear_null();
                }
            }
            Node::Digest(digest) => {
                #[cfg(feature = "premeasure")]
                super::premeasure::count(&super::premeasure::PROBES);
                if let Some(bytes) = r.resolve(digest) {
                    let digest = *digest;
                    if self.hydrate(digest, bytes)? {
                        self.resolve_with(r)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// [`Self::resolve_with`] hit: `bytes` is the authenticated encoding of
    /// the stub `*self == Node::Digest(digest)`. Decodes it in place and caches
    /// the digest as the node's encoding; a digest-for-digest answer is refused
    /// (the stub stays). Returns whether the node was resolved and its own
    /// children still need resolving.
    fn hydrate(&mut self, digest: Digest, bytes: &Bytes) -> alloy_rlp::Result<bool> {
        #[cfg(feature = "premeasure")]
        super::premeasure::count(&super::premeasure::HITS);
        self.decode_stub_in_place(&digest, bytes)?;
        // do not try to replace a node by a digest
        if matches!(self, Node::Digest(_)) {
            *self = Node::Digest(digest);
            return Ok(false);
        }
        #[cfg(feature = "premeasure")]
        super::premeasure::count(&super::premeasure::DECODES);
        self.cache_set(RlpNode::from_digest(&digest));
        Ok(true)
    }

    /// [`Self::hydrate`] for a branch slot: decode `bytes`, the authenticated
    /// encoding of the node with `digest`, into a fresh heap node carrying the
    /// digest as its cached reference. `Ok(None)` is the digest-for-digest
    /// refusal.
    pub(super) fn decode_child(digest: &Digest, bytes: &Bytes) -> alloy_rlp::Result<Option<Child<M>>> {
        #[cfg(feature = "premeasure")]
        super::premeasure::count(&super::premeasure::HITS);
        let mut child = Box::<Node<M>>::new_uninit();
        decode_node_zc_exact_into(bytes, &mut child)?;
        // SAFETY: `Ok` return above ⇒ the callee wrote a fully initialized
        // `Node` into the slot. On `Err`, `?` dropped the `Box<MaybeUninit<..>>`
        // without reading it (the slot was untouched or `Node::Null`, which
        // owns nothing).
        let mut child = unsafe { child.assume_init() };
        if matches!(*child, Node::Digest(_)) {
            return Ok(None);
        }
        #[cfg(feature = "premeasure")]
        super::premeasure::count(&super::premeasure::DECODES);
        child.cache_set(RlpNode::from_digest(digest));
        Ok(Some(child))
    }

    #[inline]
    pub(super) fn cache_set(&mut self, rlp_node: RlpNode) {
        match self {
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache) => {
                cache.set(rlp_node)
            }
            _ => {}
        }
    }

    /// jeth (advice-trie): decode `bytes` — the authenticated encoding of the
    /// [`Node::Digest`] stub `*self` — straight into this node's slot, so the
    /// resolved node is never moved (`*self = node` copied 176 B per node).
    ///
    /// Requires `*self` to be `Node::Digest(*digest)` (checked by
    /// `debug_assert` only; a violation overwrites a resource-owning node
    /// without dropping it — a leak, not UB). On `Ok`, `*self` is the decoded
    /// node (possibly itself a `Digest`); on `Err`, `*self` is the original
    /// stub again.
    pub(super) fn decode_stub_in_place(
        &mut self,
        digest: &Digest,
        bytes: &Bytes,
    ) -> alloy_rlp::Result<()> {
        debug_assert!(matches!(self, Node::Digest(d) if d == digest));
        // SAFETY: `MaybeUninit<Node<M>>` has the layout of `Node<M>`, and a
        // `Node::Digest` owns no resources, so its bytes may be overwritten
        // without a drop. `decode_node_zc_exact_into` keeps the slot either
        // untouched or holding a fully valid `Node` at every point (whole-value
        // `MaybeUninit::write`s; the branch arm then mutates the written node
        // in place through `&mut Node` and resets it to `Node::Null` on
        // failure), and on `Err` leaves it untouched or `Node::Null` — so
        // `*self` is a valid, drop-safe node at every panic point and on both
        // result paths.
        let slot = unsafe { &mut *(self as *mut Self as *mut MaybeUninit<Self>) };
        let result = decode_node_zc_exact_into(bytes, slot);
        if result.is_err() {
            *self = Node::Digest(*digest);
        }
        result
    }
}

impl<M: Memoization> Decodable for Node<M> {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        match Header::decode_raw(buf)? {
            // if the node is not a list, it must be empty or a digest
            PayloadView::String(payload) => match payload.len() {
                0 => Ok(Node::Null),
                32 => Ok(Node::Digest(Digest(B256::from_slice(payload)))),
                _ => Err(alloy_rlp::Error::UnexpectedLength),
            },
            PayloadView::List(items) => match items.len() {
                // branch node: 17-item node [ v0 ... v15, value ]
                17 => {
                    let mut children = Children::default();
                    for (i, child_rlp) in items.iter().enumerate() {
                        if child_rlp != &[EMPTY_STRING_CODE] {
                            if i == 16 {
                                return Err(alloy_rlp::Error::Custom("branch node with value"));
                            } else {
                                children.insert(i as u8, Node::decode(&mut &child_rlp[..])?.into());
                            }
                        }
                    }
                    if children.len() < 2 {
                        return Err(alloy_rlp::Error::Custom("branch node without two children"));
                    }

                    Ok(Node::Branch(children, M::default()))
                }
                // leaf or extension node: 2-item node [ encodedPath, v ]
                // they are distinguished by a flag in the first nibble of the encodedPath
                2 => {
                    let [mut encode_path, mut v] = items.as_slice() else {
                        unreachable!()
                    };
                    let (path, is_leaf) = decode_path(&mut encode_path)?;
                    if is_leaf {
                        Ok(Node::Leaf(path, Bytes::decode(&mut v)?, M::default()))
                    } else {
                        let node = Node::decode(&mut v)?;
                        if !matches!(node, Node::Branch(..) | Node::Digest(..)) {
                            return Err(alloy_rlp::Error::Custom(
                                "extension node with invalid child",
                            ));
                        }
                        Ok(Node::Extension(path, node.into(), M::default()))
                    }
                }
                _ => Err(alloy_rlp::Error::Custom("unexpected list length")),
            },
        }
    }
}

/// jeth fork: zero-copy node decode. Identical grammar and validation to the
/// [`Decodable`] impl above, except leaf values become [`Bytes::slice_ref`]
/// views into `source` — the RLP-encoded node bytes that `buf` points into —
/// instead of allocated copies. Decode-driven memcpy measured 129M trace rows
/// (9%) on block 25698189 before this change.
///
/// Out-param form: the string/leaf/extension arms write `out` once at the arm
/// end; the branch arm writes the empty branch first and decodes the children
/// into its slots in place (`Children` is never moved), reassigning
/// `Node::Null` on failure. Digest children are stored inline in their
/// [`Slot`]; other children are decoded straight into their final heap slot
/// (`Box::new_uninit`), deleting the by-value move chain (return → `?` →
/// `Box::new`, ≈3 × 176-byte memcpy per node on riscv64; 49.6M trace rows on
/// block 25905781 before this change).
///
/// List payloads are scanned in place instead of through
/// `Header::decode_raw`'s `PayloadView` `Vec` (allocation + 3 grows + 17
/// pushes per branch): pass 1 ([`count_items`]) validates every item header
/// in order and yields the item count exactly like `decode_raw`, pass 2
/// re-derives the item boundaries with the same [`item_len`] while decoding
/// (the count decides the grammar, so boundaries cannot be consumed on the
/// fly: a 33-byte leaf path item is indistinguishable from a digest item
/// until the count is known).
///
/// Contract: on `Ok(())`, `out` holds the decoded node. On `Err`, `out` is
/// either untouched or holds the resource-free [`Node::Null`] (a branch whose
/// children failed to decode is dropped and replaced) — never partially
/// written. At every panic point `out` is untouched or holds a valid node.
fn decode_node_zc_into<M: Memoization>(
    source: &Bytes,
    buf: &mut &[u8],
    out: &mut MaybeUninit<Node<M>>,
) -> alloy_rlp::Result<()> {
    let h = decode_header(buf)?;
    // `decode_header` checked `buf.len() >= payload_length`.
    let (payload, rest) = buf.split_at(h.payload_length);
    *buf = rest;
    if !h.list {
        // if the node is not a list, it must be empty or a digest
        return match payload.len() {
            0 => {
                out.write(Node::Null);
                Ok(())
            }
            32 => {
                out.write(Node::Digest(Digest(B256::from_slice(payload))));
                Ok(())
            }
            _ => Err(alloy_rlp::Error::UnexpectedLength),
        };
    }
    match count_items(payload)? {
        // branch node: 17-item node [ v0 ... v15, value ]
        17 => {
            // Write the empty branch first and decode the children into
            // its slots, so the 640-byte `Children` is never moved.
            let node = out.write(Node::Branch(Children::default(), M::default()));
            let Node::Branch(children, _) = &mut *node else {
                unreachable!()
            };
            let filled = decode_branch_children(source, payload, children);
            if filled.is_err() {
                *node = Node::Null; // drops the partial branch
            }
            filled
        }
        // leaf or extension node: 2-item node [ encodedPath, v ]
        // they are distinguished by a flag in the first nibble of the encodedPath
        2 => {
            // pass 1 validated both item headers, so this cannot fail
            let (mut encode_path, v) = payload.split_at(item_len(payload)?);
            let (path, is_leaf) = decode_path(&mut encode_path)?;
            if is_leaf {
                let value = decode_string(&mut &v[..])?;
                out.write(Node::Leaf(path, source.slice_ref(value), M::default()));
                Ok(())
            } else {
                let mut child = Box::<Node<M>>::new_uninit();
                decode_child_into(source, v, &mut child)?;
                // SAFETY: `Ok` return above ⇒ the callee wrote a fully
                // initialized `Node` into the slot.
                let child = unsafe { child.assume_init() };
                if !matches!(*child, Node::Branch(..) | Node::Digest(..)) {
                    return Err(alloy_rlp::Error::Custom(
                        "extension node with invalid child",
                    ));
                }
                out.write(Node::Extension(path, child, M::default()));
                Ok(())
            }
        }
        _ => Err(alloy_rlp::Error::Custom("unexpected list length")),
    }
}

/// [`Header::decode`] with the long-form length read byte-wise: alloy copies
/// the 1–8 length bytes into a zero-padded `[u8; 8]` and byte-swaps it
/// (`static_left_pad` + `from_be_bytes` — a `memcpy` call and a swap per
/// long header, ~80 rows on riscv64imac); here each byte is one `lbu` folded
/// into the accumulator. Same checks in the same order, same errors, same
/// buffer advance (a single byte below `0x80` is its own payload and does not
/// advance).
#[inline(always)]
pub fn decode_header(buf: &mut &[u8]) -> alloy_rlp::Result<Header> {
    let Some(&b) = buf.first() else {
        return Err(alloy_rlp::Error::InputTooShort);
    };
    let (list, payload_length) = match b {
        0..=0x7f => (false, 1),
        EMPTY_STRING_CODE..=0xb7 => {
            *buf = &buf[1..];
            let payload_length = (b - EMPTY_STRING_CODE) as usize;
            if payload_length == 1 {
                match buf.first() {
                    None => return Err(alloy_rlp::Error::InputTooShort),
                    Some(&next) if next < EMPTY_STRING_CODE => {
                        return Err(alloy_rlp::Error::NonCanonicalSingleByte)
                    }
                    Some(_) => {}
                }
            }
            (false, payload_length)
        }
        0xb8..=0xbf | 0xf8..=0xff => {
            *buf = &buf[1..];
            let list = b >= 0xf8;
            let len_of_len = (b - if list { 0xf7 } else { 0xb7 }) as usize;
            if buf.len() < len_of_len {
                return Err(alloy_rlp::Error::InputTooShort);
            }
            let (len_bytes, rest) = buf.split_at(len_of_len);
            *buf = rest;
            if len_bytes[0] == 0 {
                return Err(alloy_rlp::Error::LeadingZero);
            }
            let mut len = 0u64;
            for &x in len_bytes {
                len = (len << 8) | x as u64;
            }
            let payload_length =
                usize::try_from(len).map_err(|_| alloy_rlp::Error::Custom("Input too big"))?;
            if payload_length < 56 {
                return Err(alloy_rlp::Error::NonCanonicalSize);
            }
            (list, payload_length)
        }
        0xc0..=0xf7 => {
            *buf = &buf[1..];
            (true, (b - 0xc0) as usize)
        }
    };
    if buf.len() < payload_length {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    Ok(Header {
        list,
        payload_length,
    })
}

/// `Header::decode_bytes(buf, false)` on top of [`decode_header`]: the payload
/// of a string item, advancing `buf` past it.
#[inline(always)]
fn decode_string<'a>(buf: &mut &'a [u8]) -> alloy_rlp::Result<&'a [u8]> {
    let h = decode_header(buf)?;
    if h.list {
        return Err(alloy_rlp::Error::UnexpectedList);
    }
    let (payload, rest) = buf.split_at(h.payload_length);
    *buf = rest;
    Ok(payload)
}

/// Header + payload length of the RLP item at the start of the non-empty
/// `p`, validated exactly like [`Header::decode`] — the general arm calls
/// its local twin [`decode_header`]; the two fast paths cover the dominant branch items and cannot
/// fail: `0x80` is the empty string (payload 0) and `0xa0` a 32-byte string
/// whose payload is present when `p` holds the whole item.
#[inline(always)]
fn item_len(p: &[u8]) -> alloy_rlp::Result<usize> {
    debug_assert!(!p.is_empty());
    match p[0] {
        EMPTY_STRING_CODE => Ok(1),
        DIGEST_ITEM_PREFIX if p.len() >= DIGEST_RLP_LENGTH => Ok(DIGEST_RLP_LENGTH),
        _ => {
            let mut q = p;
            let h = decode_header(&mut q)?;
            Ok(p.len() - q.len() + h.payload_length)
        }
    }
}

/// Number of RLP items in a list payload; every item header is decoded and
/// validated in order, first error wins — the item scan of
/// `Header::decode_raw` without its `Vec`.
#[inline(always)]
fn count_items(mut p: &[u8]) -> alloy_rlp::Result<usize> {
    let mut n = 0usize;
    while !p.is_empty() {
        p = &p[item_len(p)?..];
        n += 1;
    }
    Ok(n)
}

/// Decode the 16 child items of the 17-item branch payload `p` straight into
/// `children` (the slots of a freshly written empty [`Node::Branch`]); item
/// 16 must be the empty value. Digest items — the dominant child kind — land
/// inline as [`Slot::Digest`] (a tag and four aligned `sd`, no allocation);
/// other items are decoded into a fresh heap node. Every slot is written only
/// once its item is fully decoded, so the branch is a valid node at every
/// point; children decoded before an `Err` stay owned by it.
fn decode_branch_children<M: Memoization>(
    source: &Bytes,
    mut p: &[u8],
    children: &mut Children<M>,
) -> alloy_rlp::Result<()> {
    let mut count = 0usize;
    for slot in children.iter_mut() {
        // pass 1 counted exactly 17 validated items over `p`
        let (item, rest) = p.split_at(item_len(p)?);
        p = rest;
        if item == [EMPTY_STRING_CODE] {
            continue;
        }
        if is_digest_item(item) {
            slot.fill_digest(digest_item(item));
        } else {
            let mut child = Box::<Node<M>>::new_uninit();
            decode_node_zc_into(source, &mut &item[..], &mut child)?;
            // SAFETY: `Ok` return above ⇒ the callee wrote a fully initialized
            // `Node` into the slot. On `Err`, `?` drops the `Box<MaybeUninit<..>>`
            // without reading it; the slot is untouched or `Node::Null`, so
            // nothing leaks.
            *slot = Slot::from_child(unsafe { child.assume_init() });
        }
        count += 1;
    }
    // the 17th item is the value, which this MPT never carries
    if p != [EMPTY_STRING_CODE] {
        return Err(alloy_rlp::Error::Custom("branch node with value"));
    }
    if count < 2 {
        return Err(alloy_rlp::Error::Custom("branch node without two children"));
    }
    Ok(())
}

/// Decode one child item (a complete RLP item, as cut by the parent's list
/// scan) into `out`. Digest items take the word-gather fast path; everything
/// else goes through the general decoder. Same contract as
/// [`decode_node_zc_into`].
#[inline(always)]
fn decode_child_into<M: Memoization>(
    source: &Bytes,
    item: &[u8],
    out: &mut MaybeUninit<Node<M>>,
) -> alloy_rlp::Result<()> {
    if is_digest_item(item) {
        out.write(Node::Digest(digest_item(item)));
        Ok(())
    } else {
        decode_node_zc_into(source, &mut &item[..], out)
    }
}

/// Whether `item` is `0xa0` + 32 bytes: a 32-byte string can only be encoded
/// this way, and `Header::decode` on `0xa0` applies no canonicality condition.
#[inline(always)]
fn is_digest_item(item: &[u8]) -> bool {
    item.len() == DIGEST_RLP_LENGTH && item[0] == DIGEST_ITEM_PREFIX
}

/// The digest of the `0xa0` + 32 bytes item `item`: exactly the
/// [`Node::Digest`] payload [`decode_node_zc_into`] yields for it, without the
/// recursive call and the `memcpy(32)` of `B256::from_slice` — the 32 bytes
/// at `item[1..]` are gathered word-wise ([`le_words_32`]) and land as four
/// aligned `sd`s in the 8-aligned [`Digest`].
#[inline(always)]
fn digest_item(item: &[u8]) -> Digest {
    debug_assert!(is_digest_item(item));
    Digest::from_le_limbs(le_words_32(&item[1..]))
}

/// The 32 bytes at `bytes[..32]` (any alignment) as four little-endian words
/// (word `i` = bytes `8i..8i+8`), gathered from the aligned machine words
/// containing them: 4 `ld` when `bytes` is 8-aligned, else 5 `ld` + shift/or
/// — never a sub-word access, never an unaligned one (Jolt expands every
/// `lbu` into 3 trace rows and traps on misaligned `ld`; `read_unaligned`
/// lowers to byte loads on riscv64imac).
///
/// # Safety of the containing-word reads
/// Every word read holds at least one live byte of `bytes[..32]` (word 0
/// holds byte 0, the last word holds byte 31), and by the flat-RAM argument
/// of the guest `mem.rs` overrides — Jolt guest RAM is flat and
/// word-granular; natively the containing word lies in the same allocation
/// granule / page — the aligned word containing a live byte is readable.
/// Every load address is a multiple of 8 by construction.
#[inline(always)]
pub fn le_words_32(bytes: &[u8]) -> [u64; 4] {
    assert!(bytes.len() >= 32);
    let src = bytes.as_ptr() as usize;
    let so = src & 7;
    let base = (src & !7) as *const u64;
    unsafe {
        let w0 = u64::from_le(read_volatile(base));
        let w1 = u64::from_le(read_volatile(base.add(1)));
        let w2 = u64::from_le(read_volatile(base.add(2)));
        let w3 = u64::from_le(read_volatile(base.add(3)));
        if so == 0 {
            [w0, w1, w2, w3]
        } else {
            let w4 = u64::from_le(read_volatile(base.add(4)));
            let sr = (8 * so) as u32;
            let sl = 64 - sr;
            [
                (w0 >> sr) | (w1 << sl),
                (w1 >> sr) | (w2 << sl),
                (w2 >> sr) | (w3 << sl),
                (w3 >> sr) | (w4 << sl),
            ]
        }
    }
}

/// [`decode_node_zc_into`] over the whole buffer, mirroring `alloy_rlp::decode_exact`.
///
/// Contract: on `Ok`, `out` holds the decoded node. On `Err`, `out` is either
/// untouched or holds [`Node::Null`] (inherited from [`decode_node_zc_into`],
/// plus the trailing-bytes refusal of a complete decode) — never partially
/// written, so a caller may alias `out` with a live `&mut Node<M>` slot
/// ([`Node::decode_stub_in_place`]).
fn decode_node_zc_exact_into<M: Memoization>(
    source: &Bytes,
    out: &mut MaybeUninit<Node<M>>,
) -> alloy_rlp::Result<()> {
    let mut buf = source.as_ref();
    decode_node_zc_into(source, &mut buf, out)?;
    if !buf.is_empty() {
        // SAFETY: `Ok` return above ⇒ `out` is fully initialized. Drop it and
        // leave a resource-free node behind for aliasing callers.
        unsafe { out.assume_init_drop() };
        out.write(Node::Null);
        return Err(alloy_rlp::Error::UnexpectedLength);
    }
    Ok(())
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
    match NodeRef::from_node(node) {
        NodeRef::Empty => {
            buf.0[*cursor] = EMPTY_STRING_CODE;
            *cursor += 1;
        }
        // SAFETY: `digest` is a live 32-byte `B256`; cursor bound above.
        NodeRef::Digest(digest) => unsafe {
            put_prefixed(buf, cursor, 0xa0, digest.as_ptr(), B256::len_bytes())
        },
        // SAFETY: `rlp_node` holds `len() >= 1` initialized bytes at
        // `as_ptr()` (every encoding is non-empty); cursor bound above.
        NodeRef::Cached(rlp_node) => unsafe {
            put_raw(buf, cursor, rlp_node.as_ptr(), rlp_node.len())
        },
        // cold: unmemoized non-digest child (unreachable after the post-order
        // walk, kept for NodeRef semantic parity)
        NodeRef::Rlp(rlp) => {
            if rlp.len() >= B256::len_bytes() {
                buf.0[*cursor] = 0xa0;
                buf.0[*cursor + 1..*cursor + 33].copy_from_slice(keccak256(&rlp).as_slice());
                *cursor += 33;
            } else {
                buf.0[*cursor..*cursor + rlp.len()].copy_from_slice(&rlp);
                *cursor += rlp.len();
            }
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
        2 + len
    }
}

/// An RLP-encoded node reference: the node's RLP when shorter than 32
/// bytes, else `0xa0 ++ keccak256(rlp)` ([`DIGEST_RLP_LENGTH`] bytes). The
/// bytes live in five 8-aligned little-endian words (word `i` = bytes
/// `8i..8i+8`): the digest form is assembled in registers and stored as five
/// `sd` — a byte-wise construction is a `memcpy` into a misaligned buffer,
/// and Jolt expands every sub-word store into a 6–9-row virtual sequence —
/// and the arena encoder reads it back from an aligned source. `len` is
/// non-zero (no encoding is empty); its zero doubles as the `None` niche of
/// the memoization cache.
#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub(super) struct RlpNode {
    words: [[u8; 8]; 5],
    len: NonZeroUsize,
}

impl RlpNode {
    #[inline]
    fn from_rlp(rlp: impl AsRef<[u8]>) -> Self {
        let rlp = rlp.as_ref();
        if rlp.len() >= B256::len_bytes() {
            Self::from_digest_words(le_words_32(keccak256(rlp).as_slice()))
        } else {
            let mut words = [[0u8; 8]; 5];
            words.as_flattened_mut()[..rlp.len()].copy_from_slice(rlp);
            Self {
                words,
                len: NonZeroUsize::new(rlp.len()).expect("MPT: empty node encoding"),
            }
        }
    }

    /// The reference to the node with `digest`: `0xa0 ++ digest`.
    #[inline(always)]
    pub(super) fn from_digest(digest: &B256) -> Self {
        Self::from_digest_words(le_words_32(digest.as_slice()))
    }

    /// [`Self::from_digest`] from the digest's little-endian words: the
    /// 33-byte stream shifted up one byte behind the item prefix.
    #[inline(always)]
    fn from_digest_words(w: [u64; 4]) -> Self {
        let words = [
            (w[0] << 8) | DIGEST_ITEM_PREFIX as u64,
            (w[0] >> 56) | (w[1] << 8),
            (w[1] >> 56) | (w[2] << 8),
            (w[2] >> 56) | (w[3] << 8),
            w[3] >> 56,
        ];
        Self {
            words: words.map(u64::to_le_bytes),
            len: NonZeroUsize::new(DIGEST_RLP_LENGTH).unwrap(),
        }
    }

    #[inline(always)]
    pub(super) fn len(&self) -> usize {
        self.len.get()
    }

    /// First byte of the encoding; 8-aligned.
    #[inline(always)]
    pub(super) fn as_ptr(&self) -> *const u8 {
        self.words.as_flattened().as_ptr()
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.words.as_flattened()[..self.len.get()]
    }

    #[inline]
    fn hash(&self) -> B256 {
        let rlp = self.as_slice();
        if rlp.len() == DIGEST_RLP_LENGTH {
            B256::from_slice(&rlp[1..])
        } else {
            keccak256(rlp)
        }
    }
}

impl fmt::Debug for RlpNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.as_slice()))
    }
}

impl Encodable for RlpNode {
    #[inline]
    fn encode(&self, out: &mut dyn BufMut) {
        out.put_slice(self.as_slice())
    }

    #[inline]
    fn length(&self) -> usize {
        self.len()
    }
}

/// Represents the way in which a node is referenced from within another node.
#[derive(Default)]
enum NodeRef<'a> {
    #[default]
    Empty,
    Digest(&'a B256),
    Cached(&'a RlpNode),
    Rlp(Vec<u8>),
}

impl NodeRef<'_> {
    #[inline]
    fn from_node<M: Memoization>(node: &Node<M>) -> NodeRef<'_> {
        match node {
            Node::Null => NodeRef::Empty,
            Node::Digest(digest) => NodeRef::Digest(&digest.0),
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache) => cache
                .get()
                .map_or_else(|| NodeRef::Rlp(node.rlp_encoded()), NodeRef::Cached),
        }
    }

    #[inline]
    fn from_slot<M: Memoization>(slot: &Slot<M>) -> NodeRef<'_> {
        match slot {
            Slot::Empty => NodeRef::Empty,
            Slot::Digest(digest) => NodeRef::Digest(digest),
            Slot::Node(child) => NodeRef::from_node(child),
        }
    }

    #[inline]
    fn hash(&self) -> B256 {
        match self {
            NodeRef::Empty => EMPTY_ROOT_HASH,
            NodeRef::Digest(&digest) => digest,
            NodeRef::Cached(rlp_node) => rlp_node.hash(),
            NodeRef::Rlp(rlp) => keccak256(rlp),
        }
    }
}

impl Encodable for NodeRef<'_> {
    #[inline]
    fn encode(&self, out: &mut dyn BufMut) {
        match self {
            NodeRef::Empty => out.put_u8(EMPTY_STRING_CODE),
            NodeRef::Digest(digest) => digest.encode(out),
            NodeRef::Cached(rlp_node) => rlp_node.encode(out),
            NodeRef::Rlp(rlp) => {
                if rlp.len() >= B256::len_bytes() {
                    keccak256(rlp).encode(out);
                } else {
                    out.put_slice(rlp);
                }
            }
        }
    }

    #[inline]
    fn length(&self) -> usize {
        match self {
            NodeRef::Empty => 1,
            NodeRef::Digest(_) => DIGEST_RLP_LENGTH,
            NodeRef::Cached(rlp_node) => rlp_node.length(),
            NodeRef::Rlp(rlp) => {
                if rlp.len() >= B256::len_bytes() {
                    DIGEST_RLP_LENGTH
                } else {
                    rlp.len()
                }
            }
        }
    }
}

#[inline]
fn encode_list_header(payload_length: usize) -> Vec<u8> {
    debug_assert!(payload_length > 1);
    let header = Header {
        list: true,
        payload_length,
    };
    let mut out = Vec::with_capacity(header.length() + payload_length);
    header.encode(&mut out);
    out
}

#[inline]
fn decode_path(buf: &mut &[u8]) -> alloy_rlp::Result<(Nibbles, bool)> {
    let compact = decode_string(buf)?;
    if compact.is_empty() {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    let (is_leaf, odd_len) = match compact[0] >> 4 {
        0b0000 => (false, false),
        0b0001 => (false, true),
        0b0010 => (true, false),
        0b0011 => (true, true),
        _ => return Err(alloy_rlp::Error::Custom("node is not an extension or leaf")),
    };
    // Strip the HP prefix: for odd length, the first nibble of the key is in the low nibble
    // of the first byte; for even length, skip the first byte entirely.
    let nibbles = if odd_len {
        let first = compact[0] & 0x0f;
        let mut n = Nibbles::from_nibbles_unchecked([first]);
        n.extend(&Nibbles::unpack(&compact[1..]));
        n
    } else {
        Nibbles::unpack(&compact[1..])
    };
    Ok((nibbles, is_leaf))
}

fn encode_list<B, T>(values: &[B]) -> Vec<u8>
where
    B: core::borrow::Borrow<T>,
    T: ?Sized + Encodable,
{
    let mut payload_length = 0;
    for value in values {
        payload_length += value.borrow().length();
    }
    let mut out = encode_list_header(payload_length);
    for value in values {
        value.borrow().encode(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{super::memoize::Cache, *};

    /// `item_len` agrees with `Header::decode` (length or error) on every
    /// 1-byte item, every 33-byte item prefix, truncated digest items and
    /// long-form headers.
    #[test]
    fn item_len_matches_header_decode() {
        fn via_header(p: &[u8]) -> alloy_rlp::Result<usize> {
            let mut q = p;
            let h = Header::decode(&mut q)?;
            Ok(p.len() - q.len() + h.payload_length)
        }
        let mut cases: Vec<Vec<u8>> = Vec::new();
        for b in 0..=255u8 {
            cases.push(vec![b]);
            let mut item = vec![b];
            item.extend((0..32u8).map(|i| i.wrapping_mul(7)));
            cases.push(item.clone());
            item.truncate(20);
            cases.push(item);
        }
        cases.push(vec![0xa0, 0x00]);
        cases.push(vec![0xb8, 0x38]);
        cases.push(vec![0xb8, 0x37]);
        cases.push(vec![0xb9, 0x00, 0x40]);
        cases.push(vec![0xf8, 0x40]);
        cases.push(vec![0xf9, 0x01, 0x00]);
        let mut long = vec![0xf8, 0x40];
        long.resize(2 + 0x40, 0x80);
        cases.push(long);
        for case in &cases {
            assert_eq!(item_len(case), via_header(case), "{case:02x?}");
        }
    }

    /// The zero-copy decoder agrees with the `Decodable` impl (which scans
    /// through `Header::decode_raw`) on nodes, errors and trailing bytes.
    #[test]
    fn zc_decode_matches_decodable_impl() {
        fn digest_item(seed: u8) -> Vec<u8> {
            let mut v = vec![0xa0];
            v.extend((0..32u8).map(|i| i.wrapping_mul(seed).wrapping_add(seed)));
            v
        }
        fn list(items: &[Vec<u8>]) -> Vec<u8> {
            let payload: Vec<u8> = items.concat();
            let mut out = Vec::new();
            Header {
                list: true,
                payload_length: payload.len(),
            }
            .encode(&mut out);
            out.extend_from_slice(&payload);
            out
        }
        fn branch(children: &[(usize, Vec<u8>)], value: Vec<u8>) -> Vec<u8> {
            let mut items = vec![vec![EMPTY_STRING_CODE]; 17];
            for (i, child) in children {
                items[*i] = child.clone();
            }
            items[16] = value;
            list(&items)
        }
        let leaf = list(&[vec![0x83, 0x20, 0x12, 0x34], vec![0x82, 0xab, 0xcd]]);
        let mut long_leaf_value = vec![0xb8, 0x40];
        long_leaf_value.extend(core::iter::repeat_n(0x11u8, 0x40));
        let long_leaf = list(&[vec![0x82, 0x20, 0x12], long_leaf_value]);
        let inline_branch = branch(&[(1, digest_item(3)), (2, digest_item(4))], vec![0x80]);
        let mut path32 = vec![0xa0, 0x20];
        path32.extend(core::iter::repeat_n(0x77u8, 31));
        let cases: Vec<Vec<u8>> = vec![
            vec![0x80],
            digest_item(1),
            vec![0x83, 1, 2, 3],
            vec![0xc0],
            vec![0x05],
            vec![0x81, 0x05],
            vec![0xb8, 0x05],
            vec![0xb9, 0x00, 0x40],
            branch(&[(0, digest_item(1)), (5, digest_item(2))], vec![0x80]),
            branch(&[(0, digest_item(1)), (5, leaf.clone())], vec![0x80]),
            branch(
                &[(0, digest_item(1)), (7, inline_branch.clone())],
                vec![0x80],
            ),
            branch(&[(0, digest_item(1))], vec![0x80]),
            branch(&[(0, digest_item(1)), (5, digest_item(2))], vec![0x01]),
            branch(
                &[(0, digest_item(1)), (5, digest_item(2))],
                vec![0x81, 0x05],
            ),
            branch(
                &[(3, vec![0x82, 0x01, 0x02]), (5, digest_item(2))],
                vec![0x80],
            ),
            branch(&[(3, vec![0x02]), (5, digest_item(2))], vec![0x80]),
            branch(&[(3, vec![0xc0]), (5, digest_item(2))], vec![0x80]),
            branch(&[(3, vec![0x81, 0x05]), (5, digest_item(2))], vec![0x80]),
            branch(
                &[(3, digest_item(2)[..20].to_vec()), (5, digest_item(2))],
                vec![0x80],
            ),
            leaf.clone(),
            long_leaf,
            list(&[path32, digest_item(9)]),
            list(&[vec![0x1f], digest_item(2)]),
            list(&[vec![0x00], digest_item(2)]),
            list(&[vec![0x00], inline_branch.clone()]),
            list(&[vec![0x00], leaf.clone()]),
            list(&[vec![0x00], vec![0x80]]),
            list(&[vec![0x81, 0x40], digest_item(2)]),
            list(&[vec![0x80], digest_item(2)]),
            list(&[vec![0xc1, 0x20], digest_item(2)]),
            list(&[vec![0x82, 0x20, 0x12], vec![0xc2, 0xab, 0xcd]]),
            list(&[vec![0x82, 0x20, 0x12], vec![0x81, 0x05]]),
            list(&[vec![0x82, 0x20, 0x12]]),
            list(&[vec![0x82, 0x20, 0x12], vec![0x80], vec![0x80]]),
            list(&[vec![0xa0, 0x20]]),
            vec![0xf9, 0x00, 0x10, 0x80],
            vec![0xc2, 0x80],
        ];
        for case in &cases {
            for trailing in [0usize, 1] {
                let mut bytes = case.clone();
                bytes.extend(core::iter::repeat_n(0x80u8, trailing));
                let source = Bytes::from(bytes);
                let expected = alloy_rlp::decode_exact::<Node<Cache>>(&source);
                let mut slot = MaybeUninit::<Node<Cache>>::uninit();
                let got = decode_node_zc_exact_into(&source, &mut slot);
                match (expected, got) {
                    (Ok(node), Ok(())) => {
                        assert_eq!(unsafe { slot.assume_init() }, node, "{source}")
                    }
                    (Err(e), Err(g)) => assert_eq!(e, g, "{source}"),
                    (e, g) => panic!("{source}: expected {e:?}, got {g:?}"),
                }
            }
        }
    }

    /// `decode_header` agrees with `Header::decode` (header or error, and the
    /// buffer advance) for every first byte over a range of tails: short and
    /// long lengths with and without their payload, leading zeros,
    /// non-canonical sizes, truncated length fields.
    #[test]
    fn decode_header_matches_alloy() {
        let tails: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0x05],
            vec![0x7f],
            vec![0x80],
            vec![0x37],
            vec![0x38],
            vec![0x00, 0x40],
            vec![0x01, 0x00],
            vec![0x01, 0x00, 0x00],
            vec![0xff; 8],
            vec![0x01; 9],
        ];
        for b in 0..=255u8 {
            for tail in &tails {
                for payload in [0usize, 1, 55, 56, 300] {
                    let mut bytes = vec![b];
                    bytes.extend_from_slice(tail);
                    bytes.extend(core::iter::repeat_n(0x11u8, payload));
                    let mut ours = &bytes[..];
                    let mut theirs = &bytes[..];
                    let got = decode_header(&mut ours);
                    let want = Header::decode(&mut theirs);
                    assert_eq!(got, want, "{bytes:02x?}");
                    assert_eq!(ours.len(), theirs.len(), "{bytes:02x?}");
                }
            }
        }
    }

    /// Word gather is byte-exact for every source alignment.
    #[test]
    fn le_words_32_matches_from_le_bytes() {
        let bytes: Vec<u8> = (0..48u8)
            .map(|i| i.wrapping_mul(29).wrapping_add(5))
            .collect();
        for so in 0..8 {
            let got = le_words_32(&bytes[so..]);
            for (i, w) in got.iter().enumerate() {
                let mut chunk = [0u8; 8];
                chunk.copy_from_slice(&bytes[so + 8 * i..so + 8 * i + 8]);
                assert_eq!(*w, u64::from_le_bytes(chunk), "so={so} i={i}");
            }
        }
    }

    /// The digest fast path yields the general decoder's node for every
    /// source alignment.
    #[test]
    fn digest_fast_path_matches_generic_decode() {
        let mut digest = [0u8; 32];
        for (i, b) in digest.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        for so in 0..8 {
            let mut buf = vec![0xeeu8; so];
            buf.push(DIGEST_ITEM_PREFIX);
            buf.extend_from_slice(&digest);
            buf.extend_from_slice(&[0xdd; 9]);
            let source = Bytes::from(buf);
            let item = &source[so..so + DIGEST_RLP_LENGTH];
            assert!(is_digest_item(item));
            let fast = digest_item(item);
            let mut slow = MaybeUninit::<Node<Cache>>::uninit();
            decode_node_zc_into(&source, &mut &item[..], &mut slow).unwrap();
            let slow = unsafe { slow.assume_init() };
            assert_eq!(Node::<Cache>::Digest(fast), slow, "so={so}");
            assert_eq!(fast.0.as_slice(), digest, "so={so}");
        }
    }

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
