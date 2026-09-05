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
    children::{Children, Entry},
    memoize::Memoization,
    node::Node,
};
use alloc::{boxed::Box, vec, vec::Vec};
use alloy_primitives::{hex, keccak256, map::B256IndexMap, Bytes, B256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header, PayloadView, EMPTY_STRING_CODE};
use alloy_trie::{nodes::encode_path_leaf, Nibbles, EMPTY_ROOT_HASH};
use arrayvec::ArrayVec;
use core::{fmt, mem::MaybeUninit};

/// The length in bytes of an RLP-encoded digest, i.e. hash length + 1 byte for the RLP header.
const DIGEST_RLP_LENGTH: usize = 1 + B256::len_bytes();

/// Scratch capacity for the arena encoder — a branch is ≤ 3 + 17×33 = 564 B,
/// leaves ≤ path 34 + value item ≈ 150 B; 1 KiB leaves ample margin. The
/// capacity assert turns a (dishonest) oversized claim into a refusal.
pub(super) const MAX_NODE_ENCODING: usize = 1024;

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
fn write_str_item(buf: &mut [u8], cursor: &mut usize, bytes: &[u8]) {
    let len = bytes.len();
    if len == 1 && bytes[0] < 0x80 {
        buf[*cursor] = bytes[0];
        *cursor += 1;
        return;
    }
    if len < 56 {
        buf[*cursor] = 0x80 + len as u8;
        *cursor += 1;
    } else {
        debug_assert!(len < 256);
        buf[*cursor] = 0xb8;
        buf[*cursor + 1] = len as u8;
        *cursor += 2;
    }
    buf[*cursor..*cursor + len].copy_from_slice(bytes);
    *cursor += len;
}

/// jeth (advice-trie): digest→bytes resolution callback for trie hydration.
///
/// Contract: a `Some(bytes)` return MUST be authenticated by the implementor —
/// `keccak256(bytes) == *digest` — before the bytes are handed out (the trie
/// decodes them as the node with that digest). `None` = "not available":
/// the node stays an unresolved [`Node::Digest`] stub.
pub trait DigestResolver {
    fn resolve(&mut self, digest: &B256) -> Option<Bytes>;
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

                for (i, child) in children.iter().enumerate() {
                    match child {
                        Some(node) => {
                            let node_ref = NodeRef::from_node(node);
                            payload_length += node_ref.length();
                            child_refs[i] = node_ref;
                        }
                        None => payload_length += 1,
                    }
                }

                let mut out = encode_list_header(payload_length);
                child_refs.iter().for_each(|child| child.encode(&mut out));
                // add an EMPTY_STRING_CODE for the missing value
                out.push(EMPTY_STRING_CODE);

                out
            }
            Node::Digest(digest) => alloy_rlp::encode(digest),
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
    /// dyn-`BufMut` dispatch. The payload length is UNTRUSTED ADVICE written
    /// ahead of the header and sealed by `cursor_delta == claimed` right after
    /// the parts are written, BEFORE the bytes are hashed / consumed by the
    /// parent (L2: every advice value is locally verified). The capacity
    /// assert closes the overstated-length gap; slice indexing bounds-panics
    /// close the understated one (both = refusal, no proof).
    pub(super) fn memoize_arena(&mut self, scratch: &mut [u8]) {
        // early termination for already memoized nodes or Null/Digest
        match self {
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache)
                if cache.get().is_some() =>
            {
                return;
            }
            Node::Null | Node::Digest(_) => return,
            _ => {}
        }
        match self {
            Node::Extension(_, child, _) => child.memoize_arena(scratch),
            Node::Branch(children, _) => children.memoize_arena(scratch),
            _ => {}
        }

        let claimed = advice_u64!(self.encoded_payload_length() as u64) as usize;
        assert!(
            claimed + 3 <= MAX_NODE_ENCODING,
            "MPT: node encoding too large"
        );
        let header_len = write_list_header(scratch, claimed);
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
                for child in children.iter() {
                    match child {
                        Some(node) => write_child_ref(scratch, &mut cursor, node),
                        None => {
                            scratch[cursor] = EMPTY_STRING_CODE;
                            cursor += 1;
                        }
                    }
                }
                // EMPTY_STRING_CODE for the missing branch value
                scratch[cursor] = EMPTY_STRING_CODE;
                cursor += 1;
            }
            _ => unreachable!(),
        }
        // seal the claimed length before the bytes are consumed
        advice_assert_eq!((cursor - header_len) as u64, claimed as u64);
        let rlp_node = RlpNode::from_rlp(&scratch[..cursor]);
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
                for child in children.iter() {
                    payload_length += match child {
                        Some(node) => NodeRef::from_node(node).length(),
                        None => 1,
                    };
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
                    for child in children.iter() {
                        let node_ref = child.as_ref().map_or(NodeRef::Empty, |c| rec(c, nodes));
                        list.push(node_ref);
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
                for entry in children.entries() {
                    if let Entry::Occupied(mut entry) = entry {
                        entry.get_mut().resolve_digests(rlp_by_digest)?;
                    }
                }
            }
            Node::Digest(digest) => {
                #[cfg(feature = "premeasure")]
                super::premeasure::count(&super::premeasure::PROBES);
                if let Some(bytes) = rlp_by_digest.get(digest) {
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
                for entry in children.entries() {
                    if let Entry::Occupied(mut entry) = entry {
                        entry.get_mut().resolve_with(r)?;
                    }
                }
            }
            Node::Digest(digest) => {
                #[cfg(feature = "premeasure")]
                super::premeasure::count(&super::premeasure::PROBES);
                if let Some(bytes) = r.resolve(digest) {
                    #[cfg(feature = "premeasure")]
                    super::premeasure::count(&super::premeasure::HITS);
                    let digest = *digest;
                    self.decode_stub_in_place(&digest, &bytes)?;
                    // do not try to replace a node by a digest
                    if matches!(self, Node::Digest(_)) {
                        *self = Node::Digest(digest);
                    } else {
                        #[cfg(feature = "premeasure")]
                        super::premeasure::count(&super::premeasure::DECODES);
                        self.cache_set(RlpNode::from_digest(&digest));
                        self.resolve_with(r)?;
                    }
                }
            }
        }

        Ok(())
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
    /// Requires `*self` to be `Node::Digest(*digest)`. On `Ok`, `*self` is the
    /// decoded node (possibly itself a `Digest`); on `Err`, `*self` is the
    /// original stub again.
    pub(super) fn decode_stub_in_place(
        &mut self,
        digest: &B256,
        bytes: &Bytes,
    ) -> alloy_rlp::Result<()> {
        debug_assert!(matches!(self, Node::Digest(d) if d == digest));
        // SAFETY: `MaybeUninit<Node<M>>` has the layout of `Node<M>`, and a
        // `Node::Digest` owns no resources, so its bytes may be overwritten
        // without a drop. `decode_node_zc_exact_into` touches the slot only
        // through `MaybeUninit::write` (whole-value stores, after every
        // fallible/panicking step of the arm) and, on `Err`, leaves it either
        // untouched or holding `Node::Null` — so `*self` is a valid, drop-safe
        // node at every panic point and on both result paths.
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
                32 => Ok(Node::Digest(B256::from_slice(payload))),
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
/// Out-param form: the decoded node is written to `out` exactly once, at the
/// end of the taken arm. Children are decoded straight into their final heap
/// slot (`Box::new_uninit`), deleting the by-value move chain (return → `?` →
/// `Box::new`, ≈3 × 176-byte memcpy per node on riscv64; 49.6M trace rows on
/// block 25905781 before this change).
///
/// Contract: `out` is initialized if and only if the return is `Ok(())`. On
/// `Err` — and at every panic point — `out` has not been written.
fn decode_node_zc_into<M: Memoization>(
    source: &Bytes,
    buf: &mut &[u8],
    out: &mut MaybeUninit<Node<M>>,
) -> alloy_rlp::Result<()> {
    match Header::decode_raw(buf)? {
        // if the node is not a list, it must be empty or a digest
        PayloadView::String(payload) => match payload.len() {
            0 => {
                out.write(Node::Null);
                Ok(())
            }
            32 => {
                out.write(Node::Digest(B256::from_slice(payload)));
                Ok(())
            }
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
                        }
                        let mut child = Box::<Node<M>>::new_uninit();
                        decode_node_zc_into(source, &mut &child_rlp[..], &mut child)?;
                        // SAFETY: `Ok` return above ⇒ the callee wrote a fully
                        // initialized `Node` into the slot (every `Ok` arm ends
                        // in `out.write`). On `Err`, `?` drops the
                        // `Box<MaybeUninit<..>>` without reading it.
                        children.insert(i as u8, unsafe { child.assume_init() });
                    }
                }
                if children.len() < 2 {
                    return Err(alloy_rlp::Error::Custom("branch node without two children"));
                }

                out.write(Node::Branch(children, M::default()));
                Ok(())
            }
            // leaf or extension node: 2-item node [ encodedPath, v ]
            2 => {
                let [mut encode_path, mut v] = items.as_slice() else {
                    unreachable!()
                };
                let (path, is_leaf) = decode_path(&mut encode_path)?;
                if is_leaf {
                    let payload = Header::decode_bytes(&mut v, false)?;
                    out.write(Node::Leaf(path, source.slice_ref(payload), M::default()));
                    Ok(())
                } else {
                    let mut child = Box::<Node<M>>::new_uninit();
                    decode_node_zc_into(source, &mut v, &mut child)?;
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
        },
    }
}

/// [`decode_node_zc_into`] over the whole buffer, mirroring `alloy_rlp::decode_exact`.
///
/// Contract: on `Ok`, `out` holds the decoded node. On `Err`, `out` is either
/// untouched or holds [`Node::Null`] (trailing-bytes refusal of a complete
/// decode) — never partially written, so a caller may alias `out` with a live
/// `&mut Node<M>` slot ([`Node::decode_stub_in_place`]).
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
#[inline(always)]
fn write_child_ref<M: Memoization>(buf: &mut [u8], cursor: &mut usize, node: &Node<M>) {
    match NodeRef::from_node(node) {
        NodeRef::Empty => {
            buf[*cursor] = EMPTY_STRING_CODE;
            *cursor += 1;
        }
        NodeRef::Digest(digest) => {
            buf[*cursor] = 0xa0;
            buf[*cursor + 1..*cursor + 33].copy_from_slice(digest.as_slice());
            *cursor += 33;
        }
        NodeRef::Cached(rlp_node) => {
            let bytes = rlp_node.0.as_slice();
            buf[*cursor..*cursor + bytes.len()].copy_from_slice(bytes);
            *cursor += bytes.len();
        }
        // cold: unmemoized non-digest child (unreachable after the post-order
        // walk, kept for NodeRef semantic parity)
        NodeRef::Rlp(rlp) => {
            if rlp.len() >= B256::len_bytes() {
                buf[*cursor] = 0xa0;
                buf[*cursor + 1..*cursor + 33].copy_from_slice(keccak256(&rlp).as_slice());
                *cursor += 33;
            } else {
                buf[*cursor..*cursor + rlp.len()].copy_from_slice(&rlp);
                *cursor += rlp.len();
            }
        }
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

/// An RLP-encoded node.
#[derive(Clone)]
pub(super) struct RlpNode(ArrayVec<u8, DIGEST_RLP_LENGTH>);

impl RlpNode {
    #[inline]
    fn from_rlp(rlp: impl AsRef<[u8]>) -> Self {
        let rlp = rlp.as_ref();
        if rlp.len() >= B256::len_bytes() {
            Self(alloy_rlp::encode_fixed_size(&keccak256(rlp)))
        } else {
            let mut arr = ArrayVec::new();
            // SAFETY: rlp.len() < 32 < DIGEST_RLP_LENGTH
            unsafe { arr.try_extend_from_slice(rlp).unwrap_unchecked() };
            Self(arr)
        }
    }

    #[inline]
    pub(super) fn from_digest(digest: &B256) -> Self {
        Self(alloy_rlp::encode_fixed_size(digest))
    }

    #[inline]
    fn hash(&self) -> B256 {
        if self.0.len() == DIGEST_RLP_LENGTH {
            B256::from_slice(&self.0[1..])
        } else {
            keccak256(&self.0)
        }
    }
}

impl fmt::Debug for RlpNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

impl Encodable for RlpNode {
    #[inline]
    fn encode(&self, out: &mut dyn BufMut) {
        out.put_slice(&self.0)
    }

    #[inline]
    fn length(&self) -> usize {
        self.0.len()
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
            Node::Digest(digest) => NodeRef::Digest(digest),
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache) => cache
                .get()
                .map_or_else(|| NodeRef::Rlp(node.rlp_encoded()), NodeRef::Cached),
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
    let compact = Header::decode_bytes(buf, false)?;
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
