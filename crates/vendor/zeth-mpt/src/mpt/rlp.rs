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

//! RLP node references and digest resolution: [`RlpNode`] (a node's cached
//! encoding-or-digest), the reference `Encodable` walk, and hydration of
//! digest stubs through a [`DigestResolver`].
use super::{
    children::Slot,
    decode::{decode_node_zc_exact_into, le_words_32},
    memoize::Memoization,
    node::{Child, Digest, Node},
};
use alloc::{boxed::Box, vec, vec::Vec};
use alloy_primitives::{hex, keccak256, map::B256IndexMap, Bytes, B256};
use alloy_rlp::{BufMut, Encodable, Header, EMPTY_STRING_CODE};
use alloy_trie::{nodes::encode_path_leaf, EMPTY_ROOT_HASH};
use core::{fmt, mem::MaybeUninit, num::NonZeroUsize};

/// The length in bytes of an RLP-encoded digest, i.e. hash length + 1 byte for the RLP header.
pub(super) const DIGEST_RLP_LENGTH: usize = 1 + B256::len_bytes();

/// RLP header byte of a digest item (32-byte string).
pub(super) const DIGEST_ITEM_PREFIX: u8 = EMPTY_STRING_CODE + B256::len_bytes() as u8;

/// Digest→bytes resolution callback for trie hydration.
///
/// Contract: a `Some(bytes)` return MUST be authenticated by the implementor —
/// `keccak256(bytes) == *digest` — before the bytes are handed out (the trie
/// decodes them as the node with that digest). `None` = "not available":
/// the node stays an unresolved [`Node::Digest`] stub.
pub trait DigestResolver {
    fn resolve(&mut self, digest: &B256) -> Option<&Bytes>;
}

/// [`DigestResolver`] over a prebuilt digest → encoding map ([`Node::from_rlp`]
/// and tests; production resolves through advice-indexed witness slots).
pub(super) struct MapResolver<'a>(pub(super) &'a B256IndexMap<Bytes>);

impl DigestResolver for MapResolver<'_> {
    fn resolve(&mut self, digest: &B256) -> Option<&Bytes> {
        self.0.get(digest)
    }
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

    /// Creates a new trie from the given RLP encoded nodes: the first is the
    /// root, the rest resolve wherever the root (transitively) references them.
    pub(super) fn from_rlp<T: AsRef<[u8]>>(
        nodes: impl IntoIterator<Item = T>,
    ) -> alloy_rlp::Result<Self> {
        let mut nodes = nodes
            .into_iter()
            .map(|rlp| Bytes::copy_from_slice(rlp.as_ref()));
        let Some(root_rlp) = nodes.next() else {
            return Ok(Self::default());
        };
        let mut root = MaybeUninit::uninit();
        decode_node_zc_exact_into(&root_rlp, &mut root)?;
        // SAFETY: `Ok` above ⇒ the callee wrote a fully initialized node.
        let mut root: Node<M> = unsafe { root.assume_init() };
        root.cache_set(RlpNode::from_rlp(root_rlp.as_ref()));
        let rlp_by_digest: B256IndexMap<Bytes> = nodes.map(|rlp| (keccak256(&rlp), rlp)).collect();
        root.resolve_with(&mut MapResolver(&rlp_by_digest))?;
        Ok(root)
    }

    /// Resolves every reachable digest stub through a [`DigestResolver`]. The
    /// resolver must return AUTHENTICATED bytes (`keccak(bytes) == digest`) or
    /// `None` to leave the digest stub in place (an untouched stub contributes
    /// its parent-sourced digest to encodes bit-identically; content access
    /// panics).
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
    pub(super) fn hydrate(&mut self, digest: Digest, bytes: &Bytes) -> alloy_rlp::Result<bool> {
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
    pub(super) fn from_rlp(rlp: impl AsRef<[u8]>) -> Self {
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
pub(super) enum NodeRef<'a> {
    #[default]
    Empty,
    Digest(&'a B256),
    Cached(&'a RlpNode),
    Rlp(Vec<u8>),
}

impl NodeRef<'_> {
    #[inline]
    pub(super) fn from_node<M: Memoization>(node: &Node<M>) -> NodeRef<'_> {
        match node {
            Node::Null => NodeRef::Empty,
            Node::Digest(digest) => NodeRef::Digest(&digest.0),
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache) => cache
                .get()
                .map_or_else(|| NodeRef::Rlp(node.rlp_encoded()), NodeRef::Cached),
        }
    }

    #[inline]
    pub(super) fn from_slot<M: Memoization>(slot: &Slot<M>) -> NodeRef<'_> {
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
    use super::*;

    /// `RlpNode::from_digest` is the RLP string item of the digest
    /// (`0xa0 ++ digest`), and `from_rlp` switches from the inline encoding
    /// to the digest reference exactly at 32 bytes.
    #[test]
    fn rlp_node_digest_and_inline_boundary() {
        let digest = B256::from_slice(&(0..32u8).map(|i| i.wrapping_mul(37)).collect::<Vec<_>>());
        let node = RlpNode::from_digest(&digest);
        assert_eq!(node.as_slice(), alloy_rlp::encode(digest));
        assert_eq!(node.len(), DIGEST_RLP_LENGTH);
        assert_eq!(node.hash(), digest);

        let rlp31: Vec<u8> = (0..31u8).map(|i| i.wrapping_mul(11).wrapping_add(1)).collect();
        let inline = RlpNode::from_rlp(&rlp31);
        assert_eq!(inline.as_slice(), &rlp31[..]);
        assert_eq!(inline.len(), 31);
        assert_eq!(inline.hash(), keccak256(&rlp31));

        let rlp32: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(11).wrapping_add(1)).collect();
        let referenced = RlpNode::from_rlp(&rlp32);
        assert_eq!(referenced.as_slice(), alloy_rlp::encode(keccak256(&rlp32)));
        assert_eq!(referenced.hash(), keccak256(&rlp32));
    }
}
