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
    children::{Children, Slot},
    memoize::Memoization,
    nibbles::NibbleSlice,
    rlp::{le_words_32, DigestResolver},
};
use alloc::boxed::Box;
use alloy_primitives::{Bytes, B256, U256};
use alloy_trie::Nibbles;
use core::{mem, ops::Deref};

/// Nibble `d` of the raw key bytes (two nibbles per byte, high first).
#[inline(always)]
fn key_nibble(key: &[u8], d: usize) -> u8 {
    let b = key[d >> 1];
    if d & 1 == 0 {
        b >> 4
    } else {
        b & 0xf
    }
}

/// Sixty-four zero nibbles: the shape of every packed 32-byte key.
const FULL_KEY: Nibbles = Nibbles::unpack_array(&[0; 32]);

/// `Nibbles::unpack(key)`, assembled from whole words for the 32-byte hashed
/// keys jeth looks up: the packed form is the key as a big-endian `U256`, so
/// four aligned-word loads ([`le_words_32`]) plus four byte swaps replace the
/// byte-reversing copy loop. Other lengths take `Nibbles::unpack`.
#[inline(always)]
fn packed_key(key: &[u8]) -> Nibbles {
    if key.len() != 32 {
        return Nibbles::unpack(key);
    }
    let w = le_words_32(key);
    let mut nibbles = FULL_KEY;
    *nibbles.as_mut_uint_unchecked() = U256::from_limbs([
        w[3].swap_bytes(),
        w[2].swap_bytes(),
        w[1].swap_bytes(),
        w[0].swap_bytes(),
    ]);
    nibbles
}

pub(super) type Child<M> = Box<Node<M>>;

/// The digest of an unresolved node, stored 8-aligned (`B256` itself is
/// align 1): the decode fast path gathers a digest item from the aligned
/// words containing it and stores it as four aligned `sd`s straight into the
/// node slot, and the arena encoder reads it back word-wise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, align(8))]
pub(super) struct Digest(pub(super) B256);

impl Digest {
    /// Digest from its four little-endian words (word `i` = bytes `8i..8i+8`).
    #[inline(always)]
    pub(super) fn from_le_limbs(limbs: [u64; 4]) -> Self {
        // SAFETY: `[[u8; 8]; 4]` and `[u8; 32]` have identical layout.
        Self(B256::new(unsafe {
            mem::transmute::<[[u8; 8]; 4], [u8; 32]>(limbs.map(u64::to_le_bytes))
        }))
    }
}

impl Deref for Digest {
    type Target = B256;
    #[inline(always)]
    fn deref(&self) -> &B256 {
        &self.0
    }
}

/// jeth (advice-trie): resolver that never resolves — plain `insert`/`remove`
/// keep today's panic-on-stub contract by threading this.
pub(super) struct Unresolvable;

impl DigestResolver for Unresolvable {
    #[inline]
    fn resolve(&mut self, _digest: &alloy_primitives::B256) -> Option<&Bytes> {
        None
    }
}

/// jeth fork note: `Node<Cache>` is 688 bytes — [`Children`] stores its 16
/// [`Slot`]s inline (640 B; rustc currently folds the node discriminant into
/// the first slot's tag word — an observed layout nothing here relies on),
/// with unresolved children held as bare digests instead of one heap `Node`
/// per stub (145k stub boxes of 176 B on a mainnet block, 33 B live each). Moving a node by value (decode return →
/// `?` → `Box::new`, or a split's `*self = branch`) lowers to word copy loops
/// that Jolt expands into trace rows, so nodes are constructed directly in
/// their final slot instead ([`super::rlp`]'s `decode_node_zc_into`,
/// [`Self::replace_with_branch`]). Boxing the children array (and the arena
/// layout) measured WORSE: +155M rows — hence the variant size spread.
#[derive(Debug, Clone, Default)]
#[allow(clippy::large_enum_variant)]
pub(super) enum Node<M> {
    #[default]
    Null,
    Leaf(Nibbles, Bytes, M),
    Extension(Nibbles, Child<M>, M),
    Branch(Children<M>, M),
    Digest(Digest),
}

impl<M> PartialEq for Node<M> {
    /// Equality between nodes ignores the cache.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Node::Null, Node::Null) => true,
            (Node::Leaf(n1, b1, _), Node::Leaf(n2, b2, _)) => n1 == n2 && b1 == b2,
            (Node::Extension(n1, c1, _), Node::Extension(n2, c2, _)) => n1 == n2 && c1 == c2,
            (Node::Branch(c1, _), Node::Branch(c2, _)) => c1 == c2,
            (Node::Digest(d1), Node::Digest(d2)) => d1 == d2,
            _ => false, // different variants are not equal
        }
    }
}

impl<M> Eq for Node<M> {}

impl<M: Memoization> Node<M> {
    /// Retrieves the value associated with a given key (raw key bytes).
    ///
    /// Walks by depth over the key: branch nibbles are read straight from the
    /// key bytes, extension and leaf prefixes are compared against the packed
    /// key sliced at the current depth — the key is never re-sliced per level
    /// and never unpacked byte by byte ([`packed_key`]).
    pub(super) fn get(&self, key: &[u8]) -> Option<&Bytes> {
        let total = 2 * key.len();
        let packed = packed_key(key);
        let mut node = self;
        let mut depth = 0usize;
        loop {
            match node {
                Node::Null => return None,
                Node::Leaf(prefix, value, _) => {
                    let hit = prefix.len() == total - depth
                        && packed.slice_unchecked(depth, total) == *prefix;
                    return hit.then_some(value);
                }
                Node::Extension(prefix, child, _) => {
                    let len = prefix.len();
                    if len > total - depth || packed.slice_unchecked(depth, depth + len) != *prefix
                    {
                        return None;
                    }
                    depth += len;
                    node = child;
                }
                Node::Branch(children, _) => {
                    if depth == total {
                        return None; // branch nodes don't have values in our MPT version
                    }
                    let nib = key_nibble(key, depth);
                    depth += 1;
                    match children.get(nib) {
                        Slot::Node(child) => node = child,
                        Slot::Empty => return None,
                        Slot::Digest(_) => panic!("MPT: Unresolved node access"),
                    }
                }
                Node::Digest(_) => panic!("MPT: Unresolved node access"),
            }
        }
    }

    /// Inserts a key-value pair into the trie.
    pub(super) fn insert(&mut self, key: NibbleSlice, value: Bytes) {
        self.insert_with(key, value, &mut Unresolvable)
    }

    /// jeth (advice-trie): like [`Self::insert`], but a [`Node::Digest`] on the
    /// insertion path is resolved on demand through `r` (post-root lazy
    /// materialization). A resolver miss panics — same witness-incompleteness
    /// contract as the eager build (INV-W3).
    pub(super) fn insert_with<R: DigestResolver>(
        &mut self,
        key: NibbleSlice,
        value: Bytes,
        r: &mut R,
    ) {
        assert!(!value.is_empty());
        match self {
            Node::Null => {
                *self = Node::Leaf(key.into(), value, M::default());
            }
            Node::Leaf(prefix, leaf_val, cache) => {
                let (common, key_rem, prefix_rem) = key.split_common_prefix(*prefix);
                if common.len() == prefix.len() && common.len() == key.len() {
                    *leaf_val = value;
                    cache.clear();
                    return;
                } else if common.len() == prefix.len() || common.len() == key.len() {
                    panic!("MPT: Value in branch");
                }

                let (nib, tail) = prefix_rem.split_first().expect("mid < prefix.len()");
                let leaf = Node::Leaf(tail.into(), mem::take(leaf_val), M::default());
                let (new_nib, new_tail) = key_rem.split_first().expect("mid < key.len()");
                let children = self.replace_with_branch(common);
                children.insert(nib, leaf.into());
                children.insert(
                    new_nib,
                    Node::Leaf(new_tail.into(), value, M::default()).into(),
                );
            }
            Node::Extension(prefix, child, cache) => {
                let (common, key_rem, prefix_rem) = key.split_common_prefix(*prefix);
                if common.len() == prefix.len() {
                    child.insert_with(key_rem, value, r);
                    cache.clear();
                    return;
                } else if common.len() == key.len() {
                    panic!("MPT: Value in branch");
                }

                let (nib, tail) = prefix_rem.split_first().expect("mid < prefix.len()");
                let old_child = if tail.is_empty() {
                    mem::take(child)
                } else {
                    Node::Extension(tail.into(), mem::take(child), M::default()).into()
                };
                let (new_nib, new_tail) = key_rem.split_first().expect("mid < key.len()");
                let children = self.replace_with_branch(common);
                children.insert(nib, old_child);
                children.insert(
                    new_nib,
                    Node::Leaf(new_tail.into(), value, M::default()).into(),
                );
            }
            Node::Branch(children, cache) => match key.split_first() {
                Some((nib, tail)) => {
                    let slot = children.slot_mut(nib);
                    match slot.resolve_mut(r) {
                        Some(child) => child.insert_with(tail, value, r),
                        None => {
                            *slot = Slot::from_child(
                                Node::Leaf(tail.into(), value, M::default()).into(),
                            )
                        }
                    }
                    cache.clear();
                }
                None => panic!("MPT: Value in branch"),
            },
            Node::Digest(_) => {
                self.resolve_stub(r);
                self.insert_with(key, value, r);
            }
        }
    }

    /// Replace `*self` with an empty branch — behind an extension carrying
    /// `prefix` when it is non-empty — and return its children. The branch is
    /// built in its final slot: a `Node::Branch` is 688 B, and building it
    /// on the stack first would copy it there by value.
    fn replace_with_branch(&mut self, prefix: NibbleSlice) -> &mut Children<M> {
        let branch = if prefix.is_empty() {
            *self = Node::Branch(Children::default(), M::default());
            self
        } else {
            let branch = Box::new(Node::Branch(Children::default(), M::default()));
            *self = Node::Extension(prefix.into(), branch, M::default());
            let Node::Extension(_, child, _) = self else {
                unreachable!()
            };
            &mut **child
        };
        let Node::Branch(children, _) = branch else {
            unreachable!()
        };
        children
    }

    /// Removes a key-value pair from the trie.
    pub(super) fn remove(&mut self, key: NibbleSlice) -> bool {
        self.remove_with(key, &mut Unresolvable)
    }

    /// jeth (advice-trie): like [`Self::remove`], but digest stubs on the
    /// removal path — including the branch-collapse sibling — are resolved on
    /// demand through `r`. A resolver miss panics (INV-W3); orphan-rule
    /// semantics are otherwise byte-identical to [`Self::remove`].
    pub(super) fn remove_with<R: DigestResolver>(&mut self, key: NibbleSlice, r: &mut R) -> bool {
        match self {
            Node::Null => false,
            Node::Leaf(prefix, ..) if prefix == key.as_nibbles() => {
                *self = Node::Null;
                true
            }
            Node::Leaf(..) => false,
            Node::Extension(prefix, child, cache) => {
                if !key
                    .strip_prefix(prefix)
                    .is_some_and(|tail| child.remove_with(tail, r))
                {
                    return false;
                }
                cache.clear();

                // an extension always points to a branch, if this has changed because of the remove
                match **child {
                    Node::Null => *self = Node::Null,
                    Node::Leaf(ref extension, ref mut value, _) => {
                        prefix.extend(extension);
                        *self = Node::Leaf(mem::take(prefix), mem::take(value), M::default())
                    }
                    Node::Extension(ref extension, ref mut child, _) => {
                        prefix.extend(extension);
                        *self = Node::Extension(mem::take(prefix), mem::take(child), M::default())
                    }
                    Node::Branch(..) => {}
                    Node::Digest(_) => unreachable!(), // child.remove() would have panicked
                }
                true
            }
            Node::Branch(children, cache) => {
                // branch nodes don't have values in our MPT version
                let Some((nib, tail)) = key.split_first() else {
                    return false;
                };
                let slot = children.slot_mut(nib);
                let removed = match slot.resolve_mut(r) {
                    Some(child) => child.remove_with(tail, r),
                    None => false,
                };
                if !removed {
                    return false;
                }
                slot.clear_null();
                cache.clear();

                if let Some((nib, mut only_child)) = children.take_single_child() {
                    // jeth (advice-trie): the collapse sibling may be an
                    // unresolved stub — resolve it on demand (today this is the
                    // panic below; the witness contains collapse siblings by
                    // construction, so honest proving succeeds).
                    only_child.resolve_stub(r);
                    match *only_child {
                        // if the only child is a leaf, prepend the corresponding nib to it
                        Node::Leaf(extension, value, _) => {
                            let mut prefix = Nibbles::from_nibbles_unchecked([nib]);
                            prefix.extend(&extension);
                            *self = Node::Leaf(prefix, value, M::default());
                        }
                        // if the only child is an extension, prepend the corresponding nib to it
                        Node::Extension(extension, child, ..) => {
                            let mut prefix = Nibbles::from_nibbles_unchecked([nib]);
                            prefix.extend(&extension);
                            *self = Node::Extension(prefix, child, M::default());
                        }
                        // if the only child is a branch, convert to an extension
                        Node::Branch(..) => {
                            let prefix = Nibbles::from_nibbles_unchecked([nib]);
                            *self = Node::Extension(prefix, only_child, M::default());
                        }
                        Node::Digest(_) => unreachable!(), // resolve_stub above panics on miss
                        Node::Null => unreachable!(), // children does not contain any Node::Null
                    }
                }
                true
            }
            Node::Digest(_) => {
                self.resolve_stub(r);
                self.remove_with(key, r)
            }
        }
    }

    /// jeth (advice-trie): resolve a [`Node::Digest`] in place through `r`.
    /// Panics on a resolver miss ("MPT: Unresolved node access" — INV-W3) and
    /// on the digest-for-digest refusal / malformed bytes (a malformed node on
    /// a DIRTY path fails proving, matching the eager build's reveal error).
    /// No-op on already-resolved nodes.
    pub(super) fn resolve_stub<R: DigestResolver>(&mut self, r: &mut R) {
        if let Node::Digest(digest) = self {
            let bytes = r.resolve(digest).expect("MPT: Unresolved node access");
            let digest = *digest;
            self.decode_stub_in_place(&digest, bytes)
                .expect("MPT: invalid witness node");
            if matches!(self, Node::Digest(_)) {
                *self = Node::Digest(digest);
                panic!("MPT: Unresolved node access"); // digest-for-digest refusal
            }
            self.cache_set(super::rlp::RlpNode::from_digest(&digest));
        }
    }

    /// Returns the number of full nodes in the trie.
    pub(super) fn size(&self) -> usize {
        match self {
            Node::Null | Node::Digest(_) => 0,
            Node::Leaf(..) => 1,
            Node::Extension(_, child, ..) => 1 + child.size(),
            Node::Branch(children, ..) => {
                1 + children
                    .iter()
                    .map(|slot| match slot {
                        Slot::Node(child) => child.size(),
                        Slot::Empty | Slot::Digest(_) => 0,
                    })
                    .sum::<usize>()
            }
        }
    }
}

impl<M: Memoization> Slot<M> {
    /// The child behind an occupied slot, resolving a digest stub through `r`
    /// first; `None` for an empty slot. Panics on a resolver miss and on the
    /// digest-for-digest refusal ("MPT: Unresolved node access" — INV-W3) and
    /// on malformed bytes, exactly like [`Node::resolve_stub`].
    pub(super) fn resolve_mut<R: DigestResolver>(&mut self, r: &mut R) -> Option<&mut Node<M>> {
        match self {
            Slot::Node(child) => Some(child),
            Slot::Empty => None,
            Slot::Digest(digest) => {
                let bytes = r.resolve(digest).expect("MPT: Unresolved node access");
                let child = Node::decode_child(digest, bytes)
                    .expect("MPT: invalid witness node")
                    .expect("MPT: Unresolved node access"); // digest-for-digest refusal
                // `[0x80]` (digest == EMPTY_ROOT_HASH) decodes to `Node::Null`,
                // which a slot never holds: the child is absent.
                if matches!(*child, Node::Null) {
                    *self = Slot::Empty;
                    return None;
                }
                *self = Slot::Node(child);
                let Slot::Node(child) = self else {
                    unreachable!() // stored just above
                };
                Some(child)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The word-assembled packed key equals `Nibbles::unpack` for every
    /// source alignment of a 32-byte key.
    #[test]
    fn packed_key_matches_unpack() {
        let bytes: alloc::vec::Vec<u8> = (0..48u8)
            .map(|i| i.wrapping_mul(53).wrapping_add(7))
            .collect();
        for so in 0..8 {
            let key = &bytes[so..so + 32];
            assert_eq!(packed_key(key), Nibbles::unpack(key), "so={so}");
        }
        assert_eq!(packed_key(&bytes[..5]), Nibbles::unpack(&bytes[..5]));
    }
}
