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
    arena::Scratch,
    memoize::Memoization,
    node::{Child, Digest, Node},
};
use alloc::boxed::Box;
use core::{
    mem,
    slice::{Iter, IterMut},
};

/// One child slot of a branch node.
///
/// Unresolved children — most slots of a witness branch — are held inline as
/// their digest; only decoded and embedded nodes are boxed, so decoding a
/// branch allocates nothing per digest child. The 8-byte tag makes every slot
/// write a whole-word store. A `Node` slot never holds [`Node::Null`] (the
/// mutating walks clear it) or [`Node::Digest`] ([`Slot::from_child`]
/// canonicalizes it to `Slot::Digest`), so each logical child has exactly
/// one representation and slot equality is structural.
#[derive(Debug, Clone)]
#[repr(u64)]
pub(super) enum Slot<M> {
    Empty,
    Digest(Digest),
    Node(Child<M>),
}

impl<M> Default for Slot<M> {
    #[inline(always)]
    fn default() -> Self {
        Slot::Empty
    }
}

impl<M> PartialEq for Slot<M> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Slot::Empty, Slot::Empty) => true,
            (Slot::Digest(d1), Slot::Digest(d2)) => d1 == d2,
            (Slot::Node(c1), Slot::Node(c2)) => c1 == c2,
            _ => false,
        }
    }
}

impl<M> Eq for Slot<M> {}

impl<M> Slot<M> {
    /// The slot holding `child`, which must not be `Node::Null`.
    #[inline]
    pub(super) fn from_child(child: Child<M>) -> Self {
        assert!(!matches!(*child, Node::Null));
        if let Node::Digest(digest) = *child {
            return Slot::Digest(digest);
        }
        Slot::Node(child)
    }

    #[inline(always)]
    pub(super) const fn is_empty(&self) -> bool {
        matches!(self, Slot::Empty)
    }

    /// Fill this `Empty` slot with a digest stub. `Empty` owns nothing, so the
    /// old value is forgotten instead of dropped: an assignment would re-read
    /// the tag and emit the `Node` drop glue on every decoded child.
    #[inline(always)]
    pub(super) fn fill_digest(&mut self, digest: Digest) {
        debug_assert!(self.is_empty());
        mem::forget(mem::replace(self, Slot::Digest(digest)));
    }

    /// Empty the slot when its node has become `Node::Null` (after a removal).
    #[inline]
    pub(super) fn clear_null(&mut self) {
        if matches!(self, Slot::Node(child) if matches!(**child, Node::Null)) {
            *self = Slot::Empty;
        }
    }
}

/// Implements a helper wrapper for the children of a Branch node.
///
/// This wrapper offers various convenience features and assures that there is never a Null child.
#[derive(Debug, Clone)]
pub(super) struct Children<M>([Slot<M>; 16]);

impl<M> Default for Children<M> {
    /// Sixteen explicit `Slot::Empty` writes — one tag store each. An array
    /// repeat of the constant copies whole 40-byte slots instead, and LLVM
    /// folds their undefined payload bytes into a 640-byte `memset`.
    #[inline(always)]
    fn default() -> Self {
        Self([
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
            Slot::Empty,
        ])
    }
}

impl<M> PartialEq for Children<M> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<M> Eq for Children<M> where Node<M>: Eq {}

#[allow(dead_code)]
impl<M> Children<M> {
    #[inline(always)]
    pub(super) fn get(&self, idx: u8) -> &Slot<M> {
        &self.0[idx as usize]
    }

    #[inline(always)]
    pub(super) fn slot_mut(&mut self, idx: u8) -> &mut Slot<M> {
        &mut self.0[idx as usize]
    }

    #[inline]
    pub(super) fn insert(&mut self, idx: u8, child: Child<M>) {
        self.0[idx as usize] = Slot::from_child(child);
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.0.iter().filter(|slot| !slot.is_empty()).count()
    }

    /// Take the only child if exactly one slot is occupied. A digest stub comes
    /// out boxed as a [`Node::Digest`] for the caller to resolve or refuse.
    pub(super) fn take_single_child(&mut self) -> Option<(u8, Child<M>)> {
        let mut single = None;
        for (i, slot) in self.0.iter().enumerate() {
            if !slot.is_empty() {
                if single.is_some() {
                    return None; // more than one child found
                }
                single = Some(i);
            }
        }
        let i = single?;
        let child = match mem::take(&mut self.0[i]) {
            Slot::Node(child) => child,
            Slot::Digest(digest) => Box::new(Node::Digest(digest)),
            Slot::Empty => unreachable!(), // `single` is only set for an occupied slot
        };
        Some((i as u8, child))
    }

    #[inline]
    pub(super) fn iter(&self) -> Iter<'_, Slot<M>> {
        self.0.iter()
    }

    #[inline]
    pub(super) fn iter_mut(&mut self) -> IterMut<'_, Slot<M>> {
        self.0.iter_mut()
    }

    #[inline]
    pub(super) fn into_iter(self) -> impl Iterator<Item = Slot<M>> {
        self.0.into_iter()
    }
}

impl<M: Memoization> Children<M> {
    /// Encode every dirty child through the reused arena scratch buffer.
    /// Empty and digest slots cost a tag test; clean children a cache test;
    /// neither a call.
    pub(super) fn memoize_arena(&mut self, scratch: &mut Scratch) {
        for slot in &mut self.0 {
            if let Slot::Node(child) = slot {
                if child.needs_memo() {
                    child.encode_dirty(scratch);
                }
            }
        }
    }
}

impl<M, C: Into<Child<M>>, const N: usize> From<[(u8, C); N]> for Children<M> {
    fn from(arr: [(u8, C); N]) -> Self {
        let mut children = Children::default();
        for (idx, child) in arr {
            children.insert(idx, child.into());
        }
        children
    }
}
