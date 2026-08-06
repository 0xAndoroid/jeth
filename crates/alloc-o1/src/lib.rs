//! O(1) segregated-recycling bump allocator for Jolt zkVM guests.
//!
//! Design: every allocation is rounded up to a power-of-two size class
//! (min 8 B). Alloc pops the class free list (freed blocks store the next
//! pointer in their first word) or bumps the arena cursor; dealloc pushes onto
//! the class free list. No splitting, no coalescing, no searching — every
//! operation is a handful of instructions, which is what matters when each
//! RISC-V instruction is a provable cycle.
//!
//! Blocks are aligned to their class size, so any `Layout` with
//! `align <= size_class` is satisfied (align > size rounds the class up).
//! Single-hart guest → plain statics, no locking.

#![no_std]

mod allocator;

use foundation::ops::MemoryOps;

pub const LINKED_LIST_ALLOCATOR_OPS: MemoryOps = MemoryOps {
    init: allocator::init,
    alloc: allocator::alloc,
    dealloc: allocator::dealloc,
    realloc: allocator::realloc,
};
