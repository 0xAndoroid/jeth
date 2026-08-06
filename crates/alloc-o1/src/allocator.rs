use core::alloc::Layout;
use core::ptr;

/// Size classes: 8, 16, 32, … , 2^(MIN_SHIFT + NUM_CLASSES - 1) bytes.
/// 2^33 = 8 GiB top class comfortably covers any single allocation a guest
/// with a ≤2 GiB heap can make.
const MIN_SHIFT: u32 = 3;
const NUM_CLASSES: usize = 31;

struct Arena {
    cursor: usize,
    end: usize,
    /// Head of the free list per class; freed blocks store `next` in word 0.
    free: [usize; NUM_CLASSES],
}

// Single-hart guest: no concurrent access is possible.
static mut ARENA: Arena = Arena {
    cursor: 0,
    end: 0,
    free: [0; NUM_CLASSES],
};

#[inline]
fn class_of(layout: Layout) -> u32 {
    let needed = layout.size().max(layout.align()).max(8);
    let shift = usize::BITS - (needed - 1).leading_zeros(); // ceil(log2)
    shift - MIN_SHIFT
}

pub(crate) fn init(heap_start: usize, heap_size: usize) {
    unsafe {
        let a = &mut *ptr::addr_of_mut!(ARENA);
        a.cursor = heap_start;
        a.end = heap_start + heap_size;
        a.free = [0; NUM_CLASSES];
    }
}

pub(crate) fn alloc(layout: Layout) -> *mut u8 {
    let class = class_of(layout) as usize;
    if class >= NUM_CLASSES {
        return ptr::null_mut();
    }
    let size = 1usize << (class as u32 + MIN_SHIFT);
    unsafe {
        let a = &mut *ptr::addr_of_mut!(ARENA);

        // Fast path: recycle from the class free list. In-place-grown blocks
        // (see realloc) are only guaranteed to be aligned to their ORIGINAL
        // class, so re-check the requested alignment before handing one out;
        // on a mismatch fall through to the bump path (head stays put).
        let head = a.free[class];
        if head != 0 && head & (layout.align() - 1) == 0 {
            a.free[class] = *(head as *const usize);
            return head as *mut u8;
        }

        // Bump path: blocks are class-size aligned.
        let start = (a.cursor + size - 1) & !(size - 1);
        let Some(new_cursor) = start.checked_add(size) else {
            return ptr::null_mut();
        };
        if new_cursor > a.end {
            return ptr::null_mut();
        }
        a.cursor = new_cursor;
        start as *mut u8
    }
}

pub(crate) fn dealloc(ptr_in: *mut u8, layout: Layout) {
    if ptr_in.is_null() {
        return;
    }
    let class = class_of(layout) as usize;
    if class >= NUM_CLASSES {
        return;
    }
    unsafe {
        let a = &mut *ptr::addr_of_mut!(ARENA);
        *(ptr_in as *mut usize) = a.free[class];
        a.free[class] = ptr_in as usize;
    }
}

pub(crate) fn realloc(ptr_in: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
    if ptr_in.is_null() {
        return match Layout::from_size_align(new_size, old_layout.align()) {
            Ok(l) => alloc(l),
            Err(_) => ptr::null_mut(),
        };
    }
    if new_size == 0 {
        dealloc(ptr_in, old_layout);
        return ptr::null_mut();
    }
    let Ok(new_layout) = Layout::from_size_align(new_size, old_layout.align()) else {
        return ptr::null_mut();
    };

    let old_class = class_of(old_layout);
    let new_class = class_of(new_layout);
    if new_class as usize >= NUM_CLASSES {
        return ptr::null_mut();
    }

    // Same size class (or shrink) → the existing block already fits. Shrinks
    // keep the larger footprint (the tail is orphaned when later freed into
    // the smaller class) — a deliberate space-for-copies trade.
    if new_class <= old_class {
        return ptr_in;
    }

    unsafe {
        let a = &mut *ptr::addr_of_mut!(ARENA);
        // In-place growth: if this block is the most recent bump allocation,
        // extend the cursor instead of copying (Vec doubling hits this a lot).
        let old_size = 1usize << (old_class + MIN_SHIFT);
        let new_size_class = 1usize << (new_class + MIN_SHIFT);
        let addr = ptr_in as usize;
        if addr + old_size == a.cursor
            && addr & (new_layout.align() - 1) == 0
            && addr + new_size_class <= a.end
        {
            a.cursor = addr + new_size_class;
            return ptr_in;
        }
    }

    let new_ptr = alloc(new_layout);
    if !new_ptr.is_null() {
        let copy = old_layout.size().min(new_size);
        unsafe {
            ptr::copy_nonoverlapping(ptr_in, new_ptr, copy);
        }
        dealloc(ptr_in, old_layout);
    }
    new_ptr
}
