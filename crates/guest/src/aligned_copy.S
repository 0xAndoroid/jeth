// Nonoverlapping, eight-aligned copies of 0..=256 bytes, in multiples of eight.
// a0 is both the destination argument and the return value. Only caller-saved
// registers are changed; no stack frame is needed. Other copies tail-call the
// existing Rust fallback with the original arguments.
//
// The computed entry point skips the high offsets that are outside the copy.
// Each ld/sd pair is eight instruction bytes and copies eight data bytes, so
// return_label - n selects exactly offsets n-8, n-16, ..., 0. Disabling compressed
// instructions and relaxation below is part of this invariant.
.pushsection .text.__jeth_aligned_copy,"ax",@progbits
.globl __jeth_aligned_copy
.hidden __jeth_aligned_copy
.type __jeth_aligned_copy,@function
__jeth_aligned_copy:
.option push
.option norelax
    li t0, 256
    bltu t0, a2, .Lfallback
    or t0, a0, a1
    or t0, t0, a2
    andi t0, t0, 7
    bnez t0, .Lfallback
    lla t0, .Lcopy_return
    sub t0, t0, a2
    jr t0
// Each eight-byte copy occupies exactly eight instruction bytes.
.option push
.option norvc
.set .Lcopy_offset, 248
.rept 32
    ld t1, .Lcopy_offset(a1)
    sd t1, .Lcopy_offset(a0)
.set .Lcopy_offset, .Lcopy_offset - 8
.endr
.option pop
.Lcopy_return:
    ret
.Lfallback:
    tail __jeth_copy_fallback
.option pop
.size __jeth_aligned_copy, .-__jeth_aligned_copy
.popsection
