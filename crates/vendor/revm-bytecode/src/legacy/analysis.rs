use super::JumpTable;
use crate::opcode;
use bitvec::{bitvec, order::Lsb0, vec::BitVec};
use primitives::Bytes;
use std::vec::Vec;

/// Analyzes the bytecode to produce a jump table and potentially padded bytecode.
///
/// Prefer using [`Bytecode::new_legacy`](crate::Bytecode::new_legacy) instead.
pub(crate) fn analyze_legacy(bytecode: Bytes) -> (JumpTable, Bytes) {
    let mut jumps: BitVec<u8> = bitvec![u8, Lsb0; 0; bytecode.len()];
    let range = bytecode.as_ptr_range();
    let start = range.start;
    let mut iterator = start;
    let end = range.end;
    let mut last_byte: u8 = 0;

    // Sixteen instructions advance at most 528 bytes. Leave at least one
    // instruction for the scalar tail, which records the final opcode.
    if bytecode.len() > 16 * 33 {
        let batch_end = unsafe { end.sub(16 * 33) };
        while iterator < batch_end {
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
        }
    }

    // Drain shorter batches before the scalar padding tail.
    if bytecode.len() > 4 * 33 {
        let batch_end = unsafe { end.sub(4 * 33) };
        while iterator < batch_end {
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
            iterator = unsafe { scan_step(iterator, start, &mut jumps) };
        }
    }

    while iterator < end {
        last_byte = unsafe { *iterator };
        if last_byte == opcode::JUMPDEST {
            // SAFETY: Jumps are max length of the code
            unsafe { jumps.set_unchecked(iterator.offset_from_unsigned(start), true) }
            iterator = unsafe { iterator.add(1) };
        } else {
            let push_offset = (last_byte as usize).wrapping_sub(opcode::PUSH1 as usize);
            if push_offset < 32 {
                // A final PUSH may extend past the allocation. The loop guard
                // prevents dereferencing that pointer.
                iterator = iterator.wrapping_add(push_offset + 2);
            } else {
                // SAFETY: Iterator access range is checked in the while loop
                iterator = unsafe { iterator.add(1) };
            }
        }
    }

    // Calculate padding needed:
    // push_overflow: bytes needed for incomplete PUSH immediate data
    let push_overflow = (iterator as usize) - (end as usize);
    let mut padding = push_overflow;

    if last_byte == opcode::STOP {
        // DUPN/SWAPN/EXCHANGE have 1-byte immediates that aren't handled by the loop above,
        // so we need extra padding to ensure safe execution.
        padding += ends_with_immediate_before_stop(&bytecode) as usize;
    } else {
        // Add final STOP instruction and immediate for DUPN/SWAPN/EXCHANGE
        padding += 1 + is_dupn_swapn_exchange(last_byte) as usize;
    }

    let bytecode = if padding > 0 {
        let mut padded = Vec::with_capacity(bytecode.len() + padding);
        padded.extend_from_slice(&bytecode);
        padded.resize(padded.len() + padding, 0);
        Bytes::from(padded)
    } else {
        bytecode
    };

    (JumpTable::new(jumps), bytecode)
}

// SAFETY: The caller provides a readable opcode pointer. The returned
// pointer may skip a truncated PUSH but is never dereferenced unchecked.
#[inline(always)]
unsafe fn scan_step(iterator: *const u8, start: *const u8, jumps: &mut BitVec<u8>) -> *const u8 {
    let byte = unsafe { *iterator };
    let range = (byte as usize).wrapping_sub(opcode::JUMPDEST as usize);
    // Opcodes outside this interval neither mark a destination nor skip data.
    if range > usize::from(opcode::PUSH32 - opcode::JUMPDEST) {
        return iterator.wrapping_add(1);
    }
    if range >= usize::from(opcode::PUSH1 - opcode::JUMPDEST) {
        return iterator.wrapping_add(range - usize::from(opcode::PUSH1 - opcode::JUMPDEST) + 2);
    }
    if range == 0 {
        unsafe { jumps.set_unchecked(iterator.offset_from_unsigned(start), true) };
    }
    iterator.wrapping_add(1)
}

// Only a special penultimate byte can require extra padding before a final
// STOP. Check its instruction boundary on this uncommon suffix instead of
// retaining the previous opcode at every step of the main scan.
#[cold]
fn ends_with_immediate_before_stop(bytecode: &[u8]) -> bool {
    let Some(penultimate) = bytecode.len().checked_sub(2) else {
        return false;
    };
    if !is_dupn_swapn_exchange(bytecode[penultimate]) {
        return false;
    }
    let mut offset = 0;
    while offset < penultimate {
        let push = (bytecode[offset] as usize).wrapping_sub(opcode::PUSH1 as usize);
        offset += if push < 32 { push + 2 } else { 1 };
    }
    offset == penultimate
}

/// Returns true if the opcode is DUPN, SWAPN, or EXCHANGE.
const fn is_dupn_swapn_exchange(opcode: u8) -> bool {
    opcode.wrapping_sub(opcode::DUPN) < 3
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent scalar oracle retains the original previous-opcode rule.
    fn reference(raw: &[u8]) -> (Vec<bool>, Vec<u8>) {
        let mut jumps = vec![false; raw.len()];
        let (mut offset, mut previous, mut last) = (0, 0, 0);
        while offset < raw.len() {
            previous = last;
            last = raw[offset];
            jumps[offset] = last == opcode::JUMPDEST;
            offset += if (opcode::PUSH1..=opcode::PUSH32).contains(&last) {
                usize::from(last - opcode::PUSH1) + 2
            } else {
                1
            };
        }
        let extra = offset - raw.len()
            + if last == opcode::STOP {
                usize::from(is_dupn_swapn_exchange(previous))
            } else {
                1 + usize::from(is_dupn_swapn_exchange(last))
            };
        let mut padded = raw.to_vec();
        padded.resize(raw.len() + extra, 0);
        (jumps, padded)
    }

    #[test]
    fn scan_matches_reference_at_batch_boundaries() {
        let mut state = 0x6d2b79f5u32;
        for len in 0..=1120 {
            for mode in 0..20 {
                let raw: Vec<_> = (0..len)
                    .map(|i| {
                        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                        match mode {
                            0 => opcode::PUSH32,
                            1 => opcode::JUMPDEST,
                            2 => opcode::STOP,
                            3 => {
                                [opcode::PUSH1, opcode::JUMPDEST, opcode::DUPN, opcode::STOP][i % 4]
                            }
                            _ => (state >> 24) as u8,
                        }
                    })
                    .collect();
                let (expected, padding) = reference(&raw);
                let (actual, padded) = analyze_legacy(raw.into());
                assert_eq!(
                    padded.as_ref(),
                    padding.as_slice(),
                    "len {len}, mode {mode}"
                );
                for (i, valid) in expected.into_iter().enumerate() {
                    assert_eq!(
                        actual.is_valid(i),
                        valid,
                        "len {len}, mode {mode}, offset {i}"
                    );
                }
                assert!(!actual.is_valid(len));
            }
        }
    }

    #[test]
    fn push_classification_and_truncated_immediates() {
        for first in 0..=u8::MAX {
            let (jumps, _) = analyze_legacy(vec![first, opcode::JUMPDEST, opcode::STOP].into());
            assert_eq!(
                jumps.is_valid(1),
                !(opcode::PUSH1..=opcode::PUSH32).contains(&first),
                "opcode {first:#x}"
            );
            let mut raw = vec![opcode::JUMPDEST; 529];
            raw[0] = first;
            let (expected, padding) = reference(&raw);
            let (actual, padded) = analyze_legacy(raw.into());
            assert_eq!(padded.as_ref(), padding.as_slice());
            for (offset, valid) in expected.into_iter().enumerate() {
                assert_eq!(
                    actual.is_valid(offset),
                    valid,
                    "opcode {first:#x}, offset {offset}"
                );
            }
        }
        for push in opcode::PUSH1..=opcode::PUSH32 {
            let width = usize::from(push - opcode::PUSH1) + 1;
            for available in 0..=width {
                let mut raw = vec![opcode::JUMPDEST; available + 1];
                raw[0] = push;
                let (jumps, padded) = analyze_legacy(raw.clone().into());
                assert_eq!(&padded[..raw.len()], raw.as_slice());
                assert_eq!(padded.len(), width + 2);
                assert!(padded[raw.len()..].iter().all(|&b| b == opcode::STOP));
                assert!((0..padded.len()).all(|i| !jumps.is_valid(i)));
            }
        }
    }

    #[test]
    fn special_opcode_in_push_data_before_stop_needs_no_padding() {
        for push in opcode::PUSH1..=opcode::PUSH32 {
            let width = usize::from(push - opcode::PUSH1) + 1;
            for special in [opcode::DUPN, opcode::SWAPN, opcode::EXCHANGE] {
                let mut raw = vec![0; width + 2];
                raw[0] = push;
                raw[width] = special;
                let (_, padded) = analyze_legacy(raw.clone().into());
                assert_eq!(padded.as_ref(), raw.as_slice());
            }
        }
    }

    #[test]
    fn test_bytecode_ends_with_stop_no_padding_needed() {
        let bytecode = vec![
            opcode::PUSH1,
            0x01,
            opcode::PUSH1,
            0x02,
            opcode::ADD,
            opcode::STOP,
        ];
        let (_, padded_bytecode) = analyze_legacy(bytecode.clone().into());
        assert_eq!(padded_bytecode.len(), bytecode.len());
    }

    #[test]
    fn test_bytecode_ends_without_stop_requires_padding() {
        let bytecode = vec![opcode::PUSH1, 0x01, opcode::PUSH1, 0x02, opcode::ADD];
        let (_, padded_bytecode) = analyze_legacy(bytecode.clone().into());
        assert_eq!(padded_bytecode.len(), bytecode.len() + 1);
    }

    #[test]
    fn test_bytecode_ends_with_push16_requires_17_bytes_padding() {
        let bytecode = vec![opcode::PUSH1, 0x01, opcode::PUSH16];
        let (_, padded_bytecode) = analyze_legacy(bytecode.clone().into());
        assert_eq!(padded_bytecode.len(), bytecode.len() + 17);
    }

    #[test]
    fn test_bytecode_ends_with_push2_requires_2_bytes_padding() {
        let bytecode = vec![opcode::PUSH1, 0x01, opcode::PUSH2, 0x02];
        let (_, padded_bytecode) = analyze_legacy(bytecode.clone().into());
        assert_eq!(padded_bytecode.len(), bytecode.len() + 2);
    }

    #[test]
    fn test_bytecode_with_jumpdest_at_start() {
        let bytecode = vec![opcode::JUMPDEST, opcode::PUSH1, 0x01, opcode::STOP];
        let (jump_table, _) = analyze_legacy(bytecode.into());
        assert!(jump_table.is_valid(0)); // First byte should be a valid jumpdest
    }

    #[test]
    fn test_bytecode_with_jumpdest_after_push() {
        let bytecode = vec![opcode::PUSH1, 0x01, opcode::JUMPDEST, opcode::STOP];
        let (jump_table, _) = analyze_legacy(bytecode.into());
        assert!(jump_table.is_valid(2)); // JUMPDEST should be at position 2
    }

    #[test]
    fn test_bytecode_with_multiple_jumpdests() {
        let bytecode = vec![
            opcode::JUMPDEST,
            opcode::PUSH1,
            0x01,
            opcode::JUMPDEST,
            opcode::STOP,
        ];
        let (jump_table, _) = analyze_legacy(bytecode.into());
        assert!(jump_table.is_valid(0)); // First JUMPDEST
        assert!(jump_table.is_valid(3)); // Second JUMPDEST
    }

    #[test]
    fn test_bytecode_with_max_push32() {
        let bytecode = vec![opcode::PUSH32];
        let (_, padded_bytecode) = analyze_legacy(bytecode.clone().into());
        assert_eq!(padded_bytecode.len(), bytecode.len() + 33); // PUSH32 + 32 bytes + STOP
    }

    #[test]
    fn test_bytecode_with_invalid_opcode() {
        let bytecode = vec![0xFF, opcode::STOP]; // 0xFF is an invalid opcode
        let (jump_table, _) = analyze_legacy(bytecode.into());
        assert!(!jump_table.is_valid(0)); // Invalid opcode should not be a jumpdest
    }

    #[test]
    fn test_bytecode_with_sequential_pushes() {
        let bytecode = vec![
            opcode::PUSH1,
            0x01,
            opcode::PUSH2,
            0x02,
            0x03,
            opcode::PUSH4,
            0x04,
            0x05,
            0x06,
            0x07,
            opcode::STOP,
        ];
        let (jump_table, padded_bytecode) = analyze_legacy(bytecode.clone().into());
        assert_eq!(padded_bytecode.len(), bytecode.len());
        assert!(!jump_table.is_valid(0)); // PUSH1
        assert!(!jump_table.is_valid(2)); // PUSH2
        assert!(!jump_table.is_valid(5)); // PUSH4
    }

    #[test]
    fn test_bytecode_with_jumpdest_in_push_data() {
        let bytecode = vec![
            opcode::PUSH2,
            opcode::JUMPDEST, // This should not be treated as a JUMPDEST
            0x02,
            opcode::STOP,
        ];
        let (jump_table, _) = analyze_legacy(bytecode.into());
        assert!(!jump_table.is_valid(1)); // JUMPDEST in push data should not be valid
    }

    #[test]
    fn test_bytecode_ends_with_immediate_opcode_and_stop_requires_padding() {
        // For SWAPN/DUPN/EXCHANGE, the STOP (0x00) is consumed as the immediate operand,
        // not as an actual STOP instruction, so padding is needed.
        // [OPCODE]       -> [OPCODE, STOP, STOP] (3 bytes)
        // [OPCODE, STOP] -> [OPCODE, STOP, STOP] (3 bytes)
        for op in [opcode::SWAPN, opcode::DUPN, opcode::EXCHANGE] {
            for bytecode in [vec![op], vec![op, opcode::STOP]] {
                let (_, padded_bytecode) = analyze_legacy(bytecode.into());
                assert_eq!(padded_bytecode.len(), 3);
                assert_eq!(padded_bytecode[0], op);
                assert_eq!(padded_bytecode[1], opcode::STOP);
                assert_eq!(padded_bytecode[2], opcode::STOP);
            }
        }
    }
}
