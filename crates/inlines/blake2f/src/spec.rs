use jolt_inlines_sdk::{
    assert_edge_cases_match_reference, assert_random_cases_match_reference,
    assert_reference_matches_harness, host::InlineOp, InlineReference, InlineSpec,
};
use rand::RngCore;
use tracer::emulator::mmu::DRAM_BASE;
use tracer::utils::inline_test_harness::{InlineMemoryLayout, InlineTestHarness, RegisterMapping};
use tracer::utils::virtual_registers::VirtualRegisterAllocator;

use crate::sequence_builder::Blake2bRounds;
use crate::{rounds_reference, IV, STATE_LEN};

/// Every round count with an op, in registration order.
const ROUND_COUNTS: [usize; 10] = [10, 1, 2, 3, 4, 5, 6, 7, 8, 9];

/// `(v, m)`: working state at rs1, message block at rs2.
pub type RoundsInput = ([u64; STATE_LEN], [u64; STATE_LEN]);

const STATE_BYTES: usize = STATE_LEN * 8;

impl<const R: usize> InlineReference for Blake2bRounds<R> {
    type Input = RoundsInput;
    type Output = [u64; STATE_LEN];

    fn reference((v, m): &Self::Input) -> Self::Output {
        let mut v = *v;
        rounds_reference(&mut v, m, R);
        v
    }
}

impl<const R: usize> InlineSpec for Blake2bRounds<R> {
    fn edge_cases() -> impl IntoIterator<Item = Self::Input> {
        let mut abc = [0u64; STATE_LEN];
        abc[0] = 0x0000_0000_0063_6261;
        let mut sign_bits = [0u64; STATE_LEN];
        for (i, w) in sign_bits.iter_mut().enumerate() {
            *w = if i % 2 == 0 { 1 << 63 } else { 1 };
        }
        [
            ([0; STATE_LEN], [0; STATE_LEN]),
            ([u64::MAX; STATE_LEN], [u64::MAX; STATE_LEN]),
            ([u64::MAX; STATE_LEN], [0; STATE_LEN]),
            ([0; STATE_LEN], [u64::MAX; STATE_LEN]),
            (initial_working_state(3, true), abc),
            (
                initial_working_state(u64::MAX, false),
                [u64::MAX; STATE_LEN],
            ),
            (sign_bits, sign_bits),
        ]
    }

    fn random(rng: &mut impl RngCore) -> Self::Input {
        (
            core::array::from_fn(|_| rng.next_u64()),
            core::array::from_fn(|_| rng.next_u64()),
        )
    }

    fn harness() -> InlineTestHarness {
        InlineTestHarness::new(InlineMemoryLayout::single_input(STATE_BYTES, STATE_BYTES))
    }

    fn load(harness: &mut InlineTestHarness, (v, m): &Self::Input) {
        harness.load_state64(v);
        harness.load_input64(m);
    }

    fn read(harness: &mut InlineTestHarness) -> Self::Output {
        harness.read_output64(STATE_LEN).try_into().unwrap()
    }
}

/// `v = h ‖ IV` for the BLAKE2b-512 parameter block, counter `t0`, final flag `f`.
fn initial_working_state(t0: u64, f: bool) -> [u64; STATE_LEN] {
    let mut v = [0u64; STATE_LEN];
    v[..8].copy_from_slice(&IV);
    v[0] ^= 0x0101_0000 ^ 64;
    v[8..].copy_from_slice(&IV);
    v[12] ^= t0;
    if f {
        v[14] = !v[14];
    }
    v
}

fn sequence_rows<const R: usize>(rs1: u8, rs2: u8, rs3: u8) -> usize {
    let op = InlineTestHarness::create_instruction(
        <Blake2bRounds<R>>::OPCODE,
        <Blake2bRounds<R>>::FUNCT3,
        <Blake2bRounds<R>>::FUNCT7,
        rs1,
        rs2,
        rs3,
    );
    op.inline_sequence(&VirtualRegisterAllocator::default())
        .len()
}

fn check_op<const R: usize>() {
    assert_edge_cases_match_reference::<Blake2bRounds<R>>();
    assert_random_cases_match_reference::<Blake2bRounds<R>>(0xb1a2_e2f0 + R as u64, 10_000);
    // rs1 == rs2: every load precedes every store, so the op computes R rounds of `v` with `m = v`.
    let mut aliased = InlineTestHarness::new(InlineMemoryLayout {
        input_base: DRAM_BASE,
        input_size: STATE_BYTES,
        input2_base: None,
        input2_size: None,
        output_base: DRAM_BASE,
        output_size: STATE_BYTES,
        rs1_mapping: RegisterMapping::Output,
        rs2_mapping: RegisterMapping::Output,
        rs3_mapping: None,
    });
    let v: [u64; STATE_LEN] =
        core::array::from_fn(|i| 0x9e37_79b9_7f4a_7c15u64.wrapping_mul(i as u64 + 1));
    aliased.setup_registers();
    aliased.load_state64(&v);
    aliased.execute_inline(<Blake2bRounds<R>>::instruction());
    let got: [u64; STATE_LEN] = aliased.read_output64(STATE_LEN).try_into().unwrap();
    assert_eq!(
        got,
        <Blake2bRounds<R>>::reference(&(v, v)),
        "aliased rs1/rs2, R = {R}"
    );
    // Golden rows: 32 LD + 80 per round + 16 SD + 32 resets, independent of the operand registers.
    for (rs1, rs2, rs3) in [(10, 11, 12), (1, 2, 0), (5, 5, 5)] {
        assert_eq!(
            sequence_rows::<R>(rs1, rs2, rs3),
            80 * R + 80,
            "rows, R = {R}"
        );
    }
}

macro_rules! for_each_op {
    ($f:ident) => {
        $f::<10>();
        $f::<1>();
        $f::<2>();
        $f::<3>();
        $f::<4>();
        $f::<5>();
        $f::<6>();
        $f::<7>();
        $f::<8>();
        $f::<9>();
    };
}

#[test]
fn every_op_matches_reference_and_golden_rows() {
    for_each_op!(check_op);
}

#[test]
fn eip152_vector_state_through_ten_plus_two_rounds() {
    // Vector 5/6 shape (12 rounds, "abc", t = 3): 10-round op then 2-round op equals 12 reference rounds.
    let mut m = [0u64; STATE_LEN];
    m[0] = 0x0000_0000_0063_6261;
    for f in [true, false] {
        let v0 = initial_working_state(3, f);
        let mut want = v0;
        rounds_reference(&mut want, &m, 12);
        let after_ten = <Blake2bRounds<10>>::reference(&(v0, m));
        assert_reference_matches_harness::<Blake2bRounds<10>>(&(v0, m));
        assert_reference_matches_harness::<Blake2bRounds<2>>(&(after_ten, m));
        assert_eq!(<Blake2bRounds<2>>::reference(&(after_ten, m)), want);
    }
}

#[test]
fn encoding_is_injective_and_in_range() {
    fn key<const R: usize>() -> (u32, u32, u32, &'static str) {
        (
            <Blake2bRounds<R>>::OPCODE,
            <Blake2bRounds<R>>::FUNCT7,
            <Blake2bRounds<R>>::FUNCT3,
            <Blake2bRounds<R>>::NAME,
        )
    }
    let keys = [
        key::<10>(),
        key::<1>(),
        key::<2>(),
        key::<3>(),
        key::<4>(),
        key::<5>(),
        key::<6>(),
        key::<7>(),
        key::<8>(),
        key::<9>(),
    ];
    for (i, (opcode, funct7, funct3, name)) in keys.iter().enumerate() {
        assert_eq!(*opcode, 0x2B);
        assert!(*funct7 == crate::FUNCT7_LOW || *funct7 == crate::FUNCT7_HIGH);
        assert!(*funct3 <= 7);
        assert_eq!(crate::funct3(ROUND_COUNTS[i]), *funct3);
        assert_eq!(crate::funct7(ROUND_COUNTS[i]), *funct7);
        for other in &keys[i + 1..] {
            assert_ne!(
                (funct7, funct3),
                (&other.1, &other.2),
                "{name} / {}",
                other.3
            );
            assert_ne!(name, &other.3);
        }
    }
    assert_eq!(crate::funct7(10), crate::FUNCT7_LOW);
    assert_eq!(crate::funct3(10), 0);
    assert_eq!(
        (crate::funct7(8), crate::funct3(8)),
        (crate::FUNCT7_HIGH, 0)
    );
    assert_eq!(
        (crate::funct7(9), crate::funct3(9)),
        (crate::FUNCT7_HIGH, 1)
    );
}

#[test]
fn sigma_rows_are_permutations_and_iv_is_blake2b() {
    for (i, row) in crate::SIGMA.iter().enumerate() {
        let mut seen = [false; 16];
        for &x in row {
            assert!(!seen[x], "row {i} repeats {x}");
            seen[x] = true;
        }
        assert!(seen.iter().all(|&s| s), "row {i} is not a permutation");
    }
    assert_eq!(crate::SIGMA[0], core::array::from_fn(|i| i));
    assert_eq!(IV[0], 0x6a09_e667_f3bc_c908);
    assert_eq!(IV[7], 0x5be0_cd19_137e_2179);
}
