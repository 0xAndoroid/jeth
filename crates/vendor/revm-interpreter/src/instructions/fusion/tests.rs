use super::*;
use crate::{
    host::DummyHost,
    instructions::{instruction_table, Instruction},
    interpreter::{EthInterpreter, ExtBytecode, InputsImpl},
    interpreter_types::{Jumps, LoopControl},
    Gas, InstructionResult, Interpreter, SharedMemory,
};
use bytecode::{opcode::*, Bytecode};
use primitives::{hardfork::SpecId, Bytes, U256};

fn compare(
    code: &[u8],
    depth: usize,
    condition: U256,
    gas: u64,
    table: &InstructionTable<EthInterpreter, DummyHost>,
) {
    compare_at_spec(code, depth, condition, gas, table, SpecId::AMSTERDAM);
}

fn compare_at_spec(
    code: &[u8],
    depth: usize,
    condition: U256,
    gas: u64,
    table: &InstructionTable<EthInterpreter, DummyHost>,
    spec: SpecId,
) {
    let build = || {
        let mut i = Interpreter::<EthInterpreter>::new(
            SharedMemory::new(),
            ExtBytecode::new(Bytecode::new_raw(Bytes::copy_from_slice(code))),
            InputsImpl::default(),
            false,
            spec,
            gas,
        );
        for _ in 0..depth {
            assert!(i.stack.push(condition));
        }
        i.gas = Gas::new_with_regular_gas_and_reservoir(gas, 777);
        i.gas.set_refund(-7);
        i.gas.set_state_gas_spent(123);
        i
    };
    let mut candidate = build();
    let mut reference = build();
    let actual = candidate.run_plain(table, &mut DummyHost::default());
    let mut steps = 0;
    while reference.bytecode.is_not_end() {
        reference.step(table, &mut DummyHost::default());
        steps += 1;
        assert!(steps < 100, "test unexpectedly looped");
    }
    assert_eq!(
        actual,
        reference.take_next_action(),
        "code={code:x?} depth={depth} gas={gas}"
    );
    assert_eq!(candidate.gas, reference.gas);
    assert_eq!(candidate.stack, reference.stack);
}

#[test]
fn fused_gas_and_stack_behavior_across_forks() {
    let table = instruction_table::<EthInterpreter, DummyHost>();
    for spec in [
        SpecId::FRONTIER,
        SpecId::LONDON,
        SpecId::OSAKA,
        SpecId::AMSTERDAM,
    ] {
        for op in [JUMP, JUMPI] {
            for condition in [U256::ZERO, U256::from(1), U256::MAX] {
                for gas in 0..20 {
                    compare_at_spec(
                        &[PUSH2, 0, 4, op, JUMPDEST, STOP],
                        2,
                        condition,
                        gas,
                        &table,
                        spec,
                    );
                }
            }
        }
    }
}

#[test]
fn push_jump_boundaries_match_single_step() {
    let table = instruction_table::<EthInterpreter, DummyHost>();
    assert!(
        matches(&table),
        "default table must exercise fusion in this test build"
    );
    for op in [JUMP, JUMPI] {
        for target in [0_u16, 1, 4, 65535] {
            let [hi, lo] = target.to_be_bytes();
            let code = [PUSH2, hi, lo, op, JUMPDEST, STOP];
            for depth in [0, 1, 2, 1023, 1024] {
                for condition in [U256::ZERO, U256::from(1), U256::MAX] {
                    for gas in 0..20 {
                        compare(&code, depth, condition, gas, &table);
                    }
                }
            }
        }
    }
    for code in [&[PUSH2][..], &[PUSH2, 0x5b][..], &[PUSH2, 0, 1, STOP][..]] {
        compare(code, 0, U256::ZERO, 100, &table);
    }
}

fn custom_halt(_: Ip, context: InstructionContext<'_, DummyHost, EthInterpreter>) -> Ip {
    context.interpreter.halt(InstructionResult::InvalidFEOpcode)
}

#[test]
fn custom_jumps_are_not_fused() {
    for op in [JUMP, JUMPI, JUMPDEST] {
        let mut table = instruction_table::<EthInterpreter, DummyHost>();
        table[op as usize] = Instruction::new(custom_halt);
        assert!(!matches(&table));
        compare(
            &[PUSH2, 0, 4, op, JUMPDEST, STOP],
            1,
            U256::from(1),
            100,
            &table,
        );
        compare(
            &[PUSH2, 0, 4, JUMP, JUMPDEST, STOP],
            1,
            U256::from(1),
            100,
            &table,
        );
    }
}

#[test]
fn jumpdest_at_end_and_chained_pairs_match_single_step() {
    let table = instruction_table::<EthInterpreter, DummyHost>();
    for code in [
        &[PUSH2, 0, 4, JUMP, JUMPDEST][..],
        &[PUSH2, 0, 4, JUMPI, JUMPDEST][..],
        &[
            PUSH2, 0, 4, JUMP, JUMPDEST, PUSH2, 0, 9, JUMP, JUMPDEST, STOP,
        ][..],
        &[
            PUSH2, 0, 4, JUMPI, JUMPDEST, PUSH2, 0, 9, JUMPI, JUMPDEST, STOP,
        ][..],
    ] {
        for gas in 0..32 {
            for condition in [U256::ZERO, U256::from(1), U256::MAX] {
                compare(code, 2, condition, gas, &table);
            }
        }
    }
}

#[test]
fn inspector_step_executes_only_push() {
    let table = instruction_table::<EthInterpreter, DummyHost>();
    let mut i = Interpreter::<EthInterpreter>::new(
        SharedMemory::new(),
        ExtBytecode::new(Bytecode::new_raw(Bytes::from_static(&[
            PUSH2, 0, 4, JUMP, JUMPDEST, STOP,
        ]))),
        InputsImpl::default(),
        false,
        SpecId::AMSTERDAM,
        100,
    );
    i.fuse_push_jumps = 1; // A step must also clear stale state after an unwind.
    let begin = i.bytecode.ip();
    i.step(&table, &mut DummyHost::default());
    assert_eq!(i.bytecode.ip(), unsafe { begin.add(3) });
    assert_eq!(i.stack.data(), &[U256::from(4)]);
    assert_eq!(i.gas.remaining(), 97);
}
