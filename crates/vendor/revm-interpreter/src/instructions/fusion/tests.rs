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
    compare_values(code, &vec![condition; depth], gas, table, SpecId::AMSTERDAM);
}

fn compare_values(
    code: &[u8],
    values: &[U256],
    gas: u64,
    table: &InstructionTable<EthInterpreter, DummyHost>,
    spec: SpecId,
) {
    let depth = values.len();
    let build = || {
        let mut i = Interpreter::<EthInterpreter>::new(
            SharedMemory::new(),
            ExtBytecode::new(Bytecode::new_raw(Bytes::copy_from_slice(code))),
            InputsImpl::default(),
            false,
            spec,
            gas,
        );
        for &value in values {
            assert!(i.stack.push(value));
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
    for op in [PUSH2, JUMP, JUMPI, JUMPDEST] {
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
fn test_jump_boundaries_match_single_step() {
    let table = instruction_table::<EthInterpreter, DummyHost>();
    for test in [ISZERO, EQ] {
        for target in [0_u16, 1, 2, 5, 65535] {
            let [hi, lo] = target.to_be_bytes();
            let code = [test, PUSH2, hi, lo, JUMPI, JUMPDEST, STOP];
            for depth in [0, 1, 2, 1023, 1024] {
                for top in [U256::ZERO, U256::from(1), U256::MAX] {
                    for other in [U256::ZERO, U256::from(1), U256::from(1) << 200] {
                        let mut values = vec![top; depth];
                        if depth >= 2 {
                            values[depth - 2] = other;
                        }
                        for gas in 0..24 {
                            compare_values(&code, &values, gas, &table, SpecId::AMSTERDAM);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn test_jump_padding_and_custom_handlers() {
    for test in [ISZERO, EQ] {
        for bytes in [
            vec![test],
            vec![test, PUSH2],
            vec![test, PUSH2, 0],
            vec![test, PUSH2, 0, 5],
            vec![test, PUSH2, 0, 5, JUMPI, JUMPDEST],
        ] {
            for gas in 0..24 {
                compare(
                    &bytes,
                    2,
                    U256::ZERO,
                    gas,
                    &instruction_table::<EthInterpreter, DummyHost>(),
                );
            }
        }
        for custom in [PUSH2, JUMPI, JUMPDEST] {
            let mut table = instruction_table::<EthInterpreter, DummyHost>();
            table[custom as usize] = Instruction::new(custom_halt);
            assert!(!matches(&table));
            compare(
                &[test, PUSH2, 0, 5, JUMPI, JUMPDEST, STOP],
                2,
                U256::ZERO,
                100,
                &table,
            );
        }
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
    i.step(&table, &mut DummyHost::default());
    assert_eq!(i.bytecode.pc(), 3);
    assert_eq!(i.stack.data(), &[U256::from(4)]);
    assert_eq!(i.gas.remaining(), 97);
}

fn run<EXT: Default>(
    table: &InstructionTable<EthInterpreter<EXT>, DummyHost>,
    code: &[u8],
    values: &[U256],
) -> (InstructionResult, Interpreter<EthInterpreter<EXT>>) {
    let mut i = Interpreter::<EthInterpreter<EXT>>::new(
        SharedMemory::new(),
        ExtBytecode::new(Bytecode::new_raw(Bytes::copy_from_slice(code))),
        InputsImpl::default(),
        false,
        SpecId::AMSTERDAM,
        100,
    );
    for &value in values {
        assert!(i.stack.push(value));
    }
    let action = i.run_plain(table, &mut DummyHost::default());
    (action.instruction_result().unwrap(), i)
}

type Observed = EthInterpreter<(usize, u64, usize)>;

fn observe<const OP: u8>(ip: Ip, context: InstructionContext<'_, DummyHost, Observed>) -> Ip {
    let InstructionContext { interpreter, host } = context;
    let default = instruction_table::<Observed, DummyHost>()[OP as usize];
    let next = default.execute(
        ip,
        InstructionContext {
            interpreter: &mut *interpreter,
            host,
        },
    );
    interpreter.extend = (
        interpreter.stack.len(),
        interpreter.gas.remaining(),
        interpreter.bytecode.pc_of(next),
    );
    next
}

#[test]
fn handler_wrapping_iszero_or_eq_sees_one_opcode() {
    let cases: [(u8, Instruction<Observed, DummyHost>, &[U256]); 2] = [
        (ISZERO, Instruction::new(observe::<ISZERO>), &[U256::ZERO]),
        (
            EQ,
            Instruction::new(observe::<EQ>),
            &[U256::ZERO, U256::ZERO],
        ),
    ];
    for (op, wrapper, values) in cases {
        let mut table = instruction_table::<Observed, DummyHost>();
        table[op as usize] = wrapper;
        let (result, i) = run(&table, &[op, PUSH2, 0, 5, JUMPI, JUMPDEST, STOP], values);
        assert_eq!(result, InstructionResult::Stop);
        assert_eq!(i.extend, (1, 97, 1), "op={op:#x}");
    }
}

#[test]
fn target_inside_push_data_is_an_invalid_jump() {
    let table = instruction_table::<EthInterpreter, DummyHost>();
    let one = U256::from(1);
    let cases: [(&[u8], &[U256]); 4] = [
        (&[PUSH2, 0, 6, JUMP, STOP, PUSH1, JUMPDEST, STOP], &[]),
        (&[PUSH2, 0, 6, JUMPI, STOP, PUSH1, JUMPDEST, STOP], &[one]),
        (
            &[ISZERO, PUSH2, 0, 7, JUMPI, STOP, PUSH1, JUMPDEST, STOP],
            &[U256::ZERO],
        ),
        (
            &[EQ, PUSH2, 0, 7, JUMPI, STOP, PUSH1, JUMPDEST, STOP],
            &[one, one],
        ),
    ];
    for (code, values) in cases {
        assert_eq!(
            run(&table, code, values).0,
            InstructionResult::InvalidJump,
            "code={code:x?}"
        );
    }
}

#[test]
fn immediate_is_big_endian() {
    let table = instruction_table::<EthInterpreter, DummyHost>();
    let one = U256::from(1);
    let (target, byte_swapped) = (0x0102, 0x0201);
    let cases: [(&[u8], &[U256], u64); 4] = [
        (&[PUSH2, 1, 2, JUMP], &[], 12),
        (&[PUSH2, 1, 2, JUMPI], &[one], 14),
        (&[ISZERO, PUSH2, 1, 2, JUMPI], &[U256::ZERO], 17),
        (&[EQ, PUSH2, 1, 2, JUMPI], &[one, one], 17),
    ];
    for (head, values, gas_used) in cases {
        let mut code = vec![INVALID; byte_swapped + 3];
        code[..head.len()].copy_from_slice(head);
        code[target..target + 2].copy_from_slice(&[JUMPDEST, STOP]);
        code[byte_swapped..].copy_from_slice(&[JUMPDEST, PC, STOP]);
        let (result, i) = run(&table, &code, values);
        assert_eq!(
            (result, 100 - i.gas.remaining(), i.stack.len()),
            (InstructionResult::Stop, gas_used, 0),
            "head={head:x?}"
        );
    }
}
