use super::i256::i256_cmp;
use crate::Ip;
use crate::{
    interpreter_types::{InterpreterTypes, RuntimeFlag, StackTr},
    InstructionContext,
};
use core::cmp::Ordering;
use primitives::U256;

/// Implements the LT instruction - less than comparison.
#[inline(always)]
pub fn lt<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, LT);
    popn_top!([op1], op2, context.interpreter);
    *op2 = U256::from(op1 < *op2);
    ip
}

/// Implements the GT instruction - greater than comparison.
#[inline(always)]
pub fn gt<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, GT);
    popn_top!([op1], op2, context.interpreter);
    *op2 = U256::from(op1 > *op2);
    ip
}

/// Implements the CLZ instruction - count leading zeros.
pub fn clz<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, CLZ);
    check!(context.interpreter, OSAKA);
    popn_top!([], op1, context.interpreter);
    let leading_zeros = op1.leading_zeros();
    *op1 = U256::from(leading_zeros);
    ip
}

/// Implements the SLT instruction.
///
/// Signed less than comparison of two values from stack.
#[inline(always)]
pub fn slt<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, SLT);
    popn_top!([op1], op2, context.interpreter);
    *op2 = U256::from(i256_cmp(&op1, op2) == Ordering::Less);
    ip
}

/// Implements the SGT instruction.
///
/// Signed greater than comparison of two values from stack.
pub fn sgt<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, SGT);
    popn_top!([op1], op2, context.interpreter);
    *op2 = U256::from(i256_cmp(&op1, op2) == Ordering::Greater);
    ip
}

/// Implements the EQ instruction.
///
/// Equality comparison of two values from stack.
pub fn eq<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, EQ);
    popn_top!([op1], op2, context.interpreter);
    *op2 = U256::from(op1 == *op2);
    ip
}

/// Implements the ISZERO instruction.
///
/// Checks if the top stack value is zero.
pub fn iszero<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, ISZERO);
    popn_top!([], op1, context.interpreter);
    *op1 = U256::from(op1.is_zero());
    ip
}

/// Implements the AND instruction.
///
/// Bitwise AND of two values from stack.
pub fn bitand<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, AND);
    popn_top!([op1], op2, context.interpreter);
    *op2 = op1 & *op2;
    ip
}

/// Implements the OR instruction.
///
/// Bitwise OR of two values from stack.
#[inline(always)]
pub fn bitor<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, OR);
    popn_top!([op1], op2, context.interpreter);
    *op2 = op1 | *op2;
    ip
}

/// Implements the XOR instruction.
///
/// Bitwise XOR of two values from stack.
pub fn bitxor<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, XOR);
    popn_top!([op1], op2, context.interpreter);
    *op2 = op1 ^ *op2;
    ip
}

/// Implements the NOT instruction.
///
/// Bitwise NOT (negation) of the top stack value.
#[inline(always)]
pub fn not<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, NOT);
    popn_top!([], op1, context.interpreter);
    *op1 = !*op1;
    ip
}

/// Implements the BYTE instruction.
///
/// Extracts a single byte from a word at a given index.
pub fn byte<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, BYTE);
    popn_top!([op1], op2, context.interpreter);
    let o1 = as_usize_saturated!(op1);
    *op2 = if o1 < 32 {
        // `31 - o1` because `byte` returns LE, while we want BE
        U256::from(op2.byte(31 - o1))
    } else {
        U256::ZERO
    };
    ip
}

/// EIP-145: Bitwise shifting instructions in EVM
#[inline(always)]
pub fn shl<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, SHL);
    check!(context.interpreter, CONSTANTINOPLE);
    popn_top!([op1], op2, context.interpreter);
    let shift = as_usize_saturated!(op1);
    *op2 = shift_word::<true>(*op2, shift);
    ip
}

/// EIP-145: Bitwise shifting instructions in EVM
#[inline(always)]
pub fn shr<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, SHR);
    check!(context.interpreter, CONSTANTINOPLE);
    popn_top!([op1], op2, context.interpreter);
    let shift = as_usize_saturated!(op1);
    *op2 = shift_word::<false>(*op2, shift);
    ip
}

// Whole-limb selection is separate from the residual shift so each transfer
// is a fixed-width operation and no temporary array needs a dynamic index.
#[inline(always)]
fn shift_word<const LEFT: bool>(value: U256, shift: usize) -> U256 {
    if shift >= 256 {
        return U256::ZERO;
    }
    let [a, b, c, d] = *value.as_limbs();
    let words = shift / 64;
    let bits = shift % 64;
    let inv = 63 - bits;
    let limbs = if LEFT {
        let [a, b, c, d] = match words {
            0 => [a, b, c, d],
            1 => [0, a, b, c],
            2 => [0, 0, a, b],
            _ => [0, 0, 0, a],
        };
        [
            a << bits,
            (b << bits) | ((a >> inv) >> 1),
            (c << bits) | ((b >> inv) >> 1),
            (d << bits) | ((c >> inv) >> 1),
        ]
    } else {
        let [a, b, c, d] = match words {
            0 => [a, b, c, d],
            1 => [b, c, d, 0],
            2 => [c, d, 0, 0],
            _ => [d, 0, 0, 0],
        };
        [
            (a >> bits) | ((b << inv) << 1),
            (b >> bits) | ((c << inv) << 1),
            (c >> bits) | ((d << inv) << 1),
            d >> bits,
        ]
    };
    U256::from_limbs(limbs)
}

/// EIP-145: Bitwise shifting instructions in EVM
pub fn sar<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, SAR);
    check!(context.interpreter, CONSTANTINOPLE);
    popn_top!([op1], op2, context.interpreter);
    let shift = as_usize_saturated!(op1);
    *op2 = if shift < 256 {
        op2.arithmetic_shr(shift)
    } else if op2.bit(255) {
        U256::MAX
    } else {
        U256::ZERO
    };
    ip
}

#[cfg(test)]
mod tests {
    use crate::{
        host::DummyHost,
        instructions::bitwise::{byte, clz, sar, shl, shr},
        interpreter_types::Jumps,
        InstructionContext, Interpreter,
    };
    use primitives::{hardfork::SpecId, uint, U256};

    #[test]
    fn limb_shifts_match_full_width_operations() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..32 {
            let value = U256::from_limbs(core::array::from_fn(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed
            }));
            for shift in 0..=300 {
                let left = if shift < 256 {
                    value << shift
                } else {
                    U256::ZERO
                };
                let right = if shift < 256 {
                    value >> shift
                } else {
                    U256::ZERO
                };
                assert_eq!(super::shift_word::<true>(value, shift), left);
                assert_eq!(super::shift_word::<false>(value, shift), right);
            }
            assert_eq!(super::shift_word::<true>(value, usize::MAX), U256::ZERO);
            assert_eq!(super::shift_word::<false>(value, usize::MAX), U256::ZERO);
        }
    }

    #[test]
    fn test_shift_left() {
        let mut interpreter = Interpreter::default();

        struct TestCase {
            value: U256,
            shift: U256,
            expected: U256,
        }

        uint! {
            let test_cases = [
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x00_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x01_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000002_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0xff_U256,
                    expected: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x0100_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x0101_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x00_U256,
                    expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x01_U256,
                    expected: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0xff_U256,
                    expected: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x0100_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x01_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x01_U256,
                    expected: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe_U256,
                },
            ];
        }

        for test in test_cases {
            assert!(interpreter.stack.push(test.value));
            assert!(interpreter.stack.push(test.shift));
            let ip = interpreter.bytecode.ip();
            let context = InstructionContext {
                host: &mut DummyHost::default(),
                interpreter: &mut interpreter,
            };
            shl(ip, context);
            let res = interpreter.stack.pop().unwrap();
            assert_eq!(res, test.expected);
        }
    }

    #[test]
    fn test_logical_shift_right() {
        let mut interpreter = Interpreter::default();

        struct TestCase {
            value: U256,
            shift: U256,
            expected: U256,
        }

        uint! {
            let test_cases = [
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x00_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x01_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x01_U256,
                    expected: 0x4000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0xff_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x0100_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x0101_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x00_U256,
                    expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x01_U256,
                    expected: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0xff_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x0100_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x01_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
            ];
        }

        for test in test_cases {
            assert!(interpreter.stack.push(test.value));
            assert!(interpreter.stack.push(test.shift));
            let ip = interpreter.bytecode.ip();
            let context = InstructionContext {
                host: &mut DummyHost::default(),
                interpreter: &mut interpreter,
            };
            shr(ip, context);
            let res = interpreter.stack.pop().unwrap();
            assert_eq!(res, test.expected);
        }
    }

    #[test]
    fn test_arithmetic_shift_right() {
        let mut interpreter = Interpreter::default();

        struct TestCase {
            value: U256,
            shift: U256,
            expected: U256,
        }

        uint! {
        let test_cases = [
            TestCase {
                value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                shift: 0x00_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
            },
            TestCase {
                value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                shift: 0x01_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
            },
            TestCase {
                value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0x01_U256,
                expected: 0xc000000000000000000000000000000000000000000000000000000000000000_U256,
            },
            TestCase {
                value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0xff_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0x0100_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0x0101_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0x00_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0x01_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0xff_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0x0100_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0x01_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
            },
            TestCase {
                value: 0x4000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0xfe_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
            },
            TestCase {
                value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0xf8_U256,
                expected: 0x000000000000000000000000000000000000000000000000000000000000007f_U256,
            },
            TestCase {
                value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0xfe_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
            },
            TestCase {
                value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0xff_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
            },
            TestCase {
                value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0x0100_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
            },
        ];
            }

        for test in test_cases {
            assert!(interpreter.stack.push(test.value));
            assert!(interpreter.stack.push(test.shift));
            let ip = interpreter.bytecode.ip();
            let context = InstructionContext {
                host: &mut DummyHost::default(),
                interpreter: &mut interpreter,
            };
            sar(ip, context);
            let res = interpreter.stack.pop().unwrap();
            assert_eq!(res, test.expected);
        }
    }

    #[test]
    fn test_byte() {
        struct TestCase {
            input: U256,
            index: usize,
            expected: U256,
        }

        let mut interpreter = Interpreter::default();

        let input_value = U256::from(0x1234567890abcdef1234567890abcdef_u128);
        let test_cases = (0..32)
            .map(|i| {
                let byte_pos = 31 - i;

                let shift_amount = U256::from(byte_pos * 8);
                let byte_value = (input_value >> shift_amount) & U256::from(0xFF);
                TestCase {
                    input: input_value,
                    index: i,
                    expected: byte_value,
                }
            })
            .collect::<Vec<_>>();

        for test in test_cases.iter() {
            assert!(interpreter.stack.push(test.input));
            assert!(interpreter.stack.push(U256::from(test.index)));
            let ip = interpreter.bytecode.ip();
            let context = InstructionContext {
                host: &mut DummyHost::default(),
                interpreter: &mut interpreter,
            };
            byte(ip, context);
            let res = interpreter.stack.pop().unwrap();
            assert_eq!(res, test.expected, "Failed at index: {}", test.index);
        }
    }

    #[test]
    fn test_clz() {
        let mut interpreter = Interpreter::default();
        interpreter.runtime_flag.spec_id = SpecId::OSAKA;
        let mut host = DummyHost::new(SpecId::OSAKA);

        struct TestCase {
            value: U256,
            expected: U256,
        }

        uint! {
            let test_cases = [
                TestCase { value: 0x0_U256, expected: 256_U256 },
                TestCase { value: 0x1_U256, expected: 255_U256 },
                TestCase { value: 0x2_U256, expected: 254_U256 },
                TestCase { value: 0x3_U256, expected: 254_U256 },
                TestCase { value: 0x4_U256, expected: 253_U256 },
                TestCase { value: 0x7_U256, expected: 253_U256 },
                TestCase { value: 0x8_U256, expected: 252_U256 },
                TestCase { value: 0xff_U256, expected: 248_U256 },
                TestCase { value: 0x100_U256, expected: 247_U256 },
                TestCase { value: 0xffff_U256, expected: 240_U256 },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256, // U256::MAX
                    expected: 0_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256, // 1 << 255
                    expected: 0_U256,
                },
                TestCase { // Smallest value with 1 leading zero
                    value: 0x4000000000000000000000000000000000000000000000000000000000000000_U256, // 1 << 254
                    expected: 1_U256,
                },
                TestCase { // Value just below 1 << 255
                    value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    expected: 1_U256,
                },
            ];
        }

        for test in test_cases {
            assert!(interpreter.stack.push(test.value));
            let ip = interpreter.bytecode.ip();
            let context = InstructionContext {
                host: &mut host,
                interpreter: &mut interpreter,
            };
            clz(ip, context);
            let res = interpreter.stack.pop().unwrap();
            assert_eq!(
                res, test.expected,
                "CLZ for value {:#x} failed. Expected: {}, Got: {}",
                test.value, test.expected, res
            );
        }
    }
}
