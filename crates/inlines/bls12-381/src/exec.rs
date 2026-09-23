//! Software reference: plain big-integer arithmetic reduced by `R⁻¹ mod p`.

use jolt_inlines_sdk::host::NBigUint;

use crate::{LIMBS as N, MODULUS};

pub type Element = [u64; N];

fn big(x: &Element) -> NBigUint {
    NBigUint::from_bytes_le(&x.iter().flat_map(|l| l.to_le_bytes()).collect::<Vec<u8>>())
}

fn element(x: &NBigUint) -> Element {
    let mut bytes = x.to_bytes_le();
    bytes.resize(8 * N, 0);
    core::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()))
}

fn modulus() -> NBigUint {
    big(&MODULUS)
}

/// `sum · R⁻¹ mod p` for `R = 2³⁸⁴`.
fn montgomery(sum: NBigUint) -> Element {
    let p = modulus();
    let r_inv = (NBigUint::from(1u8) << (64 * N)).modpow(&(&p - 2u8), &p);
    element(&((sum * r_inv) % p))
}

pub fn mulp(a: &Element, b: &Element) -> Element {
    montgomery(big(a) * big(b))
}

pub fn sopp2(a: &[Element; 2], b: &[Element; 2]) -> Element {
    montgomery(big(&a[0]) * big(&b[0]) + big(&a[1]) * big(&b[1]))
}

pub fn fp2mul(a: &[Element; 2], b: &[Element; 2]) -> [Element; 2] {
    let (a0, a1, b0, b1) = (big(&a[0]), big(&a[1]), big(&b[0]), big(&b[1]));
    [
        montgomery(&a0 * &b0 + &a1 * (modulus() - &b1)),
        montgomery(a0 * b1 + a1 * b0),
    ]
}
