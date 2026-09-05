//! Intrinsic transaction gas with a word-at-a-time calldata token count.
//!
//! [`calculate_initial_tx_gas_for_tx`] shadows the `context_interface::cfg::gas`
//! glob re-export in [`crate::instructions`]; revm-handler's `validation.rs`
//! imports the function from there, so the handler's initial-gas path lands
//! here. The arithmetic is `GasParams::initial_tx_gas` verbatim through its
//! public accessors; only the token count differs. Upstream filters the
//! calldata byte by byte (`LBU` + test + add + loop, 7 rows per byte on the
//! Jolt RV64 target); [`tokens_in_calldata`] tests the non-zero bytes of an
//! aligned `u64` at a time.

use context_interface::{
    cfg::{gas::InitialAndFloorGas, GasParams},
    transaction::{AccessListItemTr as _, Transaction, TransactionType},
};
use primitives::hardfork::SpecId;

/// Initial gas that is deducted for transaction to be included.
/// Initial gas contains initial stipend gas, gas for access list and input data.
///
/// Same result as [`context_interface::cfg::gas::calculate_initial_tx_gas_for_tx`].
pub fn calculate_initial_tx_gas_for_tx(tx: impl Transaction, spec: SpecId) -> InitialAndFloorGas {
    let mut accounts = 0;
    let mut storages = 0;
    // legacy is only tx type that does not have access list.
    if tx.tx_type() != TransactionType::Legacy {
        (accounts, storages) = tx
            .access_list()
            .map(|al| {
                al.fold((0, 0), |(mut num_accounts, mut num_storage_slots), item| {
                    num_accounts += 1;
                    num_storage_slots += item.storage_slots().count();

                    (num_accounts, num_storage_slots)
                })
            })
            .unwrap_or_default();
    }

    initial_tx_gas(
        &GasParams::new_spec(spec),
        tx.input(),
        tx.kind().is_create(),
        accounts as u64,
        storages as u64,
        tx.authorization_list_len() as u64,
    )
}

/// [`GasParams::initial_tx_gas`] with [`tokens_in_calldata`] as the token count.
pub fn initial_tx_gas(
    params: &GasParams,
    input: &[u8],
    is_create: bool,
    access_list_accounts: u64,
    access_list_storages: u64,
    authorization_list_num: u64,
) -> InitialAndFloorGas {
    let mut gas = InitialAndFloorGas::default();

    let tokens_in_calldata = tokens_in_calldata(input, params.tx_token_non_zero_byte_multiplier());

    // EIP-7702 auth list: regular portion in initial_total_gas, state portion in
    // initial_state_gas (EIP-8037).
    let auth_total_cost = authorization_list_num * params.tx_eip7702_per_empty_account_cost();
    let auth_state_gas = authorization_list_num * params.tx_eip7702_per_auth_state_gas();
    let auth_regular_cost = auth_total_cost - auth_state_gas;

    gas.initial_total_gas += tokens_in_calldata * params.tx_token_cost()
        + access_list_accounts * params.tx_access_list_address_cost()
        + access_list_storages * params.tx_access_list_storage_key_cost()
        + params.tx_base_stipend()
        + auth_regular_cost;
    gas.initial_state_gas += auth_state_gas;

    if is_create {
        // EIP-2 create cost, EIP-3860 initcode metering, EIP-8037 state gas.
        gas.initial_total_gas += params.tx_create_cost();
        gas.initial_total_gas += params.tx_initcode_cost(input.len());
        gas.initial_state_gas += params.create_state_gas();
    }

    // EIP-7623 floor.
    gas.floor_gas = params.tx_floor_cost(tokens_in_calldata);

    // State gas is a subset of the initial total gas.
    gas.initial_total_gas += gas.initial_state_gas;

    gas
}

/// `zero_bytes + non_zero_bytes * non_zero_data_multiplier` over `input`, as
/// `context_interface::cfg::gas::get_tokens_in_calldata`.
#[inline]
pub fn tokens_in_calldata(input: &[u8], non_zero_data_multiplier: u64) -> u64 {
    let non_zero = non_zero_bytes(input);
    let zero = input.len() as u64 - non_zero;
    zero + non_zero * non_zero_data_multiplier
}

/// Number of non-zero bytes in `input`, counted eight at a time over its
/// 8-aligned interior (only aligned `LD`s: a misaligned word load traps on the
/// Jolt target) and byte-wise over the up-to-7-byte head and tail.
fn non_zero_bytes(input: &[u8]) -> u64 {
    // SAFETY: `u64` has no invalid bit patterns and `align_to` hands out only
    // the 8-aligned interior of `input` as words; head and tail stay bytes.
    let (head, words, tail) = unsafe { input.align_to::<u64>() };
    let mut n = non_zero_bytes_slow(head) + non_zero_bytes_slow(tail);

    const LOW7: u64 = 0x7f7f_7f7f_7f7f_7f7f;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    const ONES: u64 = 0x0101_0101_0101_0101;
    // The high bit of `((b & 0x7f) + 0x7f) | b` is set exactly when `b != 0`.
    // `lanes` holds one per-byte counter; `* ONES >> 56` sums the eight lanes,
    // which is exact while the sum is < 256, hence at most 31 words per fold.
    for chunk in words.chunks(31) {
        let mut lanes = 0u64;
        for &w in chunk {
            lanes += ((((w & LOW7) + LOW7) | w) & HIGH) >> 7;
        }
        n += lanes.wrapping_mul(ONES) >> 56;
    }
    n
}

fn non_zero_bytes_slow(bytes: &[u8]) -> u64 {
    bytes.iter().filter(|b| **b != 0).count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use context_interface::cfg::gas::get_tokens_in_calldata;
    use std::vec::Vec;

    fn xorshift(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    /// Random bytes with a `zero_ppm`-per-million chance of 0 per byte, so the
    /// mix of zero and non-zero lanes (and full words of each) is covered.
    fn random_calldata(rng: &mut u64, len: usize, zero_ppm: u64) -> Vec<u8> {
        (0..len)
            .map(|_| {
                let r = xorshift(rng);
                if r % 1_000_000 < zero_ppm {
                    0
                } else {
                    (r >> 32) as u8 | 1
                }
            })
            .collect()
    }

    const SPECS: [SpecId; 21] = [
        SpecId::FRONTIER,
        SpecId::FRONTIER_THAWING,
        SpecId::HOMESTEAD,
        SpecId::DAO_FORK,
        SpecId::TANGERINE,
        SpecId::SPURIOUS_DRAGON,
        SpecId::BYZANTIUM,
        SpecId::CONSTANTINOPLE,
        SpecId::PETERSBURG,
        SpecId::ISTANBUL,
        SpecId::MUIR_GLACIER,
        SpecId::BERLIN,
        SpecId::LONDON,
        SpecId::ARROW_GLACIER,
        SpecId::GRAY_GLACIER,
        SpecId::MERGE,
        SpecId::SHANGHAI,
        SpecId::CANCUN,
        SpecId::PRAGUE,
        SpecId::OSAKA,
        SpecId::AMSTERDAM,
    ];

    /// Every length 0..=64 at every alignment of the slice start, against the
    /// upstream byte filter, with three zero densities.
    #[test]
    fn tokens_match_byte_filter_for_short_inputs_at_every_alignment() {
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        for &zero_ppm in &[0, 500_000, 1_000_000] {
            for len in 0..=64usize {
                let buf = random_calldata(&mut rng, len + 8, zero_ppm);
                for off in 0..8 {
                    let input = &buf[off..off + len];
                    for &mult in &[4u64, 16, 68] {
                        assert_eq!(
                            tokens_in_calldata(input, mult),
                            get_tokens_in_calldata(input, mult),
                            "len {len} off {off} mult {mult} zero_ppm {zero_ppm}"
                        );
                    }
                }
            }
        }
    }

    /// Long inputs cross many 31-word folds; include the all-zero and all-non-zero
    /// extremes (255 non-zero lanes per fold would overflow the byte sum).
    #[test]
    fn tokens_match_byte_filter_for_long_inputs() {
        let mut rng = 0x2545_f491_4f6c_dd1du64;
        for &len in &[247usize, 248, 249, 1000, 4097, 305_213] {
            for &zero_ppm in &[0, 20_000, 500_000, 1_000_000] {
                let buf = random_calldata(&mut rng, len + 8, zero_ppm);
                for off in [0usize, 3, 7] {
                    let input = &buf[off..off + len];
                    assert_eq!(
                        tokens_in_calldata(input, 4),
                        get_tokens_in_calldata(input, 4),
                        "len {len} off {off} zero_ppm {zero_ppm}"
                    );
                }
            }
        }
    }

    /// The shadowing `initial_tx_gas` is `GasParams::initial_tx_gas` for every
    /// spec, both tx kinds, and random access-list / auth-list sizes.
    #[test]
    fn initial_tx_gas_matches_gas_params() {
        let mut rng = 0xd1b5_4a32_d192_ed03u64;
        for spec in SPECS {
            let params = GasParams::new_spec(spec);
            for is_create in [false, true] {
                for _ in 0..16 {
                    let len = (xorshift(&mut rng) % 600) as usize;
                    let input = random_calldata(&mut rng, len, 300_000);
                    let accounts = xorshift(&mut rng) % 5;
                    let storages = xorshift(&mut rng) % 20;
                    let auths = xorshift(&mut rng) % 4;
                    assert_eq!(
                        initial_tx_gas(&params, &input, is_create, accounts, storages, auths),
                        params.initial_tx_gas(&input, is_create, accounts, storages, auths),
                        "{spec:?} create {is_create} len {len}"
                    );
                }
            }
        }
    }
}
