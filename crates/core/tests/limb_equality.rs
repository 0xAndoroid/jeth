use ark_ff::BigInt;

#[test]
fn equality_distinguishes_each_limb_bit() {
    fn check<const N: usize>() {
        let zero = BigInt::<N>([0; N]);
        let ones = BigInt::<N>([u64::MAX; N]);
        assert_eq!(zero, BigInt::default());
        let equal_ones = BigInt(core::array::from_fn(|_| u64::MAX));
        assert_eq!(ones, equal_ones);
        for limb in 0..N {
            for bit in 0..64 {
                let mut one_bit = [0; N];
                one_bit[limb] = 1 << bit;
                let mut all_but_one = [u64::MAX; N];
                all_but_one[limb] ^= 1 << bit;
                assert_ne!(BigInt(one_bit), zero);
                assert_ne!(BigInt(all_but_one), ones);
            }
        }
    }
    check::<0>();
    check::<1>();
    check::<2>();
    check::<4>();
    check::<6>();
    check::<12>();
}
