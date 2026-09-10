use crate::sequence_builder::{Fp2Mul, Mulp, Sopp2};

jolt_inlines_sdk::register_inlines! {
    trace_file: "bls12_381_trace.joltinline",
    extension: jolt_inlines_sdk::host::InlineExtension::External,
    ops: [Mulp, Sopp2, Fp2Mul],
}
