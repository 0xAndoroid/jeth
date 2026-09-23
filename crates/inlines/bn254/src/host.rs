use crate::sequence_builder::{Bn254Fp2MulQ, Bn254MulQ, Bn254SopQ2};

jolt_inlines_sdk::register_inlines! {
    trace_file: "bn254_trace.joltinline",
    extension: jolt_inlines_sdk::host::InlineExtension::External,
    ops: [Bn254MulQ, Bn254SopQ2, Bn254Fp2MulQ],
}
