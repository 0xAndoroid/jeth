use crate::sequence_builder::Blake2bRounds;

jolt_inlines_sdk::register_inlines! {
    trace_file: "blake2f_trace.joltinline",
    extension: jolt_inlines_sdk::host::InlineExtension::External,
    ops: [
        Blake2bRounds<10>,
        Blake2bRounds<1>,
        Blake2bRounds<2>,
        Blake2bRounds<3>,
        Blake2bRounds<4>,
        Blake2bRounds<5>,
        Blake2bRounds<6>,
        Blake2bRounds<7>,
        Blake2bRounds<8>,
        Blake2bRounds<9>,
    ],
}
