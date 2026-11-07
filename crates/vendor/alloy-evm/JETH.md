# Retained transaction journal

Vendored from alloy-evm 0.33.3, MIT OR Apache-2.0. EthEvm adds opt-in journal retention using revm transact_one and an explicit take_retained_state boundary. The fixed Jeth block overlay retains block-original values separately and commits every final slot. Per-transaction state maps are empty while enabled, so state hooks and state-dependent receipt builders are unsupported. Default behavior is unchanged. Cargo.toml adds an empty workspace for isolated testing.
