# Journal payload layout

Vendored from revm-context-interface 17.0.1, MIT. The only Rust change is `repr(C)` on `JournalEntry`, keeping the tagged union payload naturally aligned. The public entry variants and revert behavior are unchanged. Cargo.toml adds an empty workspace so the vendored crate can be tested independently.
