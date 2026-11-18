# jeth

Jolt proving Ethereum: stateless execution of a full, recent Ethereum mainnet block inside a Jolt RISC-V guest (pre-state witness → execute all txs → assert post-state root against the header), traced — not proved — to measure RISC-V cycle count and cycles/gas.

Status: **optimization campaign in progress**. Current: the ten-block mainnet set 25905781–25905790 validates at **13.65 cycles/gas** (gas-weighted, fully self-verifying, 2026-09-10) — from 513 c/g stock. See [RESULTS.md](RESULTS.md) for the full ladder, row-exact profiles, quartering plan, and proving memo; design in [PLAN.md](PLAN.md).

Quick start: `just jeth bench`, which runs `cargo run --release -p jeth-host -- bench` (one-time Jolt CLI build: RESULTS.md → Reproduce). `just` alone lists the build, format, lint and test recipes. `just cycles` counts expanded cycles over a frozen ten-block set, as the Cycles workflow does on every pull request (RESULTS.md → Cycle-count harness).

Upstreamed: [a16z/jolt#1746](https://github.com/a16z/jolt/pull/1746) — O(1) size-class guest allocator (the 85.7%-of-cycles finding).

### Committed-input limit

The default guest, `validate_block`, reserves 16 MiB for its committed input,
sized for one mainnet block: the largest single-block input observed is
13,627,820 bytes (block 25512816 of the Jul–Sep 2026 top-50 set, at a 60M gas
limit). The limit counts the postcard length prefix in front of `input.bin`.
`jeth trace`, `profile`, `txprofile`, `opcodes` and `bench` reject a larger
input before they build or run a guest.

`--large-input` on those commands selects `validate_block_128m`: the same
validation with a 128 MiB region, for `jeth merge` multi-block inputs (90 MB at
19 blocks). It is never selected by input size, and it cannot be combined with
`--advice` or `--trusted-digests`, whose guests already reserve 128 MiB for the
payload. The two guests have separate ELF, compute-advice ELF and trace-summary
paths (`trace-summary-large-input.json` for the large one), including with
`--skip-build`.

The default's smaller I/O reservation can reduce the RAM address domain the
prover must handle, with the same execution trace length. The effect depends
on the program's highest accessed RAM address.

For a custom prover integration, build with `JOLT_FUNC_NAME=validate_block`
and use a matching `MemoryConfig`: `max_input_size = 16777216`; output and both
advice budgets 4096 bytes, stack 33554432 bytes, heap 1610612736 bytes. Build
both the compute-advice and the proven ELF for that entry point.
`validate_block_128m` differs only in `max_input_size = 134217728`.

### Short-input Keccak cache

The standalone guest feature `keccak-cache` memoizes 32- and 64-byte Keccak
inputs in a fixed 64-entry cache (8 KiB of bucket storage). It is one of the
guest's default features: the advice and the proven guest that `jeth` builds
both have it, and no `--guest-features` flag is needed. `jeth` has no switch
for it; a guest built by hand with `--no-default-features` leaves it out
(`keccak-census` and `push-jump-fusion` too, unless `--features` names them).
Repeated inputs save Keccak permutations, while misses add lookup/copy work.
Every hit compares the complete input and length; index-hash collisions only
cause eviction. The feature changes guest execution, not the Jolt protocol.

## Native advice generation

The optional `jeth-core/native-advice` feature records the untrusted advice words
emitted during native validation. It can replace the interpreted `compute_advice`
pass; the proven guest still checks every hint and executes the same instructions.

For the ordinary guest with the code library enabled:

```sh
cargo run --profile recorder --manifest-path crates/native-advice/Cargo.toml -- input.bin advice.bin
```

`crates/native-advice` is a member of the guest's workspace (`crates/guest`), so one
`[patch]` table and one `Cargo.lock` serve both: it runs the vendored
revm-interpreter, whose MULMOD records its quotient advice through jeth-core's
`jeth_mul_mod` hook, while `jeth run-native` in the root workspace keeps the
registry interpreter. The `recorder` profile is that workspace's `release` without
the guest's fat LTO and single codegen unit.

Pass the resulting bytes as Jolt's runtime advice tape, not its trusted-advice
input. Match the native and guest source revisions, dependencies, and features.
The recorder runs one block per process and does not support the trusted-digest
guest or optional guest features such as lazy analysis. Existing tracing commands
continue to use the interpreted pass. `jeth trace` writes that pass's tape beside
its summary (`advice-tape.bin` for the default guest), and `jeth cycles run` fails
a block for which the recorder writes a different tape (RESULTS.md → Cycle-count
harness).

The library entry point is `jeth_core::advice::native::record`. It captures words
from both jeth-core and the vendored MPT encoder, on the calling thread only.
Recording scopes cannot nest; unwinding discards the tape. The recorder does not
reset other validation state after a failed run.

### Checked Keccak prefixes

The optional `keccak-prefix-cache` feature reuses states computed by the guest
while hashing trie nodes of 136–544 bytes. It retains up to three complete
136-byte input blocks. Advice selects a stored prefix; the guest compares every
prefix byte before continuing the hash. Advice never supplies the sponge state.

Enable the feature in both the guest and its matching native advice generator.
The native recorder plans which prefixes will be reused and emits cache misses
after 131,072 eligible calls. Guest storage is capped at 65,536 entries (22 MiB of
entry payload); a full cache keeps hashing normally. Hint consumption depends
only on input length, so different buffer alignments cannot change tape order.
The interpreted `compute_advice` pass emits cache misses and remains correct;
use the native planner to obtain the row savings.

The feature is disabled by default. On the combined #23–#35 branch, with native
advice and all other settings held fixed, it reduces live rows from
88,170,922 / 473,666,778 / 807,159,643 to
84,128,991 / 459,358,991 / 782,446,835 for blocks
26235156 / 26235168 / 26235159: 4.58%, 3.02%, and 3.06% fewer rows.
These are execution counts, not measured prover-time speedups. Inputs with
little prefix reuse can be slower with this feature enabled.
