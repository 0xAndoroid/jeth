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

## Native advice generation

The optional `jeth-core/native-advice` feature records the untrusted advice words
emitted during native validation. It can replace the interpreted `compute_advice`
pass; the proven guest still checks every hint and executes the same instructions.

For the ordinary guest with the code library enabled:

```sh
cargo run --release -p jeth-core --example native-advice \
  --features native-advice,secp-inline,code-library,bigint-inline -- input.bin advice.bin
```

Pass the resulting bytes as Jolt's runtime advice tape, not its trusted-advice
input. Match the native and guest source revisions, dependencies, and features.
The example runs one block per process and does not support the trusted-digest
guest or optional guest features such as lazy analysis. Existing tracing commands
continue to use the interpreted pass. `jeth trace` writes that pass's tape beside
its summary (`advice-tape.bin` for the default guest), and `jeth cycles run` fails
a block for which the example records a different tape (RESULTS.md → Cycle-count
harness).

The library entry point is `jeth_core::advice::native::record`. It captures words
from both jeth-core and the vendored MPT encoder, on the calling thread only.
Recording scopes cannot nest; unwinding discards the tape. The recorder does not
reset other validation state after a failed run.
