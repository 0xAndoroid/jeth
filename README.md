# jeth

Jolt proving Ethereum: stateless execution of a full, recent Ethereum mainnet block inside a Jolt RISC-V guest (pre-state witness → execute all txs → assert post-state root against the header), traced — not proved — to measure RISC-V cycle count and cycles/gas.

Status: **optimization campaign in progress**. Current: the ten-block mainnet set 25905781–25905790 validates at **13.65 cycles/gas** (gas-weighted, fully self-verifying, 2026-09-10) — from 513 c/g stock. See [RESULTS.md](RESULTS.md) for the full ladder, row-exact profiles, quartering plan, and proving memo; design in [PLAN.md](PLAN.md).

Quick start: `just jeth bench`, which runs `cargo run --release -p jeth-host -- bench` (one-time Jolt CLI build: RESULTS.md → Reproduce). `just` alone lists the build, format, lint and test recipes.

Upstreamed: [a16z/jolt#1746](https://github.com/a16z/jolt/pull/1746) — O(1) size-class guest allocator (the 85.7%-of-cycles finding).

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
continue to use the interpreted pass.

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
