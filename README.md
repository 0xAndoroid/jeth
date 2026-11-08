# jeth

Jolt proving Ethereum: stateless execution of a full, recent Ethereum mainnet block inside a Jolt RISC-V guest (pre-state witness → execute all txs → assert post-state root against the header), traced — not proved — to measure RISC-V cycle count and cycles/gas.

Status: **optimization campaign in progress**. Current: the ten-block mainnet set 25905781–25905790 validates at **13.65 cycles/gas** (gas-weighted, fully self-verifying, 2026-09-10) — from 513 c/g stock. See [RESULTS.md](RESULTS.md) for the full ladder, row-exact profiles, quartering plan, and proving memo; design in [PLAN.md](PLAN.md).

Quick start: `just jeth bench`, which runs `cargo run --release -p jeth-host -- bench` (one-time Jolt CLI build: RESULTS.md → Reproduce). `just` alone lists the build, format, lint and test recipes.

Upstreamed: [a16z/jolt#1746](https://github.com/a16z/jolt/pull/1746) — O(1) size-class guest allocator (the 85.7%-of-cycles finding).

### Optional short-input Keccak cache

The standalone guest feature `keccak-cache` memoizes 32- and 64-byte Keccak
inputs in a fixed 64-entry cache (8 KiB of bucket storage). Enable it alongside
`guest` in both the advice and proven guest builds. It is disabled by default:
repeated inputs save Keccak permutations, while misses add lookup/copy work.
Every hit compares the complete input and length; index-hash collisions only
cause eviction. The feature changes guest execution, not the Jolt protocol.

On mainnet blocks 26235156, 26235168, and 26235159, matched full guest traces
used 0.79%, 1.00%, and 1.43% fewer expanded rows, respectively. These are trace
counts, not end-to-end prover timings. An isolated stream of distinct,
deliberately colliding 32-/64-byte inputs added 8.5% to the hash routine's row
count. Workloads with little reuse may therefore be slower with the cache.
