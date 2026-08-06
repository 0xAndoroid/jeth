# jeth

Jolt proving Ethereum: stateless execution of a full, recent Ethereum mainnet block inside a Jolt RISC-V guest (pre-state witness → execute all txs → assert post-state root against the header), traced — not proved — to measure RISC-V cycle count and cycles/gas.

Status: **optimization campaign in progress**. Current: recent mainnet blocks at **34.5–42.7 cycles/gas** fully self-verifying (**28.0–36.9** with trusted-advice witness digests) — from 513 c/g stock. See [RESULTS.md](RESULTS.md) for the full ladder, row-exact profiles, quartering plan, and proving memo; design in [PLAN.md](PLAN.md).

Quick start: `cargo run --release -p jeth-host -- bench` (one-time Jolt CLI build: RESULTS.md → Reproduce).

Upstreamed: [a16z/jolt#1746](https://github.com/a16z/jolt/pull/1746) — O(1) size-class guest allocator (the 85.7%-of-cycles finding).
