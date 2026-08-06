# jeth

Jolt proving Ethereum: stateless execution of a full, recent Ethereum mainnet block inside a Jolt RISC-V guest (pre-state witness → execute all txs → assert post-state root against the header), traced — not proved — to measure RISC-V cycle count and cycles/gas.

Status: **v1 complete**. Headline: a mainnet block mined 2.6 min earlier validated in-guest at **63.4 cycles/gas** (2.66B cycles, 27 s trace). See [RESULTS.md](RESULTS.md); design + research in [PLAN.md](PLAN.md).

Quick start: `cargo run --release -p jeth-host -- bench` (see RESULTS.md → Reproduce for the one-time Jolt CLI build).
