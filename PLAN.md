# jeth — Jolt proving Ethereum

**Goal:** execute a full, very recent Ethereum mainnet block inside a Jolt RISC-V guest — *stateless execution with correct state-transition verification* (pre-state witness → execute all txs → verify resulting state root against the block header), then **trace it (no proving)** and report total RISC-V cycles and cycles/gas.

**Non-goals (v1):** proving, recursion, multi-block continuity, serving proofs, any on-chain artifact. Tx-replay-only execution (without MPT pre/post-state verification) does not count.

**Success criteria:** `RESULTS.md` containing, for ≥1 mainnet block that was mined within ~24h of the run: block number, `gasUsed`, total Jolt trace cycles, cycles/gas, per-phase cycle breakdown, tracer wall time. Guest must internally assert `computed_post_state_root == header.state_root` (plus the rest of `stateless_validation`'s consensus checks) — a panic is a failed run.

All facts below verified 2026-08-06 (research agents; live RPC calls; local Jolt repo at `fbb45f92e9`).

---

## 0. Architecture TL;DR

```
HOST (jeth CLI, native)                          GUEST (Jolt RV64IMAC, no_std)
┌──────────────────────────────┐  postcard bytes ┌──────────────────────────────────┐
│ 1. pick recent block N       │  ─────────────► │ 1. deserialize GuestInput        │
│ 2. eth_getBlockByNumber(N)   │   (input.bin,   │ 2. stateless_validation():       │
│ 3. debug_executionWitness(N) │    ~10-15 MB)   │    - ancestor headers chain      │
│ 4. recover tx pubkeys        │                 │    - witness reveal vs parent    │
│ 5. build GuestInput          │                 │      state root (MPT)            │
│ 6. serialize → input.bin     │                 │    - execute all txs (revm)      │
│                              │                 │    - receipts/bloom/gas/requests │
│ 7. Jolt tracer (no proving): │                 │    - post-state root == header   │
│    count cycles, parse       │  ◄───────────── │ 3. output state_root + gas_used  │
│    phase markers → RESULTS   │  cycles, output └──────────────────────────────────┘
└──────────────────────────────┘
```

- **Guest core:** `paradigmxyz/stateless` (`stateless` + `tries` crates) over reth v2.x + revm 38 — the exact stack zeth 0.3 runs inside risc0. no_std, purpose-built for zkVM guests.
- **Witness:** `debug_executionWitness` from free hosted endpoints (live-verified today — see §3). No server rental needed unless endpoints regress.
- **Keccak:** Jolt **has** a keccak256 inline (`jolt-inlines-keccak256`); wired into revm/alloy via alloy-primitives' `native-keccak` feature + one `#[no_mangle] extern "C" fn native_keccak256` shim in the guest. No crate forks.
- **Tracing:** Jolt branch `merge-1717-main` (fast tracer, 12–23× tick loop; flat-Vec guest memory). Streaming cycle count — no trace materialization, so the prover's ~2^24 default / 2^29–2^30 practical trace ceilings are irrelevant here (`max_trace_length` is enforced only at prove time).

**Expected magnitude:** ~29M-gas block (mainnet typical, Aug 2026) at software-crypto-with-keccak-inline ≈ **1–3.5B cycles, ~30–120 cycles/gas**. Fully-accelerated stacks publish 5–17 cycles/gas (see §1.4); that's the ceiling to chase later, not v1.

---

## 1. Facts and constraints

### 1.1 Jolt (local repo `~/dev/jolt`, READ-ONLY for this project)

| Fact | Detail | Source |
|---|---|---|
| ISA / target | RV64IMAC, XLEN=64. no_std: `riscv64imac-unknown-none-elf`; std: `riscv64imac-zero-linux-musl` (ZeroOS). Toolchain pinned 1.95. RUSTFLAGS include `-Cpasses=lower-atomic`, `--cfg getrandom_backend="custom"` | `common/src/constants.rs:1`, `crates/jolt-prover-legacy/src/host/program.rs:240-244`, `src/main.rs:216-223` |
| Guest declaration | `#[jolt::provable(...)]` attrs: `max_input_size` (def 4096), `max_output_size` (4096), `stack_size` (4096), `heap_size` (32 MiB), `max_trace_length` (1<<24), `max_{trusted,untrusted}_advice_size`, `profile`, `backtrace`, `guest_only` | `common/src/constants.rs:23-32`, `common/src/attributes.rs` |
| Memory layout | IO region (inputs/outputs/advice) sits below `RAM_START_ADDRESS = 0x8000_0000`, padded to pow2, hard cap ≈ 2 GiB. Program at 0x80000000, then stack (grows down), heap above. No separate `memory_size` knob — heap+stack is it. | `common/src/jolt_device.rs:295-437` |
| Trace w/o proving | `tracer::trace_lazy(...) -> impl Iterator<Item = Cycle>` — streaming, `.count()` materializes nothing. `Program::trace()` / macro `trace_{f}` materialize `Vec<Cycle>` at **96 B/cycle** (2^30 cycles ≈ 96+ GiB — do not). `trace_to_file` streams postcard batches. `analyze_{f}` → per-instruction histogram. | `tracer/src/lib.rs:79,162`, `tracer/src/instruction/mod.rs:2044` |
| `max_trace_length` | **No effect on tracing** — only checked at prove time (`prover.rs:349-361`). No chunking needed for cycle counting. | `jolt-sdk/macros`, `crates/jolt-prover-legacy/src/zkvm/prover.rs` |
| Cycle markers | Guest: `jolt::start_cycle_tracking("label")` / `end_cycle_tracking` → tracer logs `"{label}": {real} RV64IMAC cycles + {virtual} = {total}` via `tracing::info`. Caveat: marker string pointer truncated to u32 → keep guest address space < 4 GiB (0x80000000 + heap ≤ 1.5 GiB is safe). | `jolt-platform/src/cycle_tracking.rs`, `tracer/src/emulator/cpu.rs:1032-1074` |
| **Tracer branch — REQUIRED** | PR #1717 (12–23× tracer) is **NOT on main**. Main's guest memory is `HashMap<usize,u64>` per doubleword — every access hashes; a ~1 GiB-heap guest would crawl. Use branch **`merge-1717-main` @ `af1c2aef5c`** (2026-08-06, = #1717 merged with current main; flat `Vec<u64>` memory, pre-decoded instruction cache, execute-only path, `TRACER_PARALLEL`). Existing read-only worktree: `/Volumes/Dev/worktrees/jolt/merge-1717-main` (same commit as `~/dev/jolt/.worktrees/tracer-100mhz`). Post-#1717 throughput: ~16–26 MHz on example guests (M4). Reference counting harness: `crates/jolt-prover-legacy/examples/trace_bench.rs` (branch-only). | `tracer/src/emulator/memory.rs`, branch commits `785edc12b5`, `b95f4726d1` |
| Keccak inline | **Exists:** `jolt-inlines-keccak256` (opcode 0x0B, funct3 0x00, funct7 0x01 = Keccak-f[1600]). Guest API: `Keccak256::{new, update, finalize, digest}`. Host must link the crate with `features=["host"]` (inventory registration) — works in **trace-only** mode, purely emulator-level. Cost: 64 B digest = 3,680 cycles vs 7,562 software; 2 KiB = 53,880 vs 131,971 (~2–2.5×). | `jolt-inlines/keccak256/`, `examples/sha3-chain/`, `examples/hash-bench/README.md` |
| Other inlines | sha2, blake2, blake3, bigint (256-bit mul), **secp256k1** (field/point ops + `ecdsa_verify` — no ecrecover API), p256, grumpkin. No memcpy inline. | `jolt-inlines/`, `crates/jolt-riscv/src/profile.rs:34-43` |
| No keccak patches exist | No `[patch.crates-io]`, no tiny-keccak/sha3/alloy shims anywhere in the Jolt repo — wiring revm's keccak to the inline is **jeth's job** (§2 D3). | repo-wide grep |
| Prior art in-repo | `examples/sig-recovery`: a guest already compiling `reth-ethereum-primitives` + `alloy` (RLP tx decode + signer recovery), 1 MiB input / 32 MiB heap. Proof the reth crate family builds as a Jolt guest. Use as skeleton template. | `examples/sig-recovery/` |
| std guests | Supported (`guest-std`, musl target, even threads/rayon) — escape hatch if a dep refuses no_std. Prefer no_std. | `book/src/usage/guests_hosts/guests.md` |

### 1.2 Execution-core ecosystem

- **`paradigmxyz/stateless`** (github; successor of reth's `crates/stateless`, which left the reth repo after v1.10.0; crates.io `reth-stateless` is a 0.0.0 placeholder → **git dependency only**):
  - `#![no_std]`; upstream builds it for `riscv64im-unknown-none-elf` with the LLVM `lower-atomic` pass — Jolt's guest recipe (`riscv64imac` + lower-atomic) is a superset. Crates: `stateless`, `tries`, `zeth-mpt`.
  - API: `stateless_validation(current_block: Block, public_keys: Vec<UncompressedPublicKey>, witness: ExecutionWitness, chain_spec: Arc<ChainSpec>, evm_config: E) -> Result<StatelessValidationOutput, _>` (+ `_with_trie` variants; `StatelessTrie` impls: `StatelessSparseTrie` (reth_trie_sparse) or zeth-mpt).
  - Does the **full** job: ancestor-header chain checks, pre-state witness reveal vs parent state root, execution, `validate_block_post_execution` (receipts root, logs bloom, gas used, requests hash), post-state root comparison — exactly the required "state-transition verification".
  - **Sender recovery trick:** host supplies uncompressed pubkeys; guest *verifies* each tx signature against them (`verify_and_compute_signer_unchecked`, low-s check) instead of in-guest ecrecover. Same soundness (a valid sig under pubkey P whose keccak-derived address is used as sender ⟺ ecrecover), cheaper, and it maps onto Jolt's `secp256k1` inline `ecdsa_verify` as a future optimization.
  - `ExecutionWitness` (re-export of `alloy_rpc_types_debug`): `{ state: Vec<Bytes>, codes: Vec<Bytes>, keys: Vec<Bytes>, headers: Vec<Bytes> }` — `keys` is not needed by the sparse-trie path (rsp ignores it; zeth's own proxy emits `keys: []`).
- **zeth (boundless-xyz/zeth, v0.3)** — the existence proof for this architecture on risc0: pins `stateless`+`tries` @ rev `6e55612`, reth git tag `v2.1.0`, revm 38, alloy 2.0; fetches witness via `debug_executionWitness`; passes the block as **RLP bytes** in the input because `Block`'s serde is incompatible with binary serializers (adopt this). Ships `zeth-rpc-proxy` (rebuilds a witness from standard RPC by re-executing — our Tier-2 fallback, §3).
- **rsp (succinctlabs/rsp)** — the other shape (custom executor + own MPT + `eth_getProof` preflight, bincode input, sp1-patches for sha3/k256/bn). Not adopted: more code to own, and its crypto patches are SP1-specific. Reference for: `Crypto`-trait override injecting pure-Rust KZG, per-precompile cycle-tracker spans.
- **revm** (v38 as pinned by reth v2.1/v2.2): `default-features = false` for guests → ecrecover falls back to pure-Rust **k256**; KZG point-eval fallback chain c-kzg → blst → **pure-Rust ark-bls12-381**; bn254 via substrate-bn or ark-bn254; modexp via aurora-engine-modexp. The old `kzg-rs` feature is gone in revm ≥38. Keep every C-backed feature (c-kzg, blst, secp256k1, asm-keccak) OFF; verify with `cargo tree`.
- **alloy-primitives keccak backend precedence** in `keccak256_impl`: `native-keccak` (extern) → `asm-keccak` → default RustCrypto `sha3::Keccak256`; `tiny-keccak` opt-in. The `native-keccak` extern is exactly:

  ```rust
  unsafe extern "C" { fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8); } // writes 32-byte hash
  ```

  (SP1 forks `sha3`; risc0 forks `tiny-keccak`; **Jolt needs neither** — we just define the symbol. §2 D3.)

### 1.3 Mainnet, Aug 2026

- Live fork: **Fusaka (Osaka EL)** since 2025-12-03 (+BPO blob raises). A "very recent block" runs Osaka rules — hence reth v2.x / revm ≥38 pins (Osaka shipped in revm; `SpecId::OSAKA`).
- Gas limit **60M** (raised Nov 2025, EIP-7935 default); typical `gasUsed` ≈ **29.5M avg / 28.7M median / p90 ~48.6M** (sampled blocks 25.65–25.70M, Jul 30–Aug 6 2026).
- Witness size: ~8–17 MB typical (JSON hex roughly 2× binary); adversarial worst case 300+ MB (irrelevant for typical-block benching, but don't hardcode small buffers).

### 1.4 Reference cycle numbers (calibration targets)

| Stack | Crypto accel | Cycles/block | Cycles/gas |
|---|---|---|---|
| zeth 1.0 (risc0, 2023, keccak **not** accelerated) | none | 2–4B (up to 9.5B) | ~130–260 |
| SP1-Reth (2024, patched keccak/k256/sha2) | patched | 240–345M @ 10–26M gas | 13–22 |
| rsp (2025, arXiv 2509.17126, n=100 blocks) | full sp1-patches | avg 290M @ 17.7M gas | avg **16.6** (10.4–26.0) |
| Ethproofs top provers (2026-08, self-reported) | full | 139–247M @ 22–28M gas | **5–11** |
| Software ecrecover/verify (k256, no accel) | — | ~4–5M cycles **per tx** | ~200 txs ⇒ ~1B/block |
| bn254 pairing precompile, software | — | ~155M per pairing call | blowup risk on rollup-settlement blocks |

**jeth v1 prediction** (keccak inline ≈2×, everything else software, host-recovered pubkeys): **~30–120 cycles/gas → ~1–3.5B cycles for a ~29M-gas block**. At the #1717 tracer's ~15–25 MHz: ~1–4 min wall time per trace. No published Jolt-EVM numbers exist — jeth's number is novel.

---

## 2. Design decisions

**D1. Execution core = `paradigmxyz/stateless` + reth v2.x + revm 38 (zeth's exact pin set), not a hand-rolled revm+MPT stack.**
Why: no_std, purpose-built for zkVM guests, complete consensus validation (not just state root), proven inside risc0 by zeth 0.3, maintained by the reth team. Rejected: rsp-style custom `ClientExecutor` (own MPT + more surface to get wrong); raw revm + own witness DB (reimplements everything `tries` already does). Start from zeth's rev `6e55612`; bump only if Osaka-era mainnet blocks demand it (check first that the rev's reth pin executes Osaka; zeth runs it on mainnet today, so it does).

**D2. Trace-only via streaming count on Jolt `merge-1717-main` @ `af1c2aef5c`.**
Why: main's HashMap-backed guest memory makes GB-heap guests pathologically slow; #1717's flat-Vec memory + 12–23× tick loop is required for multi-billion-cycle traces. Streaming (`trace_lazy(...).count()` or the `trace_bench.rs` execute-only harness) avoids 96 B/cycle materialization (2^30 cycles would be ~100 GiB RAM). Cycle markers still fire in this mode (emulator-level `tracing::info` logs, counters from `cpu.trace_len`/`executed_instrs`). Consume Jolt via **path dependencies** into `/Volumes/Dev/worktrees/jolt/merge-1717-main` (read-only; never modify `~/dev/jolt`).

**D3. Keccak → Jolt inline via alloy's `native-keccak` feature + one shim. (The keccak-inline answer: YES, Jolt has it; wiring is trivial.)**
Guest crate:

```toml
alloy-primitives = { version = "…match stack…", default-features = false, features = ["native-keccak", "rlp"] }
jolt-inlines-keccak256 = { path = "<jolt-worktree>/jolt-inlines/keccak256", default-features = false }
```

```rust
/// alloy-primitives (feature "native-keccak") declares this extern and calls it
/// for every keccak256 — trie hashing, tx hashing, EVM KECCAK256 opcode, address derivation.
#[no_mangle]
pub unsafe extern "C" fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8) {
    let data = core::slice::from_raw_parts(bytes, len);
    let digest = jolt_inlines_keccak256::Keccak256::digest(data); // .insn 0x0B/0x00/0x01 Keccak-f[1600]
    core::ptr::copy_nonoverlapping(digest.as_ptr(), output, 32);
}
```

Host binary links `jolt-inlines-keccak256 = { …, features = ["host"] }` (+ `extern crate jolt_inlines_keccak256 as _;`) so the inline's opcode is inventory-registered with the tracer — without this the emulator panics "No inline registered". Expected effect: ~2–2.5× on all hashing (hashing is typically ~⅓–½ of unaccelerated block cycles). No sha3/tiny-keccak forks, no `[patch.crates-io]`. Verify at build time that the `sha3` crate is absent from the guest `cargo tree` (feature precedence: `native-keccak` must not be shadowed by `sha3-keccak`/`tiny-keccak`/`asm-keccak`).

**D4. Witness source = hosted `debug_executionWitness`, tiered (§3).** The method is no longer reth-only (geth ≥1.16.4, erigon ≥3.5.0) — free public endpoints serve it near-head *today*, live-verified. Cherry-hosted reth is the specced last resort, not the default path.

**D5. Input format = postcard over a `GuestInput` struct; block as RLP bytes.**

```rust
// crates/core (shared host+guest, no_std)
pub struct GuestInput {
    pub block_rlp: Vec<u8>,          // alloy Block: RLP — its serde is binary-codec-hostile (zeth learned this)
    pub witness: ExecutionWitness,   // {state, codes, keys, headers}: Vec<Bytes> — postcard-friendly
    pub pubkeys: Vec<[u8; 65]>,      // host-recovered uncompressed pubkeys, tx order
}
```

Why postcard: it's what Jolt's macro-generated guest main already uses (`postcard::take_from_bytes` per arg); Vec<Bytes> deserialization is near-memcpy. Measure deserialize cost with a cycle marker; if it exceeds ~15% of total, switch the witness blob to rkyv/zero-copy (documented fallback, not v1).

**D6. Guest sizing:** `#[jolt::provable(max_input_size = 33554432 /* 32 MiB */, max_output_size = 4096, heap_size = 1073741824 /* 1 GiB */, stack_size = 33554432 /* 32 MiB */)]`. Rationale: input ~10–15 MB observed; decoded witness + sparse trie + revm state for a 29M-gas block needs high-hundreds-MB heap (zeth/rsp comparable); all guest addresses stay < 4 GiB (cycle-marker u32 caveat, §1.1); #1717 flat memory allocates heap upfront → ~1.1 GB host RAM, fine. `max_trace_length` left default — unused when tracing.

**D7. Chain config hardcoded to mainnet in-guest** (`reth-chainspec` MAINNET / `ChainSpec` const) rather than shipped in the input — smaller input, no serde pain, and a mainnet-only tool is the stated goal.

**D8. Metrics definition (what we report):**
- **Primary: total Jolt trace length** (rows = real RV64IMAC instructions + virtual-sequence/inline expansions) — this is the prover-relevant "cycles" and what `trace_lazy().count()` returns. **cycles/gas = trace_len / header.gasUsed.**
- Secondary: real RV64IMAC instruction count (`executed_instrs`), wall time, tracer MHz.
- Phase breakdown via markers: `deserialize`, `witness_reveal` (pre-state MPT), `execute` (txs), `post_root` (state-root recompute), `sig_verify` if separable.
- Report per-block; if time allows, 3 blocks (low/median/high gas) for variance.

---

## 3. Witness acquisition (first-class)

Getting a real `ExecutionWitness` for a **very recent** block. Tiers in order; try next tier only on failure. The compatibility gate for any source is M2's *native* validation run (§5), which proves a witness actually satisfies `stateless_validation` before any guest work.

### Tier 1 — free hosted endpoints (VERIFIED live 2026-08-06, use first)

`debug_executionWitness` shipped in geth v1.16.4 (PR #32216) and erigon 3.5.0 — hosted geth nodes now serve it where the debug namespace is open:

```bash
# QuickNode public demo endpoint (geth v1.17.5) — returned a full 13 MB witness
# for block 25,697,697 (8 blocks from head) at 2026-08-06 14:28 ET. Rate limit ~1 req/s.
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"debug_executionWitness","params":["0x1881da1"]}' \
  https://docs-demo.quiknode.pro/

# BlockPI public gateway (geth v1.17.5) — same block, same shape; serves near-head only
# (block older than ~5000 → "missing trie node").
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"debug_executionWitness","params":["latest"]}' \
  https://ethereum.public.blockpi.network/v1/rpc/public
```

Response: `{state: [hex…], codes: […], keys: […], headers: [RLP hex…]}` — exactly alloy's `ExecutionWitness`. Notes: `keys` population varies by node (QuickNode 2000 entries, BlockPI 0) — harmless, the sparse-trie path ignores `keys`. Cached samples from today: `/tmp/qn_witness.json`, `/tmp/bp_witness.json` (block 25,697,697; copy into `data/` on M1 day 1 — /tmp is volatile). Providers that run reth but block the method (checked): Flashbots, BlastAPI, Nodies, merkle.io, Chainstack (explicitly disabled), dRPC, Alchemy, Tenderly, PublicNode, 1RPC. Endpoints are undocumented passthroughs → treat as fragile: the host fetcher takes an ordered endpoint list and fails over.

Bootstrap fixture (M2 bring-up only): zeth's in-repo testdata witness for block 23,446,528 (Sep 2025, 16 MB JSON, guaranteed stateless-crate-compatible). **Final numbers must come from a genuinely recent block via Tier 1–3.**

### Tier 2 — witness generation without a witness-serving node

- **`zeth-rpc-proxy`** (in boundless-xyz/zeth): local proxy that re-executes the block against any standard RPC (`eth_getProof`/`eth_getCode`/`eth_getStorageAt`/`eth_getBlockBy*`) and serves `debug_executionWitness` itself, built on the same `paradigmxyz/stateless` types → guaranteed-compatible witness. Needs the state at parent block → any full node works for blocks ≤128 old (Alchemy/QuickNode free tiers fine). Run: `ETH_RPC_URL=… cargo run --release --bin zeth-rpc-proxy`, point jeth at `127.0.0.1:8545`.
- ethPandaOps runs client-pinned mainnet **reth** endpoints (`reth.mainnet.{eu1,na1}.ethpandaops.io`) behind Cloudflare Access — token by request; whether the gateway passes debug_* is unverified.
- Known pitfall of `eth_getProof`-assembled witnesses generally: trie-deletion edge cases can omit nodes needed for post-root recomputation (orphan-node problem). zeth-rpc-proxy handles this (it collects nodes from actual re-execution); avoid naive hand-rolled assembly.

### Tier 3 — self-hosted reth on Cherry Servers (approved fallback; spec)

Only if Tiers 1–2 die. Requires a Cherry Servers account/API token.

- **Hardware** (from Cherry's live plans API, 2026-08-06): Ryzen 9700X — 8c/96 GB/2×1 TB NVMe, **€189/mo** (~$221, US-Chicago stock) is sufficient; Ryzen 9950X — 16c/192 GB/2×1 TB NVMe/10 Gbps, €389/mo if we want headroom. Hourly billing available (~€16/day) — spin up, sync, bench, tear down. Avoid their spot tier (legacy Xeons, 2-min termination).
- **Software:** reth **full node (pruned — archive NOT needed)** + Lighthouse with checkpoint sync (~1–2 min to head; ~250–350 GB incl. blobs). reth full ≈ 1.02 TB (measured at block 24.4M, Storage V2) — total fits 2 TB with ~30% slack.
- **Sync time:** `reth download --full` snapshot route → **~1 day to operational** (snapshot ~170+ GB download + staged sync); genesis sync fallback 2–4 days. Budget "days, not hours" end-to-end.
- **Why pruned suffices:** reth serves `debug_executionWitness` on a full node for the last **10,064 blocks (~33.5 h)** (`MINIMUM_UNWIND_SAFE_DISTANCE`) — it re-executes on parent state, which a pruned node retains within that window. jeth targets blocks minutes-old → comfortably inside.
- **Cost envelope:** €189–389/mo (or ~€16–35/day hourly) + ~1 day sync latency.

**Geth-vs-reth witness compatibility risk:** the JSON shape is identical and `headers` are RLP either way (verified empirically); byte-level node-set equivalence is unproven. Gate: M2 native validation against a Tier-1 witness on day 1. If geth's node set proves insufficient for `stateless_validation`, drop to Tier 2 (zeth-rpc-proxy, same-crate-guaranteed) without touching the guest.

---

## 4. Repo layout and pins

```
jeth/
├── PLAN.md                     # this file
├── RESULTS.md                  # M3 deliverable
├── Cargo.toml                  # workspace
├── crates/
│   ├── core/                   # no_std shared: GuestInput, validate() wrapper over stateless_validation
│   ├── guest/                  # jolt guest: lib.rs (#[jolt::provable] fn) + src/main.rs stub (see examples/sig-recovery)
│   └── host/                   # bin `jeth`: fetch | run-native | trace | report subcommands
├── data/<block>/               # gitignored: witness.json, input.bin, meta.json
└── fixtures/                   # ONE committed input.bin for repro/CI (~10-15 MB, acceptable)
```

Pins (start = zeth 0.3's proven set; deviate only with a reason written into RESULTS.md):
- `stateless`, `tries`: git `paradigmxyz/stateless` rev `6e55612`
- reth crates: git tag `v2.1.0`; `revm = 38`, `default-features = false`; `alloy` 2.0.x; `alloy-primitives` with `native-keccak` (version = whatever the reth pin resolves; the feature exists in the 1.5+/1.6 line)
- `jolt-sdk`, `jolt-inlines-keccak256`: **path deps** → `/Volumes/Dev/worktrees/jolt/merge-1717-main` (commit `af1c2aef5c`; read-only)
- Host: `alloy-provider`/`alloy-rpc-client` (or raw `reqwest` + serde) for the two RPC calls; `postcard`, `clap`, `tracing-subscriber`
- Toolchain: match Jolt's `rust-toolchain.toml` (1.95); guest built through the `jolt` CLI / macro machinery from that branch

Forbidden in guest `cargo tree`: `c-kzg`, `blst`, `secp256k1`(C), `keccak-asm`, `sha3`(as the active keccak backend), `getrandom`(without the custom-backend cfg), `std`.

---

## 5. Milestones (staged for one fable-max implementer agent)

### M1 — skeleton + host witness fetcher (~½ day)
1. Workspace + crates as §4; commit granularity: one commit per milestone minimum.
2. `jeth fetch [--block N | --latest-minus 8] [--rpc-list url,url]`:
   - `eth_getBlockByNumber` (full txs) → header + body; `debug_executionWitness(N)` with endpoint failover (Tier 1 list default);
   - recover per-tx uncompressed pubkeys host-side (alloy `recover_signer` → pubkey; handle all Osaka tx types incl. 7702);
   - assemble `GuestInput`, postcard → `data/<N>/input.bin`; save raw witness JSON + `meta.json` (gasUsed, txCount, witness element counts/bytes).
3. Copy `/tmp/{qn,bp}_witness.json` into `data/` as cached samples before they evaporate.
- **Accept:** `input.bin` + stats for a block ≤1 h old, from a free endpoint, in one command.

### M2 — guest compiles; native validation passes (~1–2 days, the friction milestone)
1. `crates/core::validate(input: GuestInput) -> ValidationReport` calling `stateless_validation` (mainnet chainspec, `EthEvmConfig`), returning post-root/gas; panics on any check failure.
2. `jeth run-native --input data/<N>/input.bin`: runs `validate` natively (x86/arm) — **the witness-compatibility gate**: header state root must match. Debug any geth-witness gaps here (fallback: Tier 2 proxy).
3. Guest crate: `#[jolt::provable]` wrapper over the same `core::validate`, sizing per D6; `native_keccak256` shim per D3; cycle markers per D8; no_std throughout (`guest-std` musl is the documented escape hatch).
4. Build to RV64IMAC via the Jolt branch toolchain; iterate until `cargo tree` is clean of forbidden deps and the ELF links.
- **Accept:** (a) native run validates a real recent block end-to-end; (b) guest ELF builds. (Bring-up on the zeth fixture or cached samples is fine *for (b)*; (a) must use a fresh Tier-1/2 block.)

### M3 — trace + report (~½ day)
1. `jeth trace --input data/<N>/input.bin`: drive the tracer from `merge-1717-main` — streaming count (`trace_lazy(...).count()` or a `trace_bench.rs`-style execute-only harness; `RUST_LOG=info` to capture marker lines), never a materializing `trace_*` call.
2. First smoke-trace a truncated workload if useful (e.g. fixture block), then the real recent block.
3. `jeth report` → `RESULTS.md`: block number & age, gasUsed, tx count, witness size, **total trace cycles, cycles/gas**, real-instr count, phase table (deserialize / witness-reveal / execute / post-root / sig-verify), wall time + effective MHz, machine, jolt commit. Sanity-check against §1.4 (30–120 c/g expected; <10 or >500 ⇒ investigate before reporting).
4. Stretch: 3 blocks (low/median/high gas) for variance.
- **Accept:** RESULTS.md with a genuinely-recent block's cycles + cycles/gas, guest having asserted the full state transition.

### Stretch (post-v1, do not start unproposed)
secp256k1 inline for sig-verify (swap `verify_and_compute_signer_unchecked`'s k256 with inline `ecdsa_verify` — biggest single win, ~1B cycles at stake); bigint inline into modexp/bn254 hot paths; rkyv zero-copy input; `TRACER_PARALLEL`; then an actual proving feasibility memo (segmenting a 2–3B-cycle trace against the ~2^29–2^30 practical proving ceiling).

---

## 6. Risks (ranked)

1. **Geth-witness ↔ `stateless` crate node-set mismatch** — gated day-1 by M2 native run; Tier 2 proxy is same-crate-guaranteed; Tier 3 reth is the hard floor. *Medium likelihood, low residual impact.*
2. **no_std build friction on riscv64imac** (getrandom custom backend, ark-bls12-381 pulling rand, C crates sneaking in via default features, linker limits on a ~10 MB+ rodata guest) — mitigations: zeth's Cargo.toml as the reference no_std feature set; `sig-recovery` example as the known-good Jolt-side template; `guest-std` musl escape hatch. *High likelihood of 1-day slip, low terminal risk.*
3. **Precompile-heavy block skews the number** (one bn254-pairing-heavy rollup-settlement tx ≈ +155M cycles software) — report per-block, choose a median-gas block, note composition in RESULTS.md. *Certain variance, reporting-level handling.*
4. **Tracer branch instability** (`merge-1717-main` is a merge branch, not reviewed-merged main) — golden-trace equivalence gate exists on the branch; pin the exact commit; fall back to main's tracer only for small smoke tests (it's correct, just slow).
5. **Emulator wall-clock/RAM surprise at 3B+ cycles with 1 GiB flat guest memory** — trace_lazy streams (no trace RAM); flat memory is a one-time 1.1 GB alloc; at worst hours, not days. If the marker u32 issue or memory sizing bites, shrink heap / drop markers (total count unaffected).
6. **Endpoint fragility** (undocumented free endpoints get gated) — fetch early, cache `input.bin` into `fixtures/`, three independent tiers.

---

## 7. References

- Jolt repo facts: local `~/dev/jolt` @ `fbb45f92e9` (paths inline above); branch `merge-1717-main` @ `af1c2aef5c`; worktree `/Volumes/Dev/worktrees/jolt/merge-1717-main`.
- paradigmxyz/stateless — github.com/paradigmxyz/stateless (validation.rs, tries/src/lib.rs, README riscv64im note).
- zeth — github.com/boundless-xyz/zeth (guest Cargo.toml = pin reference; crates/rpc-proxy; testdata fixture block 23,446,528).
- rsp — github.com/succinctlabs/rsp (rpc-db preflight, custom.rs Crypto override, FAQ on eth_getProof providers).
- alloy native-keccak — github.com/alloy-rs/core, crates/primitives/src/utils/mod.rs.
- geth debug_executionWitness — go-ethereum v1.16.4 release notes / PR #32216; erigon 3.5.0 ChangeLog.
- reth pruning/witness window — reth.rs/run/storage/pruning (10,064-block witness window); reth.rs/run/storage (disk sizes); snapshots page.
- Cycle calibration — blog.succinct.xyz/sp1-reth; arXiv 2509.17126 §5.3; ethproofs.org/blocks; zeth-release post (Wayback); blog.succinct.xyz/succinctshipsprecompiles (bn254/KZG patch deltas).
- Cherry Servers plans — api.cherryservers.com/v1/plans (9700X €189/mo, 9950X €389/mo, 2026-08-06).
- Mainnet context — EF Fusaka announcement (Dec 3 2025); gaslimit.pics (60M); execution-apis PR #773 (witness ~17 MB avg JSON).
