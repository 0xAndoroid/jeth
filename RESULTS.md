# jeth results — Jolt-tracing full Ethereum mainnet blocks

**Headline (after the optimization campaign): recent mainnet blocks validate inside the
Jolt RV64IMAC guest at 34.5–42.7 cycles/gas fully self-verifying, 28.0–36.9 cycles/gas
with trusted-advice witness digests — down from 62–85 at v1 (2.0–2.4× fewer rows), and
from 513 before the allocator fix (12–15× total).**

Run date: 2026-08-06. First published Jolt-zkVM full-EVM-block numbers. All runs on an
Apple M4 (10-core, 16 GB), tracer = Jolt branch `merge-1717-main` @ `af1c2aef5c`,
execute-only streaming counts (no trace materialization, no proving).

The guest does the complete state-transition check, not tx replay: ancestor-header chain
verification, pre-state witness reveal against the parent state root (MPT), full tx
execution under revm, receipts/bloom/gas/requests consensus checks, and
`computed_post_state_root == header.state_root`. Panic on any check = failed run. Per-tx
signatures verified in-guest against host-recovered pubkeys (soundness-equivalent to
ecrecover, cheaper). Every guest output hash matched an independent native
`stateless_validation` run bit-for-bit on every block and every configuration.

## Current numbers (5 recent mainnet blocks, 2026-08-06)

| block | gas used | txs | **self-verifying c/g** | rows | **trusted-digests c/g** | rows |
|---|---|---|---|---|---|---|
| 25698189 | 41,932,456 | 415 | **34.49** | 1,446.3M | **27.97** | 1,172.8M |
| 25697951 | 43,118,232 | 331 | 36.21 | 1,561.4M | 30.42 | 1,311.4M |
| 25698026 | 31,842,749 | 483 | 37.14 | 1,182.7M | 30.12 | 959.2M |
| 25698070 | 57,999,343 | 1312 | 42.69 | 2,476.3M | 36.93 | 2,142.1M |
| 25698208 | 56,690,935 | 1291 | 36.19 | 2,051.7M | 30.68 | 1,739.5M |

- **Self-verifying** (`jeth trace`): everything proven from committed input alone — the
  headline configuration.
- **Trusted-digests** (`jeth trace --trusted-digests`): witness-node keccaks + code
  hashes are precomputed on the host and delivered as Jolt TRUSTED ADVICE; the reveal
  phase skips hashing the witness entirely. *Soundness caveat:* trusted advice is
  verifier-attested input in Jolt's model, so the statement weakens to "this block is
  valid GIVEN this node-digest map" — appropriate when the verifier (e.g. the proving
  customer) independently possesses the witness. A wrong digest either breaks the reveal
  (panic) or substitutes node content — exactly the trust granted, no more: the
  pre-state root still anchors which digests are reachable.
- Input delivery via plain trusted advice (whole payload, `--advice`) is **bit-identical**
  in trace rows to committed input (measured: 2,017,685,830 both ways at an earlier
  checkpoint) — advice saves prover-side commitment cost, zero guest cycles.

## Optimization ladder (block 25698189, per-step attribution)

| step | mechanism | rows | c/g |
|---|---|---|---|
| v0 stock | linked-list first-fit allocator ate 85.7% of instrs | 21,505M* | 513 |
| + O(1) size-class allocator | cargo [patch] of ZeroOS dep ([PR #1746](https://github.com/a16z/jolt/pull/1746)) | 2,658M | 63.4 |
| + secp256k1 inline sig-verify | jolt ecdsa_verify (GLV 4×128); 1.77M → 230k rows/tx | 2,018M | 48.1 |
| + inline ecrecover precompile | revm `Crypto` override, same inline (sqrt + GLV ladder) | 1,751M | 41.8 |
| + word-wise revm `Stack::exchange` | `swap_nonoverlapping` emitted ~128 byte-ops/SWAP; SWAP1-16 = 16.9% of ALL rows | 1,448M | 34.5 |
| + word-wise memcpy/memset/memcmp | −12M only: compiler_builtins already word-copies; volume is the lever | 1,436M | 34.3 |
| + vendored trie (digest hook) | measurement noise +10M | 1,446M | 34.5 |
| + trusted-digest reveal (opt-in) | reveal keccak (81,198 perms) skipped via advice | 1,173M | **28.0** |

\* v0 extrapolated from the 58M-gas block ratio; the allocator finding was measured there (29.76B → 4.94B).

**The two structural insights of the campaign:**
1. **Jolt expands every sub-word (byte/half) memory access into a multi-row virtual
   sequence**, and riscv64imac (no `unaligned-scalar-mem`) makes LLVM lower untyped/
   align-1 copies to byte loops — so any byte-granularity code is silently 5–10× its
   apparent cost. `ptr::swap_nonoverlapping` (untyped since the padding-soundness
   change) turned every EVM SWAP into ~600+ rows. One typed-copy patch: −301M rows.
2. **Keccak-f is the single biggest row consumer**: 52,211 calls / 141,301 permutations
   = 478M rows (33%) at ~3,383 rows/permutation with the current inline. Fully
   attributed: reveal 81,198 perms / post-root 30,177 / execution 24,910 / sigs 2,547.

## Where rows go now (25698189, self-verifying, 1,446M rows — exact row attribution)

| rows | share | component |
|---|---|---|
| 478.1M | 33.1% | keccak256 inline (141,301 perms; see split above) |
| 275.5M | 19.0% | memcpy — callers: zeth-mpt `Node::decode` 129M, `NodeRef::encode` 41M, postcard input deserialize 21M, `resolve_digests` 20M, keccak shim 12M |
| ~130M | 9.0% | zeth-mpt node decode/encode/resolve/memoize/drop (own rows; nibble unpacking is an intrinsic sub-word storm) |
| 78.7M | 5.4% | sig-verify (secp256k1 inline, 415 txs) |
| 65.4M | 4.5% | revm handler loop (frame init, dispatch) |
| 50.9M | 3.5% | revm mstore/mload |
| 43.0M | 3.0% | allocator (O(1) — was 85.7% of everything at v0) |
| 39.7M | 2.7% | `analyze_legacy` — eager bytecode analysis of all 462 witness codes |
| 35.6M | 2.5% | ecrecover precompile (GLV ladder) + k256 (EIP-7702 authority recovery) |
| 23.4M | 1.6% | memcmp + memset |
| ~226M | 15.6% | everything else: interpreter arithmetic/push/dup, revm journal/state, trie logic, RLP, deserialize remainder |

## Cycle-attribution deep dive (2026-08-06, `jeth txprofile` + `--split-markers`)

Full report: `~/.pika/web/reports/jeth-cycle-attribution-2026-08.html`. New tooling:
`jeth txprofile` (per-tx cycles × native receipts), `jeth profile --split-markers
--json` (exact marker × symbol row matrix), `scripts/aggregate_profile.py`.

**Phase × component matrix (25698189, self-verifying, 1,446M rows):**

| phase | rows | top components |
|---|---|---|
| deserialize | 30.7M (2.1%) | postcard 4.4M + memcpy ~21M |
| sig_verify | 103.2M (7.1%) | secp inline 78.7M, sig-hash keccak+RLP rest |
| witness_reveal | 451.7M (31.2%) | keccak 273.3M, memcpy 66.8M, mpt 41.7M, analyze_legacy 39.8M, maps 16.8M |
| execution | 587.3M (40.6%) | memcpy 129.4M, **mpt 72.5M**, handler 66.7M, keccak 53.6M, mstore/mload 51.0M, journal 37.3M, PUSH 24.9M, k256-7702 23.5M, ecrecover 22.9M, ark-bn254 15.5M |
| post_root | 188.7M (13.0%) | keccak 102.0M, memcpy 56.4M, mpt 25.0M |
| glue (block hash, tx-root merkle, consensus, bundle) | ~84.6M (5.9%) | keccak ~40M, memcpy ~26M |

**Per-tx findings (whale question):** 25698189 has NO whale — top tx 6.4% of
execution cycles, top-10 = 37.5%. But 25698070 (the 42.7 c/g outlier) DOES:
**two EIP-7702 batch txs = 49% of execution cycles, 86% of that inside k256
software ecrecover** — 396M rows (16.0% of the whole block) recovering
authorization-list authorities. High-c/g "normal" txs (USDT/USDC transfers at
380–580 c/g, 46–54k gas) are all first-touch **storage-trie materialization**:
`RlpTrie::from_prehashed` decode/resolve storms — i.e. ~⅔ of the MPT cost hides
in the execution phase, not the reveal marker.

**Guest crypto audit:** ecrecover precompile + tx sigs = Jolt secp inline (good);
**7702 authority recovery = k256 software** (alloy-eip7702 hardwired — the one
big crypto gap, patchable like revm-interpreter); bn254 add/mul/pairing =
arkworks software (15.5M for one pairing tx); KZG point-eval = ark-bls12-381
(linked, not hit); modexp = aurora (1.6M); sha256/ripemd/blake2 = software
compress (≤0.2M, negligible); keccak fully routed through the inline — no
double-hashing found.

**Jolt bigint inline audit:** `jolt-inlines-bigint` ships exactly one op —
`bigint256_mul` (256×256→512, ~145 rows). ruint exposes no override hooks, so
wiring needs a guest `[patch]` of ruint or the vendored revm-interpreter.
Measured EVM 256-bit math surface: MUL 0.50M + EXP 0.32M + DIV 0.25M +
`div_rem` 1.27M + `mul_mod` 0.21M ≈ **2.6M rows (0.18%) — not worth it** for
EVM opcodes alone. The real 256-bit mul volume sits inside k256 (23–396M) and
ark-bn254 (15.5M) field muls — better served by curve-level inlines.

**R2 (lazy bytecode analysis) is measured DEAD:** geth witness codes ≈ executed
codes (`analyze_legacy` rows bit-identical eager vs lazy), and the lazy variant
REGRESSED +62.7M rows from outlined `IndexMap::get` in the digest-resolution hot
path. `--guest-features lazy` kept as documentation. Replacement: R7
advice-carried jump tables (−30–40M).

**Updated lever ranking (self-verifying, 25698189):**

| # | lever | saving | c/g | side |
|---|---|---|---|---|
| 1 | R4 keccak-f inline (3,383 → ~1.2k rows/perm; SP1-class ~500) | −308M … −408M | −7.4 … −9.7 | upstream |
| 2 | R1 zero-copy/arena zeth-mpt (reveal + **exec materialization** + post_root) | −180 … −230M | −4.3 … −5.5 | app |
| 3 | 7702 authority → secp inline (patch alloy-eip7702) | −18M here; **−330M / −5.7 c/g on 25698070**; kills c/g variance | −0.4 … −5.7 | app |
| 4 | R5 memcpy/memmove inline (residual after R1) | −80 … −120M | −2 … −3 | upstream |
| 5 | R3 interpreter fat (handler 66.7M + mem ops 51M + stack ops 36M) | −40 … −70M | −1 … −1.7 | app |
| 6 | R7 advice jump tables (replaces dead R2) | −30 … −40M | −0.8 | app |
| 7 | bn254 inline family | −10 … −14M (workload-dep) | −0.3 | upstream |
| 8 | bigint256_mul for EVM arithmetic | −1 … −2M | −0.05 | skip |

**Halving verdict (34.5 → ≤17.25):** achievable, but only with the upstream
keccak-f rework. Conservative R4 (1.2k rows/perm) + R1 + R5 + R3 + 7702 + R7 ≈
**16.5–17.5 c/g**; SP1-class keccak pushes ≈ **14–15**. App-side-only floor is
~25–27 c/g — no path to 17 without R4. Same stack takes trusted-digests
28.0 → **13–15 c/g**.

## Quartering plan — status and remainder

Target set by user: ~10 c/g (≈420M rows for block 25698189). Achieved so far: 41.7 →
34.5 (self) / 28.0 (trusted). Executed: allocator, secp inlines ×2, stack exchange,
mem overrides, trusted-digest reveal. Ranked remainder:

| # | item | est. saving (self) | effort | mechanism / notes |
|---|---|---|---|---|
| R1 | Zero-copy / nibble-packed zeth-mpt fork | −180–220M (−4–5 c/g) | days | Nodes reference witness `Bytes` ranges instead of owned copies; nibble paths packed 2/byte and manipulated word-wise; encode into reused arena buffers. Attacks the 129M decode-memcpy + 66M decode + 41M encode + drops. |
| R2 | Lazy bytecode analysis | −25–40M (−0.8 c/g) | hours | Defer `analyze_legacy` to first execution per code (upstream stateless HEAD does this; needs witness_db fork since the map type is fixed by the trait). |
| R3 | revm interpreter fat | −50–70M (−1.5 c/g) | days | Remaining push/dup/mload/mstore + dispatch + gas-accounting paths; same typed-copy discipline as the SWAP fix. Diminishing returns. |
| R4 | **Jolt-level: cheaper keccak-f inline** | −280–340M self / −60–90M trusted (−7–8 c/g) | upstream | 3,383 rows/perm today. A tighter virtual sequence or lookup-table-native keccak (SP1/risc0 precompiles land ≪1k row-equivalents) is the single biggest remaining lever. Benefits every Jolt EVM/storage workload. |
| R5 | Jolt-level: memcpy/memmove inline | −120–180M (−3–4 c/g) | upstream | Word-streaming copy instruction; kills residual memcpy + the copy halves of decode/encode. |
| R6 | Jolt-level: `unaligned-scalar-mem` support | opens R1-lite | upstream | If the RAM model tolerated unaligned word ops (even at 2–3 rows), LLVM could be told `+unaligned-scalar-mem` and ALL byte-storm codegen (RLP, nibbles, revm memory) collapses without app forks. |
| R7 | Advice-carried bytecode jump tables | −20–30M | research | Analysis is deterministic and cheaply spot-checkable; weaker trust than R2 with same effect. |

**Honest floor estimates for this stack** (M4-measured shares, block 25698189):
- App-level only (R1+R2+R3): self ≈ 1,130M ≈ **27 c/g**; trusted ≈ 860M ≈ **20.5 c/g**.
- + Jolt-level keccak + memcpy inlines (R4+R5): self ≈ **15–17 c/g**; trusted ≈ **11–13 c/g**.
- **~10 c/g is reachable for the trusted-digest variant with upstream inline work
  (R4+R5±R6) plus R1** — not from app-level changes alone. The fully self-verifying
  path floors around 14–16 c/g while keccak-f costs ~3.4k rows; a precompile-grade
  keccak brings it to ~11–12.

## Proving memo (no prove performed)

What proving one of these blocks would take, parameterized — **a16z/jolt has no CUDA
backend on main today** (`specs/clean-slate-prover.md` explicitly scopes GPU out,
defining only the backend seam), so GPU numbers are stated as throughput assumptions,
not measurements.

- **Trace sizes:** 0.96–2.48B rows/block (both variants, this set). `max_trace_length`
  default is 2^24 (16.8M); practical single-proof ceilings discussed in-repo are
  ~2^29–2^30. → a 1.45B-row block is ~2^30.4: **1–2 proofs at the absolute ceiling, or
  more realistically 22–87 segments** at 2^26–2^24 rows/segment, proved independently
  and aggregated (segment recursion/continuations — not yet a jolt-main feature; the
  dory commitment + sumcheck stack parallelizes per segment naturally).
- **Latency at throughput R (aggregate rows/s across devices):**
  | R | block 25698189 self (1.45B) | trusted (1.17B) |
  |---|---|---|
  | 0.5 MHz (single big CPU, order-of-magnitude for current CPU provers) | ~48 min | ~39 min |
  | 5 MHz (one modern datacenter GPU, plausible first CUDA target) | ~4.8 min | ~3.9 min |
  | 40 MHz (8 GPUs or one optimized-kernel GPU) | ~36 s | ~29 s |
  | 120 MHz (real-time: 12 s slot) | 12 s | ~10 s |
- **Real-time framing:** at today's row counts, real-time mainnet proving needs
  ~100–200M rows/s aggregate. Every c/g point removed cuts that linearly — the
  quartering campaign is the prerequisite, not an optimization afterthought: at 10 c/g a
  42M-gas block is ~420M rows → ~35M rows/s for real-time, i.e. a single-digit GPU
  count at plausible CUDA throughputs.
- **Memory:** flat guest memory (1.5 GiB heap) is preprocessing-visible but per-segment
  witness generation dominates prover RAM; per-segment at 2^26 rows lands in the
  tens-of-GB class on GPU (unmeasured — flag, don't trust).
- Comparison anchor: Ethproofs-class stacks (SP1/risc0 lineage) prove 150–250M-row
  blocks in <12 s on ~100+ GPU clusters; their row counts benefit from
  precompile-grade keccak — exactly R4.

## Setup

- **Stack:** `paradigmxyz/stateless` @ `6e55612` (+ `tries`, `zeth-mpt`) over reth
  v2.1.0 / revm 38 / alloy 2.0 (zeth 0.3's pin set); minimal Fusaka mainnet spec
  (Osaka + BPO1/BPO2), no genesis JSON in-guest.
- **Trie:** vendored `zeth-mpt`-backed `SparseState` (`crates/core/src/zeth_trie.rs`) —
  the default reth `StatelessSparseTrie` rejects geth/proxy witnesses (missing storage
  exclusion proofs); the zeth MPT proves absence from the revealed partial trie.
  Vendored to add the trusted-digest hook; behavior without digests is identical.
- **Inlines:** `jolt-inlines-keccak256` via alloy `native-keccak` shim;
  `jolt-inlines-secp256k1` for tx sig-verify AND the ecrecover precompile (revm
  `Crypto` override, k256-exact semantics incl. high-s normalize + recid flip).
- **Patches (guest workspace only):** ZeroOS allocator → `crates/alloc-o1` (O(1)
  size-class; upstreamed as [jolt#1746](https://github.com/a16z/jolt/pull/1746));
  revm-interpreter 35.0.1 → `crates/vendor/revm-interpreter` (typed `Stack::exchange`).
- **Guest:** no_std RV64IMAC, 32 MiB input / 1.5 GiB heap / 32 MiB stack; postcard
  input `{block RLP, pubkeys, witness}`; word-wise memcpy/memset/memcmp overrides;
  no-op critical-section provider.
- **Witnesses:** free hosted geth `debug_executionWitness` (QuickNode docs-demo; BlockPI
  serves JSON-object headers my fetcher skips), `zeth-rpc-proxy`→publicnode as Tier 2.
- **Profilers built for this work** (`jeth profile`): PC-sampling real-instruction
  histogram; `--rows` exact row attribution (every tick's row delta incl. inline
  expansions charged to the executing symbol); `--callers-of X` return-address
  attribution, composable with `--rows`. Plus in-guest keccak counters and phase markers
  (deserialize / sig_verify / witness_reveal / execution / post_root).

## Reproduce

```bash
cargo run --release -p jeth-host -- bench                       # fetch head−8 → native gate → trace
cargo run --release -p jeth-host -- trace --input data/<N>/input.bin [--trusted-digests]
cargo run --release -p jeth-host -- profile --input data/<N>/input.bin --rows [--callers-of SYM]
```

One-time: build the Jolt CLI from `merge-1717-main`
(`CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jolt-cli cargo build --release -p jolt`),
or point `JOLT_PATH` at any `jolt` binary from that branch.

## Notes & caveats

- Tracing only; `max_trace_length` is enforced at prove time and irrelevant here.
- `witness.keys` ignored (as in zeth/rsp); deserialize ≈ 30M rows (1.5–2%).
- sig-verify covers signature checks + sender derivation (EIP-2 low-s enforced); the
  ecrecover override mirrors revm/k256 edge semantics and is self-checked by the
  post-state-root assertion on every block.
- 7702 authority recovery still uses k256 (~13M rows) — alloy-consensus's crypto isn't
  pluggable like revm's; candidate for the same inline treatment.
- The 5 blocks are contiguous-era (one busy afternoon, 31.8–58M gas, DEX-heavy);
  composition variance is visible (SWAP-heavy block 25698070 runs hottest per gas).
