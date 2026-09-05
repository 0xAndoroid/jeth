# jeth results — Jolt-tracing full Ethereum mainnet blocks

**Headline (after Workstream A — JEF zero-parse input, 2026-08-18): recent mainnet
blocks validate inside the Jolt RV64IMAC guest at 28.2–30.5 cycles/gas fully
self-verifying, 21.6–24.1 cycles/gas with trusted-advice witness digests — down from
28.9–31.2 / 22.3–24.8 after campaign 3, 34.5–42.7 at campaign 1, 62–85 at v1, and
513 before the allocator fix. Campaign 3 replaces the eager `rlp_by_digest`-map MPT
pipeline with untrusted runtime advice: advice-indexed digest resolution, byte-walk
storage reads over raw witness RLP, on-demand post-root materialization, and a
sealed-length arena encoder (all advice locally verified in-guest; trust model
unchanged).**

Run date: 2026-08-18. First published Jolt-zkVM full-EVM-block numbers. All runs on an
Apple M4 (10-core, 16 GB), tracer = Jolt branch `merge-1717-main` @ `af1c2aef5c`,
execute-only streaming counts (no trace materialization, no proving). Traces are
two-pass since campaign 3: a `compute_advice` ELF populates the byte-FIFO advice tape
(rows never counted), then the proven ELF consumes it.

The guest does the complete state-transition check, not tx replay: ancestor-header chain
verification, pre-state witness reveal against the parent state root (MPT), full tx
execution under revm, receipts/bloom/gas/requests consensus checks, and
`computed_post_state_root == header.state_root`. Panic on any check = failed run. Per-tx
signatures verified in-guest against host-recovered pubkeys (soundness-equivalent to
ecrecover, cheaper). Every guest output hash matched an independent native
`stateless_validation` run bit-for-bit on every block and every configuration.

## Current numbers (5 recent mainnet blocks, 2026-08-18)

| block | gas used | txs | **self-verifying c/g** | rows | **trusted-digests c/g** | rows |
|---|---|---|---|---|---|---|
| 25698189 | 41,932,456 | 415 | **28.19** | 1,182.1M | **21.57** | 904.5M |
| 25697951 | 43,118,232 | 331 | 29.70 | 1,280.5M | 23.81 | 1,026.8M |
| 25698026 | 31,842,749 | 483 | 30.49 | 970.9M | 23.36 | 743.8M |
| 25698070 | 57,999,343 | 1312 | 29.80 | 1,728.3M | 23.92 | 1,387.5M |
| 25698208 | 56,690,935 | 1291 | 29.73 | 1,685.5M | 24.11 | 1,366.9M |

Workstream A replaced postcard materialization with JEF views into the input region.
On block 25698189: self-verifying **1,210,437,507 → 1,182,112,096 rows**
(−28,325,411; 28.87 → 28.19 c/g); trusted-digests **933,525,098 → 904,478,743**
(−29,046,355; 22.26 → 21.57 c/g). The `deserialize` marker is 4,381,052 rows;
keccak remains 141,300 permutations.

Campaign-2 checkpoint for comparison: 30.74 / 31.87 / 33.02 / 32.29 / 31.99 self
(1,289.1M / 1,374.3M / 1,051.6M / 1,872.5M / 1,813.5M rows); 24.26 / 26.11 / 26.04 /
26.53 / 26.50 trusted. Campaign-1: 34.49 / 36.21 / 37.14 / 42.69 / 36.19 self.

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

## Campaign 2 ladder (2026-08-06 late, block 25698189 self-verifying)

| step | mechanism | rows | c/g |
|---|---|---|---|
| campaign-1 checkpoint | | 1,446.3M | 34.49 |
| + EIP-7702 authority → secp inline | alloy-consensus `crypto-backend` CryptoProvider + vendored alloy-eip7702 [patch]; software k256 was ~1.5M rows/authorization | 1,423.2M | 33.94 |
| + zero-copy MPT decode (vendored zeth-mpt fork) | leaf values = `Bytes::slice_ref` views into witness bytes | 1,422.3M | 33.92 |
| + **word-RMW mem overrides** | boundary bytes via ld+mask+sd instead of byte loops (`sb` ≈ 12 rows in Jolt); memcpy family 276M → ~140M | 1,288.7M | 30.73 |
| whale block 25698070 (same steps compound) | 7702 −386.9M, memcpy −217M | 2,476.3M → 1,872.5M | 42.69 → **32.29** |

**Negative results, measured and reverted (kept in git history / stash):**
- `Box<Children>` node-shrink: +142M rows. Index-arena rewrite (u32 ids, parallel
  cache vec, 17/17 tests pass): +155M rows. Both foundered on the same misread:
  the "decode memcpy storm" was never move volume — it was the old override's
  ~140-row per-call byte-loop alignment overhead (~196 rows/call average over
  1.41M calls). Smaller-but-more copies made it worse; fixing the override fixed
  it everywhere. Arena kept in `git stash` for a post-R5 world.
- Lazy bytecode analysis (R2): analyze_legacy rows bit-identical (witness codes
  ≈ executed codes); +62.7M from outlined `IndexMap::get`. Dead.

## Campaign 3 ladder — advice-first lazy trie (2026-08-10, block 25698189 self-verifying)

Implements the ADVICE-TRIE spec (R1 × Jolt runtime advice, pinned `af1c2aef5c`):
prover-computed hints on a byte-FIFO tape, every value verified in-guest at its
consumption site (`ADVICE_LD` = 1 row; `check_advice_eq!` = 1 row). Proof statement,
witness format, and trust model unchanged. §8.1 pre-measurements re-verified before
implementation: witness 18,025 nodes (exact), probes 175,341 (spec ~178k), miss ratio
8.7:1 (spec 9:1), dirty nodes 10,616 = 58.9% (spec 8.6–12k).

| step | mechanism | rows | c/g |
|---|---|---|---|
| campaign-2 checkpoint (re-baselined bit-exact) | | 1,289.1M | 30.74 |
| + Phase 0: two-pass advice infra | compute_advice ELF pair + tape threading; foldhash pinned to fixed seeds (L5: identical hashbrown iteration across the ELF pair); tape-alignment sentinel | 1,288.9M | 30.74 |
| + Phase 1a: advice resolver | `rlp_by_digest` map deleted — prover advises the witness slot, guest verifies `keccak(witness[i]) == digest` against an 8-aligned memo ([u64;4] + bitmap); misses = 1 row (was ~90–320 of IndexMap traffic) | 1,261.5M | 30.08 |
| + Phase 1b: storage-trie laziness | `storage()` byte-walks raw witness RLP (advice per level, INV-W6 decode-parity validation memoized per entry, inline children in place); tries exist only for written accounts, hydrated on demand at post-root (`insert_with`/`remove_with` resolve stubs mid-mutation, incl. collapse siblings); DET-1/2 sorted post-root iteration | 1,218.4M | 29.06 |
| + Phase 3a: sealed arena encoder | dirty nodes encode into one reused scratch buffer — no per-node `Vec`, no dyn-`BufMut`; payload length = untrusted advice sealed by `cursor_delta == claimed` before any parent consumes the bytes | **1,210.4M** | **28.87** |

Battery: self −59…−106M/block (write-heavy blocks save most — bigger witnesses and
dirty sets); trusted −63…−112M (22.26 on the flagship). keccak perm totals never
exceeded baseline (141,300 ≤ 141,301 — L1: advice relocates hashing build-time →
first-touch, never multiplies it). Native gate bit-identical on every block and
variant; tape volume is exact (probes + walk steps + dirty-length words + sentinel).

**Negative result, measured and reverted (in-tree commit `87a52ff`):** Phase 2
(state-trie laziness — account byte-walks from `pre_state_root`, lazy state trie).
Battery vs 1b: +1.2M / −0.7M / +5.9M / **+26.5M / +27.8M** on the write-heavy pair;
trusted +1.1M. geth witnesses are exactly the touched set, so the never-dirty state
share is 20–30% on read-heavy blocks and vanishes on write-heavy ones (78–80% dirty):
per-call walk re-authentication plus one-node-at-a-time post-root `resolve_stub`
loses to the single-pass eager build through the resolver. The eager storage-trie
build had no such offset (its nodes were majority never-dirty) — laziness pays for
storage, not for the state trie. Phase 3b (build-plan linear loop) not attempted: its
substrate is the spec §2 flat-arena node repr, which campaign 2 measured at +155M
(pre-word-RMW; stash) — the remaining ~70–85M decode-side pool is the re-test target
if that gamble is ever taken.

Spec scorecard: Phase 1a beat its band (−27.5M vs −18…−25M); 1b landed −43M against a
"bulk" label that assumed the arena repr; 3a under band (−8M vs −28…−40M — post
word-RMW there was less alloc/dispatch fat than assumed); composite −78.7M on the
flagship vs the spec's −240…−320M target — the gap is exactly the unbuilt arena repr
and the reverted state laziness. App-side self-verifying floor now reads ~27–28.5 c/g
without the arena-repr gamble (was estimated 25–27 with it).

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

## Advice leverage (untrusted runtime advice — "prover computes, guest verifies")

Survey of where Jolt's untrusted-advice machinery (`#[jolt::advice]` two-pass:
compute_advice build writes the tape, proving build reads it via ~1-row
`AdviceReader` loads + `check_advice!` VirtualAssertEQ) can shave rows without
changing the proof statement. Measured against block 25698189 post-campaign-2:

| candidate | verdict | why |
|---|---|---|
| RLP/MPT structure advice (node boundaries, field offsets) | **not exploitable** | verifying a claimed RLP header at an offset = reading the same header bytes the parser reads; the actual decode cost was alignment overhead (fixed by word-RMW) + per-child recursion, not scanning. Zero-copy + override supersede. |
| Trie-traversal / storage-slot position advice | **not exploitable** | a Merkle lookup's verification IS the root-anchored walk; `get` is already ~free post-reveal, and reveal work is witness-bounded. Advising positions saves the compare-free walk but still pays node decode + hash — the actual costs. |
| Verify-by-multiply for U256 division | **not worth it** | Jolt's hardware DIV/REM is already advice-backed (division virtual sequence). Out-of-line `div_rem` = 1.27M rows (0.1%), mostly MULMOD's 512÷256 reduction; advice (q,r) + 256×256 mul check ≈ half of ~1M. Skip. |
| Advice-carried jump tables (R7) | **exploitable — next up** | `analyze_legacy` = 39.7M rows (3.1%). Sound WITHOUT in-guest verification: a wrong table bit either never influences execution or diverges a consensus-checked output (receipts/gas/state root) → panic → no proof. Needs the two-pass harness in trace.rs (compute_advice ELF + tape plumbing); est −35–40M, ~1 day incl. harness. |
| keccak via advice | **impossible by construction** | verification = recomputation for a hash. The trusted-digests variant is the honest version of this trade (verifier-attested digests), already shipped. |

## Quartering plan — status and remainder

Target set by user: ~10 c/g (≈420M rows for block 25698189). Achieved so far: 41.7 →
34.5 (self) / 28.0 (trusted). Executed: allocator, secp inlines ×2, stack exchange,
mem overrides, trusted-digest reveal. Ranked remainder:

| # | item | est. saving (self) | effort | mechanism / notes |
|---|---|---|---|---|
| R1 | Zero-copy / nibble-packed zeth-mpt fork | −180–220M (−4–5 c/g) | days | Nodes reference witness `Bytes` ranges instead of owned copies; nibble paths packed 2/byte and manipulated word-wise; encode into reused arena buffers. Attacks the 129M decode-memcpy + 66M decode + 41M encode + drops. |
| R2 | ~~Lazy bytecode analysis~~ | **measured dead** | — | witness codes ≈ executed codes (analyze rows bit-identical); +62.7M regression. Replaced by R7. |
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
- **Guest:** no_std RV64IMAC, 32 MiB input / 1.5 GiB heap / 32 MiB stack; JEF v1
  input views over block RLP, pubkeys, and witness; word-wise memcpy/memset/memcmp overrides;
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
- `witness.keys` omitted from JEF; the flagship deserialize marker is 4.38M rows.
- sig-verify covers signature checks + sender derivation (EIP-2 low-s enforced); the
  ecrecover override mirrors revm/k256 edge semantics and is self-checked by the
  post-state-root assertion on every block.
- 7702 authority recovery still uses k256 (~13M rows) — alloy-consensus's crypto isn't
  pluggable like revm's; candidate for the same inline treatment.
- The 5 blocks are contiguous-era (one busy afternoon, 31.8–58M gas, DEX-heavy);
  composition variance is visible (SWAP-heavy block 25698070 runs hottest per gas).

## Campaign wave 1 — JEF + committed bytecode (2026-09-04)

Gas-weighted self **26.045393 → 24.305792 c/g** (−1.739601, −6.68%); trusted **20.016668 → 19.145523 c/g** (−0.871145, −4.35%). No block regresses in either variant.

### Provenance and gates

- Baseline: `f419ad9`; Jolt `628713fd4`, read-only `main-2026-09-04` pin unchanged. Self means committed-input validation; trusted means verifier-trusted witness digests. Execute-only traces, not proofs. Rows include virtual instructions; only the proven pass counts.
- Zero-parse merge: `d5471aa` (`3827001`). Only conflict: `crates/core/Cargo.toml`; kept the new Jolt SDK path plus JEF postcard dev dependency. Bytecode stack (`7bc0b96`) merged without conflicts.
- Library: all four `library/dev` artifacts already committed; byte-identical to `7bc0b96`, not rebuilt. 907 entries, 8,338,080 analyzed-code bytes, 1,044,587 jump-table bytes, 58,064 index bytes. Sources: 25697951, 25698026, 25698070, 25698208. ID `0x226546fb8402b6c01bbf6d1a2ba8c66e9e4b32518d12d76e26e6dfe4528bad09`. No benchmark blocks used to build the library.
- Native validation: 10/10 after JEF and 10/10 after library packing; hashes match wave 0. Final self/trusted traces: 20/20, same hashes and gas. Existing nextest suite: 5/5 (includes all 907 library hash/jump-table bindings). Self permutation reductions equal covered code permutations exactly; trusted permutation totals unchanged.
- Detached both `input.bin` and `meta.json` symlinks before repack. Recovered missing `block.rlp` offline from each legacy postcard input’s first byte field; checked lengths against metadata, then native/guest hash parity. Witness symlinks remain read-only. All 50 advice-trie data SHA-256 hashes and mtimes unchanged; its git status clean.

### Intermediate: zero-parse only

| Block | Wave-0 self c/g | JEF self rows | JEF self c/g | Δ c/g | Deserialize rows | Self keccak perms (unchanged) |
|---|---:|---:|---:|---:|---:|---:|
| 25905781 | 26.218185 | 1,132,451,832 | 25.605395 | -0.612790 | 3,443,597 | 148,684 |
| 25905786 | 22.266911 | 572,513,990 | 21.723949 | -0.542962 | 1,917,515 | 78,800 |
| 25905788 | 29.364373 | 178,197,848 | 28.660207 | -0.704166 | 705,234 | 23,611 |

Three-block plain mean: 25.949823 → 25.329850; gas-weighted: 25.116991 → 24.520765. Intermediate trusted traces were not requested/measured.

### Full 10-block set: self

| Block | Gas | Wave-0 rows | Wave-0 c/g | Wave-1 rows | Wave-1 c/g | Δ c/g |
|---|---:|---:|---:|---:|---:|---:|
| 25905781 | 44,227,079 | 1,159,553,732 | 26.218185 | 1,074,581,041 | 24.296903 | -1.921282 |
| 25905782 | 47,065,991 | 1,281,959,982 | 27.237501 | 1,214,386,698 | 25.801787 | -1.435714 |
| 25905783 | 25,320,107 | 644,919,056 | 25.470629 | 590,300,791 | 23.313519 | -2.157110 |
| 25905784 | 19,039,352 | 500,722,899 | 26.299367 | 458,550,662 | 24.084363 | -2.215004 |
| 25905785 | 47,351,982 | 1,176,016,187 | 24.835628 | 1,108,179,054 | 23.403013 | -1.432614 |
| 25905786 | 26,354,048 | 586,823,238 | 22.266911 | 539,362,998 | 20.466040 | -1.800871 |
| 25905787 | 27,961,947 | 750,018,059 | 26.822812 | 698,878,917 | 24.993929 | -1.828883 |
| 25905788 | 6,217,605 | 182,576,075 | 29.364373 | 169,045,610 | 27.188220 | -2.176154 |
| 25905789 | 44,608,380 | 1,233,757,844 | 27.657535 | 1,168,484,347 | 26.194279 | -1.463256 |
| 25905790 | 32,881,199 | 844,945,431 | 25.696917 | 781,062,263 | 23.754069 | -1.942848 |
| Plain mean | — | — | 26.186986 | — | 24.349612 | -1.837374 |
| Gas-weighted mean | — | — | 26.045393 | — | 24.305792 | -1.739601 |

### Full 10-block set: trusted

| Block | Gas | Wave-0 rows | Wave-0 c/g | Wave-1 rows | Wave-1 c/g | Δ c/g |
|---|---:|---:|---:|---:|---:|---:|
| 25905781 | 44,227,079 | 879,653,583 | 19.889480 | 839,307,220 | 18.977225 | -0.912255 |
| 25905782 | 47,065,991 | 1,019,260,670 | 21.655991 | 981,953,437 | 20.863333 | -0.792658 |
| 25905783 | 25,320,107 | 487,781,368 | 19.264586 | 463,695,707 | 18.313339 | -0.951246 |
| 25905784 | 19,039,352 | 375,857,499 | 19.741087 | 356,291,764 | 18.713440 | -1.027647 |
| 25905785 | 47,351,982 | 911,097,971 | 19.240968 | 873,871,191 | 18.454796 | -0.786172 |
| 25905786 | 26,354,048 | 433,649,800 | 16.454770 | 411,716,667 | 15.622521 | -0.832249 |
| 25905787 | 27,961,947 | 580,776,145 | 20.770233 | 556,503,646 | 19.902178 | -0.868055 |
| 25905788 | 6,217,605 | 138,143,068 | 22.218051 | 131,563,392 | 21.159818 | -1.058233 |
| 25905789 | 44,608,380 | 969,623,128 | 21.736345 | 932,359,607 | 20.900997 | -0.835348 |
| 25905790 | 32,881,199 | 630,061,389 | 19.161752 | 598,980,404 | 18.216501 | -0.945251 |
| Plain mean | — | — | 20.013326 | — | 19.112415 | -0.900911 |
| Gas-weighted mean | — | — | 20.016668 | — | 19.145523 | -0.871145 |

### Coverage, self permutations, deserialize

| Block | Codes hit / total | Code perms covered / total | Self perms wave 0 → 1 | Δ perms | Deserialize rows self / trusted |
|---|---:|---:|---:|---:|---:|
| 25905781 | 229/474 (48.31%) | 14,517/31,067 (46.73%) | 148,684 → 134,167 | -14,517 | 3,429,919 / 3,429,919 |
| 25905782 | 146/364 (40.11%) | 9,929/23,451 (42.34%) | 150,676 → 140,747 | -9,929 | 3,069,996 / 3,069,996 |
| 25905783 | 160/286 (55.94%) | 9,896/17,934 (55.18%) | 81,190 → 71,294 | -9,896 | 1,894,874 / 1,894,874 |
| 25905784 | 126/221 (57.01%) | 7,334/13,931 (52.65%) | 66,064 → 58,730 | -7,334 | 1,590,210 / 1,590,210 |
| 25905785 | 161/369 (43.63%) | 10,032/25,302 (39.65%) | 151,088 → 141,056 | -10,032 | 2,826,767 / 2,826,767 |
| 25905786 | 133/303 (43.89%) | 8,283/19,815 (41.80%) | 78,800 → 70,517 | -8,283 | 1,908,819 / 1,908,819 |
| 25905787 | 147/289 (50.87%) | 8,735/18,546 (47.10%) | 89,940 → 81,205 | -8,735 | 2,042,412 / 2,042,412 |
| 25905788 | 45/71 (63.38%) | 2,263/3,918 (57.76%) | 23,611 → 21,348 | -2,263 | 701,114 / 701,114 |
| 25905789 | 150/327 (45.87%) | 9,216/21,492 (42.88%) | 157,792 → 148,576 | -9,216 | 2,926,351 / 2,926,351 |
| 25905790 | 168/312 (53.85%) | 10,687/20,155 (53.02%) | 112,956 → 102,269 | -10,687 | 2,738,879 / 2,738,879 |

Aggregate coverage: **1,465/3,016 codes (48.5743%)**, **90,892/195,611 code-hash permutations (46.4657%)**. Library source blocks are 207,573–207,839 blocks older than the benchmark. This measures cross-era held-out coverage, not a paired decay experiment on the same target blocks.

Reproduction (run cargo/build operations sequentially):

```sh
export CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-campaign-2x
export JOLT_PATH=/Volumes/Dev/cargo-target/jolt-cli-main/release/jolt
cargo build -q --message-format=short --release -p jeth-host
cargo nextest run --cargo-quiet --release --workspace
# Use local regular input.bin and meta.json files before repacking.
"$CARGO_TARGET_DIR/release/jeth" repack --dir data/25905781 --library library/dev/manifest.json
"$CARGO_TARGET_DIR/release/jeth" run-native --input data/25905781/input.bin
"$CARGO_TARGET_DIR/release/jeth" trace --input data/25905781/input.bin
"$CARGO_TARGET_DIR/release/jeth" trace --input data/25905781/input.bin --trusted-digests
```

Repeat native/traces for blocks 25905782–25905790; use `--skip-build` after each variant’s first build. Raw measurements and logs: `/tmp/jeth-wave1/{wave0,zero,both,coverage}.json`, `/tmp/jeth-wave1/{zero,both}-*.log`. Per-block copies: `data/<block>/{wave0,zero,wave1}-trace-summary*.json`.

## Campaign wave 2 — fresh-neighborhood production library (2026-09-04)

Gas-weighted self **24.305792 → 23.331042 c/g**; trusted **19.145523 → 18.911472 c/g**. No block’s trace-row count regresses in either variant. Execute-only traces; Jolt pin unchanged at `628713fd4`.

### Source window and sizing

Fetched **80/80 blocks, zero failures**: 25905701–25905780, using `jeth fetch --out data-lib`. RPC retries: 138 HTTP-429 backoffs; successful call wall times sum to 778.8 s, plus a 2 s inter-block throttle. Only this explicit window contributes to rev-1; concurrently fetched older sources are excluded. Benchmark 25905781–25905790 contributes no library code.

Rank: `block_frequency * (last_seen_block - oldest_source_block + 1)`, descending; hash ascending on ties. Frequency counts each hash once per source block. Offline coverage uses every cached witness code occurrence, with `len(code) // 136 + 1` permutations. All MB below are decimal, including analyzed code, jump tables, and index.

| K cap | Entries | Artifact MB | Codes covered | Code perms covered | Covered perms |
|---|---:|---:|---:|---:|---:|
| 500 | 500 | 5.074 | 60.345% | 59.386% | 116,166 |
| 1000 | 1,000 | 10.289 | 72.546% | 71.661% | 140,176 |
| 2000 | 2,000 | 20.619 | 82.858% | 81.456% | 159,336 |
| 3000 | 3,000 | 30.682 | 86.439% | 85.334% | 166,922 |
| 4000 | 4,000 | 41.131 | 87.467% | 86.541% | 169,284 |
| 6000 | 4,797 | 49.383 | 89.390% | 88.341% | 172,805 |
| 8000 | 4,797 | 49.383 | 89.390% | 88.341% | 172,805 |
| all | 4,797 | 49.383 | 89.390% | 88.341% | 172,805 |

**Pick K=3,000 (30.682 MB):** first measured tier above 85% permutation coverage, at 85.334%. K=4,000 adds 10.449 MB for 1.207 percentage points; the full 4,797-entry union adds 18.701 MB over the pick for 3.007 points. The curve flattens after K=2,000; K=3,000 adds 3.878 points and crosses the target. The 88.341% union ceiling is a source-window limit, not a size limit.

### Production artifact and gates

`library/production`: 3,000 entries; 27,073,904 raw-code bytes; 27,095,148 analyzed-code bytes; 3,394,869 jump-table bytes; 192,016 index bytes. ID `0x9306c4e333d2ee459ee4129edfd78f7f69aa21ced31f1b4457faab946929b12a`.

Independent source-only rank reconstruction matches the selected hashes. Rebuilding with `jeth library build` produced byte-identical index, codes, jump tables, and manifest. Both host and guest default to this artifact; `library/dev` is retained as the historical baseline.

Native validation: **10/10 benchmark hashes match wave 1**, plus the committed fixture hash matches. All 11 inputs repacked with `--library library/production/manifest.json`; stamped IDs and repack coverage match the offline calculation. Fixture witness copied read-only from `~/dev/jeth/data/25698189/witness.json`. No symlink writes; 59 protected source-data files retain their SHA-256 and mtime.

Nextest: **5/5**, including the existing per-entry binding/parity test against all 3,000 embedded entries. Binding test: **37 → 86 ms**; suite: **39 → 88 ms**. No tests removed. Full self/trusted traces: **20/20**, identical block hashes and gas. Profiling lane released the wave-1 inputs before repack.

| ELF | Wave-1 bytes | Wave-2 bytes | Delta bytes |
|---|---:|---:|---:|
| self | 11,390,304 | 32,631,616 | +21,241,312 |
| trusted | 11,391,024 | 32,632,320 | +21,241,296 |

### Full measurement ledger

#### Self

| Block | Gas | Wave-1 rows | Wave-2 rows | c/g wave 1 → 2 | Delta c/g |
|---|---:|---:|---:|---:|---:|
| 25905781 | 44,227,079 | 1,074,581,041 | 1,026,896,402 | 24.296903 → 23.218725 | -1.078177 |
| 25905782 | 47,065,991 | 1,214,386,698 | 1,174,618,499 | 25.801787 → 24.956842 | -0.844946 |
| 25905783 | 25,320,107 | 590,300,791 | 564,373,652 | 23.313519 → 22.289545 | -1.023974 |
| 25905784 | 19,039,352 | 458,550,662 | 438,819,393 | 24.084363 → 23.048021 | -1.036341 |
| 25905785 | 47,351,982 | 1,108,179,054 | 1,059,304,849 | 23.403013 → 22.370866 | -1.032147 |
| 25905786 | 26,354,048 | 539,362,998 | 504,204,199 | 20.466040 → 19.131945 | -1.334095 |
| 25905787 | 27,961,947 | 698,878,917 | 669,139,908 | 24.993929 → 23.930376 | -1.063553 |
| 25905788 | 6,217,605 | 169,045,610 | 163,174,014 | 27.188220 → 26.243869 | -0.944350 |
| 25905789 | 44,608,380 | 1,168,484,347 | 1,138,079,161 | 26.194279 → 25.512676 | -0.681603 |
| 25905790 | 32,881,199 | 781,062,263 | 751,300,423 | 23.754069 → 22.848936 | -0.905132 |
| Plain mean | — | — | — | 24.349612 → 23.355180 | -0.994432 |
| Gas-weighted mean | — | — | — | 24.305792 → 23.331042 | -0.974750 |

#### Trusted

| Block | Gas | Wave-1 rows | Wave-2 rows | c/g wave 1 → 2 | Delta c/g |
|---|---:|---:|---:|---:|---:|
| 25905781 | 44,227,079 | 839,307,220 | 827,710,368 | 18.977225 → 18.715013 | -0.262212 |
| 25905782 | 47,065,991 | 981,953,437 | 972,516,363 | 20.863333 → 20.662826 | -0.200507 |
| 25905783 | 25,320,107 | 463,695,707 | 457,357,890 | 18.313339 → 18.063031 | -0.250308 |
| 25905784 | 19,039,352 | 356,291,764 | 351,506,093 | 18.713440 → 18.462083 | -0.251357 |
| 25905785 | 47,351,982 | 873,871,191 | 862,131,507 | 18.454796 → 18.206873 | -0.247924 |
| 25905786 | 26,354,048 | 411,716,667 | 403,320,374 | 15.622521 → 15.303925 | -0.318596 |
| 25905787 | 27,961,947 | 556,503,646 | 549,405,041 | 19.902178 → 19.648311 | -0.253867 |
| 25905788 | 6,217,605 | 131,563,392 | 130,189,227 | 21.159818 → 20.938806 | -0.221012 |
| 25905789 | 44,608,380 | 932,359,607 | 925,122,559 | 20.900997 → 20.738762 | -0.162235 |
| 25905790 | 32,881,199 | 598,980,404 | 591,846,888 | 18.216501 → 17.999553 | -0.216948 |
| Plain mean | — | — | — | 19.112415 → 18.873918 | -0.238497 |
| Gas-weighted mean | — | — | — | 19.145523 → 18.911472 | -0.234051 |

### Coverage and exact permutation ledger

| Block | Codes covered | Code perms covered | Self perms wave 1 → 2 | Gained | Lost | Net drop | Trusted perms (unchanged) |
|---|---:|---:|---:|---:|---:|---:|---:|
| 25905781 | 412/474 (86.92%) | 26,055/31,067 (83.87%) | 134,167 → 122,629 | 12,006 | 468 | 11,538 | 62,694 |
| 25905782 | 307/364 (84.34%) | 19,626/23,451 (83.69%) | 140,747 → 131,050 | 9,697 | 0 | 9,697 | 70,240 |
| 25905783 | 261/286 (91.26%) | 16,159/17,934 (90.10%) | 71,294 → 65,031 | 6,310 | 47 | 6,263 | 32,841 |
| 25905784 | 195/221 (88.24%) | 12,113/13,931 (86.95%) | 58,730 → 53,951 | 5,094 | 315 | 4,779 | 27,649 |
| 25905785 | 318/369 (86.18%) | 21,907/25,302 (86.58%) | 141,056 → 129,181 | 11,875 | 0 | 11,875 | 69,854 |
| 25905786 | 264/303 (87.13%) | 16,840/19,815 (84.99%) | 70,517 → 61,960 | 8,557 | 0 | 8,557 | 31,537 |
| 25905787 | 244/289 (84.43%) | 15,975/18,546 (86.14%) | 81,205 → 73,965 | 7,453 | 213 | 7,240 | 37,882 |
| 25905788 | 67/71 (94.37%) | 3,701/3,918 (94.46%) | 21,348 → 19,910 | 1,438 | 0 | 1,438 | 9,989 |
| 25905789 | 259/327 (79.20%) | 16,624/21,492 (77.35%) | 148,576 → 141,168 | 7,467 | 59 | 7,408 | 77,040 |
| 25905790 | 280/312 (89.74%) | 17,922/20,155 (88.92%) | 102,269 → 95,034 | 7,569 | 334 | 7,235 | 47,060 |

Aggregate: **2,607/3,016 codes (86.4390%)**; **166,922/195,611 code perms (85.3336%)**. Plain per-block mean: 87.1806% codes, 86.3047% perms.

Wave-1 covered perms **90,892 → 166,922**. Gained hits cover 77,466 perms; lost dev-library hits cover 1,436; **net +76,030 = measured self permutation drop exactly**, both per block and in total. Relative to wave 0, cumulative drop is 166,922. Trusted permutation counts are unchanged; its row saving comes from non-keccak work.

### Wall time

| Counted trace pass, 10 blocks | Wave-1 seconds | Wave-2 seconds | Delta | Rows saved |
|---|---:|---:|---:|---:|
| self | 79.379 | 68.902 | -13.20% | 312,921,881 |
| trusted | 72.688 | 63.783 | -12.25% | 75,136,725 |

| Matched block 25905788, skip-build | Proven ELF decode/setup seconds | Startup through compute-ELF setup seconds | Full process seconds |
|---|---:|---:|---:|
| self | 0.633 → 1.711 | 0.650 → 1.728 | 5.008 → 7.198 |
| trusted | 0.631 → 1.702 | 0.655 → 1.733 | 4.763 → 6.962 |

ELF decode/setup timing is the interval between `advice tape:` and `tracing (` output; it includes `memory_config`/`tracer::decode` and intervening cleanup. Counted-pass timing is the existing tracer summary field. These are single runs on the same machine, with concurrent RPC fetching; wall-time differences include run-to-run noise. Trace-row and permutation counts are exact.

### Reproduction and evidence

```sh
export CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-campaign-2x
export JOLT_PATH=/Volumes/Dev/cargo-target/jolt-cli-main/release/jolt
"$CARGO_TARGET_DIR/release/jeth" library build --blocks data-lib/{25905701..25905780} --top-n 3000 --out /tmp/jeth-production-rebuild
cargo build -q --message-format=short --release -p jeth-host
"$CARGO_TARGET_DIR/release/jeth" repack --dir data/25905781 --library library/production/manifest.json
"$CARGO_TARGET_DIR/release/jeth" run-native --input data/25905781/input.bin
cargo nextest run --cargo-quiet --release --workspace
"$CARGO_TARGET_DIR/release/jeth" trace --input data/25905781/input.bin
"$CARGO_TARGET_DIR/release/jeth" trace --input data/25905781/input.bin --trusted-digests
```

Repeat native/traces for blocks 25905782–25905790; use `--skip-build` after each variant’s first build. Offline full curve, per-block candidate coverage, source fingerprints, timing captures, gate logs, and scripts: `/tmp/jeth-wave2/`. Final per-block summaries: `data/<block>/wave2-trace-summary*.json`. Papercuts logged with `--source jeth-wave2 --tag jeth`: RPC throttling; a provisional broad-glob source count mixed in the older-source lane (corrected before selection; final source allowlist is explicit).

## Campaign wave 3 — address memo + deferred recovery (2026-09-04)

Self-only: gas-weighted **23.331042 → 21.685187 c/g** (−7.0544%);
plain **23.355180 → 21.595203 c/g**. All ten blocks improve.
Merged `80eb287` (allocator kill ledger), `4156669` (address memo), and
`d7c9622` (deferred recovery), in that order; no conflicts or resolutions.
No new optimization. Jolt remains read-only at `628713fd4`.
Trusted variant dropped by user directive; no trusted gates run.

### Ladder

| Step | Mechanism | Full-set rows | Gas-weighted self c/g | Delta c/g |
|---|---|---:|---:|---:|
| Wave 2 | Production bytecode library | 7,489,910,500 | 23.331042 | — |
| Wave 3 | Address memo + deferred recovery | 6,961,545,463 | 21.685187 | -1.645855 |

### Full 10-block SELF ledger

| Block | Gas | Wave-2 rows | Wave-3 rows | Wave-2 c/g | Wave-3 c/g | Delta c/g |
|---|---:|---:|---:|---:|---:|---:|
| 25905781 | 44,227,079 | 1,026,896,402 | 938,512,897 | 23.218725 | 21.220323 | -1.998402 |
| 25905782 | 47,065,991 | 1,174,618,499 | 1,106,461,974 | 24.956842 | 23.508736 | -1.448106 |
| 25905783 | 25,320,107 | 564,373,652 | 516,751,690 | 22.289545 | 20.408748 | -1.880796 |
| 25905784 | 19,039,352 | 438,819,393 | 400,871,656 | 23.048021 | 21.054900 | -1.993121 |
| 25905785 | 47,351,982 | 1,059,304,849 | 1,003,270,651 | 22.370866 | 21.187511 | -1.183355 |
| 25905786 | 26,354,048 | 504,204,199 | 461,937,742 | 19.131945 | 17.528151 | -1.603794 |
| 25905787 | 27,961,947 | 669,139,908 | 614,337,260 | 23.930376 | 21.970475 | -1.959901 |
| 25905788 | 6,217,605 | 163,174,014 | 148,643,438 | 26.243869 | 23.906864 | -2.337005 |
| 25905789 | 44,608,380 | 1,138,079,161 | 1,086,513,295 | 25.512676 | 24.356708 | -1.155968 |
| 25905790 | 32,881,199 | 751,300,423 | 684,244,860 | 22.848936 | 20.809608 | -2.039328 |
| Plain mean | — | — | — | 23.355180 | 21.595203 | -1.759978 |
| Gas-weighted mean | — | — | — | 23.331042 | 21.685187 | -1.645855 |

Total saving: **528,365,037 rows**. Measured gas-weighted result is
0.085187 c/g above the estimated 21.2–21.6 band. Per-block savings are
1.155968–2.337005 c/g; the estimate was not a hard acceptance gate.
On 781/786/788, row savings equal the sum of the two lanes' isolated savings exactly.

### Exact permutation accounting

Temporary native probes counted memo hits at `hash_address` and equation count
at `Batch::verify`, using the merged `secp-inline` recovery/validation path.
Every probe output hash matched its recorded block hash. Probes removed before
handoff; the final host rebuilt without them. SELF measurements use unmodified
merged guest code, not probe builds.

For a nonempty batch of n equations: one 34 + 224n byte tuple transcript plus
n single-permutation challenges adds `n + floor((34 + 224n)/136) + 1` permutations.
One batch per block. Final proven-pass `post_validation` counters give the measured
delta. **Delta = −memo hits + transcript/challenge perms; residual zero on 10/10.**

| Block | Wave-2 perms | Wave-3 perms | Delta | Memo hits | Recoveries n | Added perms | Residual |
|---|---:|---:|---:|---:|---:|---:|---:|
| 25905781 | 122,629 | 121,206 | -1,423 | 2,832 | 532 | 1,409 | 0 |
| 25905782 | 131,050 | 130,184 | -866 | 1,986 | 423 | 1,120 | 0 |
| 25905783 | 65,031 | 64,506 | -525 | 1,357 | 314 | 832 | 0 |
| 25905784 | 53,951 | 53,563 | -388 | 1,066 | 256 | 678 | 0 |
| 25905785 | 129,181 | 128,159 | -1,022 | 1,984 | 363 | 962 | 0 |
| 25905786 | 61,960 | 61,356 | -604 | 1,349 | 281 | 745 | 0 |
| 25905787 | 73,965 | 73,342 | -623 | 1,534 | 344 | 911 | 0 |
| 25905788 | 19,910 | 19,861 | -49 | 375 | 123 | 326 | 0 |
| 25905789 | 141,168 | 140,584 | -584 | 1,522 | 354 | 938 | 0 |
| 25905790 | 95,034 | 94,002 | -1,032 | 2,139 | 418 | 1,107 | 0 |

### Gates and reproduction

- Release host and SELF compute/proven ELF pair built under `/tmp/jeth-w3-cargo.lock`.
- Native validation **10/10**: block hashes and gas agree with wave-2 records; SELF trace hashes match too.
- Release workspace nextest with `jeth-host/secp-inline`: **14/14 passed, zero skipped**.
- SELF traces **10/10**, no panics or regressions; exact permutation reconciliation **10/10**.

```sh
export CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-campaign-2x
export JOLT_PATH=/Volumes/Dev/cargo-target/jolt-cli-main/release/jolt
# Acquire /tmp/jeth-w3-cargo.lock with mkdir; release with rmdir after builds.
cargo build -q --message-format=short --release -p jeth-host --features secp-inline
cargo nextest run --cargo-quiet --release --workspace --features jeth-host/secp-inline
"$CARGO_TARGET_DIR/release/jeth" run-native --input data/25905781/input.bin
"$CARGO_TARGET_DIR/release/jeth" trace --input data/25905781/input.bin
```

Repeat native/SELF traces for 25905782–25905790 with `--skip-build` on traces.
Merged guest target prefix remains `/Volumes/Dev/cargo-target/jeth-w3-ecrecover-guest`.
Raw logs, baseline snapshots, counter probes, and machine-readable ledger:
`/tmp/jeth-wave3/`. Per-block `wave2-trace-summary.json` retains the baseline;
`trace-summary.json` and `wave3-trace-summary.json` contain the merged SELF result.
Papercut: macOS Bash rejects empty array expansion under `set -u`; the one-off
runner uses an explicit first-build branch. No production changes required.

## Campaign wave 4 — interpreter lane (w4-interp, 2026-09-04)

Base `85ce0d0` (post-wave-3). Scope: EVM exec-phase structural row cuts,
excluding the pre-decoded-stream lane (dispatch + PUSH + block-level
gas/stack) and keccak. Fresh exec-phase profile on this tree (781):
398.6M exec rows, 134.2M keccak, ~264M non-keccak.

### Kept: word-wise MLOAD/MSTORE/CALLDATALOAD (`4266322`)

Byte loads expand to 4-row and byte stores to 8-row virtual sequences on
Jolt RV64IMAC; aligned LD/SD are 1 row. U256 memory words moved through
per-byte paths (`try_from_be_slice` on unaligned slices, `to_be_bytes` +
memcpy). New `interpreter::words` (vendored revm-interpreter): four
aligned u64 loads/stores + `swap_bytes`; unaligned offsets shift-combine
the five covering doublewords; byte-slice fallback at buffer edges.
Pool measured 29.2M rows on 781 (mstore 15.8M + mload 10.3M +
calldataload 3.1M + their memcpy share).

| Block | Before | After | Delta | c/g |
|---|---:|---:|---:|---|
| 25905781 | 938,512,897 | 926,305,963 | -12,206,934 | 21.220 → 20.944 |
| 25905786 | 461,937,742 | 455,352,747 | -6,584,995 | 17.528 → 17.278 |
| 25905788 | 148,643,438 | 147,771,641 | -871,797 | 23.907 → 23.766 |

Gates: native parity 3/3 (hash + gas), keccak perms unchanged
(781 post_validation = 121,206), nextest 14/14, vendored words tests
cover all 8 alignments. Guest target dir renamed to
`jeth-w4-interp-guest` for lane isolation.

### Killed: storage-walk fast-skip (measured, reverted)

`walk.rs` skip_item/Header::decode on already-validated entries replaced
with size-only fast skips: **-2,057,349 rows on 781** (926,305,963 →
924,248,614, parity + perms clean). Projected ceiling with branch
child-offset memo + single-pass validate ≈ 6.5M < 8M gate → reverted.
The exec-phase trie pool (~24.5M: SparseState::storage 10.5M +
walk::validate_at 9.3M + RlpTrie::get 1.8M + hash_address 1.5M) is
dominated by first-touch node validation and per-level digest
authentication, not by the skip loops.

### Residual exec-phase budget on 781 after this lane (pertx profile, 386.4M exec rows)

| Family | Rows | Share |
|---|---:|---|
| keccak inline | 134,206,216 | 34.7% |
| dispatch loop (pre-decoded lane) | 42,497,087 | 11.0% |
| bn254/precompile backends (arkworks) | 32,435,738 | 8.4% |
| journal/state bookkeeping (revm-context/database) | 31,577,056 | 8.2% |
| mem builtins (memcpy/memset/memcmp, already word-wise) | 30,073,821 | 7.8% |
| storage/account trie walks (jeth-core) | 24,530,807 | 6.3% |
| U256 arith/bitwise (ruint) | 24,002,947 | 6.2% |
| PUSH (pre-decoded lane) | 17,559,194 | 4.5% |
| memory ops post-word-wise | 16,032,643 | 4.1% |
| DUP/SWAP/POP | 10,429,048 | 2.7% |
| JUMP/JUMPI | 5,977,018 | 1.5% |
| rest (calldataload, maps, gas calc, alloc, other) | 14,758,351 | 3.8% |

No remaining single in-lane pool clears 8M: mem builtins are already
shift-combine word-wise (disassembly-verified), journal/U256/gas pools
live in unvendored revm-context / ruint and are fragmented per-symbol.

## Campaign wave 4 — merged interpreter + keccak pin (2026-09-04)

SELF gas-weighted **21.685187 → 19.780546 c/g**
(-8.7831%); all ten blocks improve. Native parity **10/10**;
SELF traces **10/10**; release workspace nextest **14/14**, zero skipped.
No trusted gates. No new optimization.

### Ladder

| Step | Mechanism | Full-set rows | Gas-weighted SELF c/g | Delta c/g |
|---|---|---:|---:|---:|
| Wave 3 | Address memo + deferred recovery | 6,961,545,463 | 21.685187 | — |
| Wave 4 | Word-wise EVM memory ops + keccak XOR/ROTL fusion | 6,350,103,110 | 19.780546 | -1.904641 |

### Full 10-block SELF ledger and permutation accounting

| Block | Gas | Wave-3 rows | Wave-4 rows | Wave-3 c/g | Wave-4 c/g |
|---|---:|---:|---:|---:|---:|
| 25905781 | 44,227,079 | 938,512,897 | 856,491,307 | 21.220323 | 19.365767 |
| 25905782 | 47,065,991 | 1,106,461,974 | 1,012,323,673 | 23.508736 | 21.508602 |
| 25905783 | 25,320,107 | 516,751,690 | 473,117,938 | 20.408748 | 18.685464 |
| 25905784 | 19,039,352 | 400,871,656 | 364,751,467 | 21.054900 | 19.157767 |
| 25905785 | 47,351,982 | 1,003,270,651 | 915,054,927 | 21.187511 | 19.324533 |
| 25905786 | 26,354,048 | 461,937,742 | 420,011,691 | 17.528151 | 15.937274 |
| 25905787 | 27,961,947 | 614,337,260 | 559,788,641 | 21.970475 | 20.019659 |
| 25905788 | 6,217,605 | 148,643,438 | 136,331,705 | 23.906864 | 21.926723 |
| 25905789 | 44,608,380 | 1,086,513,295 | 990,428,932 | 24.356708 | 22.202755 |
| 25905790 | 32,881,199 | 684,244,860 | 621,802,829 | 20.809608 | 18.910589 |
| Plain mean | — | — | — | 21.595203 | 19.703913 |
| Gas-weighted mean | 321,027,690 | 6,961,545,463 | 6,350,103,110 | 21.685187 | 19.780546 |

| Block | Wave-3 perms | Wave-4 perms | Saved rows | 576 × perms | Non-keccak saving |
|---|---:|---:|---:|---:|---:|
| 25905781 | 121,206 | 121,206 | 82,021,590 | 69,814,656 | 12,206,934 |
| 25905782 | 130,184 | 130,184 | 94,138,301 | 74,985,984 | 19,152,317 |
| 25905783 | 64,506 | 64,506 | 43,633,752 | 37,155,456 | 6,478,296 |
| 25905784 | 53,563 | 53,563 | 36,120,189 | 30,852,288 | 5,267,901 |
| 25905785 | 128,159 | 128,159 | 88,215,724 | 73,819,584 | 14,396,140 |
| 25905786 | 61,356 | 61,356 | 41,926,051 | 35,341,056 | 6,584,995 |
| 25905787 | 73,342 | 73,342 | 54,548,619 | 42,244,992 | 12,303,627 |
| 25905788 | 19,861 | 19,861 | 12,311,733 | 11,439,936 | 871,797 |
| 25905789 | 140,584 | 140,584 | 96,084,363 | 80,976,384 | 15,107,979 |
| 25905790 | 94,002 | 94,002 | 62,442,031 | 54,145,152 | 8,296,879 |

Total rows saved: 611,442,353; keccak: 510,775,488; non-keccak: 100,666,865.
Gas-weighted change: -8.7831%.

Permutation counts unchanged **10/10**. Every block saves at least `576 × perms`.
Non-keccak saving is the measured residual after subtracting that exact keccak
term, attributed to the merged word-wise MLOAD/MSTORE/CALLDATALOAD path.
On 781/786/788, it matches the interpreter lane's isolated savings exactly:
12,206,934 / 6,584,995 / 871,797 rows; reconciliation residual zero.
Other blocks have no isolated interpreter baseline; their non-keccak column is
an inferred contribution, not an independent measurement.

### Integration and frozen dependency

Merged `1ef7089`, `745707e`, `06fc763` in order. No text conflicts. The interpreter merge
carried its lane guest target path; set the campaign-owned prefix
`/Volumes/Dev/cargo-target/jeth-campaign-2x-guest` before committing.
Predecoded/reveal merges contain ledgers only; kept interpreter code is `4266322`.

Jolt: **LOCAL, pending upstream PR**, detached read-only worktree
`/Volumes/Dev/worktrees/jolt/keccak-9340a77` at
`9340a777d86ec03f1ace78c235b32b8990ddc803`.
All Jolt path dependencies use it. Default CLI and trace `JOLT_PATH`:
`/Volumes/Dev/cargo-target/jolt-cli-keccak/release/jolt`.
Keccak permutation expansion: **3,087 → 2,511 rows** (−576).
No edits in the frozen Jolt source, no merge of `w5-keccak-repin`, no push.

### Gates and reproduction

CLI, release host, SELF proven/compute-advice ELF pair, sweep, and nextest
ran sequentially under `/tmp/jeth-w3-cargo.lock` with owner `campaign-2x 79849`.
EXIT cleanup unlinks the owner and removes the directory only on owner match.
Native and SELF output hashes/gas match wave 3 on all ten blocks; no guest panics.

```sh
CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jolt-cli-keccak cargo build -q --message-format=short --release -p jolt --manifest-path /Volumes/Dev/worktrees/jolt/keccak-9340a77/Cargo.toml
export CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-campaign-2x
export JOLT_PATH=/Volumes/Dev/cargo-target/jolt-cli-keccak/release/jolt
cargo build -q --message-format=short --release -p jeth-host --features secp-inline
"$CARGO_TARGET_DIR/release/jeth" run-native --input data/25905781/input.bin
"$CARGO_TARGET_DIR/release/jeth" trace --input data/25905781/input.bin
cargo nextest run --cargo-quiet --release --workspace --features jeth-host/secp-inline
```

Acquire the owner-checked lock before these commands. Repeat native/SELF traces
for 25905782–25905790 with `--skip-build`. Complete locked runner, logs, baseline
snapshots, accounting script, and JSON ledger: `/tmp/jeth-wave4/`.
Per-block summaries: `data/<block>/wave4-trace-summary.json`.
Papercut logged (`jeth-w4-integration`, `jeth`): commit hook rejects the `merge`
subject type; use `chore` for code integration merges.

Cleanup candidates, now merged: `w4-interp`, `w4-predecoded`, `w4-reveal`.
No lane worktrees removed. Keep the frozen Jolt dependency and leave
`w5-keccak-repin` untouched.

## Campaign opt-amber wave A — fused sub-word lane lookups (2026-09-04)

SELF gas-weighted **19.780546 → 19.364199 c/g** (−0.416347, −2.10%); plain mean
19.703913 → 19.292034. All ten blocks improve; native/trace block hashes and
keccak permutation totals unchanged (781: 121,206 · 786: 61,356 · 788: 19,861
— spot-checked exact). Total −133,659,039 rows. Guest ELF unchanged: both cuts
are Jolt expansion-layer changes in the jolt-amber worktree (base `9340a777d` +
`661d8e268..d79d89c84`); jeth tree unchanged except journal/tooling.

### Mechanism

New vertex-sum lookup-table families over interleaved (data, base-register)
operands, with the load/store immediate's mod-8 residue K baked into the table
(`(base + imm) mod 8 = ((base mod 8) + K) mod 8` — no carry into bit 3, so the
K-shift is a pure relabeling of the 8 lane vertices and all K variants share
one prefix/suffix component family):

- **LBU 4 → 3 rows** (`0efdf9725`): `window_mask_b + pext` collapse into one
  `VirtualExtractByu{K}` lookup (`rd = zext byte (base+K)&7 of dword`).
- **SB 8 → 6 rows** (`d79d89c84`): the effective-address `ADDI/ANDI` pair and
  the window-mask row collapse — `align_addr; ld; clear_lane_b{K}(dword,base);
  shift_data_b[k{K}](src,base); add; sd`.

Decomposition (new): shared prefixes ExtractEqLane0-7 / ExtractByteLsb0-7 /
ExtractBytePlace0-7 / ExtractXPass; suffixes ExtractEqLane0-7, per-K Tail/Rest
(length-gated at suffix_len 5, where the three lane-select bits sit fully in
the suffix), ClearRest0-7, joint ExtractEqLaneLow0-7 (no length gating —
store-data low byte sits below every other operand bit). combine() stays
linear in suffixes; prefix products carry the vertex pairing. 31 new tables
(78 → 109 of 126 table-ID slots), 25 prefixes, 41 suffixes, 23 instruction
kinds (0x00b9..0x00cf), legacy MAX_SUFFIXES 5 → 16.

**Soundness:** each new table is a total function of its two committed
register operands, MLE-tested against materialization (mle_random, full
hypercube at XLEN=8, prefix-suffix contract incl. 2-round phase boundaries
that split the lane-select bits, 637 lookup-table tests). Old and new
expansions compute identical rd/memory effects for all inputs (RAM ops
unchanged: same aligned address, same merged value); forged operands fail the
instruction lookup exactly as for every existing lookup instruction. The
prover-legacy mirror is pinned by the ABI cross-check; ShiftDataBK{0} is
random-tested equal to the original ShiftDataB.

### Ladder (jolt-amber @ d79d89c84, jeth @ campaign-2x 329e20a)

| Block | Gas | Wave-4 rows | Wave-A rows | Delta rows | c/g wave-4 → A |
|---|---:|---:|---:|---:|---|
| 25905781 | 44,227,079 | 856,491,307 | 838,139,317 | -18,351,990 | 19.365767 → 18.950818 |
| 25905782 | 47,065,991 | 1,012,323,673 | 991,999,817 | -20,323,856 | 21.508602 → 21.076786 |
| 25905783 | 25,320,107 | 473,117,938 | 463,599,459 | -9,518,479 | 18.685464 → 18.309538 |
| 25905784 | 19,039,352 | 364,751,467 | 357,058,625 | -7,692,842 | 19.157767 → 18.753717 |
| 25905785 | 47,351,982 | 915,054,927 | 895,527,215 | -19,527,712 | 19.324533 → 18.912138 |
| 25905786 | 26,354,048 | 420,011,691 | 410,760,612 | -9,251,079 | 15.937274 → 15.586244 |
| 25905787 | 27,961,947 | 559,788,641 | 548,047,171 | -11,741,470 | 20.019659 → 19.599750 |
| 25905788 | 6,217,605 | 136,331,705 | 133,702,434 | -2,629,271 | 21.926723 → 21.503848 |
| 25905789 | 44,608,380 | 990,428,932 | 969,527,378 | -20,901,554 | 22.202755 → 21.734198 |
| 25905790 | 32,881,199 | 621,802,829 | 608,082,043 | -13,720,786 | 18.910589 → 18.493305 |
| Gas-weighted | 321,027,690 | 6,350,103,110 | 6,216,444,071 | -133,659,039 | **19.780546 → 19.364199** |

Exact attribution on 781 (measured stepwise): LBU cut −11,666,586 =
1 row × 11,666,586 LBU execs; SB cut −6,685,404 = 2 rows × 3,342,702 SB
execs; zero residual. Dynamic op counts from the new `jeth opcodes` exact
histogram (`data/25905781/opcodes-baseline.log`).

### Gates

- Native gate: guest/ELF unchanged; all ten trace block hashes match wave-4
  records bit-for-bit.
- Keccak accounting: proven-pass permutation totals unchanged (spot-checked
  781/786/788 exact).
- Jolt: 811/811 new-stack (lookup-tables 637 + riscv 37 + tracer 137),
  jolt-prover-legacy 683/683 (+1 pre-existing skip), lookup-table ABI
  cross-check 1/1 (`--features prover-abi-tests`), jolt-program 55/55 (12 LBU
  + 8 SB golden hashes re-baselined, documented in-file), workspace check +
  clippy clean, x86 backend cross-target check clean (difftests are
  linux-gated, run in CI).
- jeth: release workspace nextest 14/14 with `jeth-host/secp-inline`.

### Reproduce

```sh
cd /Volumes/Dev/worktrees/jolt/jolt-amber   # branch jolt-amber @ d79d89c84
CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jolt-cli-amber cargo build -q --release -p jolt
cd /Volumes/Dev/worktrees/jeth/opt-amber    # branch opt-amber-work
export CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/opt-amber
export JOLT_PATH=/Volumes/Dev/cargo-target/jolt-cli-amber/release/jolt
cargo build -q --release -p jeth-host --features secp-inline
"$CARGO_TARGET_DIR/release/jeth" trace --input data/25905781/input.bin  # first run builds the guest pair
"$CARGO_TARGET_DIR/release/jeth" opcodes --input data/25905781/input.bin --skip-build
```

## Campaign opt-amber wave B — word-lane fusions (LW/LWU 5→4, SW 9→7)

Same vertex-sum lane architecture as wave A, specialized to the 2-vertex word
lane: `y_2` selects word 0/1 of the aligned doubleword and the shift K∈{0,4}
is a 1-bit XOR relabeling (`lane = y_2 XOR (K>>2)`; imm&3==0 means no carry
into bit 2, so the eq structure survives unchanged). New tables
ExtractWu/ExtractW (signed variant folds the eq factor into a sign suffix —
no double counting at short suffix lengths), ClearLaneW, ShiftDataWK4; kinds
0x00d0–0x00d6 (LookupTableKind count 109→116 < 126 cap). Expansions gated on
word-aligned immediates (`imm.trailing_zeros() >= 2`): LW/LWU = align_addr;
ld; extract → 4 rows; SW = align_addr; ld; clear_lane_w; shift_data_w; add;
sd → 7 rows. Non-aligned imms keep the old sequences.

Jolt commits: 7365999b4 (tables + P/S components), 053a633fe (instruction
kinds/wiring), ef298ff96 (jolt-prover-legacy mirror), d2d9bf2e6 (fused
expansions + 30 golden expansion hashes re-baselined: LW/LWU/SW at imm
−8/0/12 plus LR.W/SC.W, documented in-file).

### Ladder (jolt-amber @ d2d9bf2e6, jeth @ opt-amber-work)

| Block | Gas | Wave-A rows | Wave-B rows | Delta rows | c/g A → B |
|---|---:|---:|---:|---:|---|
| 25905781 | 44,227,079 | 838,139,317 | 834,033,235 | -4,106,082 | 18.950818 → 18.857977 |
| 25905782 | 47,065,991 | 991,999,817 | 987,260,970 | -4,738,847 | 21.076786 → 20.976101 |
| 25905783 | 25,320,107 | 463,599,459 | 461,310,242 | -2,289,217 | 18.309538 → 18.219127 |
| 25905784 | 19,039,352 | 357,058,625 | 355,141,134 | -1,917,491 | 18.753717 → 18.653005 |
| 25905785 | 47,351,982 | 895,527,215 | 890,812,958 | -4,714,257 | 18.912138 → 18.812580 |
| 25905786 | 26,354,048 | 410,760,612 | 408,653,601 | -2,107,011 | 15.586244 → 15.506293 |
| 25905787 | 27,961,947 | 548,047,171 | 545,552,206 | -2,494,965 | 19.599750 → 19.510523 |
| 25905788 | 6,217,605 | 133,702,434 | 132,964,080 | -738,354 | 21.503848 → 21.385096 |
| 25905789 | 44,608,380 | 969,527,378 | 964,216,410 | -5,310,968 | 21.734198 → 21.615141 |
| 25905790 | 32,881,199 | 608,082,043 | 604,977,536 | -3,104,507 | 18.493305 → 18.398889 |
| Gas-weighted | 321,027,690 | 6,216,444,071 | 6,184,922,372 | -31,521,699 | **19.364199 → 19.266009** |

Cumulative vs wave-4 baseline: **19.780546 → 19.266009 (−0.514537 c/g,
−165,180,738 rows)**.

Exact attribution on 781 (post-B `jeth opcodes` histogram): −4,106,082 =
1 row × 1,412,347 LW + 1 row × 1,231,381 LWU + 2 rows × 731,177 SW execs,
zero residual — every dynamic word op in the set resolved to the fused
word-aligned path (compilers emit 4-aligned word offsets).

### Gates

- Native gate: all ten trace block hashes match wave-4 records bit-for-bit
  (full-set sweep).
- Keccak accounting: 781 permutation total 121,206 unchanged.
- Jolt: lookup-tables + riscv + tracer suites green; jolt-prover-legacy
  mirror + lookup-table ABI cross-check 1/1; jolt-program golden expansion
  parity green after documented re-baseline; zk e2e + byte-parity green
  (zk_muldiv SIGABRT is a known flake, passes standalone).
- jeth: release workspace nextest 14/14 with `jeth-host/secp-inline`,
  re-run after the jolt dependency bump.

## Campaign opt-amber wave C — receipt bloom/root single pass with memoized accrue hashes (jeth-only)

`validate_block_post_execution(.., None)` recomputed every log bloom
internally: keccak256 of the address and of each topic per accrue, all
through the 2,511-row keccak inline (the "bloom accrue 11.9M" profile line
was this, LTO-inlined). Replaced with one `receipt_root_bloom` pass that
memoizes `keccak256(address)` and `keccak256(topic)` in fb-hashed maps and
feeds `Some((root, bloom))` to the consensus check. Dedup only — every
unique hash is still computed in-guest and both root and bloom are still
checked against the header, so a wrong memo cannot validate (receipts-root
mismatch panics before any output). Origin: wave-4 reveal candidate
(measured −3.61M topics-only, killed then by the 5M lane floor), extended
here to addresses. jeth commit 199c470; no jolt changes.

### Ladder (jolt-amber @ d2d9bf2e6, jeth @ 199c470)

| Block | Gas | Wave-B rows | Wave-C rows | Delta rows | c/g B → C | Proven perms |
|---|---:|---:|---:|---:|---|---:|
| 25905781 | 44,227,079 | 834,033,235 | 828,666,884 | -5,366,351 | 18.857977 → 18.736641 | 121,206 → 118,366 |
| 25905782 | 47,065,991 | 987,260,970 | 982,452,956 | -4,808,014 | 20.976101 → 20.873946 | 127,181 |
| 25905783 | 25,320,107 | 461,310,242 | 459,509,635 | -1,800,607 | 18.219127 → 18.148013 | 63,420 |
| 25905784 | 19,039,352 | 355,141,134 | 353,543,859 | -1,597,275 | 18.653005 → 18.569112 | 52,681 |
| 25905785 | 47,351,982 | 890,812,958 | 884,651,698 | -6,161,260 | 18.812580 → 18.682464 | 124,865 |
| 25905786 | 26,354,048 | 408,653,601 | 407,200,516 | -1,453,085 | 15.506293 → 15.451156 | 60,455 |
| 25905787 | 27,961,947 | 545,552,206 | 542,512,306 | -3,039,900 | 19.510523 → 19.401807 | 71,728 |
| 25905788 | 6,217,605 | 132,964,080 | 132,720,275 | -243,805 | 21.385096 → 21.345884 | 19,665 |
| 25905789 | 44,608,380 | 964,216,410 | 958,875,633 | -5,340,777 | 21.615141 → 21.495415 | 137,177 |
| 25905790 | 32,881,199 | 604,977,536 | 601,526,875 | -3,450,661 | 18.398889 → 18.293946 | 92,005 |
| Gas-weighted | 321,027,690 | 6,184,922,372 | 6,151,660,637 | -33,261,735 | **19.266009 → 19.162399** | 867,543 |

Cumulative vs wave-4 baseline: **19.780546 → 19.162399 (−0.618147 c/g,
−198,442,473 rows)**.

Keccak accounting: set proven-pass perms 886,763 → 867,543 (−19,220 =
exactly the deduplicated address/topic accrue hashes; every remaining perm
is a unique preimage). 781 consistency: −2,840 perms × 2,511 = 7,131,240
gross, net −5,366,351 ⇒ 1,764,889 rows of memo-map overhead, matching the
R2 shard's estimate.

### Gates

- Native gate: `run-native` all ten blocks, hashes match records bit-for-bit.
- Traces: all ten in-guest hashes match (receipts root + bloom consensus
  check exercised on every block).
- jeth: release workspace nextest 15/15 (new `receipt_root_bloom` parity
  test vs direct `with_bloom_ref` hashing over 0/1/32/96-receipt slices).
- Jolt: untouched this wave.

## Campaign opt-amber wave D — in-place MPT node construction (jeth-only)

Vendored zeth-mpt decoded every node by value: `decode_node_zc` built the
176-byte `Node<Cache>` enum (Children = `[Option<Box<Node>>; 16]` inline
128 B + `Option<RlpNode>` cache 44 B) on the stack and moved it ~3× per
child (Result sret → `?` → `Box::new`), plus a 128 B Children move into
the return and a 176 B `*self = node` per resolved stub — pure move traffic
LLVM cannot elide across two call boundaries, lowered to memcpy on riscv64
(49.6M rows of memcpy attributed under decode on 781; repo commit 7df9cd0
had documented the chain). Fix (three commits, representation unchanged —
arena and Box<Children> remain dead):

- f64e143 `decode_node_zc_into(.., out: &mut MaybeUninit<Node>)`; every
  Ok arm ends in `out.write`; children allocated with `Box::new_uninit`
  BEFORE decoding so each node is built in its final heap slot. 781
  −52,982,316.
- 72fa3a0 `decode_stub_in_place`: resolve_with/resolve_stub decode into
  the node's own slot (deletes `*self = node`); by-value
  `decode_node_zc_exact` removed. −2,020,854.
- 88e4db2 Branch children built in the node slot (empty Branch written
  first, children filled in place; safe code). −859,710.

Unsafe inventory: `Box<MaybeUninit<Node>>::assume_init` ×2 (contract:
callee's every Ok arm wrote `out`), `assume_init_drop` ×1 (trailing-bytes
refusal), one `&mut Node → &mut MaybeUninit<Node>` cast in
decode_stub_in_place (Node::Digest owns nothing; slot is untouched, Null,
or a valid node at every panic point; stub restored on every Err incl.
digest-for-digest). Independent adversarial review requested (see journal).

### Ladder (jolt-amber @ d2d9bf2e6, jeth @ 88e4db2)

| Block | Gas | Wave-C rows | Wave-D rows | Delta rows | c/g C → D |
|---|---:|---:|---:|---:|---|
| 25905781 | 44,227,079 | 828,666,884 | 772,804,004 | -55,862,880 | 18.736641 → 17.473548 |
| 25905782 | 47,065,991 | 982,452,956 | 918,303,726 | -64,149,230 | 20.873946 → 19.510982 |
| 25905783 | 25,320,107 | 459,509,635 | 428,059,864 | -31,449,771 | 18.148013 → 16.905926 |
| 25905784 | 19,039,352 | 353,543,859 | 327,029,695 | -26,514,164 | 18.569112 → 17.176514 |
| 25905785 | 47,351,982 | 884,651,698 | 820,939,382 | -63,712,316 | 18.682464 → 17.336959 |
| 25905786 | 26,354,048 | 407,200,516 | 378,374,842 | -28,825,674 | 15.451156 → 14.357371 |
| 25905787 | 27,961,947 | 542,512,306 | 508,481,563 | -34,030,743 | 19.401807 → 18.184770 |
| 25905788 | 6,217,605 | 132,720,275 | 122,277,571 | -10,442,704 | 21.345884 → 19.666346 |
| 25905789 | 44,608,380 | 958,875,633 | 887,565,591 | -71,310,042 | 21.495415 → 19.896835 |
| 25905790 | 32,881,199 | 601,526,875 | 559,141,685 | -42,385,190 | 18.293946 → 17.004906 |
| Gas-weighted | 321,027,690 | 6,151,660,637 | 5,722,977,923 | -428,682,714 | **19.162399 → 17.827054** |

Cumulative vs wave-4 baseline: **19.780546 → 17.827054 (−1.953492 c/g,
−9.9%; −627,125,187 rows)**.

Attribution on 781 (`jeth profile --callers-of memcpy --rows`, exact):
memcpy under decode_node_zc(_into) 49,595,949 → 10,827,010; under
decode_node_zc_exact 4,262,544 → 0; under resolve_with 3,770,964 →
1,184,913; under resolve_stub 1,788,633 → 768,159; memoize_arena
16,161,760 unchanged (separate lane); total memcpy ≈106.9M → 60,227,867
(−46.6M). The remaining ≈−12M of the −55.9M is decode-internal
non-memcpy move traffic that vanished with the same chain (Result<Node> →
Result<()> ABI: 176 B sret temporaries and their spill/reload); every
other symbol byte-identical in A/B. Landed above the verifier's 30–38M
band for that reason. Residue under decode (10.8M) = `B256::from_slice`
32 B copies per Digest child + Leaf/Extension path construction.

### Gates

- Native gate: `run-native` all ten blocks match records.
- Traces: all ten hashes match; 781 proven-pass perms 118,366 and set
  perms 867,543 exactly unchanged (no hash-count change).
- jeth: release workspace nextest 15/15 with `jeth-host/secp-inline`.
- Jolt: untouched this wave.

## Campaign opt-amber wave E — leak block state instead of tearing it down (jeth-only)

At the end of `validate_recovered_pertx` the trie (~350k boxed nodes), the
revm `State` cache, the bundle, the witness and the recovered block were
dropped: ~12.5M rows of `drop_in_place<[Option<Box<Node>>;16]>` +
`size_class_alloc::dealloc` on 781 plus smaller map/Vec teardowns — pure
dealloc traffic in a single-shot process. `core::mem::forget` on those five
owners after the state root is checked. No semantic change (validation
output identical; native run-native path unchanged). jeth commit 443c327.

### Ladder (jolt-amber @ d2d9bf2e6, jeth @ 443c327)

| Block | Gas | Wave-D rows | Wave-E rows | Delta rows | c/g D → E |
|---|---:|---:|---:|---:|---|
| 25905781 | 44,227,079 | 772,804,004 | 759,473,828 | -13,330,176 | 17.473548 → 17.172145 |
| 25905782 | 47,065,991 | 918,303,726 | 903,197,053 | -15,106,673 | 19.510982 → 19.190015 |
| 25905783 | 25,320,107 | 428,059,864 | 420,588,931 | -7,470,933 | 16.905926 → 16.610867 |
| 25905784 | 19,039,352 | 327,029,695 | 320,727,131 | -6,302,564 | 17.176514 → 16.845486 |
| 25905785 | 47,351,982 | 820,939,382 | 805,904,445 | -15,034,937 | 17.336959 → 17.019445 |
| 25905786 | 26,354,048 | 378,374,842 | 371,521,181 | -6,853,661 | 14.357371 → 14.097310 |
| 25905787 | 27,961,947 | 508,481,563 | 500,387,639 | -8,093,924 | 18.184770 → 17.895307 |
| 25905788 | 6,217,605 | 122,277,571 | 119,813,905 | -2,463,666 | 19.666346 → 19.270106 |
| 25905789 | 44,608,380 | 887,565,591 | 870,818,262 | -16,747,329 | 19.896835 → 19.521405 |
| 25905790 | 32,881,199 | 559,141,685 | 549,086,254 | -10,055,431 | 17.004906 → 16.699095 |
| Gas-weighted | 321,027,690 | 5,722,977,923 | 5,621,518,629 | -101,459,294 | **17.827054 → 17.511009** |

Cumulative vs wave-4 baseline: **19.780546 → 17.511009 (−2.269537 c/g,
−11.5%; −728,584,481 rows)**.

### Gates

- Native gate: `run-native` all ten blocks match records.
- Traces: all ten hashes match; per-block proven-pass perms unchanged
  (781: 118,366; set 867,543).
- jeth: release workspace nextest 15/15.
- Jolt: untouched this wave.

## Campaign opt-amber wave F — arena child refs and string items assembled from whole words (jeth-only)

`memoize_arena` built each node's RLP in an owned scratch buffer by
memcpy-ing 32-byte digests and ≤33-byte cached child refs at a byte-granular
cursor from 8-aligned sources — every copy took the generic misaligned
memcpy path (~70–116 rows); 16.16M rows of memcpy under memoize_arena on
781. Replaced with a funnel writer over an `#[repr(C, align(8))]` scratch
(`put_window`/`put_window33`/`put_raw`/`put_prefixed`): source read as the
aligned words containing it, shifted by the cursor offset, whole-word SD
stores with a first-word RMW and a ≤7-byte owned overrun; the one-byte RLP
prefix is folded into word 0 instead of a separate SB. Used for child refs
(Digest, Cached) and leaf path/value string items. Byte-exact output is
asserted by an exhaustive offset×shift×length test against the byte copy.
jeth commit d979f0c (also fixes the wave-D review nits in rlp.rs).

### Ladder (jolt-amber @ d2d9bf2e6, jeth @ d979f0c)

| Block | Gas | Wave-E rows | Wave-F rows | Delta rows | c/g E → F |
|---|---:|---:|---:|---:|---|
| 25905781 | 44,227,079 | 759,473,828 | 749,233,347 | -10,240,481 | 17.172145 → 16.940602 |
| 25905782 | 47,065,991 | 903,197,053 | 890,175,181 | -13,021,872 | 19.190015 → 18.913342 |
| 25905783 | 25,320,107 | 420,588,931 | 414,886,377 | -5,702,554 | 16.610867 → 16.385649 |
| 25905784 | 19,039,352 | 320,727,131 | 315,845,472 | -4,881,659 | 16.845486 → 16.589087 |
| 25905785 | 47,351,982 | 805,904,445 | 792,751,133 | -13,153,312 | 17.019445 → 16.741667 |
| 25905786 | 26,354,048 | 371,521,181 | 366,438,325 | -5,082,856 | 14.097310 → 13.904442 |
| 25905787 | 27,961,947 | 500,387,639 | 494,122,962 | -6,264,677 | 17.895307 → 17.671265 |
| 25905788 | 6,217,605 | 119,813,905 | 117,757,192 | -2,056,713 | 19.270106 → 18.939317 |
| 25905789 | 44,608,380 | 870,818,262 | 855,305,307 | -15,512,955 | 19.521405 → 19.173646 |
| 25905790 | 32,881,199 | 549,086,254 | 541,444,076 | -7,642,178 | 16.699095 → 16.466677 |
| Gas-weighted | 321,027,690 | 5,621,518,629 | 5,537,959,372 | -83,559,257 | **17.511009 → 17.250722** |

Cumulative vs wave-4 baseline: **19.780546 → 17.250722 (−2.529824 c/g,
−12.8%; −812,143,738 rows)**.

Attribution on 781: memcpy under memoize_arena 16,161,760 → 1,273,614
(residual = per-node `RlpNode::from_rlp` 32-B copy + 44-B cache.set move);
memoize_arena self 12,576,720 → 17,250,480 (+4.67M of inline word writes,
well under the memcpy removed); memcpy total 60,227,867 → 45,217,177; net
−10,240,481.

### Gates

- Native gate: `run-native` all ten blocks match records.
- Traces: all ten hashes match; perms unchanged (781: 118,366).
- jeth: nextest 15/15; vendored zeth-mpt 18/18 (new exhaustive
  `word_writer_matches_byte_copy`); workspace clippy `--all-targets
  -D warnings` clean.
- Jolt: untouched this wave.

## Campaign opt-amber wave G — secp256k1 limb compares, memcmp sign path, bump allocator

Three sub-lanes, measured and committed separately (builder lane, all gates
per sub-lane).

- **1a — secp256k1 equality without memcmp** (jolt e371ecd4e). LLVM lowers
  every 32-byte `==` on `[u64;4]` to a memcmp libcall on riscv64imac; the
  inline-SDK `AffinePoint::add` did three per bucket add (`is_infinity`
  ×2, `x == x`) at ~75 rows each inside `recovery_batch::pippenger`
  (9.0M rows on 781). Manual `PartialEq`/`is_zero` for `Secp256k1Fq/Fr` as
  `((a0^b0)|(a1^b1)|(a2^b2)|(a3^b3)) == 0`; every add branch kept
  (infinity / P==Q / P==−Q), exact on canonical limbs (from_u64_arr checks,
  inline outputs reduced). 781 −10,556,696 (memcmp 18.9M → 9.6M, pippenger
  call-site rows −0.8M, recover()/is_on_curve compares −0.4M).
- **1b — memcmp sign from the lowest differing byte** (jeth 20aaf76). The
  word-RMW memcmp byte-swapped both words (48 rows) to order them; now
  `t = d & −d`, `mask = ((t|(t−1)) & 0x0101…01) × 0xFF`, unsigned compare
  of the masked words. Fuzz test extended (bytes after the flipped one
  randomized, 200k iterations). 781 −2,738,891 (estimate −4M had
  double-counted the compares 1a removed).
- **2 — bump allocator** (jolt ef89da425 `jolt-platform::bump_alloc` +
  jolt-sdk feature `bump-alloc`; jeth 342c8d1 enables it in the guest).
  alloc = align round-up + checked bound (~15.6 rows incl. fn-ptr dispatch
  vs 66–74), dealloc no-op (1 row), realloc in place for the newest block
  else alloc+copy. size_class_alloc stays the jolt default. Peak heap
  measured with a temporary print (reverted): 781 46.7 MiB, 782 53.8, 785
  52.7, 789 57.8 MiB of the 1.5 GiB heap. 781 −15,788,648 (allocator
  21.1M → 3.4M; memcpy +1.9M from realloc copies of non-newest blocks).

### Ladder (jolt-amber @ ef89da425, jeth @ 342c8d1)

| Block | Gas | Wave-F rows | Wave-G rows | Delta rows | c/g F → G |
|---|---:|---:|---:|---:|---|
| 25905781 | 44,227,079 | 749,233,347 | 720,149,112 | -29,084,235 | 16.940602 → 16.282991 |
| 25905782 | 47,065,991 | 890,175,181 | 860,674,308 | -29,500,873 | 18.913342 → 18.286544 |
| 25905783 | 25,320,107 | 414,886,377 | 397,513,426 | -17,372,951 | 16.385649 → 15.699516 |
| 25905784 | 19,039,352 | 315,845,472 | 303,717,352 | -12,128,120 | 16.589087 → 15.952085 |
| 25905785 | 47,351,982 | 792,751,133 | 763,225,683 | -29,525,450 | 16.741667 → 16.118136 |
| 25905786 | 26,354,048 | 366,438,325 | 352,150,653 | -14,287,672 | 13.904442 → 13.362298 |
| 25905787 | 27,961,947 | 494,122,962 | 475,966,151 | -18,156,811 | 17.671265 → 17.021925 |
| 25905788 | 6,217,605 | 117,757,192 | 111,654,533 | -6,102,659 | 18.939317 → 17.957804 |
| 25905789 | 44,608,380 | 855,305,307 | 824,188,440 | -31,116,867 | 19.173646 → 18.476090 |
| 25905790 | 32,881,199 | 541,444,076 | 519,807,872 | -21,636,204 | 16.466677 → 15.808665 |
| Gas-weighted | 321,027,690 | 5,537,959,372 | 5,329,047,530 | -208,911,842 | **17.250722 → 16.599962** |

Per sub-lane set deltas: 1a −72,719,096 (→ 17.024202), 1b −19,775,684
(→ 16.962601), 2 −116,417,062 (→ 16.599962). Cumulative vs wave-4
baseline: **19.780546 → 16.599962 (−3.180584 c/g, −16.1%;
−1,021,055,580 rows)**.

### Gates (each sub-lane)

- Trace 781 hash + perms 118,366 exact ×3; sweep 782–790 hashes unchanged
  ×3; `run-native` 10/10 ×3 (secp-inline host path exercises the new
  compares natively).
- jeth nextest 15/15 ×3; jolt secp256k1 inline tests 15/15
  (`--features host`), jolt-platform 2/2 (bump + size_class); clippy/fmt
  clean in both worktrees.
- Follow-ups: residual memcmp 6.8M is B256 `==`/`Ord` spread across
  revm/alloy (no single hot site); a guest-owned `#[global_allocator]` with
  const-folded layouts would take alloc ~15.6 → ~6 rows (≈ −1.8M more).

## Campaign opt-amber wave H — word-wise keccak256 shim on the plain-permutation inline (jeth-only)

The guest keccak shim (`native_keccak256` → `jolt_inlines_keccak256::digest`)
spent ~613 rows/call outside the permutations on 781: two memsets (200-B
state + 136-B block), a memcpy of the tail, byte-wise padding, and a
byte-wise 32-byte digest store (32 × SB + 28 shifts = 224 rows). New
`crates/guest/src/keccak.rs`: 25 SD zero state; block 1 written into the
zeroed rate lanes and run through the PLAIN permutation inline (funct3 = 0,
emitted via `.insn` — no SDK wrapper existed), aligned middle blocks through
the absorb inline, the final block assembled word-wise into an aligned
`[u64; 17]` with the padding folded in and XORed into the state by the shim
+ plain permute; digest 4 LD + 4 SD when `out % 8 == 0`, else a 5-word RMW.
Built shim = 567 straight-line instructions, no memset/memcpy/sub-word ops.
Differential test vs `keccak`/`sha3` over lengths 0..=600 × 8 input × 8
output alignments + random ≤ 20 kB (scratch crate; crates/guest cannot
build natively as a lib test, pre-existing). jeth commit 3927376.

Permutation count is unchanged by construction (`len/136 + 1` per call);
the absorb → plain switch on first/final blocks also saves 34 inline rows
each (2.56M on 781). The `keccak-census` counters (calls/bytes/perms lines
the accounting gate reads) stay on by default: 1,053,359 rows on 781
(0.15%), removable with `--no-default-features` on the guest.

### Ladder (jolt-amber @ ef89da425, jeth @ 3927376)

| Block | Gas | Wave-G rows | Wave-H rows | Delta rows | c/g G → H |
|---|---:|---:|---:|---:|---|
| 25905781 | 44,227,079 | 720,149,112 | 699,847,443 | -20,301,669 | 16.282991 → 15.823958 |
| 25905782 | 47,065,991 | 860,674,308 | 839,467,790 | -21,206,518 | 18.286544 → 17.835974 |
| 25905783 | 25,320,107 | 397,513,426 | 386,626,391 | -10,887,035 | 15.699516 → 15.269540 |
| 25905784 | 19,039,352 | 303,717,352 | 294,892,203 | -8,825,149 | 15.952085 → 15.488563 |
| 25905785 | 47,351,982 | 763,225,683 | 742,417,399 | -20,808,284 | 16.118136 → 15.678697 |
| 25905786 | 26,354,048 | 352,150,653 | 342,306,032 | -9,844,621 | 13.362298 → 12.988746 |
| 25905787 | 27,961,947 | 475,966,151 | 463,808,305 | -12,157,846 | 17.021925 → 16.587125 |
| 25905788 | 6,217,605 | 111,654,533 | 108,365,826 | -3,288,707 | 17.957804 → 17.428869 |
| 25905789 | 44,608,380 | 824,188,440 | 801,871,557 | -22,316,883 | 18.476090 → 17.975805 |
| 25905790 | 32,881,199 | 519,807,872 | 504,029,365 | -15,778,507 | 15.808665 → 15.328801 |
| Gas-weighted | 321,027,690 | 5,329,047,530 | 5,183,632,311 | -145,415,219 | **16.599962 → 16.146994** |

Cumulative vs wave-4 baseline: **19.780546 → 16.146994 (−3.633552 c/g,
−18.4%; −1,166,470,799 rows)**.

Attribution on 781: native_keccak256 self 316,868,938 → 307,744,048, of
which inline rows 298,681,814 (118,366 × 2,511 + 34 × 43,082 aligned middle
blocks); non-permutation shim rows 9,062,234 = 190.8/call with census
(~169 without; the drafter's ~128 assumed a shorter tail mix — 58.5% of
calls are multi-block with ~15-word tails); memset under keccak 5.70M → 0,
memcpy under keccak 3.77M → 0; memset total 8.29M → 2.60M.

### Gates

- Native gate: `run-native` all ten blocks match records.
- Traces: all ten hashes match; census exact (calls 47,504, bytes
  13,417,708, perms 118,366; new `unaligned=1691` counter).
- Disassembly of the built shim: 567 instrs = reference 546 + 21-instr
  census block; 0 memset/memcpy/sub-word, 6 `.insn` sites.
- jeth nextest 15/15; scratch-crate differential tests 3/3 (release +
  debug). Jolt: untouched.

## Campaign opt-amber wave I — MPT decode/walk residue (jeth-only, 7 steps)

Seven measured steps on the vendored zeth-mpt decoder, the memoizer and
jeth's trie walk, each committed and gated separately (hash + census exact
after every commit):

| Step | Commit | Change | 781 Δ rows |
|---|---|---|---:|
| #1 | 02b2e59 | digest child items (`0xa0`+32 B) decoded straight into the child slot: aligned `Digest` wrapper, `le_words_32` containing-word gather — no recursive decode call, no memcpy(32) | -21,598,026 |
| #2 | 197f4bb | in-place list item scan (count pass + decode pass with `0x80`/`0xa0` fast paths); the `PayloadView` Vec and its grow chain are gone | -8,614,876 |
| #4 | e005be3 | walk.rs `item_header` fast paths; single-pass `validate_at` (was two 17-item passes) | -4,144,845 |
| #5 | 4db8cf2 | `needs_memo` tested by the parent before descending in `memoize_arena` (`encode_dirty`) | -3,783,557 |
| #6 | d1bb42e | `Step::Digest([u64;4])`; `verify_slot`/`walk_storage`/`storage_roots` on words; `resolve → Option<&Bytes>` (no Bytes clone/drop per hit) | -6,219,464 |
| #7 | f4e0a15 | `zeth_mpt::decode_header`: byte-wise long-form RLP lengths (replaces alloy Header's memcpy+bswap) in decoder and walk | -2,045,766 |
| #8 | 3783869 | `Node::get` depth cursor with a word-built packed key (no `Nibbles::unpack` per level); `SparseState::last_read` one-entry (address → hash, root) memo | -1,720,802 |

(60e03bb is test-only: canonical single-byte path items in the zc parity
corpus.) Unsafe added: `le_words_32` (aligned containing-word
`read_volatile`, mem.rs flat-RAM argument) and two layout-identity
transmutes (`[[u8;8];4] → [u8;32]`); removed: `read_unaligned` in
`limbs_of`, `get_unchecked` in `Node::get`. Accept set of `validate_at` is
unchanged (parity test vs `Node::decode`); only the reported error variant
for entries with several coexisting defects follows scan order.

### Ladder (jolt-amber @ ef89da425, jeth @ 3783869)

| Block | Gas | Wave-H rows | Wave-I rows | Delta rows | c/g H → I |
|---|---:|---:|---:|---:|---|
| 25905781 | 44,227,079 | 699,847,443 | 651,720,107 | -48,127,336 | 15.823958 → 14.735771 |
| 25905782 | 47,065,991 | 839,467,790 | 787,854,076 | -51,613,714 | 17.835974 → 16.739350 |
| 25905783 | 25,320,107 | 386,626,391 | 360,591,789 | -26,034,602 | 15.269540 → 14.241322 |
| 25905784 | 19,039,352 | 294,892,203 | 273,306,846 | -21,585,357 | 15.488563 → 14.354840 |
| 25905785 | 47,351,982 | 742,417,399 | 691,153,814 | -51,263,585 | 15.678697 → 14.596090 |
| 25905786 | 26,354,048 | 342,306,032 | 318,591,298 | -23,714,734 | 12.988746 → 12.088894 |
| 25905787 | 27,961,947 | 463,808,305 | 435,185,262 | -28,623,043 | 16.587125 → 15.563482 |
| 25905788 | 6,217,605 | 108,365,826 | 99,794,877 | -8,570,949 | 17.428869 → 16.050373 |
| 25905789 | 44,608,380 | 801,871,557 | 746,502,505 | -55,369,052 | 17.975805 → 16.734580 |
| 25905790 | 32,881,199 | 504,029,365 | 467,184,434 | -36,844,931 | 15.328801 → 14.208254 |
| Gas-weighted | 321,027,690 | 5,183,632,311 | 4,831,885,008 | -351,747,303 | **16.146994 → 15.051303** |

Cumulative vs wave-4 baseline: **19.780546 → 15.051303 (-4.729243 c/g,
-23.9%; -1,518,218,102 rows)**.

Attribution on 781: decode_node_zc_into 28.67M → 18.26M · memoize_arena
17.25M → 12.65M · SparseState::storage 9.56M → 5.45M · validate_at 9.33M →
5.56M · resolve_with 8.77M → 6.17M · WitnessResolver::resolve 6.11M → 3.68M
· memcpy 41.48M → 29.05M (decode's 10.83M share gone) · RlpTrie/Node::get
2.31M → 1.61M · hash_address 1.36M → 0.81M · storage_roots probe 1.18M →
0.49M. #1 beat its band (the recursive call also carried sret/frame rows);
#2/#4 landed under (the Vec cost had been measured under the size-class
allocator; long headers stayed until #7).

### Gates

- Trace 781 hash + census exact after each of the 8 commits; `run-native`
  10/10; sweep 782–790 hashes unchanged.
- jeth workspace nextest 17/17; vendored zeth-mpt 24/24 (new parity and
  fast-path tests). Jolt: untouched.

## Killed: block-level journal finalize (revm per-tx finalize+commit)

Audit (R1) sized the per-tx `finalize` + `State::commit` churn at ~4–7M
rows on 781 (per-(tx,account) `State::basic` reloads, per-(tx,slot)
`State::storage` re-probes, journal map teardown/rebuild). A drafting pass
(design + consensus argument, /tmp/journal-fix1/) found that the obvious
fix — `transact_one` × N, one `finalize`, one `State::commit` — is NOT
semantics-preserving in revm 38 + revm-database 13: (a)
`EvmStorageSlot.original_value` is reset to the present value on every
cross-tx cold load and `apply_account_state` keeps only `is_changed()`
slots, so a slot written in tx i and read in tx j drops out of the bundle
(wrong root); (b) the global `SelfDestructed` flag short-circuits
`apply_account_state`, so a contract destroyed in tx i and re-created in tx
j is deleted; (c) EIP-161 deletion of pre-state empty accounts is only
reproducible per tx. The draft repairs (a)/(b) driver-side and falls back to
per-tx finalize for (c). Verdict: killed. Any residual divergence in a
hand-patched bundle assembly is a deterministic, attacker-triggerable
semantic difference — a soundness hole, not a completeness one — and the
10-block gate cannot exclude it. Not worth ~0.7–1% of rows. Remaining
journal items (witness presize ~0.25M, `#[inline(never)]` removal ~0.6M,
fused warm-SLOAD pointer cache ~1.3M/medium-high risk) are tail.

## Campaign opt-amber wave J — revm interpreter hot paths (jeth-only, vendored revm-interpreter)

Handler::execution's dispatch loop is 22 rows per EVM op × ~1.8M ops on
781; PUSHn, MSTORE/MLOAD/CALLDATALOAD and the initial-gas calldata count
were byte-wise. Five commits, each gated (hash + census exact):

| Step | Commit | Change | 781 Δ rows |
|---|---|---|---:|
| 0 | 67d4083 | keccak-shim review nits: `#[inline(never)] native_keccak256`; in-tree `crates/guest/native-tests` (own workspace; keccak vs sha3 + mem fuzz, 4 tests); UB doctrine stated in keccak.rs | 0 |
| 1 | 2964732 | `ExtBytecode::continue_execution: bool → u64` (loop flag LD, not LBU) | -3,633,556 |
| 2 | fe1a192 | SWAR calldata token count for initial tx gas (`calculate_initial_tx_gas_for_tx` shadows the glob re-export; `GasParams::initial_tx_gas` via pub accessors; 8-aligned interior, byte head/tail) | -1,720,767 |
| 3 | 4c94224 | PUSHn via `words::read_be_immediate::<N>`: N≤4 sequential byte loads; N≥5 volatile LD of the containing words + funnel shift + 13-op asm `bswap64`; `Stack::push` stores 4 limbs directly (PUSH32 287 → ~118 rows, PUSH20 176 → ~102, PUSH4 47 → 34) | -3,826,942 |
| 4 | 8f08c51 | `read/write_u256_be` with asm bswap64, `#[inline(always)]` into mstore/mload/calldataload (no 4 LD + 4 SD temp, call, 13 spills); guest uses the containing-word rule with volatile edge RMW, native keeps a `#[cold]` byte path behind a window check | -6,331,826 |
| 5 | — | JUMP/JUMPI jumpdest bit via LD: dropped (≤ −0.37M; jump tables are not alignment-guaranteed) | 0 |

Dispatch loop now 19 rows/op; the remaining structure (ip/gas round-trip
memory, two ABI `mv`s, flag reload) is fixed under the current design —
the only structural saving left is −2 rows/op by moving static gas into
each instruction (~140 fns), not done. Unsafe added (each with SAFETY):
`align_to::<u64>` in the SWAR count; `asm!` bswap64 (pure, nomem);
volatile containing-word loads in `read_be_immediate` (analysis pads
truncated immediates + STOP); `read/write_u256_be` five-word path;
`RefCell::as_ptr` in `context_bytes(_mut)` under the invariant
`buffer_ref(_mut)` already assume.

### Ladder (jolt-amber @ ef89da425, jeth @ 8f08c51)

| Block | Gas | Wave-I rows | Wave-J rows | Delta rows | c/g I → J |
|---|---:|---:|---:|---:|---|
| 25905781 | 44,227,079 | 651,720,107 | 636,207,016 | -15,513,091 | 14.735771 → 14.385011 |
| 25905782 | 47,065,991 | 787,854,076 | 764,755,471 | -23,098,605 | 16.739350 → 16.248579 |
| 25905783 | 25,320,107 | 360,591,789 | 352,672,764 | -7,919,025 | 14.241322 → 13.928565 |
| 25905784 | 19,039,352 | 273,306,846 | 265,684,444 | -7,622,402 | 14.354840 → 13.954490 |
| 25905785 | 47,351,982 | 691,153,814 | 673,227,692 | -17,926,122 | 14.596090 → 14.217519 |
| 25905786 | 26,354,048 | 318,591,298 | 310,214,938 | -8,376,360 | 12.088894 → 11.771055 |
| 25905787 | 27,961,947 | 435,185,262 | 422,441,198 | -12,744,064 | 15.563482 → 15.107718 |
| 25905788 | 6,217,605 | 99,794,877 | 98,211,703 | -1,583,174 | 16.050373 → 15.795745 |
| 25905789 | 44,608,380 | 746,502,505 | 726,953,345 | -19,549,160 | 16.734580 → 16.296340 |
| 25905790 | 32,881,199 | 467,184,434 | 456,164,853 | -11,019,581 | 14.208254 → 13.873121 |
| Gas-weighted | 321,027,690 | 4,831,885,008 | 4,706,533,424 | -125,351,584 | **15.051303 → 14.660833** |

Cumulative vs wave-4 baseline: **19.780546 → 14.660833 (-5.119713 c/g,
-25.9%; -1,643,569,686 rows)**.

Attribution on 781: Handler::execution 38.76M → 35.14M (−2 rows × 1.81M
ops); mstore+set_u256 8.75M → 5.73M; mload+get_u256 5.83M → 3.32M;
calldataload 3.43M → 2.79M; PUSH1–32 total 15.45M → 12.03M;
calculate_initial_tx_gas 2.17M → 0.44M. SharedMemory's buffer is align-1
under the bump allocator, so ~7/8 of MSTORE/MLOAD still take the five-word
path — an 8-byte minimum alignment in bump_alloc (next lane) makes the
4 LD / 4 SD path the common one (≈ −1.9M more on 781) and aligns every
Bytes/Vec<u8> for the memcpy/keccak gathers.

### Gates

- Trace 781 hash + census exact after each commit; `run-native` 10/10;
  sweep 782–790 hashes unchanged.
- jeth nextest 17/17; vendored revm-interpreter 47/47 (5 new: SWAR vs byte
  filter, initial_tx_gas vs GasParams for all 21 specs, bswap64 vs
  swap_bytes, read_be_immediate all N × offsets, read/write_u256 all
  alignments + slice edges); guest native-tests 4/4. Jolt: untouched.

## Campaign opt-amber wave K — tail lane: allocator alignment, bn254 GLV ecmul, signed-digit pippenger, memcpy gather unroll

Four independent mechanisms, each committed and measured alone on 781
(hash 0xf691…b529 and census calls=47504 bytes=13417708 perms=118366
exact after every step):

| Step | Commit | Change | 781 Δ rows |
|---|---|---|---:|
| 0 | jeth 83cdf44, jolt 5abd70abf | review nits (LastRead invariant doc, `UnexpectedList` message, dead `Children::get_unchecked` deleted, bump_alloc round-up no-wrap `debug_assert` + realloc contract doc, `compile_error!` for `bump-alloc` on std guests) | 0 |
| 1 | jolt 920868471 | bump_alloc 8-byte minimum alignment: `mask = (align-1) \| 7`, one extra `or` per alloc, no size rounding (the next round-up absorbs odd tails) | −1,914,726 |
| 2 | jeth 7c04044 | `JoltCrypto::bn254_g1_mul`: revm-identical parsing (both rejection variants), then ark's `GLVConfig::glv_mul_affine` (128 dbl + ~64 mixed + ~32 full adds vs 253 dbl + 127 mixed via `Affine::mul_bigint`), canonical affine encoding | −1,684,270 |
| 3 | jeth b7b6098 | pippenger signed-digit buckets: low 15 windows biased by 2^(w−1) once per term (u128), digit−128 exact signed digit → 129 live buckets, reduction 2·128 instead of 2·255; top window unsigned + carry (array 257); negated points precomputed per term | −1,152,653 |
| 4 | jeth d4e980f | misaligned memcpy gather: 4 window words per iteration, carried word rotates through registers (~25 rows/32 B vs ~10/8 B) | −1,602,932 |

Attribution on 781 — step 1: memcpy −1.22M, native_keccak256 −0.87M
(aligned Bytes/Vec<u8> sources), bump_alloc::alloc +0.17M (~167k allocs).
**Refuted:** the ≥ −1.9M forecast from MSTORE/MLOAD (−4.2k / −5.4k
measured): their five-word path is EVM-offset-driven (offsets ≡ 4 mod 8
from selector packing), not buffer-alignment-driven; the total matched
the forecast by coincidence. Step 2: −210k rows/ecmul (8 ecmuls; Fq
`mul_assign` −675k, `square_in_place` −731k), below the 2–3M forecast;
JSF/all-affine-table refinement evaluated and skipped (≈ +0.45M net after
the BEA inversion cost, under the 0.5M rule). Step 3: the 3.3M forecast
double-counted — 3,808 reduction adds saved, but fewer buckets halve the
first-add copies (4,080 → 2,176), so 1,904 copies became full adds
(~540 virtual rows each ≈ 1.02M); measured −1.02M virtual + glue −0.14M.
A `flat_map/collect` first version measured only −0.30M (152-byte `Term`
moves +0.73M); explicit push loop landed. Step 4: memcpy −1.79M, memcmp
+0.13M attribution shift; ≈ 3.8 MB of misaligned bulk per block at 15 rows
saved per 32 B.

### Ladder (jolt-amber @ 920868471, jeth @ d4e980f)

| Block | Gas | Wave-J rows | Wave-K rows | Delta rows | c/g J → K |
|---|---:|---:|---:|---:|---|
| 25905781 | 44,227,079 | 636,207,016 | 629,852,435 | -6,354,581 | 14.385011 → 14.241330 |
| 25905782 | 47,065,991 | 764,755,471 | 755,248,283 | -9,507,188 | 16.248579 → 16.046582 |
| 25905783 | 25,320,107 | 352,672,764 | 348,518,980 | -4,153,784 | 13.928565 → 13.764515 |
| 25905784 | 19,039,352 | 265,684,444 | 262,030,857 | -3,653,587 | 13.954490 → 13.762593 |
| 25905785 | 47,351,982 | 673,227,692 | 661,716,123 | -11,511,569 | 14.217519 → 13.974412 |
| 25905786 | 26,354,048 | 310,214,938 | 306,039,431 | -4,175,507 | 11.771055 → 11.612616 |
| 25905787 | 27,961,947 | 422,441,198 | 418,876,331 | -3,564,867 | 15.107718 → 14.980228 |
| 25905788 | 6,217,605 | 98,211,703 | 96,999,978 | -1,211,725 | 15.795745 → 15.600859 |
| 25905789 | 44,608,380 | 726,953,345 | 714,461,354 | -12,491,991 | 16.296340 → 16.016304 |
| 25905790 | 32,881,199 | 456,164,853 | 452,385,419 | -3,779,434 | 13.873121 → 13.758179 |
| Gas-weighted | 321,027,690 | 4,706,533,424 | 4,646,129,191 | -60,404,233 | **14.660833 → 14.472674** |

Cumulative vs wave-4 baseline: **19.780546 → 14.472674 (-5.307872 c/g,
-26.8%; -1,703,973,919 rows)**.

### Gates

- Trace 781 hash + census exact after each step; `run-native` 10/10
  hashes = records; sweep 782–790 hashes unchanged.
- jeth nextest 18/18 (new: bn254 GLV parity vs `DefaultCrypto` — 66 points
  × 9 edge scalars {0, 1, 2, r−1, r, r+1, 2^128, 2^128−1, 2^256−1} + 10k
  random raw scalars + off-curve / x = p rejections; pippenger batch test
  widened to 598 equations so w = 7 and w = 8 both run natively); guest
  native-tests 4/4 (memcpy fuzz over n/soff/doff); jolt-platform nextest
  2/2 + clippy `-D warnings`.
- No new `unsafe`: mem.rs loads sw+1..sw+4 live inside the existing
  `memcpy_impl` block (liveness argument `rem ≥ 32` in the comment);
  bn254.rs / recovery_batch.rs are safe code. New jeth-core deps
  ark-bn254/ark-ec/ark-ff 0.5 (already in the graph via revm-precompile).

## Campaign opt-amber wave L — static gas charged inside each instruction (jeth-only, vendored revm-interpreter)

`Interpreter::step` loaded a 16-byte table entry {fn_, static_gas} and
charged gas in the loop (ld static_gas, ld remaining, bltu, sub, sd).
Commit 82e2b8e: `Instruction` is a `#[repr(transparent)]` fn pointer; one
authoritative `const fn static_gas(opcode, spec)` reproduces the legacy
base table + spec repricings; every instruction charges first via
`static_gas!` — spec-independent opcodes take a const path
`Gas::record_static_cost::<COST>()`, the repriced ones (SLOAD, BALANCE,
EXTCODESIZE/COPY/HASH, CALL/CALLCODE/DELEGATECALL/STATICCALL,
SELFDESTRUCT) a runtime spec switch. `instruction_table_gas_changes_spec`
is now the identity (kept for revm-handler API compatibility); dead
`Gas::record_cost_unsafe` deleted. No static+dynamic folding: every
spec-dependent op pops before its dynamic charge, so folding would flip
OOG/underflow priority (follow-up, ~5 rows × rare ops).

**Refuted first:** the plain relocation is row-neutral (first build
−202,454 on 781): RISC-V has no compare-immediate-branch, so `li; bltu`
replaced the table's `ld static_gas` 1:1 — only ~40k zero-gas ops
(STOP/RETURN/REVERT/SSTORE/CREATE) saved 5 each. Landed form: the
remaining−COST subtraction is an opaque `addi` (inline asm, riscv64 only,
COST ≤ 2047, wrapping_sub otherwise) so the OOG test is one
`bltu rem, new` → 4 rows per op instead of 5 (disassembly-confirmed:
ld/li/bltu/addi/sd → ld/addi/bltu/sd). Handler::execution 35,142,651 →
26,171,091 (−8.97M ≈ 5 rows × 1.79M ops); instructions +7.18M ≈ 4 rows/op.

### Ladder (jolt-amber @ 920868471, jeth @ 82e2b8e)

| Block | Gas | Wave-K rows | Wave-L rows | Delta rows | c/g K → L |
|---|---:|---:|---:|---:|---|
| 25905781 | 44,227,079 | 629,852,435 | 628,057,124 | -1,795,311 | 14.241330 → 14.200737 |
| 25905782 | 47,065,991 | 755,248,283 | 752,824,321 | -2,423,962 | 16.046582 → 15.995081 |
| 25905783 | 25,320,107 | 348,518,980 | 347,551,111 | -967,869 | 13.764515 → 13.726289 |
| 25905784 | 19,039,352 | 262,030,857 | 261,286,739 | -744,118 | 13.762593 → 13.723510 |
| 25905785 | 47,351,982 | 661,716,123 | 659,523,299 | -2,192,824 | 13.974412 → 13.928103 |
| 25905786 | 26,354,048 | 306,039,431 | 305,065,240 | -974,191 | 11.612616 → 11.575650 |
| 25905787 | 27,961,947 | 418,876,331 | 417,399,516 | -1,476,815 | 14.980228 → 14.927412 |
| 25905788 | 6,217,605 | 96,999,978 | 96,747,647 | -252,331 | 15.600859 → 15.560276 |
| 25905789 | 44,608,380 | 714,461,354 | 712,067,679 | -2,393,675 | 16.016304 → 15.962644 |
| 25905790 | 32,881,199 | 452,385,419 | 451,027,881 | -1,357,538 | 13.758179 → 13.716893 |
| Gas-weighted | 321,027,690 | 4,646,129,191 | 4,631,550,557 | -14,578,634 | **14.472674 → 14.427262** |

Cumulative vs wave-4 baseline: **19.780546 → 14.427262 (-5.353284 c/g,
-27.1%; -1,718,552,553 rows)**.

### Gates

- Native oracle: `static_gas(op, spec) == legacy_table(spec)[op]` for all
  256 opcodes × every SpecId; new test: every opcode halts OutOfGas at
  cost−1 and never at cost, under every spec (catches wrong-opcode
  charges). Vendored revm-interpreter 49/49; workspace nextest 18/18.
- Trace 781 hash + census exact; `run-native` 10/10; sweep 782–790 hashes
  unchanged.
- Unsafe: one new block — `asm!("addi {r}, {x}, {neg}")` in gas.rs
  `sub_const`, `cfg(target_arch = "riscv64")`, `options(pure, nomem,
  nostack)`, register-only.

## Evaluated, not built: bn254 Fq Montgomery multiplication inline

Design in `.journals/bn254-fq-inline-design.md`. q has four full limbs, so
the Montgomery m·q half costs as much as a·b (secp256k1's sparse p is why
its inline wins), and the virtual ISA has no carry primitive: floor = 60
partial-product half-terms × 4 rows. Compiled ark-ff-macros CIOS is
already ≈310 dynamic rows per `mul_assign` (≈520 per
`sum_of_products::<2>`, ≈270 per square); an inline MULQ lands at 285
(−8%), SOPQ2 at 419 (−20%), square gains nothing. Block 781: −3.2M rows
≈ 0.51% (785/789 ≈ 0.58%; +fused Fp2 ≈ 0.64%) for ~20 h (+6 h). Marginal
against the 0.5% bar; pre-gate (count calls in the trace: GO only if
≥ 305 / ≥ 515 rows per call) before committing effort.

## Documented, not built: bn254 Fq Montgomery inline (design only)

Design in `.journals/bn254-inline-design.md` (shard c9bc0c3e, 06:01).
ark-ff bn254 Fq arithmetic is ≈19.7M rows on 781 (3.1%; ~2× on 785/789):
compiled `mul_assign` ≈310 dynamic rows, `sum_of_products::<2>` ≈520,
`square` ≈270 (no-carry CIOS from `#[derive(MontConfig)]`). A jolt inline
(deterministic product-scanning REDC, no advice) reaches ≈285 / ≈419 rows —
q has four full limbs, so the m·q reduction costs as much as a·b, unlike
secp256k1's sparse p. Saving ≈ −3.2M on 781 (0.48–0.69%), ≈ −3.6M on
785/789; ≈20 h (+6 h for a fused Fp2 mul, ≈0.64%). Gate before building:
count the two symbols' calls in the 781 trace; GO iff ≥305 / ≥515 rows per
call. Square and Fr inlines: no gain, never build.
