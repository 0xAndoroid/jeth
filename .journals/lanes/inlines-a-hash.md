# Lane A-hash — SHA256 (0x02) and BLAKE2F (0x09) on the Jolt sha2 / blake2 inlines

Branch `inlines-a-hash` (base `inlines-a` @ 60283c9). Jolt pin `jolt-amber-nolane` (read-only).
Build dirs: `CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-inlines-a-hash`,
`JETH_GUEST_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-inlines-a-hash-guest` (after) /
`...-guest-off` (before = same tree, `sha2-inline`/`blake2-inline` removed from the guest's jeth-core features).
Harness copy: `/tmp/opcg-inlines-a-hash/` (`evm.py` with `JETH`/`SYNTH`/`WORK` env overrides, `lane.py`).

## Design
- `Crypto::sha256` → `jolt_inlines_sha2::Sha256::digest` (SDK: 8-aligned 64-byte buffer, SHA256INIT for
  block 0 then SHA256; the inline byte-swaps the big-endian block itself). `#[cfg(all(feature = "sha2-inline",
  target_arch = "riscv64"))]` so run-native keeps revm's sha2 crate as the independent reference.
- `Crypto::blake2_compress` → the BLAKE2b inline only when `rounds == 12 && t[1] == 0`; else revm's
  `blake2::algo::compress`. The blake2 SDK exports no compression entry point (`blake2b_compress` is
  `pub(crate)`), so jeth issues the `.insn` itself: rs1 = `h[8]` (read+written in place), rs2 = 18 words
  `m[0..16], t0, f∈{0,1}` (the inline forms the final mask as `0 - f`, so the flag must be exactly 0/1).
- Equivalence for rounds 12, t[1] = 0 (sequence_builder.rs vs revm algo.rs): v[0..8]=h, v[8..16]=IV (same
  constants), v[12]^=t0, v[13]=IV[5] (t1 = 0), v[14]^=!0 iff f; 12 rounds over `SIGMA[0..12]` where the inline's
  rows 10,11 equal rows 0,1 = revm's `SIGMA[r % 10]`; G = add/xorrot32/add/xorrot24/add/xorrot16/add/xorrot63
  (xorrotN(x,y) = (x^y).rotr(N)) = revm's g; h[i] ^= v[i]^v[i+8]. Native tests pin the crates' software
  models to sha2 / revm compress / EIP-152 vectors 5-6; the real inline is checked in-guest by the
  verification blocks (trace block_hash == run-native block_hash with every output SSTOREd).
- Features `sha2-inline`, `blake2-inline` on jeth-core (imply `secp-inline`, which owns `JoltCrypto`);
  enabled in crates/guest/Cargo.toml. Host links both crates with `host` (inventory registration).

## Steps / numbers
- 20:02 HEAD (60283c9) host + guest pair built on the lane dirs (`-guest-off` prefix). 10-block trace, HEAD tree:
  781 603,187,849 · 782 721,922,331 · 783 333,212,703 · 784 251,155,760 · 785 629,550,097 · 786 291,932,998 ·
  787 401,722,255 · 788 92,465,028 · 789 677,090,260 · 790 432,652,892 — every block 14 rows under the no-lane
  ledger in the prompt (constant offset from the two synth-tool commits on `inlines-a`); hashes == run-native,
  781 perms 115,373.
- 20:10 code: workspace/host/core/guest manifests, `extern crate` registrations, `Crypto::sha256` +
  `Crypto::blake2_compress` overrides, `blake2b_compress_inline` (.insn), 3 native tests (all green:
  sha2 model vs sha2 crate 0..=600 + 1024/8192/20000 + all-0xff; blake2 model vs revm compress 4000 random
  (h,m,t0∈{0,max,rand,128i},f); EIP-152 vectors 5/6 vs both).
- Before (whole-block Δ: block A = K units, block B = K/2 units, same code length, one tx per block; rows/unit =
  Δrows/(K/2); unit = 5×DUP + GAS + STATICCALL(warm) + POP around the precompile, cases2.py inputs):
  SHA256/0B 9,726.6 rows/u (179 gas, 54.34 c/g) · 32B 9,751.0 (191, 51.05) · 1024B 78,673.4 (563, 139.74) ·
  8192B 554,560.1 (3,251, 170.58) · BLAKE2F/r0 6,905.7 (119, 58.03) · r1 7,052.1 (120, 58.77) ·
  r12 9,853.2 (131, 75.21) · r1000 260,009.4 (1,119, 232.36). K = 1000/1000/400/100/1000/1000/1000/200.
- Verification blocks (before, software path): sha256 block 7,263,798 rows, blake2f block 6,762,282 rows; trace
  hash == native hash, all 39 txs successful (EQ against Python/hashlib expectations inside the contracts).
- 20:18 after pair built (`sha2-inline`,`blake2-inline` on; guest dirs seeded from the -off dirs, incremental).
  Verification blocks (after, inline path): sha256 block 6,550,252 rows (−713,546), blake2f block 6,746,000
  (−16,282: 8 of the 21 units are rounds-12/t1=0 → inline); trace hash == native hash on both, 39/39 txs ok.
- 10-block gate (rows before → after, Δ; all 10 trace hashes == run-native, keccak perms identical, 781 = 115,373):
  781 603,187,849 → 603,149,073 (−38,776) · 782 721,922,331 → same (0) · 783 333,212,703 → 333,164,576 (−48,127) ·
  784 251,155,760 → 251,140,035 (−15,725) · 785 629,550,097 → 629,443,720 (−106,377) · 786 291,932,998 →
  291,907,684 (−25,314) · 787 401,722,255 → 401,655,739 (−66,516) · 788 92,465,028 → same · 789 677,090,260 →
  676,983,883 (−106,377) · 790 432,652,892 → same. Total −407,212 rows (−0.009%); gas-weighted 13.814672 →
  13.813403 c/g over 321,027,690 gas. Blocks with BLAKE2F calls: none observed (delta is all SHA256).
- After (same K, same blocks, after binaries), rows/unit before → after (unit c/g before → after; op-only c/g with the
  study's 188-row/19-gas glue in brackets):
  SHA256/0B 9,726.6 → 6,964.6 (54.34 → 38.91 [59.6 → 42.4]) · 32B 9,751.0 → 7,004.0 (51.05 → 36.67 [55.6 → 39.6]) ·
  1024B 78,673.4 → 38,595.3 (139.74 → 68.55 [144.3 → 70.6]) · 8192B 554,560.1 → 255,650.1 (170.58 → 78.64
  [171.5 → 79.0]) · BLAKE2F/r0 6,905.7 → 6,907.7 (+2 rows: the rounds/t1 branch) · r1 7,052.1 → 7,054.1 (+2) ·
  r12 9,853.2 → 7,814.2 (75.21 → 59.65 [86.3 → 68.1]) · r1000 260,009.4 → 260,011.4 (232.36, unchanged: software).
  Per 64-byte SHA-256 block: (255,650 − 38,595)/(128 − 16) = 1,938 rows = inline 1,900 + ~38 rows block copy/loop.
  Adversarial 60M-gas block (unit gas incl. warm STATICCALL glue): SHA256/8 KiB 10.23 G → 4.72 G rows;
  BLAKE2F r12 loop 4.51 G → 3.58 G; BLAKE2F r1000 loop stays 13.94 G (software path, 253 rows/round asymptote —
  the inline cannot serve non-12-round calls).
- Rigor: the -off pair rebuilt from the final tree with the two features removed reproduces the HEAD rows exactly
  (781 603,187,849 · 788 92,465,028 · 790 432,652,892) → no contamination from the wiring itself.
- 781 attribution (`jeth profile --rows --top 3000`, symbols build; rows identical to the streaming trace):
  `sha2::sha256::compress256` 72,296 → 4,603 (the residual = one software SHA-256 per block: EIP-7685
  requests hash in post-execution validation, alloy-eips) · `JoltCrypto::sha256` 3,194 → 31,541 (15 inline
  compressions) · `sha256_precompile` 469 → 469. `jeth opcodes`: INLINE(custom-0) 224,264 → 224,279 executions
  (+15, +28,248 rows) while C.other −17,494, ALU-I −19,282, ALU-R −15,593, LBU −3,268, LD −5,106, SD −3,537 rows.
  Net −38,776 = the SHA256 precompile's 15 blocks moving from ~4.6k software rows to ~1.9k inline rows each.
- Residual software sha2 in the guest (`cargo tree -i sha2`, riscv target): alloy-eips (EIP-7685 requests hash,
  1 compress/block; KZG versioned hash per POINTEVAL), k256 / p256 (type-level digests only, no runtime calls on
  jeth's paths), revm-precompile (now only the KZG versioned hash). None is a measured hot path (≤ 4.6k rows/block)
  → not routed; `blake2` crate absent from the guest graph.
- Gates: nextest 27/27 (3 new) · fmt/clippy (-D warnings, default + secp-inline, all targets) green on both commits ·
  typos clean on changed files (DISABLE_TYPOS=1 only for the pre-existing failures elsewhere).
- Commits: `feat(core): route the SHA256 precompile through the Jolt SHA-256 inline` (4325239) ·
  `feat(core): route 12-round BLAKE2F compressions through the Jolt BLAKE2b inline` (+ this journal).
  Rebuild from HEAD reproduces 781 = 603,149,073 rows / hash / 115,373 perms and both verification blocks exactly.

## Kill list / open
- revm-precompile's `blake2::run` parses the 213-byte input byte-wise (LBU) and re-serializes h word-by-word: ~2.7k
  of the 7.8k rows/unit at r12 are outside the compression; only a vendored revm-precompile could remove them.
- BLAKE2F adversarial bound is set by high-round software compress (r1000: 232 c/g, 253 rows/round); the inline is
  fixed at 12 rounds, so non-canonical round counts stay software by construction.
- The one residual software SHA-256 per block (EIP-7685 requests hash, alloy-eips) costs ~4.6k rows: not worth a
  vendor patch.
- Gas-weighted headline moves 13.814672 → 13.813403 c/g: SHA256 precompile traffic in these blocks is tiny.
