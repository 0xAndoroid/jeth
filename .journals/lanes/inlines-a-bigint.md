# Lane A-bigint — BIGINT256_MUL inline in jeth

Branch `inlines-a-bigint` (base `inlines-a` @ 60283c9). Jolt pin `jolt-amber-nolane` (read-only).
Inline: `.insn r 0x0B, 0x0, 0x04` — 256×256→512-bit product, 141 rows (8 LD, 30 MUL/MULHU, carries, 8 SD, 11 zeroing).

## Method
- Static: `llvm-objdump` on the symbolized guest (`jeth profile` build) for MUL/MULHU counts per handler.
- Dynamic: `jeth profile --rows` (exact per-symbol rows) plus new flags `--pcs-of` (per-PC split of one
  symbol), `--entries` (call counts), `--skip-build`. Synth harness (`crates/host/src/bin/synth.rs` +
  `/tmp/opcg-abigint`), per-tx Δ method, tx gas cap 16,777,216.
- Before = inline feature off, after = on; same tree, same host binary, same K. Guest target dirs
  `…-guest` (off) / `…-guest-on` (MULMOD) / `…-guest-on2` (MULMOD + MODEXP).
- Baseline of this tree vs the no-lane records: hashes equal, keccak perms equal (781 = 115,373), rows
  exactly −14 on every block (build-path/rodata layout; identical guest sources).

## Site anatomy (base, rows)
| site | product | reduction / rest | total per op | verdict |
|---|---|---|---|---|
| MULMOD (`mul_mod_by_ref`, a=b=2^256−1, N 255-bit) | 300 (addmul 4×4) | 609 (Knuth 512/256) + 90 prologue/trim | 1,014 call / 1,239 op | replace product → **win** |
| MULMOD N128 | 300 | 520 | 820 call / 1,015 op | win |
| MUL (`wrapping_mul`, 10 MUL + 6 MULHU, 83 instrs) | ~95 rows/op | — | 178 op | 141-row inline ≥ product → **loss, no build** |
| EXP (`wrapping_pow`, 18 MUL + 12 MULHU per step) | ~95/step | — | 27,628 op (exp256) | same as MUL → **loss, no build** |
| MODEXP 32-32-32 (aurora Montgomery) | monsq big_sq 415 | monsq reduction 399 + compare/copies 156; monpro CIOS 693 | 1,850/bit, 485k/call | fixed 4-limb ladder → measured below |
| MODEXP 1024-e1-1024 (s=128 limbs) | schoolbook 128² | 6.02M/call, monpro 543k/call | no fixed-width form; EIP-7823 caps at 1024 B | **not attempted** |
| ark-ff bn254 Fq (`mul_assign`/`square_in_place`/`sum_of_products`) | Montgomery, interleaved | 781: 17,556 / 4,573 / 28,133 calls | — | out of scope (Phase B) |

1:1 replacement candidates: ruint `algorithms::addmul(product[8], a[4], b[4])` inside `mul_mod_by_ref` (exact);
aurora `big_sq`/`big_wrapping_mul` only for s=4 (product then separate reduction). Monpro is CIOS-interleaved and
ark-ff is interleaved Montgomery: no 1:1 product slot without restructuring.

## Dynamic call counts (base ELF, `--entries`)
| block | MULMOD | MUL | EXP | MODEXP calls (monpro) | bn254 Fq mul / sq / sop |
|---|---|---|---|---|---|
| 25905781 | 5,288 | 6,260 | 759 | 0 | 17,556 / 4,573 / 28,133 |
| 25905782 | 29,480 | 6,287 | 652 | 0 | 35,095 / 9,073 / 56,250 |
| 25905783 | 983 | 3,534 | 499 | 1 (5) | 14,860 / 2,471 / 27,891 |
| 25905784 | 1,425 | 3,364 | 482 | 2 (10) | 0 |
| 25905785 | 1,342 | 8,576 | 1,114 | 8 (415) | 29,044 / 17,639 / 19,360 |
| 25905786 | 819 | 4,371 | 530 | 2 (10) | 0 |
| 25905787 | 15,710 | — | — | 58 (1,481) | 5,846 / 6 / 17,278 |
| 25905788 | 26 | — | — | 0 | 0 |
| 25905789 | 284 | — | — | 6 (405) | 28,924 / 17,521 / 19,323 |
| 25905790 | 193 | — | — | 0 | 0 |

## Change 1 — MULMOD (kept, commit c5634ca)
Vendored `revm-interpreter` `mulmod` → `jeth_mul_mod` extern hook (feature `bigint-inline`) → guest `#[no_mangle]`
→ `jeth_core::bigint::mul_mod`: inline product into `[u64; 8]`, then ruint `algorithms::div` (unchanged reduction).
Zero modulus short-circuits like ruint. Host registers the inline (`extern crate jolt_inlines_bigint`, host feature).

Synth (rows/unit, before → after): MULMOD 1,239.1 → 1,005.1 (−234; op c/g 65.2 → 52.9), MULMOD/N128 1,015.0 → 788.0
(−227), MULMOD/N3 947.0 → 718.0 (−229). Controls unchanged: ADDMOD 861.3, MUL 177.8, ADD 148.0, EXP/exp256 27,628.2,
EXP/exp8 1,093.5, EXP/exp2^255 15,898.8, all MODEXP cases identical.

10-block set (plain ELF, after vs this tree's baseline; hashes == record, keccak perms == baseline on all):
| block | before rows | after rows | Δ |
|---|---|---|---|
| 25905781 | 603,187,849 | 602,030,877 | −1,156,972 (−0.19%) |
| 25905782 | 721,922,331 | 715,141,963 | −6,780,368 |
| 25905783 | 333,212,703 | 333,166,456 | −46,247 |
| 25905784 | 251,155,760 | 251,022,540 | −133,220 |
| 25905785 | 629,550,097 | 629,442,964 | −107,133 |
| 25905786 | 291,932,998 | 291,856,600 | −76,398 |
| 25905787 | 401,722,255 | 398,393,266 | −3,328,989 |
| 25905788 | 92,465,028 | 92,464,391 | −637 |
| 25905789 | 677,090,260 | 677,076,034 | −14,226 |
| 25905790 | 432,652,892 | 432,649,242 | −3,650 |
Per MULMOD: ≈ −219 rows (781: 1,156,972 / 5,288).

Correctness: `jeth-core` tests `bigint::tests::{edge_operands_match_ruint, random_operands_match_ruint}` (16³ edge
triples incl. 0, 1, 2^256−1, N=1, N=2^255, even N, a=b=N−1; 4,000 random rounds with 1–4 limb operands, even-N and
reduced variants) vs ruint `mul_mod`. Harness block `verify-mulmod-on` (28 edge + 64 limb-shape random + 20 N−1 +
20 random + 10 even-N triples SSTORE'd, 8 MULMOD chains): guest trace block_hash == run-native block_hash.

## Change 2 — MODEXP (kept for 9..=32-byte odd moduli)
`Crypto::modexp` override on `JoltCrypto` (feature `bigint-inline`): odd modulus of 9..=32 significant bytes and
base ≤ 32 bytes → `bigint::modexp`: fixed 4-limb Montgomery ladder, inline product + 4-round word-serial REDC
(`mont_mul`), `a_bar` via `mul_mod`; every other shape → `DefaultCrypto.modexp` (aurora). Output is the minimal BE
encoding; revm `left_pad_vec_be(out, mod_len)` makes the precompile output identical to aurora's (aurora keeps
whole limbs, e.g. `[0,0,0,0,0,0,0,1]` for 1 with a 2-limb modulus — the tests compare padded outputs).

Synth (rows/unit, aurora → ladder; E = 256 bits set unless noted):
| case | before | after | Δ | rows/bit before → after |
|---|---|---|---|---|
| MODEXP/32-32-32 | 479,810 | 207,818 | −56.7% | 1,882 → 815 |
| MODEXP/24-32-24 | 338,167 | 202,788 | −40.0% | 1,326 → 795 |
| MODEXP/20-32-20 | 332,906 | 201,089 | −39.6% | 1,306 → 789 |
| MODEXP/16-32-16 | 220,236 | 200,035 | −9.2% | 864 → 784 |
| MODEXP/12-32-12 | 217,326 | 200,186 | −7.9% | 852 → 785 |
| MODEXP/8-32-8 (1 limb) | 145,027 | 199,670 with ladder; 145,119 after routing to aurora (`len > 8`) | +37.7% → +0.1% | 569 → 783 → 569 |
| MODEXP/32-e1-32 | 19,192 | 11,950 | −37.7% | — |
| MODEXP/32-e2-32 | 19,289 | 11,957 | −38.0% | — |
| MODEXP/16-e1-16 | 13,093 | 11,856 | −9.4% | — |
| MODEXP/1-1-1, 64-32-64, 1024-e1-1024 | 11,421 / 1,421,869 / 6,023,990 | 11,509 / 1,421,653 / 6,024,328 (aurora path, +88 dispatch) | ~0 | — |
Ladder cost is flat (~785–815 rows/bit: one `mont_mul` ≈ 470 rows, 1.5 per bit + overhead); aurora is quadratic in
limbs, so one-limb moduli stay on aurora. MULMOD control in the same block: 1,015 rows/unit (vs 1,005 in the
MULMOD-only build; layout noise).

Block impact: MODEXP is rare in the 10-block set (calls: 783:1, 784:2, 785:8, 786:2, 787:58, 789:6, others 0; 781: 0),
so the 10-block table above is unchanged by this change except through modulus-size-dependent savings on those
calls; 781 attribution is identical (no modexp entries).

Correctness: `bigint::tests::{modexp_edge_inputs_match_aurora, modexp_declines_unsupported_shapes,
modexp_random_inputs_match_aurora}` — 14 odd moduli (1, 3, 5, 7, 0xff, 2^64±1, 2^128±1, 2^255+1, 2^255−19, 2^256−1,
bn254 p, secp256k1 n) × 8 bases (0, 1, 2, n−1, n, n+1, 2^256−1, random) × 12 exponents (empty, 0, 1, 2, 3, 65537,
2^255, 2^256−1, 2^264−1, p−2, leading zeros) in minimal / 32-byte / over-padded encodings, plus 1,500 random shapes
(1–32-byte moduli, 0–32-byte bases, 0–40-byte exponents, even-modulus twins); the shape predicate is asserted
exactly. Harness block `verify-modexp-on3` (761 precompile calls SSTORE'd — same edge grid, fallback shapes: even /
zero / empty / 33-byte / 40-byte-padded / 64–96-byte moduli, 33–64-byte bases — plus 4 × 30-step modexp chains):
guest trace block_hash == run-native block_hash (native = aurora only); 99,287,599 rows (103,384,682 before the
one-limb threshold).

## Gates
1. Synth before/after: tables above (MULMOD ×3 down, controls flat, MODEXP ≥ 9-byte moduli down, ≤ 8 flat).
2. 10-block set, final ELF (plain, `--skip-build`), before = this tree with the feature off:
| block | before rows | final rows (MULMOD + MODEXP) | Δ | Δ vs MULMOD-only | hash == record | perms == base |
|---|---|---|---|---|---|---|
| 25905781 | 603,187,849 | 602,030,877 | -1,156,972 (-0.19%) | +0 | yes | yes (115,373) |
| 25905782 | 721,922,331 | 715,141,963 | -6,780,368 (-0.94%) | +0 | yes | yes (124,117) |
| 25905783 | 333,212,703 | 333,156,314 | -56,389 (-0.02%) | -10,142 | yes | yes (61,886) |
| 25905784 | 251,155,760 | 251,002,256 | -153,504 (-0.06%) | -20,284 | yes | yes (51,424) |
| 25905785 | 629,550,097 | 628,697,153 | -852,944 (-0.14%) | -745,811 | yes | yes (121,623) |
| 25905786 | 291,932,998 | 291,836,316 | -96,682 (-0.03%) | -20,284 | yes | yes (59,024) |
| 25905787 | 401,722,255 | 395,704,811 | -6,017,444 (-1.50%) | -2,688,455 | yes | yes (70,085) |
| 25905788 | 92,465,028 | 92,464,391 | -637 (-0.00%) | +0 | yes | yes (19,238) |
| 25905789 | 677,090,260 | 676,352,069 | -738,191 (-0.11%) | -723,965 | yes | yes (133,642) |
| 25905790 | 432,652,892 | 432,649,242 | -3,650 (-0.00%) | +0 | yes | yes (90,051) |
| total | 4,434,892,173 | 4,419,035,392 | -15,856,781 (-0.36%) | | | |
3. 781 attribution (final tree, `jeth profile --rows`): 602,030,877 rows; `jeth_mul_mod` 5,192,904 rows (0.86%) replaces
   `mul_mod_by_ref` 6,254,692 (1.04%); `mulmod` handler entries 5,288; `bigint::modexp` entries 0; perms 115,373.
4. `cargo nextest run --release --workspace --features jeth-host/secp-inline`: 29 passed; pre-commit fmt + clippy
   `-D warnings` green on every commit; typos clean on changed files.
5. Forged/edge inputs: `verify-mulmod-on` and `verify-modexp-on3` guest hash == native hash; native tests vs ruint /
   aurora as listed.

## Kill list
- MUL, EXP: inline (141) ≥ software product (~95 rows); static count only, no build.
- MODEXP one-limb (≤ 8-byte) moduli: ladder +37.7% → aurora keeps them. ≥ 33-byte / even moduli: aurora (no
  fixed-width form; CRT path for even). 1024-byte case not attempted (128-limb schoolbook, EIP-7823-capped).
- ark-ff bn254: out of scope.

## Incident
`jeth trace` writes `trace-summary.json` next to its input; via the `data` symlink two read-only records in
`amber-nolane/data/` (25905781, 25905788) were overwritten and then restored from the original numbers
(trace_rows_total, block_hash, gas_used exact; wall_seconds/effective_mhz re-derived estimates). Inputs now live in
`/tmp/abigint-data/<block>/input.bin`.
