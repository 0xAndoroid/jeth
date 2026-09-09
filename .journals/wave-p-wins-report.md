# opt-amber wins lane — final

Block 25905781: 596,333,114 → 591,493,066 rows (−4,840,048, −0.81%). Hash 0xf691da3f…b529 and census `keccak[post_validation]: calls=44511 bytes=13335528 perms=115373 unaligned=470` EXACT after every step. Both worktrees clean.

## Steps (jeth `opt-amber-work`, jolt `jolt-amber`)

| step | commit | 781 delta | mechanism |
|---|---|---|---|
| 0 chore(mpt) wave-N nits | jeth b8dc277 | +51,195 | `resolve_mut` now decodes `[0x80]` stubs to `Slot::Empty` in place: 10,760 stub resolutions × ~4.8 rows (opcode histogram diff); rlp boundary test added |
| 1 perf(recovery) duplicate-key merge | jeth 49d3a0a (+ 4563c46 test warning fix) | −2,182,350 | 77 merged key terms × ~28.3k rows/term (GLV split + 16 signed-digit bucket adds each). Distinct/total keys: 781 455/532, 782 335/423, 789 309/354. Probe-bounded `KeyIndex` (8 probes, merge is optimization-only). Tests: `shared_key_equations_verify`, `forged_equation_behind_a_shared_key_must_panic` |
| 2 perf(secp256k1) MaybeUninit outputs | jolt 84e338927 | −506,964 | 12 `sd zero` removed per affine add ≈ 12.5 rows × ~40k field ops |
| 3 affine add glue + add_nonzero | — dropped | −101,412 (<0.2M) | glue reorder ineffective: LLVM reloads limbs regardless of source ordering; reverted in both worktrees |
| 4 perf(trie) flat keccak memos | jeth 65c78a7 | −1,466,238 | hashbrown memo cost 2.9M → 1.1M (open addressing, xor-fold key, `AlignedB256` word-stored digest, cold out-of-line insert; ~0.12M table fill in memset). Test `memos_match_keccak_across_growth` (10k keys) |
| 5 perf(trie) storage() trims | jeth 7598863 | −735,691 | memcmp −353k, memcpy −216k, word-keyed `LastRead`; keccak-from-words on miss so `&Address` never escapes (an escaping borrow made revm callers repack the by-value Address: +438k, now gone) |

Cumulative 781: 596,384,309 → 594,201,959 → 593,694,995 → 592,228,757 → 591,493,066.

## Sweep (baseline → new, hashes = trusted records)

| block | baseline | new | delta |
|---|---|---|---|
| 25905781 | 596,333,114 | 591,493,066 | −4,840,048 (−0.81%) |
| 25905782 | 714,587,202 | 709,207,370 | −5,379,832 (−0.75%) |
| 25905783 | 329,918,101 | 327,160,868 | −2,757,233 (−0.84%) |
| 25905784 | 246,786,378 | 246,310,281 | −476,097 (−0.19%) |
| 25905785 | 621,484,417 | 617,194,378 | −4,290,039 (−0.69%) |
| 25905786 | 288,467,506 | 286,011,545 | −2,455,961 (−0.85%) |
| 25905787 | 397,307,708 | 394,374,132 | −2,933,576 (−0.74%) |
| 25905788 | 91,371,953 | 90,793,431 | −578,522 (−0.63%) |
| 25905789 | 668,276,137 | 663,777,488 | −4,498,649 (−0.67%) |
| 25905790 | 427,470,870 | 424,011,714 | −3,459,156 (−0.81%) |
| total | 4,382,003,386 | 4,350,334,273 | −31,669,113 (−0.72%) |

## Gates
- 781 hash + census EXACT per step ✓ (5/5 kept steps)
- run-native 10/10 hashes = `trace-summary-trusted.json` ✓
- trace sweep 782–790 hashes unchanged ✓
- `cargo nextest run --release --workspace --features jeth-host/secp-inline`: 24/24 (21 + 3 new) ✓
- jolt `jolt-inlines-secp256k1 --features host`: 15/15 ✓
- pre-commit fmt+clippy on every commit (DISABLE_TYPOS=1 only) ✓; no vendored Cargo.lock committed ✓; RESULTS.md/.journals untouched by me ✓ (branch also carries 3 docs commits 3093a91/2e2c9fa/6115edb from the review lane — not mine)
- temp eprintln/counters removed before commit ✓

## Unsafe inventory
- jolt `jolt-inlines/secp256k1/src/sdk.rs`: six `e.assume_init()` blocks (Fq/Fr × mul/square/div_assume_nonzero), each with SAFETY comment (inline sequence stores all four result words before retiring).
- jeth: no new unsafe (step 4's `read_volatile` gather was replaced by in-bounds `from_le_bytes` in step 5).

## Refuted / notes
- Step 3 glue reorder: register allocation reloads limbs anyway → −0.1M, dropped.
- Step 5 first design (aligned word gather via `read_volatile`/ptrtoint) cost +438k in revm callers: not the volatile/ptrtoint — a `&Address` escaping into the non-inlined miss path defeats by-value elision. Fixed by keccak-from-words.
- hashbrown probe cost was ~200 rows/lookup, below the 300 estimate; census estimated 570 equations, actual 532.
- Step 0 costs +51k (expected 0): in-place stub decode adds ~4.8 rows per stub resolution; kept as review-mandated correctness/clarity change.
