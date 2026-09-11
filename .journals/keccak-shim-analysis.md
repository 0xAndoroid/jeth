# native_keccak256 per-call / per-block overhead — block 25905781 (jeth opt-amber, ELF 2026-09-05 07:12)

Sources: `crates/guest/src/keccak.rs` (3927376 + 67d4083), `crates/guest/src/lib.rs:174-183` (census), disassembly
`/tmp/keccak-shim/native_keccak256.s` (0x8011c4fe–0x8011cb76, 1658 B, 567 instrs), Jolt inline
`jolt-inlines/keccak256/src/sequence_builder.rs`, shift expansions `crates/jolt-program/src/expand/shifts/*.rs`,
call sites `/tmp/keccak-shim/callsite-syms.txt` (54 sites), witness `data/25905781/witness.json`, `block.rlp`,
census lines `data/25905781/profile-waveH-rows.log`. Model: `/tmp/keccak-shim/model.py`.

## 0. Row costs used
- 1 row per RV64 instruction; `ld`/`sd` 1; **`sll`/`srl` with a register shift = 2 rows**
  (`expand_sll`: VirtualPow2 + MUL; `expand_srl`: VirtualShiftRightBitmask + VirtualSRL — shifts/sll.rs:14-21, srl.rs:13-20);
  `slli`/`srli` = 1 (VirtualMULI / VirtualSRLI); `mulhu` = 1 (no inline_sequence in tracer/src/instruction/mulhu.rs).
- Inline (sequence_builder.rs:83-121): per round θ 20 XOR + 5 XORROTL1 + 1 XOR, ρπ 24 XORROT, χ 50, ι 1 = **101**;
  ×24 = 2,424; + `load_state` 25 LD + `store_state` 25 SD ⇒ **plain P = 2,474**; absorb adds 17 LD + 17 XOR ⇒ **AP = 2,508**.
  RESULTS.md attributes 2,511/perm (wave-4 measurement on keccak-9340a77); the 3-row gap is unverified here (no tracer run);
  all savings below are independent of it.

## 1. Exact rows per call (from the disassembly)
Common: frame 4 (`addi sp`, `sd s0`, `sd s1`, `li a6`) + shared 3 (`andi t3,a0,7`; `li t1,0x87`; `slli a6,a6,63`)
+ **census 22** (0x8011c506–0x8011c554: auipc, lui, addi×2, slli, add, 4 LD, mulhu, srli, add, snez, add, addi, add, addi, 4 SD —
Cargo.toml says 21; it is 22) + 8 `sd zero` capacity lanes + `bltu` = 38 rows before dispatch (16 without census); epilogue 4.

Single block (len < 136; 0x8011c56a): 17 SD zero fill (16 zero + lane16 = 1<<63) + 3 (`srli/andi/slli`) + `beqz t3`.
- aligned (0x8011c8cc): 3 + [t≥4: 2 + 11·⌊t/4⌋ + 2 (+1 `j` if t%4==0) | t<4: 2] + [t%4>0: 1 + 6·(t%4)] + (r>0: 3 | 2)
- misaligned (0x8011c59c): 1 + 4 + [t>0: 7 + **11**/word (mv, ld, srl₂, sll₂, or, sd, addi, addi, bne)] + 5 + (spill off+r>8: 7)
- pad (0x8011ca6e–0x8011ca8a): 13 (12 instrs, one reg `sll`) ; permute P ; digest 4 LD + `andi` + branch = 6 ;
  out aligned: 4 SD + 4 = 8 ; **out misaligned: 38 + 4 = 42** (0x8011caa0–0x8011caf6: 8 reg shifts = 16 rows).
- Totals (no census): 20 B 2,559 · 32 B 2,559 · 64 B 2,570 · 83 B 2,583 · 115 B 2,594 (85–120 rows over P); +22 with census.

Multi block (len ≥ 136; 0x8011c5fe `beqz t3`):
- first block aligned (0x8011c90a): 17 LD + 17 SD = 34, `addi`, P, 4 loop-head = 39 + P.
  misaligned (0x8011c602): 18 LD + 17×(srl₂+sll₂+or+sd) + 3 = **123** + 1 + P + 4.
- middle blocks aligned (0x8011c96c): 2 setup + per block AP + 3 (`addi t1`, `addi t6`, `bltu`) ⇒ 2,511/block.
  misaligned (0x8011c76e–0x8011c8c6): 6 setup + per block **163** + P = 2,637/block (35 LD, 17 XOR, 17 SD, 34 reg shifts = 68 rows, 17 or, 5 ctl).
- final block (0x8011c982): 5 dispatch; aligned XOR-merge (0x8011c9fc): 3 + [t≥4: 2 + **19**/4 words + 2 (+1)] + [1 + **8**/word tail] + (3|2);
  misaligned (0x8011c996): 5 + [7 + **13**/word] + 5 (+7 spill); pad-XOR 17 (+3 `ld/xor/sd` lane16 when rem<128) + `addi` + P.
- Example 532-B branch node (aligned, out aligned): 16 + 1 + 39 + 2 + 2·3 + 5 + 3 + (2+57+2) + (1+24) + 3 + 20 + 1 + 6 + 8 = **196 non-permutation rows**
  + 2P + 2AP = 10,160 (10,182 with census). Final-block merge alone = 87 rows for 15 words + 4 B (5.8 rows/word vs 2/word inside the absorb inline).

## 2. Call mix (fits census: 44,511 calls / 13.34 MB / 115,373 perms → model 44,511 / 13.38 MB / 115,736)
Derived from the phase census deltas (profile-waveH-rows.log proven pass) − wave-M's 2,993 memo'd keys, witness.json node
lengths (19,448 nodes: 532 B ×8,883 = 45.7 %, 83 B ×1,579, 115 B ×947, 104 B, 436, 468, 500, 147, 404 …; ⌊len/136⌋ = 0: 32.9 %,
1: 5.9 %, 2: 7.1 %, 3: 54.1 %; len%8 ≡ 4: 62.8 %, ≡ 3: 22.8 %), block.rlp tx lengths (434 txs, mean 835 B; sig preimage ≈ len−67 → 2,641 perms
vs 2,645 census).

| class | calls | bytes | perms | rows (model) | rows/call | in/out align |
|---|---:|---:|---:|---:|---:|---|
| keys 32 B (hash_slot, topics) | 3,000 | 96,000 | 3,000 | 7.74M | 2,581 | sp+0x58 / sp+0x38 aligned |
| keys 20 B (hash_address) | 1,000 | 20,000 | 1,000 | 2.62M | 2,615 | in aligned, **out sp+0x6c misaligned** (+34) |
| pubkey 64 B (`&vk[1..]`) | 434 | 27,776 | 434 | 1.16M | 2,665 | **in sp+0x499 misaligned** (+84) |
| tx sig preimages | 434 | 333,144 | 2,641 | 6.83M | 15,735 | 321/434 misaligned in |
| glue (tx enc, receipts, tx/receipt trie nodes) | 1,020 | 571,550 | 4,768 | 12.24M | 12,001 | mostly aligned |
| codes (62 uncovered, 10.9 KB mean) | 62 | 677,040 | 5,022 | 12.62M | 203,474 | aligned |
| MPT nodes (witness distribution) | 33,061 | 11.39M | 93,371 | 238.20M | 7,205 | aligned / aligned |
| EVM KECCAK256 + small (32/64 B) | 5,500 | 264,000 | 5,500 | 14.23M | 2,587 | aligned |
| **total** | 44,511 | 13.38M | 115,736 | **295.6M** | 6,641 | unaligned 755→470 census |

(With the profiler's 2,511/perm the same mix gives 299.9M ≈ the 299.7M implied by RESULTS' 307.7M − 2,993 memo'd calls.)

## 3. Where the non-round rows go (model, 781)
| component | rows | % of keccak |
|---|---:|---:|
| inline rounds (2,424 × 115.7k) | 280.54M | 94.94 |
| inline state I/O 25 LD + 25 SD per perm | 5.79M | 1.96 |
| absorb 17 LD + 17 XOR (aligned middle) / shim gather (misaligned) | 1.88M | 0.64 |
| final-block XOR merge (multi-block calls) | 1.82M | 0.62 |
| **census** | **0.98M** | 0.33 |
| first-block copy (34) / gather (123) | 0.82M | 0.28 |
| single-block data copy/gather | 0.78M | 0.26 |
| frame + dispatch + epilogue | 0.76M | 0.26 |
| pad word ops (13 / 17–20) | 0.74M | 0.25 |
| digest 4 LD + 4 SD (+34 RMW when out misaligned) | 0.48M | 0.16 |
| 17-SD zero fill (single) + 8-SD capacity zero | 0.72M | 0.24 |
| middle-loop control | 0.19M | 0.06 |
Non-round total 15.1M (5.1 % of keccak, 2.4 % of the block); shim-owned (excl. inline I/O and absorb) 8.3M + census 0.98M = 9.3M = 209/call.

Answers to the specific questions:
- Aligned fast path: yes, exploited (keccak.rs:241-250 `copy_words`/absorb inline; 0x8011c8cc/0x8011c90a). 470/44,511 calls
  are misaligned: 434 pubkeys (`&vk[1..]`), ~36 tx encodes. Misaligned cost: +84/call (64 B), +126/middle block, +89 first block.
- Multi-block state: kept in memory on the shim's stack; **every permutation reloads/stores 25 lanes = 50 rows** (inline load_state/store_state) —
  per extra block: 50 + 34 absorb + 3 loop = 87 non-round rows (aligned). 70.9k extra blocks ⇒ 3.54M in reloads alone.
- Census: 22 rows/call = 979k rows (0.158 % of 781). Cargo.toml's "21" undercounts by one.
- Padding/tail: already word-wise (no SB/SH anywhere in the function); pad = 13–20 rows.
- Digest copy-out: alloy's `keccak256_impl` (alloy-primitives-1.5.7/src/utils/mod.rs:180-214) hands the shim a stack `MaybeUninit<B256>`;
  after inlining, most hot callers consume it in place (resolve: `mv a2,sp` then 4 LD into `verified[i]` — 8 rows; hash_slot: memo insert).
  The exception is post_root `Node::encode_dirty` (full.s:201317): digest → `sp+0x28` → `memcpy(dst=buf+cursor+1, 32)` into the RLP buffer
  (misaligned by the 0xa0 prefix) ≈ 40–50 rows/node × ~11.5k nodes ≈ 0.5M — a zeth-mpt (MPT lane) item, not the shim's.

## 4. Ranked fixes (rows on 781 = 621.5M; 1 c/g = 44.2M rows)
| # | fix | rows | c/g | effort | where |
|---|---|---:|---:|---|---|
| 1 | **Inline I/O variants** reusing the round code untouched: V1 `FirstFinal` (rs1 = padded 17-word block, capacity zeroed in-register, store 4 digest lanes to rs2), V2 `First` (17 LD from caller memory + 8 zero + 25 SD), V3 `PermuteFinal` (25 LD + 4 SD) | −2.16M | −0.049 | 1–2 d, Jolt-side (sequence_builder.rs + exec.rs + registration) + shim dispatch | jolt-amber inline crate + keccak.rs |
| 1b | + V4 `Absorb2Permute` (blocks at rs2, rs2+136, one load/store of state) and `AbsorbPermuteFinal` (absorb padded scratch block at rs1+200, store 4 lanes): −50 per fused pair | −4.38M total with #1 | −0.099 | +1 d | same |
| 2 | **Drop the in-guest census from the proven ELF**; the accounting gate reads perms from the tracer's inline-execution count (the profiler already attributes 118,366 × 2,511 exactly) or from a census-feature build used only for the gate | −0.98M | −0.022 | 2 h (host trace.rs gate) | guest Cargo default features |
| 3 | ≤ 64-B aligned direct path (4/8 LD → t SD + (16−t) SD zero + pad SD, no loop, no `andi/beq` dispatch): −33 (32 B) / −40 (64 B) | −0.27M | −0.006 | 2 h | keccak.rs |
| 4 | `hash_address` misaligned out (sp+0x6c, 1k calls × 34) and `&vk[1..]` misaligned in (434 × 84): call `keccak256_into` with an 8-aligned `[u64;4]` / place the 65-B point at offset 7 | −0.07M | −0.002 | 1 h | jeth-core |
| ✗ | Final block via scratch copy + absorb inline instead of the XOR merge | **+0.14M (worse)** | — | — | keep current design |
| ~ | encode_dirty digest memcpy into misaligned RLP buffer (caller side) | ≈ −0.3…0.5M | −0.01 | MPT lane | zeth-mpt put_raw |

## 5. Floors (rounds fixed at 2,424/perm; data words loaded once; 4 SD digest; ~10 frame/dispatch)
| len | current (no census) | floor | gap | gap % |
|---|---:|---:|---:|---:|
| 20/32 B key | 2,559 | 2,446 | 113 | 4.4 |
| 64 B | 2,570 | 2,450 | 120 | 4.7 |
| 83 / 115 B leaf | 2,583 / 2,594 | 2,453 / 2,457 | 130 / 137 | 5.0 / 5.3 |
| 296 B receipt | 7,589 | 7,327 | 262 | 3.5 |
| 532 B branch | 10,160 | 9,781 | 379 | 3.7 |
| 10.9 KB code | 203,452 | 197,727 | 5,725 | 2.8 |
Block-wide: non-round 15.1M vs floor ≈ 1.67M LD (13.34 MB/8) + 44.5k × 18 ≈ 2.5M ⇒ ≤ 12.6M theoretically removable, ≈ 4.4M of it
by #1/#1b, ≈ 1.3M by #2–#4; the rest is the per-perm state reload of the *un-fusable* single permutation (25 LD from the padded
block are the data loads themselves) and loop/pad glue.

## 6. Code shape — top 2
### #1/#1b inline variants (jolt-amber `jolt-inlines/keccak256`)
`sequence_builder.rs`: replace `absorb_block: bool` by
```rust
enum Io { Permute, AbsorbPermute, First, FirstFinal, PermuteFinal, Absorb2Permute, AbsorbPermuteFinal }
fn load_state(&mut self) {
    match self.io {
        First | FirstFinal => {                       // rate lanes straight from rs1 (First) / rs2 (FirstFinal)
            let src = if matches!(self.io, First) { self.operands.rs2 } else { self.operands.rs1 };
            self.asm.load_u64_range(src, 0, &self.a[..RATE_IN_U64]);
            for i in RATE_IN_U64..NUM_LANES { self.asm.xor(Reg(*self.a[i]), Reg(*self.a[i]), *self.a[i]); } // 8 rows, zero
        }
        _ => { self.asm.load_u64_range(self.operands.rs1, 0, &self.a); if absorbing { 17 × (LD rs2+8i → scratch; XOR) } }
    }
}
fn build(mut self) { self.load_state(); self.rounds(); if Absorb2Permute { absorb(rs2 + 136); self.rounds(); }
                     if AbsorbPermuteFinal { absorb(rs1 + 200); self.rounds(); } self.store_state(); … }
fn store_state(&mut self) { match self.io { FirstFinal | PermuteFinal | AbsorbPermuteFinal =>
        self.asm.store_u64_range(self.operands.rs2 /* out */, 0, &self.a[..4]),  _ => …25 lanes… } }
```
funct3 2..6, `InlineOp` impls per variant, `exec.rs` host models, `KECCAK256_*_NAME` registrations; `sdk.rs` wrappers
`keccak256_first(state, block)`, `keccak256_first_final(block, out)`, `keccak256_permute_final(state, out)`, `keccak256_absorb2(state, blocks)`,
`keccak256_absorb_final(state /* scratch at +200 */, out)`.
Shim (`keccak.rs`): `state: [u64; 25 + 17]` (scratch block after the state); single block: `merge_final_block::<false>(scratch, src, rem)`
then `first_final(scratch, out)` when `out % 8 == 0`, else into a `[u64;4]` and the existing RMW; multi: `first(state, src)` (aligned) /
gather + `first(state, scratch)`; middle: pairs via `absorb2`, odd one via `absorb_permute`; final: `merge_final_block::<false>(scratch, …)`
+ `absorb_final(state, out)`. Zero fill of capacity lanes disappears from the shim (`keccak.rs:228-230`).
Rows for a 532-B node: 16 + 1 + (17 LD in V2) … ⇒ 10,160 → ≈ 9,880 (−280: 8 + 34 + 42 + 50 + 21 + ~25 shim glue).
Tests: `jolt-inlines/keccak256/src/tests.rs` — per variant vs `spec.rs` reference (XKCP vectors, random states) incl. the 4-lane store
and the untouched rest of `out`; jeth `native-tests` differential (host fallbacks in keccak.rs mirror each variant with `keccak::f1600`);
trace gate: census line unchanged (calls/bytes/perms are computed from `len`, not from inline counts), hash 0xf691…b529 exact,
profiler inline count = perms − fused pairs (document the new identity).

### #2 census off in the proven ELF
`crates/guest/Cargo.toml`: `default = []`; host `trace.rs`: build the gate ELF with `--features guest,keccak-census` only for the
accounting run, or take `perms` from the tracer's inline-execution counter (already exact: RESULTS attribution 118,366 × 2,511).
Test: census build still prints `keccak[post_validation]: calls=44511 bytes=… perms=115373 unaligned=470`; proven build hash unchanged;
rows −979,242 ± 0 on 781 (22 × 44,511).

### #3 (if #1 lands, fold into V1) ≤ 64-B path
```rust
if len <= 64 && (bytes as usize & 7) == 0 {   // 4k keys + 5.5k EVM small
    let t = len >> 3; let r = len & 7;
    for i in 0..t { write_volatile(blk.add(i), read_volatile(src.add(i))) }                    // 2t rows
    let last = if r != 0 { read_volatile(src.add(t)) & ((1 << (8*r)) - 1) } else { 0 };
    write_volatile(blk.add(t), last | 1 << (8*r));                                            // pad 0x01
    for i in t+1..16 { write_volatile(blk.add(i), 0) }  write_volatile(blk.add(16), 1 << 63);  // 0x80
    first_final(blk, out) …
}
```
