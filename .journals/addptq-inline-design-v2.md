# ADDPTQ — fused secp256k1 affine add inline (design, read-only pass, 2026-09-05)

Repo: /Volumes/Dev/worktrees/jolt/jolt-amber (HEAD 920868471). jeth: /Volumes/Dev/worktrees/jeth/opt-amber.
Notation: q = 2^256 − 2^32 − 977 (Fq modulus), pc := 2^256 − q = 2^32 + 977 = 0x1_0000_03D1 (the `p` register of
MulqBuilder, sequence_builder.rs:198), MAX = 2^64 − 1, ~v := 2^256 − 1 − v (limb-wise xori −1), all limbs 64-bit LE.

## 0. Verdict (numbers first)

| item | value | source |
|---|---|---|
| inline rows (modelled, incl. 38 reset ADDIs) | **699** (target 450 not reachable, see §3.4) | /tmp/addptq/count_addptq.py |
| today per generic add | 862 = 316 real + 546 virtual | /tmp/pippenger-glue/analysis.md §2 |
| new per generic add | 699 + 1 anchor + ≈46 caller real = **≈746** | §4.3 |
| saving | −116 rows/add × 39k adds ≈ **−4.5M rows on 781** (−0.72 % of 628M block, −13 % of recovery_msm) | §6 |
| effort | ≈ 2.5 days (18–20 h, §5) | §5 |
| decision rule | ship iff fixture `row_count` ≤ 720 AND measured recovery_msm on 781 drops ≥ 4M; else do analysis fixes 3+4+5 only | §6 |

Why not 450: three 256×256 products are unavoidable (3 unknowns λ,x3,y3 → 3 independent identities; §2.4), and one
product on this ISA costs 157 rows (32 mul/mulhu halves + 8 pc-halves, each `add,sltu,add` = 3 rows to accumulate;
MulqBuilder core = 170 − 8 ld − 4 advice − 1 lui, count_mulq.py). 3 cores = 471 before any add/sub/advice/reset.
The analysis' 440 estimate counted 16 partial products at 3.5 rows; the real cost is 32 halves × 4 + pc-MACs.

## 1. Instruction semantics

| field | value |
|---|---|
| encoding | `.insn r 0x0B, funct3=0x03, funct7=0x05, rd, rs1, rs2` — opcode/funct7 = lib.rs:16-17; funct3 0x03 is "RESERVED" (lib.rs:6) |
| rs1 | `*const u64` → P = (x1 @+0, y1 @+32), canonical Fq limbs |
| rs2 | `*const u64` → Q = (x2 @+0, y2 @+32), canonical |
| rd (rs3) | `*mut u64` → out (x3 @+0, y3 @+32). **In-place form rd == rs1 is the intended use** (bucket += point): the compiler's 8-`sd` write-back (analysis §2 "bucket write-back") disappears; safe because every input limb is loaded into vregs before the first store (§3.1 order) and no memory is re-read afterwards (cf. DIVQ aliasing warning sequence_builder.rs:384-393) |
| layout req. | `#[repr(C)]` on `AffinePoint` (ec.rs:49-54 has no repr) and `#[repr(transparent)]` on `Secp256k1Fq` (sdk.rs:92-95) |
| preconditions (caller) | P ≠ ∞, Q ≠ ∞ ((0,0) encoding, ec.rs:48), x1 ≠ x2. Caller keeps the branches of ec.rs:184-191; the sequence additionally **aborts on x1 = x2** (5 rows, §3.1 block D) because with d = 0 identity (1) holds for every λ (unsound otherwise, §2.3) |
| postcondition | (x3,y3) = P + Q by the chord formula ec.rs:193-198, canonical (range-checked in-sequence) |
| doubling | not handled. Occurrences: 120 `double()` per block (analysis §0) + bucket P = Q collisions ≈ 70 dup-key pairs × 32 half-windows × P(same digit) 1/256 × P(bucket holds exactly that point) ≈ 1/18 ≈ **0.5 events/block**; P = −Q same order. Software path (ec.rs:188-191) stays for them |
| advice (24 words, in emission order) | λ[4], W1[4], x3[4], W2[4], y3[4], W3[4] — consumed in `VirtualAdvice` order (tracer inline.rs:339-350) |

## 2. Verification identities and soundness

Inputs x1,y1,x2,y2 ∈ [0,q). Advice λ,x3,y3,W1,W2,W3 ∈ [0,2^256) (4 limbs each, nothing more assumed).
mod-sub block (§3.1 B): t = x1 − x2 mod 2^256, β = [x1 < x2], d = (t − β·pc) mod 2^256. Lemma: for x1,x2 ∈ [0,q),
d = (x1 − x2) mod q (β=1 ⇒ t = x1−x2+2^256 > pc, d = x1−x2+q ∈ (0,q); β=0 ⇒ d = x1−x2). Same block gives
d' = (x1 − x3) mod q **iff x3 < q** (x3 > x1 + q would wrap; hence the range check on x3 precedes block (3)).

| # | integer identity asserted by the accumulator (LHS all non-negative) | ⇔ mod q | honest quotient, bounds |
|---|---|---|---|
| (1) | λ·d + y2 + W1·pc = 2^256·W1 + y1 | λ(x1−x2) ≡ y1−y2 | W1 = (λd+y2−y1)/q ∈ [0,q): λ≥1,d≥1 ⇒ λd+y2−y1 > −q and ≡0 ⇒ ≥0; λ=0 ⇔ y1=y2 ⇒ W1=0 |
| (2) | λ² + ~x1 + ~x2 + K + W2·pc = 2^256·W2 + x3, K := 2^256 + 2 − 3pc = [k0, MAX, MAX, MAX], k0 = 0xFFFFFFFCFFFFF48F | λ² − x1 − x2 + 3q ≡ x3 | W2 = (λ²−x1−x2−x3+3q)/q ∈ [0,q+3): x1+x2+x3 < 3q ⇒ numerator > 0; n=3 is the least multiple of q making it non-negative (x1+x2+x3 ≥ 2q occurs) |
| (3) | λ·d' + ~y1 + W3·pc = 2^256·W3 + (y3 + pc − 1) | λ(x1−x3) − y1 + q ≡ y3 | W3 = (λd'−y1−y3+q)/q ∈ [0,q+1); y3 < q ⇒ y3+pc−1 ≤ 2^256−2, no carry out |
| R | x3 < q, y3 < q (§3.1 block R), d ≠ 0 (block D) | — | — |

Derivations: ~v = 2^256−1−v, so (2): λ² + (2^257 − 2 − x1 − x2) + 2^256 + 2 − 3pc = λ² − x1 − x2 + 3(2^256 − pc) = λ² − x1 − x2 + 3q.
(3): λd' + 2^256 − 1 − y1 − (y3 + pc − 1) = λd' − y1 − y3 + q. Verified on 200k random + edge tuples (/tmp/addptq/check.py:
remainders 0, all W < 2^256, all LHS totals < 2^512, λ=0 case P+φ(P) gives W1=0, W2=1).

Exactness (inherited from MulqBuilder): every 64-bit add's wrap is captured by `sltu` and added into the next column's
carry register (≤ ~45 carries per column, cannot wrap); limb 7 gets only carry-in + hi(a3·b3) and its wrap is excluded by
`assert_lte aux, r1` (sequence_builder.rs:379-383). Hence the 8-limb value the sequence compares against
(W‖C) is the exact integer LHS; no wrap-around at 2^512 is possible for any advice. All operations are additions
(complements instead of subtractions) so no carry register ever goes negative — the reason (2) uses ~x and K instead of `sub`.

Uniqueness / lying prover: d ∈ [1,q) is invertible mod q ⇒ (1) fixes λ mod q (a second lift λ+q gives identical
x3,y3 mod q, so λ needs no range check). Given λ mod q, (2)+R fix x3 = (λ²−x1−x2) mod q exactly; then d' is exact and
(3)+R fix y3. W_i are forced limb-wise by `assert_eq r_k, W_{k−4}`. Any deviation trips a `VirtualAssertEQ`/`LTE`
row → `assert!` panic in the tracer (virtual_assert_eq.rs:18, virtual_assert_lte.rs:17) → no trace, no proof; in a
proof the same rows are unsatisfiable lookups. This is exactly DIVQ's mechanism (sequence_builder.rs:217-219, 353, 362).
Non-canonical inputs are excluded upstream: every MSM point is `from_u64_arr`-validated or an inline output
(recovery_batch.rs:76, crypto.rs:144,163,177).

### 2.4 Why three products
3 unknowns need 3 independent relations; eliminating λ (collinearity + on-curve) costs 5 products; merging (2)+(3) into
one identity admits (x3,y3) pairs off the true sum (only their sum is pinned). Karatsuba/28-bit-limb variants were
costed (≥ 200 rows/product) — worse on an ISA without add-with-carry.

## 3. Sequence at virtual-op level

### 3.1 Blocks (row counts from count_addptq.py; every listed kind is a 1-row final instruction)

| blk | ops | rows |
|---|---|---|
| L | `ld` x1[0..4]←rs1+0.., y1←rs1+32.., x2←rs2+0.., y2 streamed later (see A1) → 12 ld here + 4 in A1 | 16 |
| A0 | `advice` λ0..λ3 | 4 |
| C | `lui pc,0x1000003D1; lui k0,0xFFFFFFFCFFFFF48F; lui q0,0xFFFFFFFEFFFFFC2F; addi MAX,x0,−1; addi one,x0,1` | 5 |
| B1 | mod-sub d = x1−x2: limb0 `sub d0,x1_0,x2_0; sltu b,x1_0,x2_0`; limbs1-3 each `sub u,a,c; sltu ba,a,c; sub d_i,u,b; sltu bb,u,b; or b,ba,bb` (5); `sub m,x0,b; and m,m,pc`; then `sub d0,d0,m; sltu b,d0,m; sub d1,d1,b; sltu b',d1,b; sub d2..; sltu; sub d3,d3,b` (7) | 26 |
| D | `or t,d0,d1; or t,t,d2; or t,t,d3; sltu t,x0,t; assert_eq t,one` (aborts when x1 = x2) | 5 |
| A1 | `advice` W1_0..3 | 4 |
| P1 | product core λ·d (MulqBuilder column loop, MulqType::Mul shape, a=λ, b=d, w=W1): per column k: lo(W1_k pc), hi(W1_{k−1} pc), lo(λ_i d_j) i+j=k, hi(λ_i d_j) i+j=k−1, **+ addend y2_k** (`ld aux,rs2,32+8k; add r,r,aux; sltu c,r,aux; add rn,rn,c`, k<4), C-slot k<4: `assert_eq r_k, y1_k`; k≥4: `assert_eq r_k, W1_{k−4}`; tail `mulhu; add; assert_eq; assert_lte` | 157 + 12 (+4 ld counted in L) |
| N | `xori x1c_i, x1_i, −1` into D regs (x1 still needed), `xori x2_i, x2_i, −1` in place | 8 |
| A2 | `advice` x3_0..3 ; `advice` W2_0..3 | 8 |
| P2 | square core λ² (MulqType::Square shape: 4 squares + 6 doubled cross terms m2ac) + addends ~x1, ~x2, K (limb0 k0, limbs1-3 MAX) each `add,sltu,add` per column 0..3; C-slot `assert_eq r_k, x3_k`; k≥4 vs W2 | 145 + 36 |
| R1 | range x3 < q: `and a,x3_1,x3_2; and a,a,x3_3; sltu f1,a,MAX; sltu f2,x3_0,q0; or f,f1,f2; assert_eq f,one` | 6 |
| S1 | `sd rd+0..24 ← x3` (after R1; only register values are used afterwards) | 4 |
| B2 | mod-sub d' = x1 − x3 (same as B1, into D regs) | 26 |
| N2 | `xori y1_i,y1_i,−1` in place (y1 dead after) | 4 |
| A3 | `advice` y3_0..3 (into X2 regs, free) ; `advice` W3_0..3 | 8 |
| R2 | range y3 < q (as R1) | 6 |
| S2 | `sd rd+32..56 ← y3` | 4 |
| Y | y3 += pc−1 in place: `addi t,pc,−1; add y3_0,y3_0,t; sltu c,y3_0,t; add y3_1,y3_1,c; sltu c,y3_1,c; add y3_2..; sltu; add y3_3,y3_3,c` | 8 |
| P3 | product core λ·d' + addend ~y1 (columns 0..3); C-slot `assert_eq r_k, y3'_k`; k≥4 vs W3 | 157 + 12 |
| Z | reset ADDIs appended by materializer, one per distinct inline vreg (materialize.rs:157-171; bitmask ⇒ reuse is free, allocator.rs:153-158) | 38 |
| **Σ** | | **699** |

Order matters for aliasing (rd == rs1): all 16 loads happen in L/A1 (y2 loads inside P1 are from rs2 only) before S1.
Column loop and mac/m2ac helpers are the existing `MulAccExt` ones (sdk host.rs:423-571); the builder is a new
`AddPtqBuilder` that generalises `MulqBuilder::inline_sequence` with (a) a list of per-column addend registers,
(b) a C-slot closure (assert vs register). Pool: 80 inline vregs (allocator.rs:13, NUM_VIRTUAL_REGISTERS 96 −16;
spec inline-expansion-grammar.md:283 vr48..vr127) — pressure is not an issue; resets are (1 row each).

### 3.2 Register plan (38 distinct → 38 resets)
X1[4] Y1[4] X2[4] L[4] D[4] W[4] X3[4] (Y3 reuses X2, ~x1 reuses D, y2 streamed through aux) = 28;
consts pc,k0,q0,MAX,one = 5; aux,aux2,r0,r1 = 4; borrow temp t = 1. (analysis' "≥24 vregs" concern is moot: pool = 80.)

### 3.3 Cost table per primitive (for the builder's own bookkeeping)
| primitive | rows | note |
|---|---|---|
| 64×64 product half into column | 4 (3 first-in-column) | mul/mulhu, add, sltu, add — MulAccExt::mac_*_w_carry |
| 256-bit addend | 12 | 4 × (add, sltu, add) |
| mod-sub (x−y mod q) | 26 | 17 borrow chain + 9 correction |
| complement ~v | 4 | xori −1 |
| range check v<q | 6 | uses shared MAX,q0,one |
| product core (mul / square) | 157 / 145 | incl. 4 C-slot + 4 W asserts + tail |

### 3.4 Where the 699 go
cores 471 (67 %) · addends 60 · mod-subs 52 · resets 38 · advice 24 · loads 16 · range 12 · complements 12 · stores 8 · y3 adj 8 · consts 5 · d≠0 5.
Only a Jolt ISA change (a 3-input add-with-carry virtual instruction, new lookup table) would cut the cores by ~1 row per
term (≈ −120 rows); out of scope here, flagged as the only lever toward ≤ 550.

## 4. SDK wrapper and jeth call site

### 4.1 jolt-inlines/secp256k1/src/sdk.rs (on `Secp256k1PointExt`, sdk.rs:682-688; impl at 690-767)
```rust
// guest: cfg(all(not(feature="host"), any(target_arch="riscv32", target_arch="riscv64")))  (pattern sdk.rs:265-289)
#[inline(always)]
fn add_assign_unequal(&mut self, other: &Secp256k1Point) {           // pre: both finite, x1 != x2
    unsafe {
        core::arch::asm!(".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
            opcode = const INLINE_OPCODE, funct3 = const SECP256K1_ADDPTQ_FUNCT3, funct7 = const SECP256K1_FUNCT7,
            rd = in(reg) self as *mut Self, rs1 = in(reg) self as *const Self, rs2 = in(reg) other as *const Self,
            options(nostack));                                      // no `nomem`: memory is read and written
    }                                                               // x3,y3 range-checked in-sequence: no spoil_proof pass needed
}
// host (cfg(feature="host")) and non-riscv stub: software formula, byte-identical to ec.rs:193-199
fn add_assign_unequal(&mut self, other: &Self) { *self = self.add(other); }   // host
#[inline(always)]
fn add_assign(&mut self, other: &Self) {                               // generic dispatcher, replaces `a = a.add(b)`
    if self.is_infinity() { *self = other.clone(); }
    else if other.is_infinity() {}
    else if self.x() == other.x() { *self = self.add(other); }         // P == ±Q → ec.rs double()/infinity path
    else { self.add_assign_unequal(other); }
}
```
Rows kept in the caller per add: is_infinity(self) 4 ld+3 or+bnez ≈ 9 (loads reused by the x-compare), is_infinity(other) ≈ 9,
x1==x2 4 ld+4 xor+3 or+bne ≈ 12 (limbs_eq, sdk.rs:48-50), pointer setup + anchor ≈ 3 → **≈ 33 + loop bookkeeping 24 (analysis §2) ≈ 46–57 real rows**.
No `MaybeUninit` output buffer: in-place form writes the bucket slot directly (the 8 `sd` inside the inline replace both the
zero-fill and the compiler write-back).

### 4.2 jeth crates/core/src/recovery_batch.rs (pippenger 190-249)
| line | today | new |
|---|---|---|
| 224 | `buckets[term.top] = buckets[term.top].add(&term.point);` | `buckets[term.top].add_assign(&term.point);` |
| 238 | `buckets[index] = buckets[index].add(point);` | `buckets[index].add_assign(point);` |
| 244 | `sum = sum.add(bucket);` | `sum.add_assign(bucket);` |
| 245 | `result = result.add(&sum);` | `result.add_assign(&sum);` |
| 216 | `result = result.double();` | unchanged (120/block) |
No feature change: `secp-inline` already pulls jolt-inlines-secp256k1 (core/Cargo.toml:10,30; guest/Cargo.toml:34).
`Term` layout (175-180) unchanged. `Secp256k1PointExt` is already imported (recovery_batch.rs:7).

### 4.3 Per-add row budget after the change
| part | rows |
|---|---|
| inline virtual rows | 699 |
| inline anchor (real, mod.rs:1137) | 1 |
| caller real rows (§4.1) | ≈ 46 |
| **total** | **≈ 746** (today 862) |

## 5. Integration checklist (jolt then jeth)

| # | file / action | detail | h |
|---|---|---|---|
| 1 | jolt-inlines/secp256k1/src/lib.rs | `SECP256K1_ADDPTQ_FUNCT3 = 0x03`, `SECP256K1_ADDPTQ_NAME = "SECP256K1_ADDPTQ"`, fix doc line 6 | 0.2 |
| 2 | jolt-inlines/sdk/src/host.rs | `pub struct AddPtqAdvice { lambda, w1, x3, w2, y3, w3: FieldElementLimbs }` + `InlineAdvice` impl emitting 24 words in that order (pattern host.rs:155-159, 217-226); helper `fq_sub_advice` not needed — use ark `Fq` | 0.5 |
| 3 | jolt-inlines/secp256k1/src/sequence_builder.rs | `AddPtqBuilder` (allocate per §3.2, emit blocks §3.1 in order L,A0,C,B1,D,A1,P1,N,A2,P2,R1,S1,B2,N2,A3,R2,S2,Y,P3; release all; `finalize`). Generalise the column loop of `MulqBuilder::inline_sequence` (162-364) into a private fn `product_core(a, b_or_square, w, addends: [&[InlineRegister;4]], cslot: impl FnMut(k, r_k))`; reuse `MulAccExt` (drop the duplicate mac helpers at 413-498 while there). `Secp256k1AddPtq: InlineOp` with `type Advice = AddPtqAdvice`, `build_advice`: load x1,y1 (rs1), x2,y2 (rs2) via `load_field_element_limbs` (host.rs:58-70); Fq ops in ark (`Fq::new(BigInt(..))`, `.inverse().expect("ADDPTQ: x1 == x2")` like 151-155); W_i as `NBigUint` exact divisions of the §2 numerators (debug_assert remainder 0) | 6 |
| 4 | jolt-inlines/secp256k1/src/host.rs | add `Secp256k1AddPtq` to `register_inlines!` ops (host.rs:9-17) | 0.1 |
| 5 | jolt-inlines/sdk/src/ec.rs, secp256k1/src/sdk.rs | `#[repr(C)]` on `AffinePoint` (ec.rs:49), `#[repr(transparent)]` on `Secp256k1Fq` (sdk.rs:92); §4.1 methods (guest asm / host / non-riscv panic stub, pattern sdk.rs:181-221) | 1 |
| 6 | jolt-inlines/secp256k1/src/tests.rs | (a) direct execution via `InlineTestHarness` with `InlineMemoryLayout::two_inputs(64,64,64)` and the aliased variant `output_base: DRAM_BASE` (pattern tests.rs:207-227), compare to `Secp256k1Point::add` host formula; (b) randomized ≥10k: random canonical (x1,y1,x2,y2) — the sequence never checks on-curve, so arbitrary canonical tuples exercise the chord arithmetic — plus 10k real points k·G via ark projective; (c) edge: y1=y2 (P and `P.endomorphism()`, λ=0), Q=−2P (d'=0, x3=x1), x2>x1 borrow path, x1+x2+x3 ≥ 2q (W2 = 0), limbs = MAX, y3 ≥ q−pc; (d) tamper: `INLINE::inline_sequence(&VirtualRegisterAllocator::default())` → patch one `VirtualAdvice.advice` (λ, x3, y3, each W) → `harness.execute_sequence` inside `catch_unwind`, expect panic; (e) x1 == x2 → panic (block D) | 4 |
| 7 | jolt-inlines/fixtures | `JOLT_UPDATE_INLINE_EXPANSION_FIXTURES=1 cargo nextest run -p jolt-inlines-fixtures` regenerates registered_inline_expand_parity_hashes.jsonl (fixtures/src/lib.rs:222-236); bump `assert_eq!(actual.len(), 25)` → 26 (lib.rs:246). The fixture's `row_count` is the authoritative row number — gate ≤ 720 here | 0.5 |
| 8 | lints/tests | `cargo clippy --all --features host -q --all-targets -- -D warnings` (+ `host,zk`), `cargo nextest run -p jolt-inlines-secp256k1 --features host`, `cargo install --path . --locked` (CLAUDE.md) | 1 |
| 9 | jeth recovery_batch.rs | 4 call sites (§4.2) | 0.3 |
| 10 | jeth native gate | `cargo build -q --release -p jeth-host --features secp-inline` + `jeth run-native --input data/25905781/input.bin` (RESULTS.md:640-642): host build uses the software `add` → unchanged output is the gate; `cargo nextest run --cargo-quiet --release --workspace --features jeth-host/secp-inline` | 1 |
| 11 | jeth guest trace | rebuild guest, trace 781, read `recovery_msm` real/virtual from profile-rows log (analysis §0 cites data/25905781/profile-waveI-rows.log:17); expect ≈ 12.47M real → ≈ 1.8M+…, total phase ≈ 33.7M → ≈ 29.1M | 3 |
| Σ | | | ≈ 18 h |

Native path: only riscv guest builds emit the `.insn`; the `host` feature and the non-riscv stub keep the software
formula (same cfg pattern as `mul`/`div`, sdk.rs:181-221, 265-337), so run-native parity is unaffected by construction.

## 6. Expected effect on block 25905781 and decision rule

| quantity | value |
|---|---|
| generic adds N | ≈ 39k (analysis §0: 21.2M virt / 545 ≈ 38.9k; 12.47M real / 316 ≈ 39.4k) |
| rows/add today → new | 862 → ≈ 746 (§4.3) |
| Δ | −116 × 39k ≈ **−4.5M rows** (range −4.1M…−4.9M for 46–57 caller rows; −3.0M if the sequence lands at 740) |
| share | −0.72 % of the 628M block; −13 % of the 33.7M recovery_msm phase |
| vs. analysis §3 fix 1 claim | −14M was based on ≈440 inline rows; not achievable with 3 products at 157 rows each |

Decision rule: implement only if the ≈4.5M rows justify ≈2.5 days; ship iff (a) fixture `row_count` ≤ 720, (b) 10k-pair
parity + tamper tests pass, (c) measured recovery_msm on 781 drops ≥ 4M rows and run-native output is unchanged.
If (a) fails (builder lands > 760 rows) the gain is < 3M and the 2-hour fixes 3+4+5 of analysis §3 (−1.4M) dominate on ROI.
Independent of this lane: fix 2 (merge duplicate keys, jeth-only) stays the best rows-per-hour item.
