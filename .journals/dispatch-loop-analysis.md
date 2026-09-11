# jeth dispatch loop: fixed per-op cost census + register-resident ip/gas designs

Guest: `/Volumes/Dev/cargo-target/opt-amber-guest-validate_block/riscv64imac-unknown-none-elf/release/jeth-guest`
(opt-amber @ cbf87a1, vendored revm-interpreter 35.0.1 at `crates/vendor/revm-interpreter`, patched only in
`crates/guest/Cargo.toml:53`). Row model: 1 row/instruction, LBU=3, LB=4, LH/LHU=5, LW=4, LWU=5, SB=6, SH=9, SW=7/9.
Block 25905781: `Handler::execution` = 26,171,091 rows, ≈1.79M ops.

## Verdict

* Land **(a) register ip + (b) null-ip stop** in one gated change: loop 14 → 11 rows/op, PUSHn −2 rows, JUMP/JUMPI-taken −1.
  Savings on 781: **5.37M (loop, mix-independent) + ≈0.9M (PUSH ≈25% of ops) + ≈0.07M (jumps) ≈ 6.3M rows**
  (26.17M → ≈19.9M for `execution` incl. body effects). ≈250 line edits, compile-error driven; 2–2.5 h for one builder incl. a 781 verification run.
* **(d) register gas** is a second wave: −2 rows on every static-gas-only op (≈85% of ops) ≈ **3.0M rows**; ≈60 more edits but the
  spill/reload protocol is semantic (not compile-checked) → not inside the same 3 h.
* **(c) threaded dispatch: drop.** `rust-toolchain.toml` pins stable 1.95; guaranteed tail calls (`become`, `explicit_tail_calls`) are nightly-only,
  and LLVM RISC-V sibling calls are opportunistic (visible only for the `jr` to `#[cold]` halt helpers).
* (e) extras: `swap` has a dead 32-byte frame (2 rows/SWAPn ≈ 0.36M rows); MSTORE/MLOAD/MUL/SHR spill 4–8 s-regs across a cold call
  (MSTORE pays 18 rows of frame per execution). Separate lane, see §5.

## 1. Loop census (`Handler::execution`, 0x800fdd34–0x800fdd52, 12 instructions = 14 rows/op)

```
800fdd30: ld   s1, 0x470(s6)      ; table base — hoisted, once per run_plain entry (not per op)
800fdd34: ld   a0, 0x120(s0)      ; 1  ip load           (bytecode.instruction_pointer)
800fdd38: lbu  a1, 0x0(a0)        ; 3  opcode load
800fdd3c: addi a0, a0, 0x1        ; 1  ip += 1           (relative_jump(1))
800fdd3e: sd   a0, 0x120(s0)      ; 1  ip store
800fdd42: slli a1, a1, 0x3        ; 1  table index ×8
800fdd44: add  a1, a1, s1         ; 1  table addr
800fdd46: ld   a2, 0x0(a1)        ; 1  table load (fn ptr)
800fdd48: mv   a0, s0             ; 1  ABI: ctx.interpreter
800fdd4a: mv   a1, s6             ; 1  ABI: ctx.host
800fdd4c: jalr a2                 ; 1  indirect call
800fdd4e: ld   a0, 0x128(s0)      ; 1  continue_execution load
800fdd52: bnez a0, 0x800fdd34     ; 1  loop test
                                  = 14 rows/op  (+1 `ret` inside every instruction fn)
```
14 × 1.79M = 25.06M; the remaining ≈1.1M rows of the 26.17M are the per-`run_plain`-entry code of the same
function (frame-stack indexing at 0x800fdd18–0x800fdd2e, `process_next_action` glue, memcpys), i.e. ≈8–10k frame runs × ≈120 rows.
Nothing else per-op: no redundant table-base reload, no spill of s0/s6.

Interpreter offsets (from the disassembly): 0x28 stack.data ptr, 0x30 stack.len, 0x118 bytecode.base (Arc), 0x120 ip,
0x128 continue_execution, 0x178 memory len, 0x190 gas.remaining.

## 2. Per-instruction fixed prologue/epilogue (every instruction fn pays; rows on the happy path)

Common shape (`static_gas!` → `Gas::record_static_cost`, gas.rs:248; then stack len/data loads):
```
ld   a1, 0x190(a0)   ; 1 gas.remaining load
addi a2, a1, -COST   ; 1
bltu a1, a2, OOG     ; 1
ld   a1, 0x30(a0)    ; 1 stack.len load
li   a3, LIMIT       ; 1 (0x400 push / 0x3fe dup / 2 for popn)
sd   a2, 0x190(a0)   ; 1 gas.remaining store
b??  a1, a3, ERR     ; 1 stack bound check
ld   a2, 0x28(a0)    ; 1 stack.data ptr load
...                  ;   body
sd   len, 0x30(a0)   ; 1 stack.len store (if len changed)
ret                  ; 1
```
Fixed per op = **gas 4 + stack 4–5 + ret 1 ≈ 10 rows**, on top of the 14 loop rows → ≈24 rows/op before any real work.

| op | body rows (happy path) | of which ip | of which gas | frame (sp/s-reg) | total rows/op today |
|---|---|---|---|---|---|
| PUSH2 `stack::push::<2>` @0x8005c034 | 29 | ld ip 1 + sd ip 1 | 4 | 0 | 43 |
| DUP1 `stack::dup::<1>` @0x8005a11a | 22 | 0 | 4 | 0 | 36 |
| SWAP1 `stack::swap::<1>` @0x8005cc3e | 30 | 0 | 4 | 2 (dead `addi sp,±0x20`) | 44 |
| ADD `arithmetic::add` @0x800542b4 | 39 | 0 | 4 | 0 | 53 |
| JUMPI taken / not taken @0x800600d4 | 46 / 25 | sd ip 1 / 0 | 4 | 0 | 60 / 39 |
| MSTORE `memory::mstore` @0x8005da20 | 118 (aligned path) | 0 | 4 | 18 (8 `sd s*`+8 `ld s*`+2 sp) | 132 |

PUSH2 detail: `ld a2,0x120(a0)` … `addi a2,a2,2` … `sd a2,0x120(a0)` (0x8005c04e/0x8005c066/0x8005c07a) — the ip round-trip
through memory is exactly what (a) removes. Two `lbu` (6 rows) read the 2 immediate bytes. JUMPI taken: `sd a1,0x120(a0)` at 0x8006015c.

## 3. Designs

### (a) register-resident ip — signature `fn(ip: Ip, ctx: InstructionContext) -> Ip`  (Ip = *const u8)

ABI: `ip` first → a0; `InstructionContext {interpreter, host}` is a ScalarPair → a1, a2 (today it is a0, a1: `mv a0,s0; mv a1,s6`);
return in a0. The returned ip is already in a0 for the next iteration → zero ip moves. A 3-field context struct would be passed
indirectly (>2×XLEN aggregate) — do NOT put ip inside `InstructionContext`.

Aliasing argument: `ip` is a by-value scalar, never lives in memory, so `&mut Interpreter` aliasing is irrelevant; LLVM needs no
alias analysis. Inside leaf fns (add/dup/swap/push…) a0 is live-in and live-out; with 13 free temporaries the allocator keeps it in
a0 (0 extra rows). In fns with a hot-path call (none of the top-6 except MSTORE's cold `resize_memory` tail) ip is kept in an s-reg
(+2 rows only if a new s-reg is needed; MSTORE already saves s0–s6).

Loop after (a) alone (still `ld continue_execution`): lbu 3 + addi 1 + slli 1 + add 1 + ld 1 + mv 2 + jalr 1 + ld 1 + bnez 1 = **12 rows** (−2).
Instruction-side: PUSHn −2 (ld+sd ip), JUMP/JUMPI-taken −1 (sd ip), PC −1, others 0.

Mechanical plan (89 instruction fn definitions in `instructions/`: `grep -c "context: InstructionContext"` = 89; the table has 256
entries but push/dup/swap/log/create are const-generic):
1. `instructions.rs:44-66` — `Instruction { fn_: fn(Ip, InstructionContext<'_,H,W>) -> Ip }`, `new`, `execute(self, ip, ctx) -> Ip`, `unknown`.
   `revm-handler` only names `Instruction<W,H>`/`InstructionTable` opaquely (`instructions.rs:25,70`) — unaffected.
2. `interpreter.rs:286-333` — `run_plain`: `let mut ip = self.bytecode.ip(); loop { let op = *ip; ip = ip.add(1); let f = table[op];
   ip = f.execute(ip, ctx); if ip.is_null() { break } }` then `take_next_action()`. Keep `step()` as a compat shim for
   `revm_inspector::inspect_instructions` (handler.rs:247 calls `interpreter.step(instructions, context)`, 243 `bytecode.is_end()`,
   `take_next_action()`): shim = load ip, store `ip+1` (keeps today's pc-after-halt semantics), dispatch once, store returned ip if non-null.
3. `interpreter/ext_bytecode.rs` — add `ip()`, `set_ip()`, `pc_of(ip)`, `jump_target(offset) -> Ip` (= `base.as_ptr().add(offset)`);
   keep the `Jumps`/`Immediates`/`LoopControl` impls (public traits used by inspector + serde).
4. Signatures: sed `(context: InstructionContext<'_, H, WIRE>)` / `<'_, H, ITy>` / multi-line variants → `(ip: Ip, context: …) -> Ip`
   (89 sites), and append `ip` as the tail expression of each body (89 sites; scriptable by brace matching, or ~15 s each by hand).
5. ip-touching bodies (only these read/write ip): `stack.rs:35,45` push (`read_be_immediate(ip)`, return `ip.add(N)`),
   `control.rs:14-43` jump/jumpi/jump_inner (return `bytecode.jump_target(target)`), `control.rs:60` pc (`pc_of(ip) - 1`),
   `stack.rs:81-124` dupn/swapn/exchange (EOF-gated, 3×2 edits). 6 fns.
6. Nested calls of instruction fns are test-only (`bitwise.rs:246,329,437,475,529` are `#[cfg(test)]`); helpers taking
   `&mut InstructionContext` (`call_helpers.rs:56,110`) are unaffected.

### (b) fold `continue_execution` into the returned ip (null ⇒ stop) — loop test becomes one `bnez a0`

Loop after (a)+(b): **11 rows/op** (−3 vs today = −5.37M on 781). Protocol: the ONLY producers of a null ip are the halt helpers and
`set_action`, which become `#[must_use] -> Ip`:
* `interpreter.rs:211-270` — `halt`, `halt_fatal`, `halt_oog`, `halt_memory_oog`, `halt_memory_limit_oog`, `halt_overflow`,
  `halt_underflow`, `halt_not_activated` return `core::ptr::null()` (8 fns; stay `#[cold] #[inline(never)]` so the existing
  `auipc/jr` tail jumps keep working — the callee's null becomes the caller's return).
* new `Interpreter::set_action_at(&mut self, ip: Ip, action) -> Ip { self.bytecode.set_ip(ip); self.bytecode.set_action(action); null }`
  — persists ip because CALL/CREATE frames resume at it. Sites: `contract.rs:127,168,214,260,306`, `control.rs:87` (`return_inner`
  becomes `-> Ip`; `ret`/`revert` return it). 6 edits.
* `instructions/macros.rs` — every `()`-arm `X.halt_*(); return;` → `return X.halt_*();` (lines 10, 26, 39, 84, 159, 181/188, 201, 120/124
  via `$ret`, 147, 264 …): ≈14 edits; `$ret` arms keep `let _ = halt(); return $ret;` (helpers returning `Option`/`bool`:
  `call_helpers.rs:20`, `system.rs copy_cost_and_memory_resize`, `berlin_load_account!`).
* Bodies: 27 explicit `return;` after a halt → `return …halt…;`; ≈15 bare `halt(...)` without return (e.g. `dup` stack.rs:57,
  `dupn` stack.rs:83-90, `stop/invalid/unknown` control.rs:117-129) → `return`/`if … { return halt } ip`.
  Enforce with `#![deny(unused_must_use)]` in `lib.rs`: a halt whose null is dropped is a compile error, so "loop continues after halt"
  cannot be introduced silently. The converse (calling `bytecode.set_action` directly and returning a live ip) is a review item — 6 sites, all converted.
* `continue_execution` and `is_not_end/is_end/reset_action` stay (inspector API, `take_next_action` at interpreter.rs:199); the hot loop
  simply no longer reads the field. `take_next_action()` still `.expect()`s an action → a null return without an action panics loudly.

Semantic identity: ip after CALL/CREATE = today's post-instruction ip (persisted by `set_action_at`); after halts ip is dead
(`process_next_action` in revm-handler frame.rs never reads `bytecode`; only `interpreter.gas` at frame.rs:484-517, in memory,
between `run_plain` calls). Gas untouched by (a)/(b). Inspector hooks compile via the `step` shim (guest never instantiates them).

### (c) opcode-indexed threaded dispatch — DROP
Stable 1.95 (rust-toolchain.toml) has no guaranteed tail calls; without `become` each of 89 fns would end in a 6-row dispatch
sequence that LLVM may or may not sibling-call (fns with frames, e.g. MSTORE, must restore 8 regs first). Gain if it worked: only the
`jalr`+`ret` pair (−2 rows/op) — not worth the fragility.

### (d) register-resident gas — return `#[repr(C)] struct Regs { ip: Ip, gas: u64 }` in a0/a1
Args `(regs, ctx)` → a0,a1 / a2,a3; return a0,a1; loop unchanged at 11 rows (still 2 `mv`). `static_gas!` on the register:
`addi a1,a1,-COST; bltz a1, OOG` = 2 rows using the invariant `remaining < 2^63` (tx gas_limit ≤ block gas limit ≪ 2^63; document it),
else `sltiu/bnez/addi` = 3 rows. Saves 2 (or 1) rows on every op whose only gas is static: PUSH/DUP/SWAP/POP/JUMP*/arith/bitwise
≈85% of ops → **≈1.7 rows/op ≈ 3.0M rows** (≈1.5M without the sign trick). Dynamic-gas ops (MLOAD/MSTORE via `resize_memory!`,
SLOAD/SSTORE/CALL/LOG via `gas!`) spill+reload (sd+ld = 2 rows) around the memory-based accounting → net 0 for them.
Protocol: `regs.gas` is authoritative inside an instruction; `interpreter.gas.remaining` is stale. Every read/write of the memory copy
must be bracketed by `spill()`/`reload()`: macros `gas!`, `state_gas!`, `resize_memory!`, `berlin_load_account!` (4 macro edits cover
20+4+11+5 sites); halt helpers take `regs` and spill before `new_halt(result, self.gas)` copies gas (8 fns); `set_action_at` spills (6 sites);
direct `.gas.remaining()` reads in bodies: `call_helpers.rs:90,116`, `host.rs:211,260,297,382`, `system.rs:245` (GAS opcode), `contract.rs`
`reservoir()` ×5 (different field, no spill needed) → ≈10 edits; `Interpreter::resize_memory` (used by `return_inner`) spills. `run_plain`
loads gas at entry and stores at exit (frame.rs mutates gas only between runs). ≈60 edits; risk = a missed spill silently changes gas on
one path (state-root mismatch only when that path executes) — the reason to land it after (a)+(b), with a grep audit of `\.gas\b` (22 sites in instructions/).

### (e) other findings
* e1. Table base already hoisted; no redundant per-op `ld`; the 2 `mv` are ABI moves for a0/a1 — unavoidable while the callee
  receives interpreter+host in argument registers.
* e2. Fold `host` into the interpreter (raw `*mut ()` in `extend`, set at `run_plain` entry) → `fn(ip, &mut Interpreter)`: loop 11 → 10,
  host-touching ops (≈5%) pay 1 `ld` → net ≈ −0.95 rows/op ≈ 1.7M. Needs unsafe erasure of `H: ?Sized`; ~75 `context.host` sites become
  `context.host()`. Optional third wave.
* e3. `stack::swap::<N>` allocates and frees a dead 32-byte frame (`addi sp,sp,-0x20` @0x8005cc3e, `addi sp,sp,0x20` @0x8005cc9e): a
  U256 temp from `exchange`'s limb swap survives as an alloca. 2 rows × every SWAPn (≈10% of ops) ≈ 0.36M rows; fix = swap limb-wise
  through registers in `interpreter/stack.rs:294`. 1 fn.
* e4. Callee-saved spills across cold calls: MSTORE 8 s-regs + ra + 2 sp = 18 rows/op (0x8005da20–0x8005da30, epilogue 0x8005dbb8),
  MLOAD 10, MUL 12, SHR 10, KECCAK 16, CALLDATALOAD 26. Cause: value limbs loaded before the `resize_memory` cold call stay live across
  it. Fix per fn: resize before loading the limbs (pop offset via `popn_top!`, resize, then read the value) so shrink-wrapping applies.
  MSTORE+MLOAD ≈ 6% of ops × ~12 rows ≈ 1.3M rows. Separate lane (not dispatch), ≈1 h for the two memory ops.
* e5. Direct-threaded pre-decoded code (array of fn ptrs per code byte): loop → `ld/addi/2mv/jalr/bnez` = 6 rows (−5/op = −9M) but
  costs ≈7 rows per distinct code byte at analysis + 8× code memory; break-even ≈1.3MB of distinct code on 781 (unknown, likely
  0.8–2.4MB) → not now. A u32-offset array is worse: `lw` = 4 rows → saves only 1 row/op.

## 4. Order of steps for one builder (fable-max, ≤3 h, gated)

1. (20 min) `instructions.rs` Instruction type; `run_plain` loop + `step` shim; `ext_bytecode.rs` ip accessors; halt helpers `-> Ip`;
   `set_action_at`; `#![deny(unused_must_use)]`.
2. (30 min) `instructions/macros.rs` return arms; sed the 89 signatures; script the 89 `ip` tails.
3. (40 min) compile loop: fix the 27 `return;` sites, ~15 bare halts, 6 set_action sites, 6 ip-touching fns, `return_inner`/`jump_inner`.
   Every remaining error is a site the type checker found for you; when it compiles, the protocol holds except the 6 reviewed set_action sites.
4. (30–40 min) guest build + 781 run: expect `execution` ≈ 26.17M − 5.37M = 20.8M (loop) and PUSH/JUMP bodies −≈1.0M elsewhere;
   state root must match host. Check `llvm-objdump` of the loop shows exactly 9 instructions (lbu, addi, slli, add, ld, mv, mv, jalr, bnez).
5. If time remains: e3 (swap frame, 10 min, −0.36M). Then (d) as the next wave (−3.0M), then e4 (−1.3M), e2 (−1.7M).

Arithmetic (781, 1.79M ops): (a)+(b) −6.3M (−5.4M guaranteed, mix-independent); +(e3) −0.36M; next wave (d) −3.0M; e4 −1.3M; e2 −1.7M.
Total addressable ≈ 12.7M of the 26.2M + instruction-body overheads.
