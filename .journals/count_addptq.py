# Row model for the ADDPTQ sequence. Each emit(k) = k final rows (all 1-row kinds:
# LD/SD/ADD/SUB/SLTU/AND/OR/XORI/MUL/MULHU/LUI/ADDI/VirtualAdvice/VirtualAssertEQ/LTE).
rows = {}
def blk(name):
    rows.setdefault(name, 0)
    def emit(k=1): rows[name] += k
    return emit

# ---- product core, MulqBuilder::inline_sequence structure (sequence_builder.rs:200-383)
# op: 'mul' (a*b, 16 products) or 'square' (10 distinct products, cross terms doubled)
# addends: list of (col_lo, ncols) 256-bit values added into columns col_lo..col_lo+ncols-1
# cslot: 'assert' (assert_eq r_k, c_k) or 'sd'
def core(name, op, addends=(), extra_col=None):
    e = blk(name)
    def mac(carry): e(4 if carry else 3)       # mul/mulhu, add, sltu[, add]
    def m2ac(carry): e(7 if carry else 6)
    def addend(carry): e(3 if carry else 2)    # add, sltu[, add]   (fold 256-bit value limb)
    e(1)                                       # mul r0 = lo(a0*b0)
    mac(False)                                 # + lo(w0*pc)
    for (lo, n) in addends:
        if lo == 0: addend(True)
    e(1)                                       # C slot: assert_eq / sd
    for k in range(1, 7):
        first = True
        if k < 4: mac(False); first = False          # lo(w_k pc)
        if k - 1 < 4: mac(not first); first = False  # hi(w_{k-1} pc)
        for i in range(0, k + 1):
            j = k - i
            if i < 4 and j < 4:
                if op == 'square':
                    if i > j: break
                    elif i == j: mac(not first); first = False
                    else: m2ac(not first); first = False
                else: mac(not first); first = False
        for i in range(0, k):
            j = k - 1 - i
            if i < 4 and j < 4:
                if op == 'square':
                    if i > j: break
                    elif i == j: mac(not first); first = False
                    else: m2ac(not first); first = False
                else: mac(not first); first = False
        for (lo, n) in addends:
            if lo <= k < lo + n: addend(True)
        if extra_col is not None and extra_col[0] == k: e(extra_col[1])
        e(1)                                   # k<4: C slot (assert_eq/sd); k>=4: assert_eq r_k, w_{k-4}
    e(1)                                       # mulhu aux = hi(a3*b3)
    e(3)                                       # add r1; assert_eq r1,w3; assert_lte aux,r1

# ---- ADDPTQ blocks
e = blk('loads');    e(16)                     # ld x1[4] y1[4] x2[4] y2[4]
e = blk('advice');   e(4+4+4+12)               # lambda, x3, y3, W1..W3
e = blk('consts');   e(5)                      # lui pc; lui k0; lui q0; addi MAX,-1; addi one,1
e = blk('assert_d_nonzero'); e(5)             # or,or,or,sltu,assert_eq
# (1) d = x1 - x2 mod q : borrow chain 2+5+5+5, mask = 0-beta, bpc = mask & pc, sub chain 7
e = blk('modsub_d');  e(17 + 1 + 1 + 7)
core('core1_mul_lambda_d', 'mul', addends=[(0, 4)])          # + y2 folded, C = y1 (assert)
# (2) lambda^2 + ~x1 + ~x2 + K + W2 pc = 2^256 W2 + x3
e = blk('compl_x1_x2'); e(8)                                  # 8 xori
core('core2_square_lambda', 'square', addends=[(0,4),(0,4),(0,4)])  # ~x1, ~x2, K (limb0=k0, limbs1-3=MAX)
e = blk('range_x3'); e(6)                                     # and,and,sltu,sltu,or,assert_eq
e = blk('store_x3'); e(4)
# (3) d' = x1 - x3 mod q ; lambda d' + ~y1 + W3 pc = 2^256 W3 + (y3 + pc - 1)
e = blk('modsub_dp'); e(26)
e = blk('compl_y1');  e(4)
e = blk('range_y3');  e(6)
e = blk('store_y3');  e(4)
e = blk('y3_plus_pcm1'); e(8)                                 # addi t,pc,-1; add,sltu,add,sltu,add,sltu,add
core('core3_mul_lambda_dp', 'mul', addends=[(0,4)])           # + ~y1 folded, C = y3' (assert)
e = blk('resets'); e(38)

total = sum(rows.values())
for k, v in rows.items(): print(f"{k:28s} {v}")
print("TOTAL", total)
# reference: today's MULQ/SQUAREQ/DIVQ emitted rows via same model
rows.clear(); core('mulq_core_ref','mul'); print("mulq core (no ld/advice/lui) =", rows['mulq_core_ref'])
rows.clear(); core('sq_core_ref','square'); print("squareq core =", rows['sq_core_ref'])
