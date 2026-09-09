"""Row model of native_keccak256 (ELF 2026-09-05, jeth opt-amber) evaluated on block 25905781's call mix.
Row costs: every RV64 instr = 1 row except sll/srl (reg shift) = 2 (VirtualPow2+MUL / ShiftRightBitmask+VirtualSRL);
slli/srli = 1; ld/sd = 1. Inline: P = 24*101 + 25 LD + 25 SD = 2474 (plain), AP = P + 17 LD + 17 XOR = 2508 (absorb)."""
import json, collections
P, AP = 2474, 2508
CENSUS = 22          # 8011c506..8011c554 minus the 3 shared instrs (andi t3 / li t1 / slli a6)
PROLOGUE = 4 + 3 + 8 + 1   # frame 4 (addi sp, sd s0, sd s1, li a6) + shared 3 + 8 capacity SD zero + bltu
EPILOGUE = 4         # ld s0, ld s1, addi sp, ret

def digest(out_aligned):
    return 6 + (8 if out_aligned else 42)   # 4 LD + andi + branch, then 4 SD + epilogue, or 38-row RMW + epilogue

def pad_write():   # 8011ca6e..8011ca8a: 12 instrs, sll = 2 rows
    return 13

def pad_xor(rem):  # 8011cb20..8011cb46 = 17 rows (sll=2) ; + ld/xor/sd of lane 16 when rem < 128
    return 17 + (3 if rem < 128 else 0)

def single_block(len_, in_aligned, out_aligned):
    t, r = len_ >> 3, len_ & 7
    rows = PROLOGUE + 17 + 3 + 1            # zero fill 17 SD, srli/andi/slli, beqz t3
    if in_aligned:
        rows += 3                            # andi t2 / add a7 / beqz t2
        k, tail = t >> 2, t & 3
        if k:
            rows += 2 + 11 * k + 2 + (1 if tail == 0 else 0)
        else:
            rows += 2                        # addi a5 / beq a0,a7
        if tail:
            rows += 1 + 6 * tail
        rows += 3 if r else 2                # beqz t0 (+ld a0 + j) | li a0,0
    else:
        rows += 1                            # beqz a1 (len==0)
        if len_ == 0:
            rows += 1                        # li a0,0
        else:
            off = 1  # any nonzero offset; spill decided by off+r>8 — use offset distribution outside
            rows += 4                        # andi t2 / ld W0 / slli a7 / beqz a4
            if t:
                rows += 7 + 11 * t
            rows += 5                        # add / li / srl(2) / bltu
            rows += 7 if (off + r > 8) else 0
    rows += pad_write() + P + digest(out_aligned)
    return rows

def multi_block(len_, in_aligned, out_aligned):
    nfull = len_ // 136          # blocks before the final one (>=1)
    rem = len_ - 136 * nfull
    t, r = rem >> 3, rem & 7
    rows = PROLOGUE + 1          # beqz t3 (multi dispatch)
    if in_aligned:
        rows += 34 + 1 + P + 4   # first block copy, addi, permute, loop head
        if nfull > 1:
            rows += 2 + (nfull - 1) * (AP + 3)
        rows += 5                # final: srli/andi/andi/slli/beqz
        rows += 3                # andi t3 / add a7 / beqz t3
        k, tail = t >> 2, t & 3
        if k:
            rows += 2 + 19 * k + 2 + (1 if tail == 0 else 0)
        else:
            rows += 2
        if tail:
            rows += 1 + 8 * tail
        rows += 3 if r else 2
        rows += pad_xor(rem) + 1 + P
    else:
        rows += 123 + 1 + P + 4                  # misaligned first block (18 LD, 17x(srl2+sll2+or+sd), 3 setup)
        if nfull > 1:
            rows += 6 + (nfull - 1) * (163 + P) + 1
        rows += 5                                # final dispatch
        rows += 1                                # beqz t1 (rem==0)
        if rem == 0:
            rows += 1
        else:
            rows += 4
            if t:
                rows += 7 + 13 * t
            rows += 5 + (7 if (1 + r > 8) else 0)
        rows += pad_xor(rem) + 1 + P
    rows += digest(out_aligned)
    return rows

def call(len_, in_aligned=True, out_aligned=True, census=True):
    base = single_block(len_, in_aligned, out_aligned) if len_ < 136 else multi_block(len_, in_aligned, out_aligned)
    return base + (CENSUS if census else 0)

def perms(len_): return len_ // 136 + 1

# ---------------- mix for 25905781 (wave M: 44,511 calls / 13.34 MB / 115,373 perms / unaligned 470) ------------
d = json.load(open('data/25905781/witness.json'))
node_lens = [(len(h) - 2) // 2 for h in d['state']]
blk = open('data/25905781/block.rlp', 'rb').read()
def dec(b, i=0):
    p = b[i]
    if p < 0x80: return b[i:i+1], i+1
    if p < 0xb8: l = p-0x80; return b[i+1:i+1+l], i+1+l
    if p < 0xc0: ll = p-0xb7; l = int.from_bytes(b[i+1:i+1+ll], 'big'); return b[i+1+ll:i+1+ll+l], i+1+ll+l
    if p < 0xf8: l = p-0xc0; return ('list', b[i+1:i+1+l]), i+1+l
    ll = p-0xf7; l = int.from_bytes(b[i+1:i+1+ll], 'big'); return ('list', b[i+1+ll:i+1+ll+l]), i+1+ll+l
def items(payload):
    out = []; i = 0
    while i < len(payload):
        it, i2 = dec(payload, i); out.append(payload[i:i2]); i = i2
    return out
parts = items(dec(blk)[0][1]); txs = items(dec(parts[1])[0][1]); tx_lens = [len(t) for t in txs]

classes = {}
# keys: 3,000 x 32 B (hash_slot, topics) aligned in/out ; 1,000 x 20 B hash_address (out sp+0x6c misaligned)
classes['keys32'] = ([32] * 3000, True, True)
classes['keys20'] = ([20] * 1000, True, False)
classes['pubkey64'] = ([64] * 434, False, True)           # &vk[1..]: sp+0x499
classes['tx_sig'] = ([max(l - 67, 1) for l in tx_lens], None, True)  # 321/434 misaligned
classes['glue_txenc'] = (tx_lens, None, True)
classes['glue_receipts'] = ([296] * 434, True, True)
classes['glue_trienodes'] = ([532] * 152, True, True)
classes['codes'] = ([677072 // 62] * 62, True, True)
# nodes: witness distribution scaled to 33,061 calls
N_NODES = 33061
scale = N_NODES / len(node_lens)
classes['mpt_nodes'] = (node_lens, True, True)
classes['evm_small'] = ([32] * 2750 + [64] * 2750, True, True)

def evaluate(census=True, patch=None):
    tot_rows = tot_calls = tot_perms = tot_bytes = 0
    per = {}
    for name, (lens, aligned, out_al) in classes.items():
        w = scale if name == 'mpt_nodes' else 1.0
        rows = 0
        for i, L in enumerate(lens):
            a = aligned if aligned is not None else (i % 434 >= 321)  # 321 of 434 misaligned
            c = call(L, a, out_al, census) if patch is None else patch(L, a, out_al, census)
            rows += c
        n = len(lens) * w
        rows *= w
        pm = sum(perms(L) for L in lens) * w
        by = sum(lens) * w
        per[name] = (n, by, pm, rows)
        tot_rows += rows; tot_calls += n; tot_perms += pm; tot_bytes += by
    return tot_calls, tot_bytes, tot_perms, tot_rows, per

if __name__ == '__main__':
    calls, by, pm, rows, per = evaluate()
    print(f"mix: calls={calls:,.0f} bytes={by:,.0f} perms={pm:,.0f}  (census target 44,511 / 13.34M / 115,373)")
    print(f"total native_keccak256 rows (model) = {rows:,.0f}")
    inline_rows = 0
    for name, (n, b, p_, r) in per.items():
        print(f"  {name:16s} calls={n:8,.0f} bytes={b:11,.0f} perms={p_:8,.0f} rows={r:13,.0f} rows/call={r/n:8.1f} perms/call={p_/n:5.2f}")
    # decomposition
    pure_rounds = pm * 2424
    print(f"pure round rows = {pure_rounds:,.0f}; state I/O (50/perm) = {pm*50:,.0f}; everything else = {rows - pure_rounds - pm*50:,.0f}")
    c0 = evaluate(census=False)[3]
    print(f"census cost = {rows - c0:,.0f} rows ({(rows-c0)/calls:.1f}/call)")

# ---------------- component breakdown + fixes ----------------
def components():
    comp = collections.Counter()
    for name, (lens, aligned, out_al) in classes.items():
        w = scale if name == 'mpt_nodes' else 1.0
        for i, L in enumerate(lens):
            a = aligned if aligned is not None else (i % 434 >= 321)
            comp['census'] += CENSUS * w
            comp['frame+dispatch'] += (PROLOGUE - 8 + EPILOGUE + 1 + (3 if L < 136 else 5)) * w  # frame, shared, bltu, epilogue, t/r split
            comp['capacity zero (8 SD)'] += 8 * w
            comp['digest 4LD+4SD (+RMW)'] += (10 + (0 if out_al else 34)) * w
            nperm = perms(L)
            comp['inline rounds'] += 2424 * nperm * w
            comp['inline state LD/SD (50/perm)'] += 50 * nperm * w
            if L < 136:
                comp['single: 17 SD zero fill'] += 17 * w
                c = call(L, a, out_al, False) - (PROLOGUE + EPILOGUE + 17 + 3 + 1 + 13 + P + 6 + (4 if out_al else 38))
                comp['single: data copy/gather'] += c * w
                comp['pad word ops'] += 13 * w
            else:
                nfull = L // 136; rem = L % 136
                comp['multi: first block copy/gather'] += (34 if a else 123) * w
                if nfull > 1:
                    comp['multi: middle loop ctl'] += ((2 + 3 * (nfull - 1)) if a else (7 + 5 * (nfull - 1))) * w
                    comp['multi: absorb 17LD+17XOR (aligned) / shim gather (misal.)'] += ((34 if a else 158) * (nfull - 1)) * w
                fixed = PROLOGUE + 1 + (34 + 1 + P + 4 if a else 123 + 1 + P + 4) + (((2 + (nfull-1)*(AP+3)) if a else (6 + (nfull-1)*(163+P) + 1)) if nfull > 1 else 0) + 5 + pad_xor(rem) + 1 + P + digest(out_al)
                comp['multi: final block merge'] += (call(L, a, out_al, False) - fixed) * w
                comp['pad word ops'] += pad_xor(rem) * w
    return comp

comp = components()
tot = sum(comp.values())
print("\n--- component breakdown (model rows on 781) ---")
for k, v in sorted(comp.items(), key=lambda x: -x[1]):
    print(f"  {k:52s} {v:14,.0f}  {100*v/tot:5.2f}%")
print(f"  {'TOTAL':52s} {tot:14,.0f}")

# fixes
def rows_fix_inline_variants(L, a, out_al, census):
    """V1 FirstFinal (single-block: 17 LD + 8 zero + 4 SD, digest straight to out when aligned): -29 (shim skips 8 capacity SDs, inline 29 vs 50 I/O)
       V2 First (multi first block from caller memory: 17 LD + 8 zero + 25 SD, shim skips 34-row copy + 8 SD): -42 aligned / -16 misaligned
       V3 PermuteFinal (25 LD + 4 SD): -21 on the last permutation of multi-block calls"""
    base = call(L, a, out_al, census)
    if L < 136:
        return base - 29 - (4 if out_al else 0)   # aligned out: digest lands directly (skip 4 LD + 4 SD -> keep 4 SD in inline: -4 net)
    return base - (42 if a else 16) - 21

def rows_fix_pair_fusion(L, a, out_al, census):
    base = rows_fix_inline_variants(L, a, out_al, census)
    if L >= 136 and a:
        nfull = L // 136
        # fuse consecutive middle absorbs pairwise (Absorb2Permute): -50 per fused pair, plus fusing the final padded block into the
        # preceding permutation (AbsorbPermuteFinal from scratch): -50 once when nfull>=1
        pairs = (nfull - 1) // 2
        return base - 50 * pairs - 50
    return base

def rows_fix_keys(L, a, out_al, census):
    base = call(L, a, out_al, census)
    if L <= 64 and a and L < 136:
        t, r = L >> 3, L & 7
        direct = PROLOGUE + EPILOGUE + 3 + (t + (1 if r else 0)) * 2 + (16 - t - (1 if r else 0)) + 1 + 13 + P + 6 + (4 if out_al else 38)
        return direct + (CENSUS if census else 0)
    return base

def rows_fix_final_absorb(L, a, out_al, census):
    """final block of multi-block calls: copy t words into scratch (2/word, 4-unrolled loop 11/4w) + zero fill + pad + absorb inline (+34)"""
    base = call(L, a, out_al, census)
    if L >= 136 and a:
        nfull = L // 136; rem = L % 136; t, r = rem >> 3, rem & 7
        k, tail = t >> 2, t & 3
        cur = 3 + ((2 + 19*k + 2 + (1 if tail == 0 else 0)) if k else 2) + ((1 + 8*tail) if tail else 0) + (3 if r else 2) + pad_xor(rem) + 1 + P
        new = 3 + ((2 + 11*k + 2 + (1 if tail == 0 else 0)) if k else 2) + ((1 + 6*tail) if tail else 0) + (3 if r else 2) + (16 - t) + 13 + 1 + AP
        return base - cur + new
    return base

for label, fn in [('F1 census off', lambda L,a,o,c: call(L,a,o,False)),
                  ('F2 inline I/O variants V1-V3', rows_fix_inline_variants),
                  ('F2+V4 pair fusion', rows_fix_pair_fusion),
                  ('F3 final block via scratch+absorb', rows_fix_final_absorb),
                  ('F4 <=64B direct key path', rows_fix_keys)]:
    r = evaluate(census=True, patch=fn)[3]
    print(f"{label:40s} saves {rows - r:12,.0f} rows  ({100*(rows-r)/621_516_063:.3f}% of 781's 621.5M; {(rows-r)/44_227_079:.4f} c/g)")
print(f"F5 hash_address aligned out: {34*1000:,} rows; F6 pubkey aligned: {84*434:,} rows")
# floors
def floor_rows(L):
    words = (L + 7) // 8
    return 2424 * perms(L) + words + 4 + 4 + 10   # data words LD, pad const + lane16 + 4 SD digest, frame/dispatch ~10
for L in (20, 32, 64, 83, 115, 296, 532, 10920):
    print(f"len {L:5d}: current {call(L, True, True, False):7,d} (no census)  floor {floor_rows(L):7,d}  gap {call(L,True,True,False)-floor_rows(L):5d} ({100*(call(L,True,True,False)-floor_rows(L))/call(L,True,True,False):.1f}%)")
