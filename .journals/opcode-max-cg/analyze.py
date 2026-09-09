"""Combine results → per-opcode table with glue subtracted; CSV + JSON for the report."""
import json, csv, re
from pathlib import Path
R = {}
for tag in ('p1b', 'px2', 'p2c', 'p2d', 'p3'):
    p = Path(f'/tmp/opcg/results-{tag}.json')
    if p.exists():
        for k, v in json.loads(p.read_text()).items():
            v['tag'] = tag; R[k] = v
def rows(name): return R[name]['rows_per_unit']
def gas(name): return R[name]['gas_per_unit']
# --- anchors (rows) ---
POP = rows('PUSH1-POP') - rows('PUSH1/deep200')      # PUSH1 straight-line (shallow-ish) 
PUSH = {0: rows('PUSH0-POP') - POP, 1: rows('PUSH1-POP') - POP, 2: rows('PUSH2-POP') - POP, 3: rows('PUSH3-POP') - POP,
        20: rows('PUSH20-POP') - POP, 32: rows('PUSH32-POP') - POP}
for n in range(4, 33):
    if n not in PUSH: PUSH[n] = PUSH[3] + (PUSH[20] - PUSH[3]) * (n - 3) / 17 if n < 20 else PUSH[20] + (PUSH[32] - PUSH[20]) * (n - 20) / 12
DUP = {i: rows(f'DUP{i}') - POP for i in (1, 2, 3, 4, 7, 16)}
DUP[5] = rows('DUP5-POP') - POP; DUP[6] = rows('DUP6-POP') - POP
DUPavg = sum(DUP.values()) / len(DUP)
GAS = rows('GAS-POP') - POP
SWAP1 = rows('SWAP1'); JUMPDEST = rows('JUMPDEST')
MSTORE = rows('MSTORE') - 2 * DUP[2]
ANCH = dict(POP=POP, PUSH0=PUSH[0], PUSH1=PUSH[1], PUSH2=PUSH[2], PUSH3=PUSH[3], PUSH20=PUSH[20], PUSH32=PUSH[32], DUP=DUPavg, GAS=GAS, SWAP1=SWAP1, JUMPDEST=JUMPDEST, MSTORE=MSTORE)

def glue_for(name, unit_note=''):
    """(glue_rows, glue_gas) per unit for each case family, from the unit templates in cases*.py."""
    n = name.split('/')[0]
    grp = R[name]['group']
    tag = R[name]['tag']
    if tag == 'p3':
        # whole-block: per unit glue = PUSHk + POP etc.
        if n in ('SLOAD',): return PUSH[2] + POP, 5
        if n == 'SSTORE': return PUSH[1] + PUSH[2], 6
        if n in ('BALANCE', 'EXTCODESIZE'): return PUSH[20] + POP, 5
        if n == 'CALL' and 'new-value' in name: return 4 * PUSH[0] + PUSH[1] + PUSH[20] + GAS + POP, 4*2+3+3+2+2
        if n == 'CALL': return 5 * PUSH[0] + PUSH[20] + GAS + POP, 5*2+3+2+2
        if n == 'LOG0': return PUSH[2] + PUSH[0], 5
        return 0, 0
    if grp == 'precompile': return 5 * DUPavg + GAS + POP, 5*3+2+2
    if n in ('CALL', 'CALLCODE') and tag != 'p3':
        if 'cold-empty' in name: return 5 * PUSH[0] + PUSH[20] + GAS + POP, 5*2+3+2+2
        if 'cold-new' in name: return 4 * PUSH[0] + PUSH[1] + PUSH[20] + GAS + POP, 4*2+3+3+2+2
        if 'invalid' in name: return 6 * DUPavg + PUSH[2] + POP, 6*3+3+2
        return 6 * DUPavg + GAS + POP, 6*3+2+2
    if n in ('STATICCALL', 'DELEGATECALL'): return 5 * DUPavg + GAS + POP, 5*3+2+2
    if n in ('BALANCE', 'EXTCODESIZE', 'EXTCODEHASH') and 'cold' in name: return PUSH[20] + POP, 5
    if n == 'SLOAD' and 'cold' in name: return PUSH[2] + POP, 5
    if n == 'SSTORE' and 'cold' in name: return PUSH[1] + PUSH[2], 6
    if n in ('TSTORE',) and 'distinct' in name: return PUSH[1] + PUSH[2], 6
    if n == 'TLOAD' and 'distinct' in name: return PUSH[2] + POP, 5
    if n == 'SELFDESTRUCT': return PUSH[20] + PUSH[0] + MSTORE + 2*PUSH[0] + PUSH[1] + 2*PUSH[0] + PUSH[20] + GAS + POP, 3+2+3+2*2+3+2*2+3+2+2
    if n == 'EXTCODECOPY' and 'cold' in name: return PUSH[2] + 2 * PUSH[0] + PUSH[20], 3+2+2+3
    if n == 'EXTCODECOPY': return 4 * DUPavg, 12
    if n in ('CREATE',): return PUSH[1 if 'empty' in name else 2] + 2 * PUSH[0] + POP, 3+2+2+2
    if n == 'CREATE2': return PUSH[1 if 'empty' in name else 2] + 2 * PUSH[0] + POP + PUSH[2], 3+2+2+2+3
    if name.startswith('LOG'):
        k = int(n[3]) + 2; return k * DUPavg, 3 * k
    if n in ('CALLDATACOPY', 'CODECOPY', 'MCOPY', 'RETURNDATACOPY'): return 3 * DUPavg, 9
    if n in ('MSTORE', 'MSTORE8', 'TSTORE', 'SSTORE'): return 2 * DUP[2], 6
    if n in ('ADDMOD', 'MULMOD'): return 3 * DUP[3] + POP, 11
    if n in ('ISZERO', 'NOT', 'CLZ', 'CALLDATALOAD', 'MLOAD', 'BALANCE', 'EXTCODESIZE', 'EXTCODEHASH', 'SLOAD', 'TLOAD', 'BLOCKHASH'): return DUP[1] + POP, 5
    if n == 'JUMP': return PUSH[2] + JUMPDEST, 4
    if n == 'JUMPI' and 'taken' in name and 'not' not in name: return PUSH[1] + PUSH[2] + JUMPDEST, 7
    if n == 'JUMPI': return PUSH[0] + PUSH[2], 5
    if n in ('POP',): return PUSH[0], 2
    if re.fullmatch(r'DUP\d+', n): return POP, 2
    if n in ('SWAP1', 'SWAP16', 'JUMPDEST'): return 0, 0
    if re.fullmatch(r'PUSH\d+', n) and 'deep' in name: return 0, 0
    if name.endswith('-POP'): return POP, 2
    # binary ops (DUP2 DUP2 OP POP)
    if grp == 'arith' or n in ('KECCAK256',): return 2 * DUP[2] + POP, 8
    if grp == 'env' and tag != 'p3': return POP, 2
    return 0, 0

OUT = []
for name, r in R.items():
    if name in ('SSTORE/warm-dirty-alt',) or r.get('cg_unit') is None and r['tag'] != 'p3': pass
    g_rows, g_gas = glue_for(name)
    op_rows = r['rows_per_unit'] - g_rows
    op_gas = r['gas_per_unit'] - g_gas
    OUT.append(dict(name=name, group=r['group'], tag=r['tag'], ok=r['ok'], units=r['units'], method=r['method'], note=r.get('note', ''),
                    unit_rows=r['rows_per_unit'], unit_gas=r['gas_per_unit'], unit_cg=r['cg_unit'],
                    glue_rows=g_rows, glue_gas=g_gas, op_rows=op_rows, op_gas=op_gas, op_cg=(op_rows / op_gas if op_gas else None),
                    witness_bytes_per_unit=r.get('witness_bytes_per_unit')))
OUT.sort(key=lambda x: -(x['op_cg'] or 0))
json.dump({'anchors': ANCH, 'rows': OUT}, open('/tmp/opcg/analysis.json', 'w'), indent=1)
with open('/tmp/opcg/analysis.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(OUT[0].keys())); w.writeheader(); w.writerows(OUT)
print('anchors', {k: round(v, 1) for k, v in ANCH.items()})
for o in OUT[:60]:
    print(f"{o['name']:30s} {o['group']:10s} op_gas={o['op_gas']:10.1f} op_rows={o['op_rows']:12.1f} op_cg={o['op_cg'] if o['op_cg'] is None else round(o['op_cg'],1)!s:>8} unit_cg={round(o['unit_cg'],1) if o['unit_cg'] else None} ok={o['ok']}")
