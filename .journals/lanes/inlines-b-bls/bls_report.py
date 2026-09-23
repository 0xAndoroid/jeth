"""Assemble the lane gate tables from the before/after result files."""
import json, re
from pathlib import Path
ROOT = Path('/Volumes/Dev/jeth-scratch/inlines-b-bls')
def load(p): return json.loads((ROOT / p).read_text()) if (ROOT / p).exists() else {}
b, a = load('opcg/results-bls-before.json'), load('opcg/results-bls-after.json')
print('## Synth configs (rows per precompile call, per-tx Δ method)\n')
print('| config | gas/call | rows/call before | rows/call after | Δ | rows/gas before → after |\n|---|---:|---:|---:|---:|---:|')
for k in b:
    if 'rows_per_call' in b[k] and k in a:
        rb, ra, g = b[k]['rows_per_call'], a[k]['rows_per_call'], b[k]['gas_per_call']
        print(f"| {k} | {g:,.0f} | {rb:,.0f} | {ra:,.0f} | {100 * (ra - rb) / rb:+.1f}% | {rb / g:,.0f} → {ra / g:,.0f} |")
print('\nsynth blocks:')
for k in b:
    if isinstance(b[k].get('block'), dict) and k in a:
        hb, ha = b[k]['block'], a[k]['block']
        print(f"- {k}: rows {hb['rows']:,} → {ha['rows']:,} ({100 * (ha['rows'] - hb['rows']) / hb['rows']:+.2f}%), hash equal: {hb['hash'] == ha['hash']}")

def perms(log):
    m = re.findall(r'keccak\[post_validation\]: .*perms=(\d+)', Path(log).read_text()) if Path(log).exists() else []
    return int(m[-1]) if m else None
bb, ab = load('opcg/results-blocks-before.json'), load('opcg/results-blocks-after.json')
print('\n## Blocks (jeth trace, proven ELF; hash vs record; keccak perms of the proven run)\n')
print('| block | rows before | rows after | Δ | hash == record | perms before → after |\n|---|---:|---:|---:|---|---:|')
for n in bb:
    if n not in ab: continue
    pb = perms(ROOT / 'data' / n / 'trace-before-block.log'); pa = perms(ROOT / 'data' / n / 'trace-after-block.log')
    rb, ra = bb[n]['rows'], ab[n]['rows']
    print(f"| {n} | {rb:,} | {ra:,} | {100 * (ra - rb) / rb:+.2f}% | {bb[n]['hash_ok'] and ab[n]['hash_ok'] and bb[n]['hash'] == ab[n]['hash']} | {pb} → {pa} |")

fn = load('opcg/results-forged-native.json'); fb, fa = load('opcg/results-forged-before.json'), load('opcg/results-forged-after.json')
plan = load('opcg/cases/forged-plan.json')
print('\n## Forged / edge blocks (guest hash == native hash)\n')
print('| block | cases | native hash | before rows / hash eq | after rows / hash eq |\n|---|---:|---|---|---|')
for k in fn:
    row = f"| {k} | {len(plan.get(k, []))} | {fn[k]['hash'][:14]}… |"
    for s in (fb, fa):
        row += f" {s[k]['rows']:,} / {s[k]['hash'] == fn[k]['hash']} |" if k in s else ' — |'
    print(row)

def prof(log):
    t = Path(log).read_text() if Path(log).exists() else ''
    total = re.search(r'trace rows.*?(\d[\d,]*)', t)
    top = re.findall(r'^\s*([\d.]+)%\s+([\d,]+)\s+(\S.*)$', t, re.M)
    ent = {}
    if '=== symbol entries' in t:
        for m in re.finditer(r'^\s*([\d,]+)\s+(\S.*)$', t.split('=== symbol entries')[1], re.M):
            ent[m.group(2).strip()] = int(m.group(1).replace(',', ''))
    return total.group(1) if total else None, top, ent
for blk in ('25905781', '25694235'):
    for side in ('before', 'after'):
        total, top, ent = prof(ROOT / 'logs' / f'profile{blk}-{side}.log')
        if not top: continue
        print(f"\n## Profile {blk} {side}: total {total}; top symbols\n")
        for pct, rows, name in top[:12]:
            print(f"- {pct}% {rows} {name[:110]}")
        bls = {k: v for k, v in ent.items() if re.search(r'bls12_381|kzg|QuadExt|Fp<|MontBackend|sum_of_products|mul_assign|square_in_place', k)}
        if bls:
            print('  entries (calls):')
            for k, v in sorted(bls.items(), key=lambda kv: -kv[1])[:16]:
                print(f"  - {v:,} {k[:120]}")
