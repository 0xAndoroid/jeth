"""bn254 ECPAIRING k=1 synth gate (per-tx Δ method, same harness as bls_gate.py).

  bn254_gate.py <side> <tag>   # build (once) + txprofile + trace → results-bn254-<tag>.json
"""
import json, subprocess, sys
sys.path.insert(0, '/Volumes/Dev/jeth-scratch/inlines-b-bls/opcg')
import bls_gate as g
from runner import build_case

g.CONFIGS = [('BN254_PAIRING/k1', 0x08, g.VEC['bn254_pair1'], 32, 8)]
D = g.ROOT / 'opcg/cases/bn254-00'
PLAN = g.ROOT / 'opcg/cases/bn254-plan.json'

def build():
    chunk = g.cases()
    contracts, txs, metas = [], [], []
    for j, c in enumerate(chunk):
        cts, ts, m = build_case(c, 1 + j)
        contracts += cts; txs += ts; metas.append(dict(m, name=c['name']))
    for j, c in enumerate(chunk):
        va = g.addr(9000 + j)
        contracts.append({'address': va, 'code': c['verify']})
        txs.append({'to': va, 'data': b'', 'gas': 16_000_000, 'value': 0})
    PLAN.write_text(json.dumps(metas, indent=1))
    if (D / 'input.bin').exists():
        return
    D.mkdir(parents=True, exist_ok=True)
    spec = {'number': g.NUMBER, 'timestamp': g.TIMESTAMP, 'gas_limit': 2_000_000_000, 'ancestors': 0,
            'contracts': [{'address': c['address'], 'code': g.hx(c.get('code', b'')), 'balance': hex(c.get('balance', 0)),
                           'nonce': c.get('nonce', 0), 'storage': {hex(k): hex(v) for k, v in c.get('storage', {}).items()}} for c in contracts],
            'txs': [{'to': t.get('to'), 'data': g.hx(t.get('data', b'')), 'gas': t['gas'], 'value': hex(t.get('value', 0))} for t in txs]}
    (D / 'spec.json').write_text(json.dumps(spec))
    for cmd in ([g.SYNTH, str(D / 'spec.json'), str(D)], [g.JETH, 'repack', '--dir', str(D)]):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f'{cmd[0]} failed:\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}')
    print('built', D.name, 'txs', len(txs), flush=True)

def measure(side, tag):
    metas = json.loads(PLAN.read_text())
    g.run([g.JETH, 'txprofile', '--input', str(D / 'input.bin'), '--skip-build', '--top', '500'], side, D / f'txprofile-{tag}.log')
    tp = json.loads((D / 'txprofile.json').read_text())
    receipts = json.loads((D / 'receipts.json').read_text())
    byidx = {t['index']: t['cycles'] for t in tp['txs']}
    n = len(metas)
    res = {}
    for j, m in enumerate(metas):
        a, b, v = 2 * j, 2 * j + 1, 2 * n + j
        ok = receipts[a]['success'] and receipts[b]['success'] and receipts[v]['success']
        units = m['K'] - m['K2']
        res[m['name']] = dict(rows_per_call=(byidx[a] - byidx[b]) / units, units=units, ok=ok,
                              gas_per_call=(receipts[a]['gas_used'] - receipts[b]['gas_used']) / units, verify_gas=receipts[v]['gas_used'])
    t = g.trace(D / 'input.bin', side, tag)
    res[D.name] = dict(block=t, txprofile_total=tp['trace_rows_total'])
    (g.ROOT / f'opcg/results-bn254-{tag}.json').write_text(json.dumps(res, indent=1))
    for k, v in res.items():
        if 'rows_per_call' in v:
            print(f"{tag:8s} {k:18s} rows/call={v['rows_per_call']:14,.1f} gas/call={v['gas_per_call']:10.1f} ok={v['ok']}", flush=True)
    print(tag, D.name, t, flush=True)

if __name__ == '__main__':
    build()
    measure(sys.argv[1], sys.argv[2])
