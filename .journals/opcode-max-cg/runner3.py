"""Phase 3: whole-block method with deep (pruned) tries. Each case builds blocks for n and 2n units; Δrows/Δgas from `jeth trace`."""
import sys, json, time, subprocess; sys.path.insert(0, '/tmp/opcg')
from evm import *
import prune
from py_ecc.secp256k1 import secp256k1
from Crypto.Hash import keccak as K
def keccak(b): return K.new(digest_bits=256, data=bytes(b)).digest()
_pub = secp256k1.privtopub(b'\x11' * 32)
SENDER = keccak(_pub[0].to_bytes(32, 'big') + _pub[1].to_bytes(32, 'big'))[12:]
SYSTEM = [bytes.fromhex(a) for a in ['000F3df6D732807Ef1319fB7B8bB8522d0Beac02', '0000F90827F1C53a10cb7A02335B175320002935', '00000961Ef480Eb55e80D19ad83579A64c007002', '0000BBdDc7CE488642fb579F8B00f3a590007251']]
assert all(len(a) == 20 for a in SYSTEM), [len(a) for a in SYSTEM]
COINBASE = b'\xbe' * 20
def ab(h): return bytes.fromhex(h[2:])

def run_deep_block(name, contracts, txs, deep, touched_accounts, touched_storage, gas_limit=2_000_000_000, ancestors=0, force=False, siblings=False):
    d = WORK / name; d.mkdir(parents=True, exist_ok=True)
    rp = d / 'result-trace.json'
    if rp.exists() and not force: return json.loads(rp.read_text())
    spec = {'number': NUMBER, 'timestamp': TIMESTAMP, 'gas_limit': gas_limit, 'ancestors': ancestors,
            'contracts': [{'address': c['address'], 'code': hx(c.get('code', b'')), 'balance': hex(c.get('balance', 0)), 'nonce': c.get('nonce', 0),
                           'storage': {hex(k): hex(v) for k, v in c.get('storage', {}).items()}} for c in contracts],
            'txs': [{'to': t.get('to'), 'data': hx(t.get('data', b'')), 'gas': t['gas'], 'value': hex(t.get('value', 0))} for t in txs],
            'deep': deep}
    (d / 'spec.json').write_text(json.dumps(spec))
    t0 = time.time()
    r = subprocess.run([SYNTH, str(d / 'spec.json'), str(d)], capture_output=True, text=True)
    if r.returncode != 0: raise RuntimeError(f'synth failed {name}: {r.stdout}\n{r.stderr}')
    acc = set(touched_accounts) | {SENDER, COINBASE} | set(SYSTEM) | {ab(c['address']) for c in contracts}
    before, kept, kbytes = prune.prune(str(d / 'witness.json'), list(acc), touched_storage, siblings=siblings)
    r = subprocess.run([JETH, 'repack', '--dir', str(d)], capture_output=True, text=True)
    if r.returncode != 0: raise RuntimeError(f'repack failed {name}: {r.stdout}\n{r.stderr}')
    r = subprocess.run([JETH, 'trace', '--input', str(d / 'input.bin'), '--skip-build'], capture_output=True, text=True)
    (d / 'trace.log').write_text(r.stdout + r.stderr)
    if r.returncode != 0: raise RuntimeError(f'trace failed {name}: {r.stdout[-2000:]}\n{r.stderr[-2000:]}')
    s = json.loads((d / 'trace-summary.json').read_text())
    receipts = json.loads((d / 'receipts.json').read_text())
    out = {'name': name, 'rows': s['trace_rows_total'], 'gas': s['gas_used'], 'nodes_full': before, 'nodes': kept, 'witness_bytes': kbytes,
           'ok': all(x['success'] for x in receipts), 'ntx': len(txs), 'wall_s': time.time() - t0}
    rp.write_text(json.dumps(out)); return out

def run_case3(c, force=False):
    outs = []
    for mult in (1, 2):
        n = c['n'] * mult
        contracts, txs, deep, ta, ts, extra = c['build'](n)
        outs.append(run_deep_block(f"p3-{c['name'].replace('/', '_')}-n{n}", contracts, txs, deep, ta, ts, force=force, **extra))
    a, b = outs
    units = c['n']
    drows, dgas = b['rows'] - a['rows'], b['gas'] - a['gas']
    dbytes = b['witness_bytes'] - a['witness_bytes']
    r = dict(name=c['name'], group=c['group'], note=c['note'], ok=a['ok'] and b['ok'], units=units, drows=drows, dgas=dgas,
             rows_per_unit=drows / units, gas_per_unit=dgas / units, cg_unit=(drows / dgas if dgas else None),
             witness_bytes_per_unit=dbytes / units, nodes_per_unit=(b['nodes'] - a['nodes']) / units,
             method='whole-block Δ(2n − n), pruned deep witness', blocks=[a['name'], b['name']], rows_a=a['rows'], rows_b=b['rows'])
    print(f"{c['name']:34s} ok={r['ok']!s:5s} units={units:5d} gas/u={r['gas_per_unit']:10.1f} rows/u={r['rows_per_unit']:12.1f} c/g={None if r['cg_unit'] is None else round(r['cg_unit'], 2)} wit/u={r['witness_bytes_per_unit']:.0f}B nodes/u={r['nodes_per_unit']:.2f}", flush=True)
    return r

if __name__ == '__main__':
    mod = __import__(sys.argv[1]); tag = sys.argv[2]
    only = set(sys.argv[3].split(',')) if len(sys.argv) > 3 else None
    out = Path(f'/tmp/opcg/results-{tag}.json'); prev = json.loads(out.read_text()) if out.exists() else {}
    for c in mod.CASES:
        if only and c['name'] not in only: continue
        try:
            prev[c['name']] = run_case3(c)
        except Exception as e:
            print(f"CASE {c['name']} FAILED: {e}", flush=True)
        out.write_text(json.dumps(prev, indent=1))
