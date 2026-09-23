"""BLS12-381 / KZG precompile gate: synth blocks (per-tx Δ method + verify tx), run them with a
before/after guest ELF pair, report rows per call, block hashes and keccak perms.

  bls_gate.py build                 # synth + repack every block into cases/bls-*
  bls_gate.py measure <side>        # txprofile + trace with target prefix target/guest-<side>
  bls_gate.py report                # before/after table
  bls_gate.py blocks <side> [n...]  # real blocks: trace rows + hash + perms
"""
import json, os, re, subprocess, sys, time
sys.path.insert(0, '/Volumes/Dev/jeth-scratch/inlines-b-bls/opcg')
from evm import *
from runner import build_case

ROOT = Path('/Volumes/Dev/jeth-scratch/inlines-b-bls')
WT = '/Volumes/Dev/worktrees/jeth/inlines-b-bls'
VEC = json.load(open(ROOT / 'opcg/vectors.json'))
PE = json.load(open(ROOT / 'opcg/pointeval.json'))[0]['Input']
OUT_OFF = 0x100000
RECORDS = Path('/Volumes/Dev/worktrees/jeth/amber-nolane/data')

# name, precompile address, input hex, output size, K (units in tx A; tx B runs K/2)
CONFIGS = [
    ('BLS_G1ADD', 0x0b, VEC['bls_g1add'], 128, 40),
    ('BLS_G2ADD', 0x0d, VEC['bls_g2add'], 256, 40),
    ('BLS_G1MSM/k1', 0x0c, VEC['bls_g1msm1'], 128, 8),
    ('BLS_G1MSM/k8', 0x0c, VEC['bls_g1msm8'], 128, 4),
    ('BLS_G2MSM/k1', 0x0e, VEC['bls_g2msm1'], 256, 8),
    ('BLS_G2MSM/k8', 0x0e, VEC['bls_g2msm8'], 256, 4),
    ('BLS_PAIRING/k1', 0x0f, VEC['bls_pair1'], 32, 8),
    ('BLS_PAIRING/k2', 0x0f, VEC['bls_pair2'], 32, 4),
    ('BLS_MAP_FP_TO_G1', 0x10, VEC['bls_mapg1'], 128, 16),
    ('BLS_MAP_FP2_TO_G2', 0x11, VEC['bls_mapg2'], 256, 8),
    ('POINTEVAL', 0x0a, PE, 64, 8),
]

def mem_store(data: bytes, off=0) -> bytes:
    code = b''
    for i in range(0, len(data), 32):
        code += push(data[i:i + 32].ljust(32, b'\0')) + push(off + i) + asm('MSTORE')
    return code

def call(addr_, insize, outsize, pop=True):
    return asm(f'PUSH2 {outsize} PUSH3 {OUT_OFF} PUSH2 {insize} PUSH0 PUSH1 {addr_} GAS STATICCALL' + (' POP' if pop else ''))

def verify_contract(addr_, data: bytes, outsize) -> bytes:
    """One precompile call; slot 0 = success, slots 1.. = output words, last slot = returndatasize."""
    nw = outsize // 32
    code = mem_store(data) + call(addr_, len(data), outsize, pop=False) + asm('PUSH0 SSTORE')
    for w in range(nw):
        code += asm(f'PUSH3 {OUT_OFF + 32 * w} MLOAD PUSH1 {w + 1} SSTORE')
    return code + asm(f'RETURNDATASIZE PUSH1 {nw + 1} SSTORE STOP')

def cases():
    out = []
    for name, a, hexin, outsize, K in CONFIGS:
        data = bytes.fromhex(hexin)
        unit = call(a, len(data), outsize)
        out.append(dict(name=name, group='bls', unit=(lambda i, u=unit: u), setup=mem_store(data), K=K, loop=False,
                        note=f'addr {a:#x} in {len(data)} out {outsize}', contracts=[], calldata=b'', gas=16_000_000, value=0,
                        verify=verify_contract(a, data, outsize)))
    return out

def block_dirs():
    return sorted(p for p in (ROOT / 'opcg/cases').glob('bls-*') if (p / 'input.bin').exists())

def build(per_block=4, force=False):
    cs = cases()
    plan = {}
    for b in range(0, len(cs), per_block):
        chunk = cs[b:b + per_block]
        name = f'bls-{b // per_block:02d}'
        d = ROOT / 'opcg/cases' / name
        contracts, txs, metas = [], [], []
        for j, c in enumerate(chunk):
            cts, ts, m = build_case(c, 1 + b + j)
            contracts += cts; txs += ts; metas.append(dict(m, name=c['name']))
        for j, c in enumerate(chunk):
            va = addr(9000 + b + j)
            contracts.append({'address': va, 'code': c['verify']})
            txs.append({'to': va, 'data': b'', 'gas': 16_000_000, 'value': 0})
        plan[name] = metas
        if (d / 'input.bin').exists() and not force:
            continue
        d.mkdir(parents=True, exist_ok=True)
        spec = {'number': NUMBER, 'timestamp': TIMESTAMP, 'gas_limit': 2_000_000_000, 'ancestors': 0,
                'contracts': [{'address': c['address'], 'code': hx(c.get('code', b'')), 'balance': hex(c.get('balance', 0)),
                               'nonce': c.get('nonce', 0), 'storage': {hex(k): hex(v) for k, v in c.get('storage', {}).items()}} for c in contracts],
                'txs': [{'to': t.get('to'), 'data': hx(t.get('data', b'')), 'gas': t['gas'], 'value': hex(t.get('value', 0))} for t in txs]}
        (d / 'spec.json').write_text(json.dumps(spec))
        for cmd in ([SYNTH, str(d / 'spec.json'), str(d)], [JETH, 'repack', '--dir', str(d)]):
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                raise RuntimeError(f'{cmd[0]} failed for {name}:\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}')
        print('built', name, 'txs', len(txs), flush=True)
    (ROOT / 'opcg/cases/bls-plan.json').write_text(json.dumps(plan, indent=1))
    return plan

def env_for(side):
    e = dict(os.environ)
    e.pop('CARGO_TARGET_DIR', None)
    e['JETH_GUEST_TARGET_DIR'] = f'{WT}/target/guest-{side}'
    e['JOLT_PATH'] = '/Volumes/Dev/worktrees/jolt/jolt-inlines-b/target/release/jolt'
    return e

def run(cmd, side, log):
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True, env=env_for(side))
    Path(log).write_text(r.stdout + r.stderr)
    if r.returncode != 0:
        raise RuntimeError(f'{" ".join(cmd)} failed:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}')
    return r.stdout, time.time() - t0

def trace(input_bin: Path, side, tag):
    out, wall = run([JETH, 'trace', '--input', str(input_bin), '--skip-build'], side, input_bin.parent / f'trace-{side}-{tag}.log')
    s = json.loads((input_bin.parent / 'trace-summary.json').read_text())
    m = re.search(r'perms=(\d+)', out)
    return dict(rows=s['trace_rows_total'], hash=s['block_hash'], gas=s.get('gas_used'), perms=int(m.group(1)) if m else None, wall=wall,
                panicked=s.get('guest_panicked'))

def measure(side):
    plan = json.loads((ROOT / 'opcg/cases/bls-plan.json').read_text())
    res = {}
    for d in block_dirs():
        metas = plan[d.name]
        run([JETH, 'txprofile', '--input', str(d / 'input.bin'), '--skip-build', '--top', '500'], side, d / f'txprofile-{side}.log')
        tp = json.loads((d / 'txprofile.json').read_text())
        receipts = json.loads((d / 'receipts.json').read_text())
        byidx = {t['index']: t['cycles'] for t in tp['txs']}
        n = len(metas)
        for j, m in enumerate(metas):
            a, b, v = 2 * j, 2 * j + 1, 2 * n + j
            ok = receipts[a]['success'] and receipts[b]['success'] and receipts[v]['success']
            units = m['K'] - m['K2']
            res[m['name']] = dict(rows_per_call=(byidx[a] - byidx[b]) / units, units=units, ok=ok, block=d.name,
                                  gas_per_call=(receipts[a]['gas_used'] - receipts[b]['gas_used']) / units,
                                  verify_gas=receipts[v]['gas_used'])
        t = trace(d / 'input.bin', side, 'bls')
        res[d.name] = dict(block=t, txprofile_total=tp['trace_rows_total'])
        print(side, d.name, t, flush=True)
    (ROOT / f'opcg/results-bls-{side}.json').write_text(json.dumps(res, indent=1))
    for k, v in res.items():
        if 'rows_per_call' in v:
            print(f"{side:7s} {k:20s} rows/call={v['rows_per_call']:14,.1f} gas/call={v['gas_per_call']:10.1f} ok={v['ok']}")
    return res

def report():
    b = json.loads((ROOT / 'opcg/results-bls-before.json').read_text())
    a = json.loads((ROOT / 'opcg/results-bls-after.json').read_text())
    print(f"{'config':20s} {'before rows/call':>18s} {'after rows/call':>16s} {'Δ%':>8s}  ok  gas/call")
    for k in b:
        if 'rows_per_call' in b[k]:
            rb, ra = b[k]['rows_per_call'], a[k]['rows_per_call']
            print(f"{k:20s} {rb:18,.0f} {ra:16,.0f} {100 * (ra - rb) / rb:7.1f}%  {b[k]['ok'] and a[k]['ok']!s:5s} {b[k]['gas_per_call']:10.0f}")
    for k in b:
        if 'block' in b[k]:
            hb, ha = b[k]['block'], a[k]['block']
            print(f"{k}: rows {hb['rows']:,} -> {ha['rows']:,} ({100 * (ha['rows'] - hb['rows']) / hb['rows']:.2f}%) hash_equal={hb['hash'] == ha['hash']} perms {hb['perms']} -> {ha['perms']}")

def blocks(side, nums):
    res = {}
    for n in nums:
        inp = ROOT / 'data' / str(n) / 'input.bin'
        t = trace(inp, side, 'block')
        rec = RECORDS / str(n) / 'trace-summary.json'
        if rec.exists():
            r = json.loads(rec.read_text()); t['record_hash'] = r['block_hash']; t['record_rows'] = r['trace_rows_total']
        ch = ROOT / 'data' / str(n) / 'chain-hash.txt'
        if ch.exists():
            t['record_hash'] = ch.read_text().split()[1]
        t['hash_ok'] = t.get('record_hash') == t['hash']
        res[str(n)] = t
        print(side, n, f"rows={t['rows']:,} perms={t['perms']} hash_ok={t['hash_ok']} wall={t['wall']:.1f}s", flush=True)
    p = ROOT / f'opcg/results-blocks-{side}.json'
    prev = json.loads(p.read_text()) if p.exists() else {}
    prev.update(res); p.write_text(json.dumps(prev, indent=1))

if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'build': build(force='--force' in sys.argv)
    elif cmd == 'measure': measure(sys.argv[2])
    elif cmd == 'report': report()
    elif cmd == 'blocks': blocks(sys.argv[2], [int(x) for x in sys.argv[3:]] or [25905781 + i for i in range(10)] + [25694235])
