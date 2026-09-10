"""Forged / edge-input blocks for the BLS12-381 + KZG precompiles: every case is one tx whose contract
calls the precompile once and SSTOREs success flag, output words and returndatasize, so the block
hash covers the precompile result. Compare native (software) vs guest-before vs guest-after.

  bls_forged.py build            # synth + repack blocks cases/forged-*
  bls_forged.py native           # jeth run-native hashes
  bls_forged.py trace <side>     # guest trace with target/guest-<side>
  bls_forged.py report
"""
import json, re, subprocess, sys
sys.path.insert(0, '/Volumes/Dev/jeth-scratch/inlines-b-bls/opcg')
from evm import *
from bls_gate import verify_contract, run, trace, ROOT, VEC, PE
from py_ecc import bls12_381 as bls

E = ROOT / 'opcg/eip2537'
G1ADD, G1MSM, G2ADD, G2MSM, PAIR, MAPG1, MAPG2, KZG = 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x0a
OUT = {G1ADD: 128, G1MSM: 128, G2ADD: 256, G2MSM: 256, PAIR: 32, MAPG1: 128, MAPG2: 256, KZG: 64}
P = bls.field_modulus
R = bls.curve_order
MAX_IN = {G1MSM: 8 * 160, G2MSM: 4 * 288, PAIR: 3 * 384}

def be(x, n): return int(x).to_bytes(n, 'big')
def fp(x): return be(0, 16) + be(x, 48)
def g1(p): return fp(p[0]) + fp(p[1]) if p is not None else b'\0' * 128
def g2(p): return (fp(p[0].coeffs[0]) + fp(p[0].coeffs[1]) + fp(p[1].coeffs[0]) + fp(p[1].coeffs[1])) if p is not None else b'\0' * 256
G1, G2 = bls.G1, bls.G2

def eip_cases():
    out = []
    files = {G1ADD: ['add_G1_bls', 'fail-add_G1_bls'], G2ADD: ['add_G2_bls', 'fail-add_G2_bls'],
             G1MSM: ['msm_G1_bls', 'fail-msm_G1_bls'], G2MSM: ['msm_G2_bls', 'fail-msm_G2_bls'],
             PAIR: ['pairing_check_bls', 'fail-pairing_check_bls'], MAPG1: ['map_fp_to_G1_bls', 'fail-map_fp_to_G1_bls'],
             MAPG2: ['map_fp2_to_G2_bls', 'fail-map_fp2_to_G2_bls']}
    for a, names in files.items():
        for f in names:
            for v in json.load(open(E / f'{f}.json')):
                data = bytes.fromhex(v['Input'])
                if len(data) > MAX_IN.get(a, 10_000):
                    continue
                out.append((f"{f}/{v['Name']}", a, data, 'fail' if 'ExpectedError' in v else 'ok'))
    return out

def hand_cases():
    c = []
    inf1, inf2 = g1(None), g2(None)
    two = bls.multiply(G1, 2); two2 = bls.multiply(G2, 2)
    c += [('g1add/inf+inf', G1ADD, inf1 + inf1, 'ok'), ('g2add/inf+inf', G2ADD, inf2 + inf2, 'ok'),
          ('g1add/x=p', G1ADD, fp(P) + fp(G1[1]) + g1(G1), 'fail'), ('g1add/x=p+1', G1ADD, fp(P + 1) + fp(G1[1]) + g1(G1), 'fail'),
          ('g1add/y=p', G1ADD, fp(G1[0]) + fp(P) + g1(G1), 'fail'), ('g2add/x0=p', G2ADD, fp(P) + g2(G2)[64:] + g2(G2), 'fail'),
          ('g1add/inf_padding_bit', G1ADD, b'\x80' + b'\0' * 127 + g1(G1), 'fail')]
    for name, a, gen, enc, mul in [('g1msm', G1MSM, G1, g1, bls.multiply), ('g2msm', G2MSM, G2, g2, bls.multiply)]:
        c += [(f'{name}/s=0', a, enc(gen) + be(0, 32), 'ok'), (f'{name}/s=r', a, enc(gen) + be(R, 32), 'ok'),
              (f'{name}/s=r-1', a, enc(gen) + be(R - 1, 32), 'ok'), (f'{name}/s=2^256-1', a, enc(gen) + be(2**256 - 1, 32), 'ok'),
              (f'{name}/inf*5', a, enc(None) + be(5, 32), 'ok'), (f'{name}/(r-1)G+1G', a, enc(gen) + be(R - 1, 32) + enc(gen) + be(1, 32), 'ok'),
              (f'{name}/dup_G3+G4', a, enc(gen) + be(3, 32) + enc(gen) + be(4, 32), 'ok'),
              (f'{name}/k3_dup', a, enc(gen) + be(3, 32) + enc(mul(gen, 2)) + be(4, 32) + enc(gen) + be(R - 11, 32), 'ok'),
              (f'{name}/k0', a, b'', 'fail'), (f'{name}/x=p', a, fp(P) + enc(gen)[64:] + be(1, 32), 'fail')]
    c += [('pair/e(0,G2)e(G1,0)', PAIR, inf1 + g2(G2) + g1(G1) + inf2, 'ok'), ('pair/e(G1,G2)', PAIR, g1(G1) + g2(G2), 'ok'),
          ('pair/e(2G1,G2)e(-G1,2G2)', PAIR, g1(two) + g2(G2) + g1(bls.neg(G1)) + g2(two2), 'ok'),
          ('pair/x=p', PAIR, fp(P) + fp(G1[1]) + g2(G2), 'fail'), ('pair/k0', PAIR, b'', 'fail')]
    c += [('mapg1/u=0', MAPG1, fp(0), 'ok'), ('mapg1/u=p-1', MAPG1, fp(P - 1), 'ok'), ('mapg1/u=p', MAPG1, fp(P), 'fail'),
          ('mapg2/u=(0,0)', MAPG2, fp(0) + fp(0), 'ok'), ('mapg2/u=(p-1,p-1)', MAPG2, fp(P - 1) + fp(P - 1), 'ok'), ('mapg2/u=(p,0)', MAPG2, fp(P) + fp(0), 'fail')]
    pe = bytes.fromhex(PE); zero = bytes.fromhex(VEC['kzg'])
    flip = lambda b, i: b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]
    c += [('kzg/valid', KZG, pe, 'ok'), ('kzg/zero_poly_inf_commitment', KZG, zero, 'ok'),
          ('kzg/wrong_proof', KZG, flip(pe, 191), 'fail'), ('kzg/wrong_commitment', KZG, flip(pe, 143), 'fail'),
          ('kzg/wrong_versioned_hash', KZG, flip(pe, 31), 'fail'), ('kzg/wrong_y', KZG, flip(pe, 95), 'fail'),
          ('kzg/z=r', KZG, pe[:32] + be(R, 32) + pe[64:], 'fail'), ('kzg/z=2^256-1', KZG, pe[:32] + be(2**256 - 1, 32) + pe[64:], 'fail'),
          ('kzg/y=r', KZG, pe[:64] + be(R, 32) + pe[96:], 'fail'), ('kzg/inf_commitment_y=1', KZG, zero[:64] + be(1, 32) + zero[96:], 'fail'),
          ('kzg/commitment_ff', KZG, pe[:96] + b'\xff' * 48 + pe[144:], 'fail'), ('kzg/len191', KZG, pe[:191], 'fail'), ('kzg/len193', KZG, pe + b'\0', 'fail'),
          ('kzg/valid_twice_z', KZG, pe[:32] + be(0, 32) + pe[64:], 'fail')]
    return c

def all_cases():
    return eip_cases() + hand_cases()

def build(per_block=40, force=False):
    cs = all_cases()
    plan = {}
    for b in range(0, len(cs), per_block):
        chunk = cs[b:b + per_block]
        name = f'forged-{b // per_block:02d}'
        d = ROOT / 'opcg/cases' / name
        contracts, txs = [], []
        for j, (cname, a, data, expect) in enumerate(chunk):
            va = addr(7000 + b + j)
            contracts.append({'address': va, 'code': verify_contract(a, data, OUT[a])})
            txs.append({'to': va, 'data': b'', 'gas': 16_000_000, 'value': 0})
        plan[name] = [dict(name=cn, addr=a, expect=e, len=len(dt)) for cn, a, dt, e in chunk]
        if not (d / 'input.bin').exists() or force:
            d.mkdir(parents=True, exist_ok=True)
            spec = {'number': NUMBER, 'timestamp': TIMESTAMP, 'gas_limit': 2_000_000_000, 'ancestors': 0,
                    'contracts': [{'address': c['address'], 'code': hx(c['code']), 'balance': '0x0', 'nonce': 0, 'storage': {}} for c in contracts],
                    'txs': [{'to': t['to'], 'data': '0x', 'gas': t['gas'], 'value': '0x0'} for t in txs]}
            (d / 'spec.json').write_text(json.dumps(spec))
            for cmd in ([SYNTH, str(d / 'spec.json'), str(d)], [JETH, 'repack', '--dir', str(d)]):
                r = subprocess.run(cmd, capture_output=True, text=True)
                if r.returncode != 0:
                    raise RuntimeError(f'{cmd[0]} failed for {name}:\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}')
        rec = json.loads((d / 'receipts.json').read_text())
        for j, c in enumerate(plan[name]):
            c['tx_success'] = rec[j]['success']; c['gas'] = rec[j]['gas_used']
        print('built', name, len(txs), 'txs', flush=True)
    (ROOT / 'opcg/cases/forged-plan.json').write_text(json.dumps(plan, indent=1))

def dirs():
    return sorted(p for p in (ROOT / 'opcg/cases').glob('forged-*') if (p / 'input.bin').exists())

def native():
    res = {}
    for d in dirs():
        r = subprocess.run([JETH, 'run-native', '--input', str(d / 'input.bin')], capture_output=True, text=True)
        m = re.search(r'block_hash: (0x[0-9a-f]+)', r.stdout)
        res[d.name] = dict(hash=m.group(1) if m else None, ok=r.returncode == 0)
        print(d.name, res[d.name], flush=True)
    (ROOT / 'opcg/results-forged-native.json').write_text(json.dumps(res, indent=1))

def guest(side):
    res = {}
    for d in dirs():
        res[d.name] = trace(d / 'input.bin', side, 'forged')
        print(side, d.name, res[d.name], flush=True)
    (ROOT / f'opcg/results-forged-{side}.json').write_text(json.dumps(res, indent=1))

def report():
    n = json.loads((ROOT / 'opcg/results-forged-native.json').read_text())
    sides = {s: json.loads((ROOT / f'opcg/results-forged-{s}.json').read_text()) for s in ('before', 'after') if (ROOT / f'opcg/results-forged-{s}.json').exists()}
    plan = json.loads((ROOT / 'opcg/cases/forged-plan.json').read_text())
    for b in n:
        line = f"{b}: native {n[b]['hash'][:18]}"
        for s, r in sides.items():
            line += f" | {s} rows={r[b]['rows']:,} hash_eq={r[b]['hash'] == n[b]['hash']}"
        print(line)
    cases = [c for b in plan.values() for c in b]
    ok = sum(1 for c in cases if c['tx_success']); print(f'{len(cases)} cases, {ok} tx ok')
    # precompile outcome = slot 0 of each verify contract: infer from expectation vs. native receipts is not visible here;
    # expectation coverage:
    from collections import Counter
    print(Counter((c['expect'], c['addr']) for c in cases))

if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'build': build(force='--force' in sys.argv)
    elif cmd == 'native': native()
    elif cmd == 'trace': guest(sys.argv[2])
    elif cmd == 'report': report()
