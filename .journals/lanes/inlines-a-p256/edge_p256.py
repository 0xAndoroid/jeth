"""Forged/edge P256VERIFY inputs: one synthetic block, one tx per vector. Each tx calls a contract that
STATICCALLs 0x100 with the input, SSTOREs ok<<24 | 1<<16 | returndatasize<<8 | mload(ret) into its slot and
reverts if that word differs from the software expectation carried in calldata. Native (software p256) vs
guest (inline) agreement = block_hash equality (post-state root pins every stored word)."""
import sys, json, re, subprocess, time; sys.path.insert(0, '/tmp/opcg-p256')
from evm import *
from p256_math import *

VEC = json.load(open('/tmp/opcg-p256/vectors.json'))
DAIMO = [
 '4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e',
 '3fec5769b5cf4e310a7d150508e82fb8e3eda1c2c94c61492d3bd8aea99e06c9e22466e928fdccef0de49e3503d2657d00494a00e764fd437bdafa05f5922b1fbbb77c6817ccf50748419477e843d5bac67e6a70e97dde5a57e0c983b777e1ad31a80482dadf89de6302b1988c82c29544c9c07bb910596158f6062517eb089a2f54c9a0f348752950094d3228d3b940258c75fe2a413cb70baa21dc2e352fc5',
 '3cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e',
]

def parse(hexstr):
    b = bytes.fromhex(hexstr)
    z, r, s, x, y = (int.from_bytes(b[i:i + 32], 'big') for i in range(0, 160, 32))
    return z, r, s, (x, y)

def expect_sw(raw):
    """Software accept set (p256/ecdsa crates) for an arbitrary-length input."""
    if len(raw) != 160: return False
    return verify(*parse(raw.hex()))

VECTORS = []  # (name, raw_input_bytes, note)
def add(name, raw, note=''): VECTORS.append((name, raw, note))

z0, r0, s0, q0 = parse(VEC['p256verify'])
add('valid/study', inp(z0, r0, s0, q0), 'the c/g study vector')
add('valid/rip7212-1', bytes.fromhex(DAIMO[0]), 'daimo/RIP-7212 vector 1')
add('valid/rip7212-2', bytes.fromhex(DAIMO[1]), 'daimo/RIP-7212 vector 2')
add('invalid/rip7212-wrong-msg', bytes.fromhex(DAIMO[2]), 'daimo fail vector')
add('r=0', inp(z0, 0, s0, q0)); add('s=0', inp(z0, r0, 0, q0))
add('r=n', inp(z0, N, s0, q0)); add('s=n', inp(z0, r0, N, q0))
add('r=n-1', inp(z0, N - 1, s0, q0), 'valid s')
add('valid/high-s', inp(z0, r0, N - s0, q0), 'n - s of the study vector')
add('r=2^256-1', inp(z0, 2**256 - 1, s0, q0)); add('s=2^256-1', inp(z0, r0, 2**256 - 1, q0))
x0, y0 = q0
add('pk.x=p', inp(z0, r0, s0, (P, y0)))
add('pk.x>=p', inp(z0, r0, s0, ((x0 + P) if x0 + P < 2**256 else 2**256 - 1, y0)))
add('pk.y>=p', inp(z0, r0, s0, (x0, y0 + P if y0 + P < 2**256 else 2**256 - 1)))
add('pk-off-curve', inp(z0, r0, s0, (x0, y0 + 1)))
add('pk=(0,0)', inp(z0, r0, s0, (0, 0)))
add('pk=-Q', inp(z0, r0, s0, (x0, P - y0)), 'on curve, wrong key')
add('pk=(1,1)', inp(z0, r0, s0, (1, 1)))
# msg >= n: sign a small z, present msg = z + n
d = 0x1234_5678_9abc_def0; q = mul(d, G); zs = 0xabcdef
r, s = sign(d, zs, 0x777_0001)
add('valid/msg>=n', inp(zs + N, r, s, q), 'msg = z + n reduces to signed z')
add('invalid/msg>=n', inp(zs + N + 1, r, s, q), 'msg = z + n + 1')
add('valid/msg=2^256-1', inp(2**256 - 1, *sign(d, (2**256 - 1) % N, 0x777_0002), q))
add('valid/msg=n-1', inp(N - 1, *sign(d, N - 1, 0x777_0003), q))
# z = 0 (msg = 0 and msg = n): accepted by the software path
r, s = sign(d, 0, 0x777_0004)
add('valid/msg=0', inp(0, r, s, q), 'z = 0, generic key')
add('valid/msg=n', inp(N, r, s, q), 'z = n mod n = 0')
add('valid/msg=0/high-s', inp(0, r, N - s, q))
add('invalid/msg=0/wrong-s', inp(0, r, s + 1, q))
add('invalid/msg=0/wrong-key', inp(0, r, s, mul(d + 1, G)))
for dd, name in [(1, 'Q=G'), (2, 'Q=2G'), (3, 'Q=3G')]:
    rr, ss = sign(dd, 0, 0x777_0010 + dd)
    add(f'valid/msg=0/{name}', inp(0, rr, ss, mul(dd, G)))
    add(f'invalid/msg=0/{name}-wrong-r', inp(0, (rr + 1) % N or 1, ss, mul(dd, G)))
add('valid/msg=1/Q=G', inp(1, *sign(1, 1, 0x777_0020), G))
# length edges (handled before the hook)
add('len159', inp(z0, r0, s0, q0)[:159], 'truncated')
add('len161', inp(z0, r0, s0, q0) + b'\x00', 'one extra byte')
add('len0', b'', 'empty input')

def contract_code():
    # calldata: slot(32) | expected_word(32) | input
    code = asm('PUSH0 CALLDATALOAD PUSH1 32 CALLDATALOAD PUSH1 64 CALLDATASIZE SUB DUP1 PUSH1 64 PUSH0 CALLDATACOPY')
    code += asm('PUSH1 32 PUSH2 0x1000 DUP3 PUSH0 PUSH2 0x100 GAS STATICCALL')          # slot expected len ok
    code += asm('PUSH1 24 SHL PUSH3 0x010000 OR RETURNDATASIZE PUSH1 8 SHL OR PUSH2 0x1000 MLOAD OR')  # slot expected len v
    code += asm('SWAP1 POP DUP1 SWAP3 SSTORE')                                             # expected v
    code += asm('EQ ISZERO')
    fail = len(code) + 3 + 1 + 1
    code += pushn(fail, 2) + asm('JUMPI STOP JUMPDEST PUSH0 PUSH0 REVERT')
    return code

def word_for(raw):
    ok = 1 << 24
    if len(raw) != 160 or not expect_sw(raw):
        return ok | (1 << 16)
    return ok | (1 << 16) | (32 << 8) | 1

def run(name, jeth, force=False):
    cont = addr(0x256)
    contracts = [{'address': cont, 'code': contract_code()}]
    txs, expected = [], []
    for i, (vname, raw, note) in enumerate(VECTORS):
        w = word_for(raw)
        txs.append({'to': cont, 'data': (i + 1).to_bytes(32, 'big') + w.to_bytes(32, 'big') + raw, 'gas': 300_000})
        expected.append((vname, bool(w & 1), note))
    d = WORK / name
    d.mkdir(parents=True, exist_ok=True)
    spec = {'number': NUMBER, 'timestamp': TIMESTAMP, 'gas_limit': 200_000_000, 'ancestors': 0,
            'contracts': [{'address': c['address'], 'code': hx(c['code']), 'balance': '0x0', 'nonce': 0, 'storage': {}} for c in contracts],
            'txs': [{'to': t['to'], 'data': hx(t['data']), 'gas': t['gas'], 'value': '0x0'} for t in txs]}
    (d / 'spec.json').write_text(json.dumps(spec))
    r = subprocess.run([SYNTH, str(d / 'spec.json'), str(d)], capture_output=True, text=True)
    if r.returncode != 0: raise RuntimeError(f'synth failed:\n{r.stdout}\n{r.stderr}')
    r = subprocess.run([jeth, 'repack', '--dir', str(d)], capture_output=True, text=True)
    if r.returncode != 0: raise RuntimeError(f'repack failed:\n{r.stdout}\n{r.stderr}')
    receipts = json.loads((d / 'receipts.json').read_text())
    rows = []
    for (vname, acc, note), rc in zip(expected, receipts):
        rows.append(dict(name=vname, software_accepts=acc, tx_success=rc['success'], gas=rc['gas_used'], note=note))
        flag = '' if rc['success'] else '   <-- tx REVERTED: software result != python expectation'
        print(f"{vname:32s} accept={acc!s:5s} tx_ok={rc['success']!s:5s} gas={rc['gas_used']}{flag}")
    nat = subprocess.run([jeth, 'run-native', '--input', str(d / 'input.bin')], capture_output=True, text=True)
    (d / 'native.log').write_text(nat.stdout + nat.stderr)
    m = re.search(r'block_hash: (0x[0-9a-f]+)', nat.stdout)
    native_hash = m.group(1) if m else None
    t0 = time.time()
    tr = subprocess.run([jeth, 'trace', '--input', str(d / 'input.bin'), '--skip-build'], capture_output=True, text=True)
    (d / 'trace.log').write_text(tr.stdout + tr.stderr)
    summ = json.loads((d / 'trace-summary.json').read_text()) if (d / 'trace-summary.json').exists() else {}
    out = dict(name=name, native_hash=native_hash, native_rc=nat.returncode, trace_rc=tr.returncode, trace_hash=summ.get('block_hash'),
               trace_rows_total=summ.get('trace_rows_total'), perms=summ.get('keccak_perms'), wall_s=time.time() - t0, vectors=rows,
               all_tx_ok=all(r['tx_success'] for r in rows))
    (d / 'edge-result.json').write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if k != 'vectors'}, indent=1))
    print('HASH MATCH' if native_hash and native_hash == out['trace_hash'] else 'HASH MISMATCH / FAILURE')
    return out

if __name__ == '__main__':
    run(sys.argv[1] if len(sys.argv) > 1 else 'edge-after', sys.argv[2] if len(sys.argv) > 2 else JETH)
