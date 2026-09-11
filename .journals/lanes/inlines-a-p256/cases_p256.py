"""P256VERIFY synth configs (lane inlines-a-p256): the study's exact config + a small-K twin. Per-tx method."""
import sys, json; sys.path.insert(0, '/tmp/opcg-p256')
from evm import *
VEC = json.load(open('/tmp/opcg-p256/vectors.json'))
CASES = []
def case(name, group, unit, setup=b'', K=None, note='', contracts=None, calldata=b'', gas=16_000_000, value=0, gas_est=None, verify=None, balance=0, disjoint=False):
    CASES.append(dict(name=name, group=group, unit=unit, setup=setup, K=K, loop=False, note=note, contracts=contracts or [],
                      calldata=calldata, gas=gas, value=value, gas_est=gas_est, verify=verify, balance=balance, disjoint=disjoint))
U = lambda code: (lambda i: code)
p = push
RET = {0x100: 32}
def pc_case(name, paddr, vec, gas_est, note='', expected=None, retsz=None, K=None):
    data = bytes.fromhex(vec) if isinstance(vec, str) else vec
    rs = retsz if retsz is not None else RET[paddr]
    setup = p(len(data)) + p(0) + p(0) + asm('CALLDATACOPY') + p(rs) + p(0x20000) + p(len(data)) + p(0) + p(paddr)
    unit = asm('DUP5 DUP5 DUP5 DUP5 DUP5 GAS STATICCALL POP')
    ver = setup + asm('DUP5 DUP5 DUP5 DUP5 DUP5 GAS STATICCALL ISZERO')
    tail = b''
    if expected is not None:
        tail = p(0x20000) + asm('MLOAD') + p(expected) + asm('EQ ISZERO') + b'\x61\x00\x00' + asm('JUMPI')
    fail_pc = len(ver) + 3 + 1 + len(tail) + 1
    verify = ver + pushn(fail_pc, 2) + asm('JUMPI') + tail.replace(b'\x61\x00\x00\x57', pushn(fail_pc, 2) + asm('JUMPI')) + asm('STOP JUMPDEST INVALID')
    case(name, 'precompile', U(unit), setup=setup, calldata=data, note=note, gas_est=gas_est + 200, verify=verify, K=K)
pc_case('P256VERIFY/k200', 0x100, VEC['p256verify'], 6900, expected=1, note='valid signature → 1; K=200', K=200)
pc_case('P256VERIFY', 0x100, VEC['p256verify'], 6900, expected=1, note='valid signature → 1 (study config, K auto)')
