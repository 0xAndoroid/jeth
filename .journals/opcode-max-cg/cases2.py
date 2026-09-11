"""Phase 2: calls, creates, cold-ish state (tiny trie), precompiles. Per-tx method."""
import sys, json; sys.path.insert(0, '/tmp/opcg')
from evm import *
VEC = json.load(open('/tmp/opcg/vectors.json'))
CASES = []
def case(name, group, unit, setup=b'', K=None, note='', contracts=None, calldata=b'', gas=16_000_000, value=0, gas_est=None, verify=None, balance=0, disjoint=False):
    CASES.append(dict(name=name, group=group, unit=unit, setup=setup, K=K, loop=False, note=note, contracts=contracts or [],
                      calldata=calldata, gas=gas, value=value, gas_est=gas_est, verify=verify, balance=balance, disjoint=disjoint))
U = lambda code: (lambda i: code)
p = push
PRE = asm('PUSH0 PUSH3 0x100100 MSTORE')

# callees
CALLEE = {
 'stop': (addr(7001), asm('STOP')),
 'ret32': (addr(7002), asm('PUSH1 32 PUSH0 RETURN')),
 'rev32': (addr(7003), asm('PUSH1 32 PUSH0 REVERT')),
 'invalid': (addr(7004), asm('INVALID')),
 'ret8k': (addr(7005), asm('PUSH2 8192 PUSH0 RETURN')),
 'big': (addr(7006), asm('STOP') + b'\x5b' * 24575),
 'sd': (addr(7007), asm('PUSH0 CALLDATALOAD SELFDESTRUCT')),
 'sstore1': (addr(7008), asm('PUSH1 1 PUSH0 SSTORE STOP')),
}
def callee(k, balance=0): a, c = CALLEE[k]; return {'address': a, 'code': c, 'balance': balance}
def call_setup(addr_hex, value=0, argsz=0, retsz=0):  # stack: retSize retOff argSize argOff value addr
    return p(retsz) + p(0x20000) + p(argsz) + p(0) + p(value) + p(int(addr_hex, 16))
CALL7 = asm('DUP6 DUP6 DUP6 DUP6 DUP6 DUP6 GAS CALL POP')
CALL6 = asm('DUP5 DUP5 DUP5 DUP5 DUP5 GAS STATICCALL POP')
DCALL6 = asm('DUP5 DUP5 DUP5 DUP5 DUP5 GAS DELEGATECALL POP')
CCALL7 = asm('DUP6 DUP6 DUP6 DUP6 DUP6 DUP6 GAS CALLCODE POP')
for k, note in [('stop', 'warm callee STOP'), ('ret32', 'callee RETURN 32B'), ('rev32', 'callee REVERT 32B'), ('big', 'warm callee 24KB code (STOP)'), ('sstore1', 'callee SSTORE slot0=1 (dirty after first)')]:
    case(f'CALL/{k}', 'call', U(CALL7), setup=call_setup(CALLEE[k][0], retsz=32), contracts=[callee(k)], note=note, gas_est=200 if k != 'sstore1' else 400)
case('CALL/invalid', 'call', U(asm('DUP6 DUP6 DUP6 DUP6 DUP6 DUP6 PUSH2 1000 CALL POP')), setup=call_setup(CALLEE['invalid'][0]), contracts=[callee('invalid')], note='callee INVALID, 1000 gas stipend burned', gas_est=1200)
case('CALL/value-existing', 'call', U(CALL7), setup=call_setup(CALLEE['stop'][0], value=1), contracts=[callee('stop')], note='warm, 1 wei to existing account (9000-2300)', gas_est=7000, balance=10**18)
case('STATICCALL/stop', 'call', U(CALL6), setup=p(0) + p(0x20000) + p(0) + p(0) + p(int(CALLEE['stop'][0], 16)), contracts=[callee('stop')], gas_est=200)
case('DELEGATECALL/stop', 'call', U(DCALL6), setup=p(0) + p(0x20000) + p(0) + p(0) + p(int(CALLEE['stop'][0], 16)), contracts=[callee('stop')], gas_est=200)
case('CALLCODE/stop', 'call', U(CCALL7), setup=call_setup(CALLEE['stop'][0]), contracts=[callee('stop')], gas_est=200)
case('CALL/cold-empty', 'state', (lambda i: asm('PUSH0 PUSH0 PUSH0 PUSH0 PUSH0') + p(int(addr(20000 + i), 16)) + asm('GAS CALL POP')), note='cold nonexistent target, no value (2600); tiny trie', gas_est=2800)
case('CALL/cold-new-value', 'state', (lambda i: asm('PUSH0 PUSH0 PUSH0 PUSH0 PUSH1 1') + p(int(addr(30000 + i), 16)) + asm('GAS CALL POP')), note='cold new account + 1 wei (36600); exec-only, account creation lands in post_root', gas_est=37000, balance=10**18, disjoint=True)
case('BALANCE/cold', 'state', (lambda i: p(int(addr(40000 + i), 16)) + asm('BALANCE POP')), note='cold nonexistent (2600); tiny trie', gas_est=2700)
case('EXTCODESIZE/cold', 'state', (lambda i: p(int(addr(40000 + i), 16)) + asm('EXTCODESIZE POP')), note='cold nonexistent; tiny trie', gas_est=2700)
case('EXTCODEHASH/cold', 'state', (lambda i: p(int(addr(40000 + i), 16)) + asm('EXTCODEHASH POP')), note='cold nonexistent; tiny trie', gas_est=2700)
case('EXTCODESIZE/warm-big', 'state', U(asm('DUP1 EXTCODESIZE POP')), setup=p(int(CALLEE['big'][0], 16)), contracts=[callee('big')], note='warm, 24KB code', gas_est=110)
case('EXTCODECOPY/cold-big', 'state', (lambda i: p(24576) + p(0) + p(0) + p(int(CALLEE['big'][0], 16)) + asm('EXTCODECOPY')), contracts=[callee('big')], note='first is cold, rest warm — 24KB copy each (3/word)', gas_est=2400 + 100)
case('SLOAD/cold-empty', 'state', (lambda i: p(0x1000 + i) + asm('SLOAD POP')), note='cold, nonexistent slot (2100); empty storage trie', gas_est=2200)
case('SSTORE/cold-new', 'state', (lambda i: asm('PUSH1 1') + p(0x1000 + i) + asm('SSTORE')), note='cold zero→nonzero (22100); exec-only, trie insert lands in post_root', gas_est=22200)
STOR = {i: 1 for i in range(2000)}
case('SLOAD/cold-existing', 'state', (lambda i: p(i) + asm('SLOAD POP')), contracts=[{'address': addr(7100), 'code': b'', 'storage': STOR}], note='PLACEHOLDER', gas_est=2200)
case('TSTORE/distinct', 'state', (lambda i: asm('PUSH1 1') + p(0x1000 + i) + asm('TSTORE')), gas_est=110)
case('TLOAD/distinct', 'state', (lambda i: p(0x1000 + i) + asm('TLOAD POP')), gas_est=110)
# SELFDESTRUCT via callee: beneficiary distinct cold, callee balance 0
case('SELFDESTRUCT/cold-benef', 'state', (lambda i: p(int(addr(50000 + i), 16)) + asm('PUSH0 MSTORE PUSH0 PUSH0 PUSH1 32 PUSH0 PUSH0') + p(int(CALLEE['sd'][0], 16)) + asm('GAS CALL POP')),
     contracts=[callee('sd')], note='CALL(100) + SELFDESTRUCT 5000 + cold beneficiary 2600; zero balance', gas_est=8000)
# RETURNDATACOPY 8KB after a call returning 8KB
case('RETURNDATACOPY/8192B', 'memory', U(asm('DUP3 DUP3 DUP3 RETURNDATACOPY')), setup=asm('PUSH0 PUSH0 PUSH0 PUSH0 PUSH0') + p(int(CALLEE['ret8k'][0], 16)) + asm('GAS CALL POP') + p(8192) + p(0) + p(0x30000),
     contracts=[callee('ret8k')], note='returndata 8KB, memory pre-expanded', gas_est=800)
# CREATE / CREATE2
INIT_STOP = asm('STOP')
INIT_BIG = asm('PUSH0 PUSH0 RETURN') + b'\x00' * (49152 - 3)
INIT_DEPLOY24K = asm('PUSH2 24576 PUSH0 RETURN')
def create_setup(init): return asm('PUSH2', ) if False else (p(len(init)) + p(0) + p(0) + asm('CALLDATACOPY'))
case('CREATE/empty', 'create', U(p(1) + p(0) + p(0) + asm('CREATE POP')), setup=create_setup(INIT_STOP), calldata=INIT_STOP, note='initcode STOP (1B) → empty-code account; exec-only', gas_est=33000)
case('CREATE/init48K', 'create', U(p(len(INIT_BIG)) + p(0) + p(0) + asm('CREATE POP')), setup=create_setup(INIT_BIG), calldata=INIT_BIG, note='initcode 49152B, returns empty', gas_est=36000)
case('CREATE2/empty', 'create', (lambda i: p(i + 1) + p(1) + p(0) + p(0) + asm('CREATE2 POP')), setup=create_setup(INIT_STOP), calldata=INIT_STOP, note='initcode 1B, distinct salts', gas_est=33000)
case('CREATE2/init48K', 'create', (lambda i: p(i + 1) + p(len(INIT_BIG)) + p(0) + p(0) + asm('CREATE2 POP')), setup=create_setup(INIT_BIG), calldata=INIT_BIG, note='initcode 49152B hashed (6/word)', gas_est=45000)
case('CREATE/deploy24K', 'create', U(p(len(INIT_DEPLOY24K)) + p(0) + p(0) + asm('CREATE POP')), setup=create_setup(INIT_DEPLOY24K), calldata=INIT_DEPLOY24K, note='deploys 24576 zero bytes (200/byte deposit)', gas_est=5_000_000, K=4)
# --- precompiles ---
RET = {1: 32, 2: 32, 3: 32, 4: None, 5: None, 6: 64, 7: 64, 8: 32, 9: 64, 10: 64, 11: 128, 12: 128, 13: 256, 14: 256, 15: 32, 16: 128, 17: 256, 0x100: 32}
def pc_case(name, paddr, vec, gas_est, note='', expected=None, retsz=None):
    data = bytes.fromhex(vec) if isinstance(vec, str) else vec
    rs = retsz if retsz is not None else RET[paddr]
    setup = p(len(data)) + p(0) + p(0) + asm('CALLDATACOPY') + p(rs) + p(0x20000) + p(len(data)) + p(0) + p(paddr)
    unit = asm('DUP5 DUP5 DUP5 DUP5 DUP5 GAS STATICCALL POP')
    ver = setup + asm('DUP5 DUP5 DUP5 DUP5 DUP5 GAS STATICCALL ISZERO')
    fail_pc_placeholder = len(ver) + 3 + 1  # PUSH2(3) JUMPI(1) then optional check then STOP then JUMPDEST INVALID
    tail = b''
    if expected is not None:
        tail = p(0x20000) + asm('MLOAD') + p(expected) + asm('EQ ISZERO') + b'\x61\x00\x00' + asm('JUMPI')
    fail_pc = len(ver) + 3 + 1 + len(tail) + 1
    verify = ver + pushn(fail_pc, 2) + asm('JUMPI') + tail.replace(b'\x61\x00\x00\x57', pushn(fail_pc, 2) + asm('JUMPI')) + asm('STOP JUMPDEST INVALID')
    case(name, 'precompile', U(unit), setup=setup, calldata=data, note=note, gas_est=gas_est + 200, verify=verify)
pc_case('ECRECOVER', 1, VEC['ecrecover'], 3000, expected=int(VEC['ecrecover_expected'], 16), note='valid sig (3000)')
for sz in (0, 32, 1024, 8192):
    d = bytes(range(256)) * (sz // 256) + bytes(range(sz % 256))
    pc_case(f'SHA256/{sz}B', 2, d, 60 + 12 * ((sz + 31) // 32), note=f'{sz}B input')
    pc_case(f'RIPEMD160/{sz}B', 3, d, 600 + 120 * ((sz + 31) // 32), note=f'{sz}B input')
    pc_case(f'IDENTITY/{sz}B', 4, d, 15 + 3 * ((sz + 31) // 32), note=f'{sz}B input', retsz=sz)
MODEXP = {  # name: (vec, gas_est, retsz, note)
 'MODEXP/32-32-32': ('modexp_32_32_32', 4080, 32, 'B,M 32B odd; E 255 bits set (gas 16*255)'),
 'MODEXP/32-e1-32': ('modexp_32_e1_32', 500, 32, 'E=1 → gas floor 500'),
 'MODEXP/32-e2-32': ('modexp_32_e2_32', 500, 32, 'E=2 (1 squaring) → floor 500'),
 'MODEXP/1024-32-1024': ('modexp_1024_32_1024', 8_355_840, 1024, 'B,M 1024B odd; E 256 bits set'),
 'MODEXP/1024-e1-1024': ('modexp_1024_e1_1024', 32768, 1024, 'B,M 1024B; E=1'),
 'MODEXP/1024-32-1024even': ('modexp_1024_32_1024even', 8_355_840, 1024, 'even modulus 1024B; E 256 bits'),
 'MODEXP/32-1024-32': ('modexp_32_1024_32', 258_032, 32, 'B,M 32B; E 1024B all ones (iter 16127)'),
 'MODEXP/256-32-256': ('modexp_256_32_256', 522_240, 256, 'B,M 256B; E 256 bits'),
 'MODEXP/64-32-64': ('modexp_64_32_64', 32_640, 64, 'B,M 64B; E 256 bits'),
 'MODEXP/8-32-8': ('modexp_8_32_8', 4080, 8, 'B,M 8B; E 256 bits'),
 'MODEXP/1-1-1': ('modexp_1_1_1', 500, 1, '2^3 mod 5 → floor 500'),
}
for n, (v, g, r, note) in MODEXP.items(): pc_case(n, 5, VEC[v], g, retsz=r, note=note)
pc_case('BN254ADD', 6, VEC['bn254_add'], 150, note='G1 + 7·G1')
pc_case('BN254MUL/full-scalar', 7, VEC['bn254_mul'], 6000, note='scalar n−1 (GLV override)')
pc_case('BN254MUL/scalar2', 7, VEC['bn254_mul_small'], 6000, note='scalar 2')
pc_case('BN254PAIRING/k1', 8, VEC['bn254_pair1'], 45000 + 34000, note='1 pair (result 0)')
pc_case('BN254PAIRING/k2', 8, VEC['bn254_pair2'], 45000 + 68000, expected=1, note='2 pairs, e(G1,G2)e(−G1,G2)=1')
pc_case('BN254PAIRING/k4', 8, VEC['bn254_pair4'], 45000 + 136000, expected=1, note='4 pairs')
pc_case('BN254PAIRING/k8', 8, VEC['bn254_pair8'], 45000 + 272000, expected=1, note='8 pairs')
for r in (0, 1, 12, 1000): pc_case(f'BLAKE2F/r{r}', 9, VEC[f'blake2f_{r}'], max(r, 1), note=f'{r} rounds (gas = rounds)')
pc_case('POINTEVAL', 10, VEC['kzg'], 50000, note='zero polynomial: commitment/proof = G1 infinity, z=y=0')
pc_case('BLS_G1ADD', 11, VEC['bls_g1add'], 375)
for k in (1, 2, 8, 32, 128): pc_case(f'BLS_G1MSM/k{k}', 12, VEC[f'bls_g1msm{k}'], 12000 * k, note=f'{k} points, scalars r−1')
pc_case('BLS_G2ADD', 13, VEC['bls_g2add'], 600)
for k in (1, 2, 8, 32): pc_case(f'BLS_G2MSM/k{k}', 14, VEC[f'bls_g2msm{k}'], 22500 * k, note=f'{k} points, scalars r−1')
pc_case('BLS_PAIRING/k1', 15, VEC['bls_pair1'], 37700 + 32600, note='1 pair (result 0)')
pc_case('BLS_PAIRING/k2', 15, VEC['bls_pair2'], 37700 * 2 + 32600, expected=1, note='2 pairs → 1')
pc_case('BLS_PAIRING/k4', 15, VEC['bls_pair4'], 37700 * 4 + 32600, expected=1)
pc_case('BLS_PAIRING/k8', 15, VEC['bls_pair8'], 37700 * 8 + 32600, expected=1)
pc_case('BLS_MAP_FP_TO_G1', 16, VEC['bls_mapg1'], 5500)
pc_case('BLS_MAP_FP2_TO_G2', 17, VEC['bls_mapg2'], 23800)
pc_case('P256VERIFY', 0x100, VEC['p256verify'], 6900, expected=1, note='valid signature → 1')
# fix placeholder note
for c in CASES:
    if c['name'] == 'SLOAD/cold-existing': c['note'] = 'cold existing slot (2100); storage trie of 2000 slots'; c['contracts'] = []
    if c['name'] == 'SLOAD/cold-existing': c['self_storage'] = STOR
