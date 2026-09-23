"""Phase 1 cases: straight-line units (cheap ops) and loop units (expensive ops), per-tx method."""
import sys; sys.path.insert(0, '/tmp/opcg')
from evm import *

A = (1 << 256) - 1
B = (1 << 255) - 1 | 0x1234567  # 255-bit odd-ish
C = 0xdeadbeefcafebabe0123456789abcdef  # 128-bit
S = 3
P32 = bytes([0x7f]) + b'\xff' * 32

def p(v): return push(v)

CASES = []  # dict(name, group, setup(bytes), unit(callable i->bytes), K or None, loop(bool), note)
def case(name, group, unit, setup=b'', K=None, loop=False, note='', contracts=None, calldata=b'', gas=16_000_000, value=0):
    CASES.append(dict(name=name, group=group, unit=unit, setup=setup, K=K, loop=loop, note=note,
                      contracts=contracts or [], calldata=calldata, gas=gas, value=value))

U = lambda code: (lambda i: code)

# --- anchors -------------------------------------------------------------
case('PUSH0', 'stack', U(asm('PUSH0')), K=1000, note='straight-line, 1000 deep')
case('PUSH1', 'stack', U(asm('PUSH1 0x7f')), K=1000)
case('PUSH32', 'stack', U(P32), K=1000)
case('POP', 'stack', U(asm('PUSH0 POP')), note='minus PUSH0')
case('DUP1', 'stack', U(asm('DUP1 POP')), setup=p(A), note='minus POP')
case('DUP2', 'stack', U(asm('DUP2 POP')), setup=p(A)+p(B), note='minus POP')
case('DUP3', 'stack', U(asm('DUP3 POP')), setup=p(A)+p(B)+p(C), note='minus POP')
case('DUP4', 'stack', U(asm('DUP4 POP')), setup=p(A)+p(B)+p(C)+p(S), note='minus POP')
case('DUP7', 'stack', U(asm('DUP7 POP')), setup=p(A)*7, note='minus POP')
case('DUP16', 'stack', U(asm('DUP16 POP')), setup=p(A)*16, note='minus POP')
case('SWAP1', 'stack', U(asm('SWAP1')), setup=p(A)+p(B))
case('SWAP16', 'stack', U(asm('SWAP16')), setup=p(A)*17)
case('JUMPDEST', 'control', U(asm('JUMPDEST')))

# --- binary arithmetic / bitwise: setup [second, top]; unit DUP2 DUP2 OP POP -----------------
def binop(name, top, second, tag='', note=''):
    case(name + tag, 'arith', U(asm('DUP2 DUP2 ' + name + ' POP')), setup=p(second) + p(top), note=note or f'top={hex(top)[:12]}.. second={hex(second)[:12]}..')
for op in ['ADD', 'MUL', 'SUB', 'AND', 'OR', 'XOR', 'LT', 'GT', 'SLT', 'SGT', 'EQ']:
    binop(op, A, B)
binop('MUL', C, C, tag='/128x128')
for op in ['DIV', 'SDIV', 'MOD', 'SMOD']:
    binop(op, A, B, tag='/256by255', note='dividend 256-bit, divisor 255-bit')
    binop(op, A, C, tag='/256by128', note='dividend 256-bit, divisor 128-bit')
    binop(op, A, S, tag='/256by3', note='dividend 256-bit, divisor 3')
binop('SDIV', 1 << 255, A, tag='/minby-1', note='MIN / -1 overflow path')
binop('EXP', A, A, tag='/exp256', note='base 2^256-1, exponent 256-bit (gas 10+50*32)')
binop('EXP', A, 0xff, tag='/exp8', note='exponent 1 byte (gas 60)')
binop('EXP', A, 1 << 255, tag='/exp2^255', note='exponent 2^255 (gas 1610, sparse bits)')
binop('SIGNEXTEND', A, 0, note='top=value, second=byte index 0')
binop('BYTE', A, 31, note='index 31')
binop('SHL', A, 200); binop('SHR', A, 200); binop('SAR', A, 200)
binop('SHL', A, 300, tag='/ge256'); 
binop('KECCAK256', 0, 32, tag='/32B', note='offset 0, size 32')
binop('KECCAK256', 0, 136, tag='/136B', note='exactly one permutation block')
binop('KECCAK256', 0, 1024, tag='/1KB')
binop('KECCAK256', 0, 8192, tag='/8KB', note='memory pre-expanded')
binop('KECCAK256', 0, 0, tag='/0B', note='empty input (30 gas)')
# ternary
def terop(name, top, second, third, tag='', note=''):
    case(name + tag, 'arith', U(asm('DUP3 DUP3 DUP3 ' + name + ' POP')), setup=p(third) + p(second) + p(top), note=note)
terop('ADDMOD', A, A, B, note='a=b=2^256-1, N 255-bit')
terop('MULMOD', A, A, B, note='a=b=2^256-1, N 255-bit')
terop('MULMOD', A, A, C, tag='/N128', note='N 128-bit')
terop('MULMOD', A, A, S, tag='/N3', note='N=3')
# unary
def unop(name, a, tag='', note='', **kw):
    case(name + tag, kw.pop('group', 'arith'), U(asm('DUP1 ' + name + ' POP')), setup=p(a), note=note, **kw)
unop('ISZERO', A); unop('NOT', A); unop('CLZ', 1, note='value 1 (255 leading zeros)'); unop('CLZ', A, tag='/full')
unop('CALLDATALOAD', 0, group='env'); unop('MLOAD', 0, group='memory'); unop('MLOAD', 0x100000, tag='/1MB', group='memory', note='offset 1 MiB, pre-expanded')
unop('BALANCE', int(addr(1), 16), group='state', note='warm (self)')
unop('EXTCODESIZE', int(addr(1), 16), group='state', note='warm (self, code ~24KB)')
unop('EXTCODEHASH', int(addr(1), 16), group='state', note='warm (self)')
unop('SLOAD', 1, group='state', note='warm, slot 1 (nonexistent)')
unop('TLOAD', 1, group='state')
unop('BLOCKHASH', NUMBER - 1, group='env', note='parent (1 ancestor in witness)')
unop('BLOCKHASH', 5, tag='/out', group='env', note='out of range')
# nullary
for op in ['ADDRESS', 'ORIGIN', 'CALLER', 'CALLVALUE', 'CALLDATASIZE', 'CODESIZE', 'GASPRICE', 'RETURNDATASIZE', 'COINBASE', 'TIMESTAMP', 'NUMBER', 'PREVRANDAO', 'GASLIMIT', 'CHAINID', 'SELFBALANCE', 'BASEFEE', 'BLOBBASEFEE', 'PC', 'MSIZE', 'GAS']:
    case(op, 'env', U(asm(op + ' POP')), note='minus POP')
# stores: setup [value, key/offset(top)]; unit DUP2 DUP2 OP
case('MSTORE', 'memory', U(asm('DUP2 DUP2 MSTORE')), setup=p(A) + p(0))
case('MSTORE8', 'memory', U(asm('DUP2 DUP2 MSTORE8')), setup=p(A) + p(0))
case('TSTORE', 'state', U(asm('DUP2 DUP2 TSTORE')), setup=p(A) + p(1))
case('SSTORE/warm-dirty', 'state', U(asm('DUP2 DUP2 SSTORE')), setup=p(A) + p(1), note='same slot rewritten (100 gas after first), pre-state slot 1 = 0')
case('SSTORE/warm-dirty-alt', 'state', (lambda i: asm('DUP2 DUP2 SSTORE DUP2 DUP2 SSTORE')), setup=p(A) + p(1), note='2 stores per unit; placeholder')
# copies: setup [size, src, dst(top)]; unit DUP3 DUP3 DUP3 OP
for op, sizes in [('CALLDATACOPY', [32, 1024, 8192]), ('CODECOPY', [32, 1024, 8192]), ('MCOPY', [32, 1024, 8192]), ('RETURNDATACOPY', [0])]:
    for sz in sizes:
        case(f'{op}/{sz}B', 'memory', U(asm(f'DUP3 DUP3 DUP3 {op}')), setup=p(sz) + p(0) + (p(0) if op != 'MCOPY' else p(16384)), note='memory pre-expanded; src 0' + ('; dst 16K' if op == 'MCOPY' else ''),
             calldata=b'\x11' * 8192 if op == 'CALLDATACOPY' else b'')
case('EXTCODECOPY/8KB', 'state', U(asm('DUP4 DUP4 DUP4 DUP4 EXTCODECOPY')), setup=p(8192) + p(0) + p(0) + p(int(addr(1), 16)), note='warm self, 8KB')
case('EXTCODECOPY/32B', 'state', U(asm('DUP4 DUP4 DUP4 DUP4 EXTCODECOPY')), setup=p(32) + p(0) + p(0) + p(int(addr(1), 16)), note='warm self, 32B')
# control flow
case('JUMP', 'control', (lambda i: b'\x61' + b'\x00\x00' + b'\x56\x5b'), note='PUSH2 target JUMP JUMPDEST; target patched by assembler')
case('JUMPI/taken', 'control', (lambda i: b'\x60\x01' + b'\x61' + b'\x00\x00' + b'\x57\x5b'), note='PUSH1 1 PUSH2 t JUMPI JUMPDEST')
case('JUMPI/not-taken', 'control', U(asm('PUSH0 PUSH2 0x0000 JUMPI')), note='cond 0')
# logs: setup [topics..., size, offset(top)] ; unit DUPk*k LOGn
for n in range(5):
    for sz in ([0, 1024] if n in (0, 4) else [0]):
        k = n + 2
        case(f'LOG{n}/{sz}B', 'log', U(asm(' '.join([f'DUP{k}'] * k) + f' LOG{n}')), setup=b''.join(p(0x1111 * (t + 1)) for t in range(n)) + p(sz) + p(0), note=f'{n} topics, {sz} bytes data')

_KCAP = {'KECCAK256/8KB': 2000, 'KECCAK256/1KB': 4000, 'LOG0/1024B': 1200, 'LOG4/1024B': 1200, 'LOG4/0B': 3000, 'LOG3/0B': 4000,
         'CALLDATACOPY/8192B': 2000, 'CODECOPY/8192B': 2000, 'MCOPY/8192B': 2000, 'EXTCODECOPY/8KB': 2000, 'EXP/exp256': 4000, 'EXP/exp2^255': 4000}
for c in CASES:
    if c['name'] in _KCAP: c['K'] = _KCAP[c['name']]
CASES = [c for c in CASES if c['name'] != 'SSTORE/warm-dirty-alt']
