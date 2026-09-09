import sys; sys.path.insert(0, '/tmp/opcg')
from evm import *
from cases1 import U
CASES = []
def case(name, group, unit, setup=b'', K=None, note=''):
    CASES.append(dict(name=name, group=group, unit=unit, setup=setup, K=K, loop=False, note=note, contracts=[], calldata=b'', gas=16_000_000, value=0))
for K in (200, 1000):
    case(f'PUSH0/deep{K}', 'stack', U(asm('PUSH0')), K=K, note=f'straight-line, stack grows to {K}')
    case(f'PUSH1/deep{K}', 'stack', U(asm('PUSH1 0x7f')), K=K)
    case(f'PUSH2/deep{K}', 'stack', U(asm('PUSH2 0x7f7f')), K=K)
    case(f'PUSH20/deep{K}', 'stack', U(asm('PUSH20 0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f')), K=K)
case('PUSH2-POP', 'stack', U(asm('PUSH2 0x7f7f POP')))
case('PUSH3-POP', 'stack', U(asm('PUSH3 0x7f7f7f POP')))
case('PUSH20-POP', 'stack', U(asm('PUSH20 0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f POP')))
case('PUSH32-POP', 'stack', U(bytes([0x7f]) + b'\x7f' * 32 + asm('POP')))
case('PUSH1-POP', 'stack', U(asm('PUSH1 0x7f POP')))
case('PUSH0-POP', 'stack', U(asm('PUSH0 POP')))
case('DUP5-POP', 'stack', U(asm('DUP5 POP')), setup=push(1) * 5)
case('DUP6-POP', 'stack', U(asm('DUP6 POP')), setup=push(1) * 6)
case('GAS-POP', 'env', U(asm('GAS POP')))
case('MSTORE-zero', 'memory', U(asm('DUP2 DUP2 MSTORE')), setup=push(0) + push(0), note='value 0')
case('MSTORE-hi', 'memory', U(asm('DUP2 DUP2 MSTORE')), setup=push((1 << 256) - 1) + push(0x8000))
