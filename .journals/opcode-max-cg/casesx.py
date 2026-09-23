import sys; sys.path.insert(0, '/tmp/opcg')
from evm import *
from cases1 import case, U, CASES as _c
CASES = []
def case(name, group, unit, setup=b'', K=None, loop=False, note='', **kw):
    CASES.append(dict(name=name, group=group, unit=unit, setup=setup, K=K, loop=loop, note=note, contracts=[], calldata=b'', gas=16_000_000, value=0, **kw))
for K in (200, 500, 1000):
    case(f'PUSH0/K{K}', 'stack', U(asm('PUSH0')), K=K)
    case(f'PUSH1/K{K}', 'stack', U(asm('PUSH1 0x7f')), K=K)
for K in (1000, 3000, 6000):
    case(f'PUSH0-POP/K{K}', 'stack', U(asm('PUSH0 POP')), K=K)
case('PUSH0x2-POPx2', 'stack', U(asm('PUSH0 PUSH0 POP POP')), K=3000)
case('PUSH1-POP', 'stack', U(asm('PUSH1 0x7f POP')), K=6000)
case('PUSH0x8-POPx8', 'stack', U(asm('PUSH0 PUSH0 PUSH0 PUSH0 PUSH0 PUSH0 PUSH0 PUSH0 POP POP POP POP POP POP POP POP')), K=1000)
