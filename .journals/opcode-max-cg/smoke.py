import sys; sys.path.insert(0, '/tmp/opcg')
from evm import *
c = {'address': addr(1), 'code': loop_contract(asm('PUSH0 POP'))}
res = run_block('smoke', [c], [{'to': addr(1), 'data': (1000).to_bytes(32,'big'), 'gas': 5_000_000},
                             {'to': addr(1), 'data': (2000).to_bytes(32,'big'), 'gas': 5_000_000}], force=True)
print(json.dumps(res, indent=1))
