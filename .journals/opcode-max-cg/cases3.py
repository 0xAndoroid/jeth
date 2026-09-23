import sys; sys.path.insert(0, '/tmp/opcg')
from evm import *
from runner3 import SENDER, ab
CASES = []
def case(name, group, n, build, note=''): CASES.append(dict(name=name, group=group, n=n, build=build, note=note))
p = push
def tgt(i): return addr(100000 + i)
C = addr(1)
def straight(units_code, extra_contracts=(), balance=0, storage=None):
    code = units_code + asm('STOP'); assert len(code) <= 24576
    return [{'address': C, 'code': code, 'balance': balance, 'storage': storage or {}}] + list(extra_contracts), [{'to': C, 'data': b'', 'gas': 16_000_000}]

# a/b: storage cold reads at depth 6
def b_sload_exist(n):
    cs, txs = straight(b''.join(p(i) + asm('SLOAD POP') for i in range(n)), storage={i: 1 for i in range(n)})
    return cs, txs, [{'storage': [[C, list(range(n))]], 'depth': 6}], [], {ab(C): list(range(n))}, {}
case('SLOAD/cold-existing-deep6', 'state', 500, b_sload_exist, 'cold existing slots, storage trie depth 6 (full 16-way branches), witness pruned to paths')
def b_sload_empty(n):
    cs, txs = straight(b''.join(p(i) + asm('SLOAD POP') for i in range(n)))
    return cs, txs, [{'storage': [[C, list(range(n))]], 'depth': 6}], [], {ab(C): list(range(n))}, {}
case('SLOAD/cold-empty-deep6', 'state', 500, b_sload_empty, 'cold nonexistent slots, deep exclusion paths')
def b_sstore_new(n):
    cs, txs = straight(b''.join(asm('PUSH1 1') + p(i) + asm('SSTORE') for i in range(n)))
    return cs, txs, [{'storage': [[C, list(range(n))]], 'depth': 6}], [], {ab(C): list(range(n))}, {}
case('SSTORE/cold-new-deep6', 'state', 250, b_sstore_new, 'zero→nonzero (22100), deep storage trie: reveal + post-root insert')
def b_sstore_mod(n):
    cs, txs = straight(b''.join(asm('PUSH1 2') + p(i) + asm('SSTORE') for i in range(n)), storage={i: 1 for i in range(n)})
    return cs, txs, [{'storage': [[C, list(range(n))]], 'depth': 6}], [], {ab(C): list(range(n))}, {}
case('SSTORE/cold-modify-deep6', 'state', 500, b_sstore_mod, 'nonzero→nonzero (5000), deep: reveal + post-root rehash')
def b_sstore_clear(n):
    cs, txs = straight(b''.join(asm('PUSH0') + p(i) + asm('SSTORE') for i in range(n)), storage={i: 1 for i in range(n)})
    return cs, txs, [{'storage': [[C, list(range(n))]], 'depth': 6}], [], {ab(C): list(range(n))}, {'siblings': True}
case('SSTORE/cold-clear-deep6', 'state', 500, b_sstore_clear, 'nonzero→zero (5000, refund 4800 → net gas after refund cap), deep: leaf delete')
# e/f: account cold reads at depth 7
def b_balance_exist(n):
    cs, txs = straight(b''.join(p(int(tgt(i), 16)) + asm('BALANCE POP') for i in range(n)), extra_contracts=[{'address': tgt(i), 'balance': 1} for i in range(n)])
    return cs, txs, [{'accounts': [tgt(i) for i in range(n)], 'depth': 7}], [ab(tgt(i)) for i in range(n)], {}, {}
case('BALANCE/cold-existing-deep7', 'state', 400, b_balance_exist, 'cold existing EOA, state trie depth 7')
def b_balance_empty(n):
    cs, txs = straight(b''.join(p(int(tgt(i), 16)) + asm('BALANCE POP') for i in range(n)))
    return cs, txs, [{'accounts': [tgt(i) for i in range(n)], 'depth': 7}], [ab(tgt(i)) for i in range(n)], {}, {}
case('BALANCE/cold-empty-deep7', 'state', 400, b_balance_empty, 'cold nonexistent account, deep exclusion')
def b_extcodesize_big(n):
    cs, txs = straight(b''.join(p(int(tgt(i), 16)) + asm('EXTCODESIZE POP') for i in range(n)), extra_contracts=[{'address': tgt(i), 'code': asm('STOP') + i.to_bytes(4, 'big') + b'\x5b' * (24576 - 5)} for i in range(n)])
    return cs, txs, [{'accounts': [tgt(i) for i in range(n)], 'depth': 7}], [ab(tgt(i)) for i in range(n)], {}, {}
case('EXTCODESIZE/cold-big-deep7', 'state', 50, b_extcodesize_big, 'cold contract with distinct 24KB code: path reveal + code keccak')
def b_extcodesize_small(n):
    cs, txs = straight(b''.join(p(int(tgt(i), 16)) + asm('EXTCODESIZE POP') for i in range(n)), extra_contracts=[{'address': tgt(i), 'code': asm('STOP') + i.to_bytes(4, 'big') + b'\x5b' * 59} for i in range(n)])
    return cs, txs, [{'accounts': [tgt(i) for i in range(n)], 'depth': 7}], [ab(tgt(i)) for i in range(n)], {}, {}
case('EXTCODESIZE/cold-small-deep7', 'state', 400, b_extcodesize_small, 'cold contract with 64B code')
def b_call_big(n):
    cs, txs = straight(b''.join(asm('PUSH0 PUSH0 PUSH0 PUSH0 PUSH0') + p(int(tgt(i), 16)) + asm('GAS CALL POP') for i in range(n)), extra_contracts=[{'address': tgt(i), 'code': asm('STOP') + i.to_bytes(4, 'big') + b'\x5b' * (24576 - 5)} for i in range(n)])
    return cs, txs, [{'accounts': [tgt(i) for i in range(n)], 'depth': 7}], [ab(tgt(i)) for i in range(n)], {}, {}
case('CALL/cold-big-deep7', 'state', 50, b_call_big, 'cold CALL into distinct 24KB-code contracts (STOP): reveal + keccak + jump analysis')
def b_call_new(n):
    cs, txs = straight(b''.join(asm('PUSH0 PUSH0 PUSH0 PUSH0 PUSH1 1') + p(int(tgt(i), 16)) + asm('GAS CALL POP') for i in range(n)), balance=10**18)
    return cs, txs, [{'accounts': [tgt(i) for i in range(n)], 'depth': 7}], [ab(tgt(i)) for i in range(n)], {}, {}
case('CALL/cold-new-value-deep7', 'state', 200, b_call_new, '1 wei to new account (36600): exclusion reveal + post-root leaf insert')
# j/k: plain transfers
def b_tx_new(n):
    txs = [{'to': tgt(i), 'data': b'', 'gas': 21000, 'value': 1} for i in range(n)]
    return [], txs, [{'accounts': [tgt(i) for i in range(n)], 'depth': 7}], [ab(tgt(i)) for i in range(n)], {}, {}
case('TX/transfer-new-deep7', 'tx', 200, b_tx_new, '21000-gas ETH transfer to a new account: sig verify + sender/recipient paths + receipt + post-root')
def b_tx_exist(n):
    txs = [{'to': tgt(i), 'data': b'', 'gas': 21000, 'value': 1} for i in range(n)]
    return [{'address': tgt(i), 'balance': 1} for i in range(n)], txs, [{'accounts': [tgt(i) for i in range(n)], 'depth': 7}], [ab(tgt(i)) for i in range(n)], {}, {}
case('TX/transfer-existing-deep7', 'tx', 200, b_tx_exist, '21000-gas transfer to existing EOA')
def b_tx_same(n):
    txs = [{'to': tgt(0), 'data': b'', 'gas': 21000, 'value': 1} for i in range(n)]
    return [{'address': tgt(0), 'balance': 1}], txs, [{'accounts': [tgt(0)], 'depth': 7}], [ab(tgt(0))], {}, {}
case('TX/transfer-same-target', 'tx', 200, b_tx_same, '21000-gas transfers, all to one warm account: pure per-tx overhead (sig, nonce, receipt)')
def b_calldata_zero(n):  # n KB
    cs, txs = straight(asm(''))
    txs = [{'to': C, 'data': b'\x00' * (n * 1024), 'gas': 16_000_000}]
    return cs, txs, [], [], {}, {}
case('TX/calldata-zero', 'tx', 128, b_calldata_zero, 'per KB of zero calldata (EIP-7623 floor 10 gas/byte)')
def b_calldata_ff(n):
    cs, txs = straight(asm(''))
    txs = [{'to': C, 'data': b'\xff' * (n * 1024), 'gas': 16_000_000}]
    return cs, txs, [], [], {}, {}
case('TX/calldata-nonzero', 'tx', 64, b_calldata_ff, 'per KB of 0xff calldata (floor 40 gas/byte)')
def b_log_data(n):
    cs, txs = straight(asm('PUSH0 PUSH2 0x2000 MSTORE') + b''.join(p(8192) + p(0) + asm('LOG0') for i in range(n)))
    return cs, txs, [], [], {}, {}
case('LOG0/8KB-whole', 'log', 100, b_log_data, 'LOG0 with 8KB data: exec + receipt RLP/bloom/receipt-root (whole block)')
def b_blockhash(n):  # n = ancestors (block A: 1 ancestor & 256 BLOCKHASH of parent; B: 256 ancestors, distinct)
    anc = 1 if n == 128 else 256
    code = b''.join(p(NUMBER - 1 - (i if anc == 256 else 0)) + asm('BLOCKHASH POP') for i in range(256))
    cs, txs = straight(code)
    return cs, txs, [], [], {}, {'ancestors': anc}
case('BLOCKHASH/256-ancestors', 'env', 128, b_blockhash, 'Δ = 255 extra ancestor headers revealed (hashed) + distinct lookups; gas Δ 0 → see rows/header')
