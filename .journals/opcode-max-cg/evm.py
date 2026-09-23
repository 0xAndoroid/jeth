"""Tiny EVM assembler + synthetic-block driver for the per-opcode c/g study."""
import json, os, re, subprocess, sys, time
from pathlib import Path

JETH = "/Volumes/Dev/cargo-target/jeth-amber-nolane/release/jeth"
SYNTH = "/Volumes/Dev/cargo-target/jeth-amber-nolane/release/synth"
WORK = Path("/tmp/opcg/cases")
NUMBER, TIMESTAMP = 25694235, 1785999191

OPS = {
 'STOP':0x00,'ADD':0x01,'MUL':0x02,'SUB':0x03,'DIV':0x04,'SDIV':0x05,'MOD':0x06,'SMOD':0x07,'ADDMOD':0x08,'MULMOD':0x09,'EXP':0x0a,'SIGNEXTEND':0x0b,
 'LT':0x10,'GT':0x11,'SLT':0x12,'SGT':0x13,'EQ':0x14,'ISZERO':0x15,'AND':0x16,'OR':0x17,'XOR':0x18,'NOT':0x19,'BYTE':0x1a,'SHL':0x1b,'SHR':0x1c,'SAR':0x1d,'CLZ':0x1e,
 'KECCAK256':0x20,'ADDRESS':0x30,'BALANCE':0x31,'ORIGIN':0x32,'CALLER':0x33,'CALLVALUE':0x34,'CALLDATALOAD':0x35,'CALLDATASIZE':0x36,'CALLDATACOPY':0x37,'CODESIZE':0x38,'CODECOPY':0x39,'GASPRICE':0x3a,'EXTCODESIZE':0x3b,'EXTCODECOPY':0x3c,'RETURNDATASIZE':0x3d,'RETURNDATACOPY':0x3e,'EXTCODEHASH':0x3f,
 'BLOCKHASH':0x40,'COINBASE':0x41,'TIMESTAMP':0x42,'NUMBER':0x43,'PREVRANDAO':0x44,'GASLIMIT':0x45,'CHAINID':0x46,'SELFBALANCE':0x47,'BASEFEE':0x48,'BLOBHASH':0x49,'BLOBBASEFEE':0x4a,
 'POP':0x50,'MLOAD':0x51,'MSTORE':0x52,'MSTORE8':0x53,'SLOAD':0x54,'SSTORE':0x55,'JUMP':0x56,'JUMPI':0x57,'PC':0x58,'MSIZE':0x59,'GAS':0x5a,'JUMPDEST':0x5b,'TLOAD':0x5c,'TSTORE':0x5d,'MCOPY':0x5e,'PUSH0':0x5f,
 'LOG0':0xa0,'LOG1':0xa1,'LOG2':0xa2,'LOG3':0xa3,'LOG4':0xa4,
 'CREATE':0xf0,'CALL':0xf1,'CALLCODE':0xf2,'RETURN':0xf3,'DELEGATECALL':0xf4,'CREATE2':0xf5,'STATICCALL':0xfa,'REVERT':0xfd,'INVALID':0xfe,'SELFDESTRUCT':0xff,
}
for i in range(1,33): OPS[f'PUSH{i}'] = 0x5f + i
for i in range(1,17): OPS[f'DUP{i}'] = 0x7f + i; OPS[f'SWAP{i}'] = 0x8f + i

def push(v):
    """Shortest PUSHn for int v (PUSH0 for 0)."""
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
        return bytes([0x5f + len(b)]) + b
    if v == 0: return bytes([0x5f])
    b = v.to_bytes((v.bit_length() + 7)//8, 'big')
    return bytes([0x5f + len(b)]) + b

def pushn(v, n):
    """PUSHn with fixed width n."""
    return bytes([0x5f + n]) + v.to_bytes(n, 'big')

def asm(*items):
    """items: opcode names (str), ints (auto push), bytes (raw)."""
    out = bytearray()
    for it in items:
        if isinstance(it, str):
            toks = it.split(); i = 0
            while i < len(toks):
                tok = toks[i]; i += 1
                m = re.fullmatch(r'PUSH(\d+)', tok)
                if m and int(m.group(1)) > 0:
                    v = toks[i]; i += 1
                    out += pushn(int(v, 0), int(m.group(1)))
                elif tok in OPS: out.append(OPS[tok])
                elif tok.startswith('0x'): out += push(int(tok, 16))
                else: out += push(int(tok))
        elif isinstance(it, int): out += push(it)
        else: out += bytes(it)
    return bytes(out)

def loop_contract(body: bytes, setup: bytes = b'') -> bytes:
    """n = calldataload(0); setup; while n: body; n -= 1. Body must be stack-neutral;
    stack below n is setup's leftovers (accessible via DUPk with k offset by 1)."""
    # layout: [setup...] PUSH0 CALLDATALOAD  loop: JUMPDEST DUP1 ISZERO PUSH2 end JUMPI body PUSH1 1 SWAP1 SUB PUSH2 loop JUMP end: JUMPDEST STOP
    head = setup + asm('PUSH0 CALLDATALOAD')
    loop_pc = len(head)
    # size of loop block: JUMPDEST(1) DUP1(1) ISZERO(1) PUSH2(3) JUMPI(1) body PUSH1 1(2) SWAP1(1) SUB(1) PUSH2(3) JUMP(1)
    end_pc = loop_pc + 1+1+1+3+1 + len(body) + 2+1+1+3+1
    code = head + asm('JUMPDEST DUP1 ISZERO') + pushn(end_pc, 2) + asm('JUMPI') + body + asm('PUSH1 1 SWAP1 SUB') + pushn(loop_pc, 2) + asm('JUMP JUMPDEST STOP')
    assert len(code) <= 24576, len(code)
    return code

def straight_contract(body: bytes, setup: bytes = b'') -> bytes:
    code = setup + body + asm('STOP')
    assert len(code) <= 24576, len(code)
    return code

def addr(i: int) -> str:
    return '0x' + (0xC0DE << 144 | i).to_bytes(20, 'big').hex()

def hx(b: bytes) -> str: return '0x' + bytes(b).hex()

def run_block(name, contracts, txs, gas_limit=200_000_000, mode='txprofile', ancestors=0, force=False):
    """contracts: list of dict(address, code(bytes), balance, nonce, storage{int:int}); txs: list of dict(to, data(bytes), gas, value).
    Returns dict with per-tx (success, gas, cycles) and block totals."""
    d = WORK / name
    d.mkdir(parents=True, exist_ok=True)
    result_path = d / f'result-{mode}.json'
    if result_path.exists() and not force:
        return json.loads(result_path.read_text())
    spec = {
        'number': NUMBER, 'timestamp': TIMESTAMP, 'gas_limit': gas_limit, 'ancestors': ancestors,
        'contracts': [{'address': c['address'], 'code': hx(c.get('code', b'')), 'balance': hex(c.get('balance', 0)),
                       'nonce': c.get('nonce', 0), 'storage': {hex(k): hex(v) for k, v in c.get('storage', {}).items()}} for c in contracts],
        'txs': [{'to': t.get('to'), 'data': hx(t.get('data', b'')), 'gas': t['gas'], 'value': hex(t.get('value', 0))} for t in txs],
    }
    (d / 'spec.json').write_text(json.dumps(spec))
    t0 = time.time()
    r = subprocess.run([SYNTH, str(d / 'spec.json'), str(d)], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f'synth failed for {name}:\n{r.stdout}\n{r.stderr}')
    r = subprocess.run([JETH, 'repack', '--dir', str(d)], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f'repack failed for {name}:\n{r.stdout}\n{r.stderr}')
    receipts = json.loads((d / 'receipts.json').read_text())
    out = {'name': name, 'receipts': receipts}
    if mode == 'txprofile':
        r = subprocess.run([JETH, 'txprofile', '--input', str(d / 'input.bin'), '--skip-build', '--top', '500'], capture_output=True, text=True)
        (d / 'txprofile.log').write_text(r.stdout + r.stderr)
        if r.returncode != 0:
            raise RuntimeError(f'txprofile failed for {name}:\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}')
        tp = json.loads((d / 'txprofile.json').read_text())
        out['trace_rows_total'] = tp['trace_rows_total']
        out['phases'] = tp['phases']
        byidx = {t['index']: t for t in tp['txs']}
        out['txs'] = [{'success': receipts[i]['success'], 'gas': receipts[i]['gas_used'], 'cycles': byidx[i]['cycles']} for i in range(len(receipts))]
    else:
        r = subprocess.run([JETH, 'trace', '--input', str(d / 'input.bin'), '--skip-build'], capture_output=True, text=True)
        (d / 'trace.log').write_text(r.stdout + r.stderr)
        if r.returncode != 0:
            raise RuntimeError(f'trace failed for {name}:\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}')
        s = json.loads((d / 'trace-summary.json').read_text())
        out['trace_rows_total'] = s['trace_rows_total']
        out['gas_used'] = s.get('gas_used')
    out['wall_s'] = time.time() - t0
    result_path.write_text(json.dumps(out))
    return out
