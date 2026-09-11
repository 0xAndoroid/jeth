"""Run a case list (per-tx method): each case → 2 txs (A, control); pack cases into blocks; compute per-unit Δrows/Δgas."""
import sys, json, math; sys.path.insert(0, '/tmp/opcg')
from evm import *

PRE_EXPAND = asm('PUSH0 PUSH3 0x100100 MSTORE')  # 1 MiB + 256 B of memory, warm for every unit
KMAX_DEFAULT = 6000
GAS_CAP = {  # per-unit gas guesses for expensive units → cap K so tx stays < 16M gas
}

def build_case(c, idx):
    """Return (contracts, txs, meta)."""
    unit0 = c['unit'](0)
    setup = PRE_EXPAND + c['setup']
    cont_addr = addr(idx)
    if c['loop']:
        R = c.get('R') or max(1, min(c.get('Rmax', 4000), (24000 - len(setup) - 40) // len(unit0)))
        body = b''.join(c['unit'](i) for i in range(R))
        code = loop_contract(body, setup)
        n = c.get('n', 4)
        txs = [{'to': cont_addr, 'data': n.to_bytes(32, 'big') + c['calldata'], 'gas': c['gas'], 'value': c['value']},
               {'to': cont_addr, 'data': (2 * n).to_bytes(32, 'big') + c['calldata'], 'gas': c['gas'], 'value': c['value']}]
        contracts = [{'address': cont_addr, 'code': code}] + c['contracts']
        return contracts, txs, {'units': n * R, 'R': R, 'n': n, 'code_len': len(code)}
    K = c['K'] or max(1, min(KMAX_DEFAULT, (24000 - len(setup) - 1) // len(unit0)))
    if c.get('gas_est'):
        K = max(1, min(K, 12_500_000 // int(c["gas_est"] * 1.05)))
    K2 = K // 2
    def body_with_stop(kstop, off=0):
        body = bytearray()
        for i in range(K):
            if i == kstop:
                body += asm('STOP')
            u = bytearray(c['unit'](i + off))
            pos = len(setup) + len(body)
            for j in range(len(u) - 3):
                if u[j] == 0x61 and u[j+1] == 0 and u[j+2] == 0 and u[j+3] in (0x56, 0x57) and u[-1] == 0x5b:
                    tgt = pos + len(u) - 1
                    u[j+1], u[j+2] = tgt >> 8, tgt & 0xff
            body += u
        if kstop >= K:
            body += asm('STOP')
        return bytes(body)
    code_a = setup + body_with_stop(K)      # runs K units
    code_b = setup + body_with_stop(K2, 100000 if c.get('disjoint') else 0)     # runs K2 units, same code length (+0/1 byte)
    ctrl_addr = addr(idx + 5000)
    contracts = [{'address': cont_addr, 'code': code_a, 'balance': c.get('balance', 0), 'storage': c.get('self_storage', {})}, {'address': ctrl_addr, 'code': code_b, 'balance': c.get('balance', 0), 'storage': c.get('self_storage', {})}] + c['contracts']
    txs = [{'to': cont_addr, 'data': c['calldata'], 'gas': c['gas'], 'value': c['value']},
           {'to': ctrl_addr, 'data': c['calldata'], 'gas': c['gas'], 'value': c['value']}]
    return contracts, txs, {'units': K - K2, 'K': K, 'K2': K2, 'code_len': len(code_a)}

def run_cases(cases, tag, per_block=12, force=False):
    results = {}
    for b in range(0, len(cases), per_block):
        chunk = cases[b:b + per_block]
        contracts, txs, metas = [], [], []
        for j, c in enumerate(chunk):
            cs, ts, m = build_case(c, 1 + b + j)
            # dedupe contracts by address
            for x in cs:
                if all(x['address'] != y['address'] for y in contracts):
                    contracts.append(x)
            txs += ts; metas.append(m)
        nver = 0
        for j, c in enumerate(chunk):
            if c.get('verify'):
                va = addr(9000 + b + j)
                contracts.append({'address': va, 'code': c['verify'], 'balance': c.get('balance', 0)})
                txs.append({'to': va, 'data': c['calldata'], 'gas': c['gas'], 'value': c['value']}); nver += 1
        name = f'{tag}-{b // per_block:02d}'
        try:
            res = run_block(name, contracts, txs, gas_limit=2_000_000_000, force=force)
            if 'metas' in res:
                metas = res['metas']
            else:
                res['metas'] = metas
                (WORK / name / 'result-txprofile.json').write_text(json.dumps(res))
        except Exception as e:
            print(f'BLOCK {name} FAILED: {e}', flush=True)
            continue
        for j, c in enumerate(chunk):
            ta, tb = res['txs'][2 * j], res['txs'][2 * j + 1]
            m = metas[j]
            ok = ta['success'] and tb['success']
            if c.get('verify'):
                vi = 2 * len(chunk) + sum(1 for cc in chunk[:j] if cc.get('verify'))
                ok = ok and res['txs'][vi]['success']
                if not res['txs'][vi]['success']: print(f"  VERIFY FAILED for {c['name']}", flush=True)
            if c['loop']:
                drows, dgas = tb['cycles'] - ta['cycles'], tb['gas'] - ta['gas']
            else:
                drows, dgas = ta['cycles'] - tb['cycles'], ta['gas'] - tb['gas']
            units = m['units']
            r = dict(name=c['name'], group=c['group'], note=c['note'], ok=ok, units=units, drows=drows, dgas=dgas,
                     rows_per_unit=drows / units, gas_per_unit=dgas / units, cg_unit=(drows / dgas if dgas else None),
                     method=('loop Δ(2n−n)' if c['loop'] else 'straight-line Δ(K − K/2 units, equal code length)'), block=name, **{k: v for k, v in m.items() if k != "units"})
            results[c['name']] = r
            print(f"{c['name']:28s} ok={ok!s:5s} units={units:6d} gas/u={r['gas_per_unit']:10.2f} rows/u={r['rows_per_unit']:12.1f} c/g={r['cg_unit'] if r['cg_unit'] is None else round(r['cg_unit'],2)}", flush=True)
    return results

if __name__ == '__main__':
    mod = sys.argv[1]; tag = sys.argv[2]
    m = __import__(mod)
    res = run_cases(m.CASES, tag, per_block=int(sys.argv[3]) if len(sys.argv) > 3 else 12)
    out = Path(f'/tmp/opcg/results-{tag}.json')
    prev = json.loads(out.read_text()) if out.exists() else {}
    prev.update(res)
    out.write_text(json.dumps(prev, indent=1))
