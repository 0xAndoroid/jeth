"""Generate the HTML report + CSV from analysis.json (html-report-design skeleton)."""
import json, html, re, shutil, subprocess, csv
from pathlib import Path
SK = Path('/Users/andoroid/.dotfiles/skills/html-report-design')
OUT = Path('/Users/andoroid/.pika/web/reports/jeth-opcode-max-cycles-per-gas-2026-09.html')
CSV = Path('/Users/andoroid/.pika/web/reports/jeth-opcode-max-cycles-per-gas-2026-09.csv')
A = json.load(open('/tmp/opcg/analysis.json'))
rows = [r for r in A['rows'] if r['ok'] and r['name'] not in ('PUSH0', 'PUSH0/deep200', 'PUSH0/deep1000')]
BLOCK_AVG, WORST_REAL_ROWS, WORST_REAL_CG, TEN_BLOCK = 12.29, 1_430_619_793, 23.84, 13.81
INPUT_CAP = 32 * 1024 * 1024
esc = html.escape
def f(x, d=1):
    if x is None: return '—'
    if abs(x) >= 1e9: return f'{x/1e9:.2f}B'
    if abs(x) >= 1e6: return f'{x/1e6:.2f}M'
    if abs(x) >= 1e4: return f'{x/1e3:.1f}k'
    return f'{x:,.{d}f}' if isinstance(x, float) else f'{x:,}'
def fi(x): return f'{int(round(x)):,}'
GROUP_LABEL = {'arith': 'Arithmetic / bitwise / hashing', 'stack': 'Stack & push', 'memory': 'Memory & copies', 'control': 'Control flow', 'env': 'Environment', 'state': 'State access (storage, accounts, code)', 'call': 'Calls', 'create': 'CREATE / CREATE2', 'log': 'Logs', 'precompile': 'Precompiles', 'tx': 'Transaction-level'}
GROUP_ORDER = ['precompile', 'state', 'arith', 'call', 'env', 'memory', 'stack', 'control', 'create', 'log', 'tx']
def bound(r):
    n = r['name']
    if r['tag'] == 'p3' and r.get('witness_bytes_per_unit'):
        units = INPUT_CAP // max(1, int(r['witness_bytes_per_unit'] + (24576 if 'big' in n else 0)))
        return f'input cap: ≈{units:,} units/block ({f(units * r["op_gas"])} gas)'
    if n.startswith(('KECCAK256', 'SHA256', 'RIPEMD160', 'IDENTITY', 'CALLDATACOPY', 'CODECOPY', 'MCOPY', 'RETURNDATACOPY', 'EXTCODECOPY', 'LOG', 'CREATE/init', 'CREATE2/init')):
        return 'per-byte; c/g plateaus with size'
    if n.startswith('BLAKE2F'): return 'per-round; c/g plateaus with rounds (gas = rounds)'
    if n.startswith(('BLS_G1MSM', 'BLS_G2MSM')): return 'discount table: worst at k=1'
    if n.startswith(('BN254PAIRING', 'BLS_PAIRING')): return 'linear in pairs'
    if n.startswith('MODEXP'): return 'EIP-7883 formula; see variants'
    if n.startswith('BLOCKHASH/256'): return 'bounded: 256 ancestors/block'
    if n.startswith('TX/'): return 'bounded by tx count / calldata gas'
    return 'unbounded (repeat in a loop)'
def fix_class(r):
    n = r['name']
    if n.startswith('KECCAK256'): return ('keccak-f inline rework (2,511 → ~500 rows/perm, SP1-class)', 0.22)
    if n.startswith('SHA256'): return ('sha256 compress inline (software today, ~68 rows/byte)', 0.15)
    if n.startswith('RIPEMD160'): return ('software compress; low priority', 0.5)
    if n.startswith('BLAKE2F'): return ('blake2 compress inline (software today, ~253 rows/round)', 0.15)
    if n.startswith('MODEXP'): return ('bigint mul inline (`bigint256_mul` exists) + Montgomery in inline', 0.35)
    if n.startswith('BN254'): return ('bn254 Fq/curve inlines (arkworks software today; cf. ecrecover on secp inline = 3.4 c/g)', 0.05)
    if n.startswith('BLS_'): return ('BLS12-381 Fp/Fp2/curve inlines (arkworks software today)', 0.05)
    if n.startswith('POINTEVAL'): return ('BLS12-381 pairing inline (ark-bls12-381 software today)', 0.08)
    if n.startswith('P256VERIFY'): return ('P-256 inline (p256 crate software today)', 0.05)
    if n.startswith('ECRECOVER'): return ('already on the secp256k1 inline', 1.0)
    if 'cold-big' in n: return ('lazy/advice jump-table analysis (55%) + keccak inline rework (42%)', 0.12)
    if r['tag'] == 'p3': return ('keccak inline rework (≈78% of reveal rows are keccak)', 0.35)
    if n.startswith(('MULMOD', 'ADDMOD', 'DIV', 'MOD', 'SDIV', 'SMOD')): return ('U256 mul/div inlines (ruint software; Jolt DIV is 64-bit)', 0.4)
    if n.startswith('EXP'): return ('bigint256_mul inline for the square-and-multiply chain', 0.5)
    if n.startswith(('PREVRANDAO', 'COINBASE', 'ADDRESS', 'ORIGIN', 'CALLER', 'SELFBALANCE', 'CALLDATALOAD', 'BLOCKHASH')): return ('interpreter: word-wise B256/Address→U256 conversion (R3)', 0.5)
    if n.startswith(('CALL', 'STATICCALL', 'DELEGATECALL', 'CALLCODE')): return ('frame init / memcpy / journal (R3 interpreter fat; 18% memcpy, 19% run_frame)', 0.5)
    if n.startswith('TSTORE'): return ('transient-storage map insert (hashbrown); cheaper map', 0.5)
    if n.startswith(('MLOAD', 'MSTORE', 'PUSH', 'POP', 'DUP', 'SWAP', 'JUMPDEST', 'CLZ', 'LT', 'GT', 'SAR', 'SHL', 'SHR')): return ('interpreter dispatch / stack (R3); limited', 0.7)
    return ('—', 1.0)

top = sorted([r for r in rows if r['unit_cg'] and r['op_gas'] and r['op_gas'] > 0], key=lambda r: -r['unit_cg'])
best_by_family = {}
for r in top:
    fam = r['name'].split('/')[0]
    if fam not in best_by_family: best_by_family[fam] = r
top10 = list(best_by_family.values())[:10]
# adversarial scenarios (unit c/g = executable tight loop incl. glue)
def scen(name, cg, note, cap_units=None, cap_gas_each=None):
    if cap_units:
        gas_capped = cap_units * cap_gas_each
        rest = 60_000_000 - gas_capped
        best_pc = max(r['unit_cg'] for r in rows if r['group'] == 'precompile')
        total = gas_capped * cg + rest * best_pc
        return dict(name=name, cg=cg, rows=total, note=f'{note}; {cap_units:,} units = {f(gas_capped)} gas at the 32 MiB input cap, remaining gas at the best precompile ({best_pc:.0f} c/g)')
    return dict(name=name, cg=cg, rows=60_000_000 * cg, note=note)
R = {r['name']: r for r in rows}
S = []
for r in top10[:6]:
    S.append(scen(r['name'], r['unit_cg'], r['note'] or ''))
if 'EXTCODESIZE/cold-big-deep7' in R:
    r = R['EXTCODESIZE/cold-big-deep7']; per = r['witness_bytes_per_unit'] + 24576
    S.append(scen('EXTCODESIZE/cold-big-deep7', r['unit_cg'], 'distinct 24 KB contracts, cold', cap_units=int(INPUT_CAP // per), cap_gas_each=r['unit_gas']))
for nm in ('KECCAK256/8KB', 'PREVRANDAO', 'MULMOD', 'SLOAD/cold-existing-deep6', 'TX/transfer-new-deep7'):
    if nm in R: S.append(scen(nm, R[nm]['unit_cg'], 'pure-opcode loop' if R[nm]['group'] != 'state' and R[nm]['group'] != 'tx' else R[nm]['note']))
S.append(dict(name='worst real block 25694235 (Aztec BLS/bn254 txs)', cg=WORST_REAL_CG, rows=WORST_REAL_ROWS, note='top-50 gas blocks Jul–Sep 2026'))
S.append(dict(name='gas-weighted average real block', cg=BLOCK_AVG, rows=60_000_000 * BLOCK_AVG, note='top-50 set, 12.29 c/g'))

# ---- HTML pieces ----
def table(rs, cols, cls='tbl', sortable=False):
    th = ''.join(f'<th{" class=\"r\"" if c[2] else ""}{" data-sort=\"num\"" if sortable and c[2] else (" data-sort=\"str\"" if sortable else "")}>{esc(c[0])}</th>' for c in cols)
    body = ''
    for r in rs:
        tds = ''
        for c in cols:
            v = c[1](r)
            tds += f'<td class="{"r num" if c[2] else ("k" if c is cols[0] else "sub")}">{v}</td>'
        body += f'<tr>{tds}</tr>'
    return f'<table class="{cls}"><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>'

def chart_for_group(g):
    rs = sorted([r for r in rows if r['group'] == g and r['op_cg'] is not None and r['unit_cg'] is not None and r['op_gas'] > 0], key=lambda r: -r['op_cg'])
    if not rs: return ''
    x = [r['name'] for r in rs]
    spec = {"type": "bar", "interactive": True, "title": f"{GROUP_LABEL[g]} — cycles per gas", "format": "num", "unit": "c/g",
            "xLabel": "opcode / configuration", "yLabel": "rows per gas",
            "x": x, "series": [{"name": "opcode alone (glue subtracted)", "data": [round(r['op_cg'], 1) for r in rs]},
                                {"name": "tight loop as measured (incl. glue)", "color": "muted", "data": [round(r['unit_cg'], 1) for r in rs]}],
            "annotations": [{"y": BLOCK_AVG, "label": "real-block average 12.3"}, {"y": 3 * BLOCK_AVG, "label": "3× average"}]}
    cap = {
        'precompile': 'Every elliptic-curve precompile runs in software (arkworks / p256) and lands 150–540 c/g (P256VERIFY 539, BLS G2MSM k=1 439); ecrecover, on the secp256k1 inline, is 3.4.',
        'state': 'Cold access to a 24 KB contract is the single worst item (465 c/g: eager jump-table analysis + code keccak). Deep-trie cold reads sit at 20–28 c/g.',
        'arith': 'KECCAK256 plateaus near 100 c/g; 256-bit MULMOD/DIV/MOD are 3–6× the block average because 8-gas ops cost 400–1,100 rows of ruint software.',
        'call': 'A warm CALL costs ≈5,700 rows for 100 gas: frame setup, memcpy and journaling — 47 c/g regardless of callee.',
        'env': 'PREVRANDAO (2 gas) costs 337 rows: the B256→U256 push. ADDRESS/CALLER/COINBASE/ORIGIN are the same shape at ~55 c/g.',
        'memory': 'Word-wise MLOAD/MSTORE are ~130–150 rows per 3-gas op; bulk copies get cheaper per gas as size grows.',
        'stack': 'PUSH/DUP/SWAP/POP sit at 9–14 c/g; PUSH20 (address immediates) is the odd one at ~36.',
        'control': 'JUMP/JUMPI are below average; JUMPDEST is 25 rows for 1 gas.',
        'create': 'Account creation is cheap per gas; CREATE2 with 48 KB initcode is 34 c/g because of the initcode keccak.',
        'log': 'LOG gas is far above jeth cost (<1 c/g) — logs are the most over-priced opcode family.',
        'tx': 'A plain 21,000-gas transfer is ~217k rows (10.3 c/g) with deep-trie paths; per-KB calldata is 4.3 c/g for zero bytes.',
    }.get(g, '')
    return f'<figure class="chart-fig card reveal" data-chart=\'{json.dumps(spec)}\'><figcaption>{esc(cap)}</figcaption></figure>'

full_cols = [
    ('opcode / configuration', lambda r: f'<code>{esc(r["name"])}</code>', False),
    ('group', lambda r: esc(r['group']), False),
    ('gas (op)', lambda r: f(r['op_gas'], 0), True),
    ('rows (op)', lambda r: fi(r['op_rows']), True),
    ('c/g op', lambda r: f'<b>{r["op_cg"]:.1f}</b>' if r['op_cg'] is not None else '—', True),
    ('c/g loop', lambda r: f'{r["unit_cg"]:.1f}' if r['unit_cg'] else '—', True),
    ('units', lambda r: fi(r['units']), True),
    ('method', lambda r: esc('per-tx ' + r['method'] if r['tag'] != 'p3' else r['method']), False),
    ('bound', lambda r: esc(bound(r)), False),
    ('operand / note', lambda r: esc(r['note'] or ''), False),
]
mismatch = sorted([r for r in rows if r['op_cg'] and r['op_cg'] > 3 * BLOCK_AVG and r['op_gas'] > 0 and not r['name'].startswith('PUSH0/deep')], key=lambda r: -r['op_cg'])
mm_cols = [
    ('opcode / configuration', lambda r: f'<code>{esc(r["name"])}</code>', False),
    ('c/g op', lambda r: f'<b>{r["op_cg"]:.0f}</b>', True),
    ('× avg', lambda r: f'{r["op_cg"] / BLOCK_AVG:.1f}×', True),
    ('rows / op', lambda r: fi(r['op_rows']), True),
    ('fix class', lambda r: esc(fix_class(r)[0]), False),
    ('est. c/g after', lambda r: f'≈{r["op_cg"] * fix_class(r)[1]:.0f}', True),
]
adv_cols = [
    ('block filled with', lambda s: f'<code>{esc(s["name"])}</code>', False),
    ('c/g', lambda s: f'{s["cg"]:.1f}', True),
    ('rows in a 60M-gas block', lambda s: f'<b>{s["rows"]/1e9:.2f}B</b>', True),
    ('× worst real', lambda s: f'{s["rows"]/WORST_REAL_ROWS:.1f}×', True),
    ('note', lambda s: esc(s['note']), False),
]
anch = A['anchors']
n_meas = len(rows); n_ok = sum(1 for r in A['rows'] if not r['ok'])
worst = top10[0]
content = f'''
<header class="report-head"><div class="wrap rh">
  <div class="rh__main">
    <span class="kicker">jeth · PR #1 tree (amber-nolane @ 278c754, jolt-amber-nolane @ a0d7b74baa)</span>
    <h1>Maximum cycles-per-gas by EVM opcode and precompile</h1>
    <p class="rh__sub">Osaka opcode set + precompiles 0x01–0x11 and 0x100, each in its worst measured operand configuration. <b>{n_meas} configurations</b>, exact Jolt trace rows, synthetic blocks.</p>
  </div>
  <div class="rh__meta"><span class="badge badge--orange">adversarial</span><span class="rh__date num">Sep 9, 2026</span></div>
</div></header>
<main>
<section id="verdict"><div class="wrap block">
  <h2>Verdict</h2>
  <p class="prose">Real blocks run at {BLOCK_AVG} c/g (gas-weighted, top-50 by gas) and the worst real block at {WORST_REAL_CG}. Software elliptic-curve precompiles are 12–44× that: a block that does nothing but <code>{esc(worst["name"])}</code> calls costs <b>{worst["unit_cg"]:.0f} rows per gas</b>, i.e. <b>{60e6*worst["unit_cg"]/1e9:.1f}B rows for 60M gas</b> — {60e6*worst["unit_cg"]/WORST_REAL_ROWS:.0f}× the worst block seen on mainnet. Among plain opcodes the ceiling is ~100 c/g (KECCAK256 over large memory, PREVRANDAO+POP loops); cold state access in a mainnet-depth trie is 20–28 c/g, and cold access to a large contract is 465 c/g but bounded by the 32 MiB input cap.</p>
  <div class="verdict card verdict--orange reveal"><span class="vlabel">Verdict</span>
    <blockquote>The gas schedule protects jeth against ordinary execution (stack, arithmetic, memory, logs, storage writes all land within 3× of the block average), but not against the software precompiles: bn254, BLS12-381, KZG point evaluation, P-256, BLAKE2F and SHA-256 all sit between 110 and 540 c/g (P-256 verify worst at 539), so an adversarial 60M-gas block is 13–32B rows, an order of magnitude past anything real. Curve-field inlines are the fix; nothing on the interpreter side changes the picture.</blockquote>
    <div class="vwho">Basis: {n_meas} measured configurations, exact row counts on the Jolt RV64IMAC tracer · Sep 9, 2026</div></div>
  <h3>Top 10 worst families (one configuration each)</h3>
  <div class="tblwrap card reveal"><div class="table-scroll">{table(top10, [
    ('opcode / precompile', lambda r: f'<code>{esc(r["name"])}</code>', False),
    ('c/g loop', lambda r: f'<b>{r["unit_cg"]:.0f}</b>', True),
    ('c/g op', lambda r: f'{r["op_cg"]:.0f}', True),
    ('gas', lambda r: f(r['op_gas'], 0), True),
    ('rows', lambda r: fi(r['op_rows']), True),
    ('60M block', lambda r: f'{60e6*r["unit_cg"]/1e9:.1f}B', True),
    ('configuration', lambda r: esc(r['note'] or ''), False)])}</div></div>
  <h3>Adversarial 60M-gas blocks</h3>
  <div class="tblwrap card reveal"><div class="table-scroll">{table(S, adv_cols)}</div></div>
  <p class="prose">"c/g loop" is the tightest executable loop I measured (the opcode plus its unavoidable DUP/PUSH/POP glue); "c/g op" subtracts the glue and is an upper bound for what a cleverer loop could approach. Both use exact row counts, not samples.</p>
</div></section>

<section id="method"><div class="wrap block">
  <h2>Method</h2>
  <ul class="prose">
    <li><b>Harness.</b> jeth has no synthetic or EEST path (inputs are geth <code>debug_executionWitness</code> + block RLP), and EEST fixtures carry no MPT witnesses. An uncommitted host binary (<code>crates/host/src/bin/synth.rs</code>) builds a full pre-state trie (sender, loop contracts, the four system contracts with mainnet code), a parent header, legacy txs signed with a fixed key, and fixes gas_used / receipts root / bloom / requests hash / state root from the validation errors until the block passes. Then <code>jeth repack</code> → <code>input.bin</code>.</li>
    <li><b>Per-tx method (opcodes, calls, precompiles).</b> <code>jeth txprofile</code> per-tx cycle markers. Each case is two txs in the same block with the same code length: K units followed by STOP, and K/2 units followed by STOP then K/2 unreachable units. Δrows/Δgas over K/2 units. Deterministic emulator → no sampling noise; residual nonlinearity is ≤5 rows on the cheapest ops (PUSH/POP anchors agree within that). Unit glue is subtracted using measured anchors: POP {anch["POP"]:.0f}, PUSH0 {anch["PUSH0"]:.0f}, PUSH1 {anch["PUSH1"]:.0f}, PUSH2 {anch["PUSH2"]:.0f}, PUSH20 {anch["PUSH20"]:.0f}, PUSH32 {anch["PUSH32"]:.0f}, DUPn {anch["DUP"]:.0f}, GAS {anch["GAS"]:.0f} rows.</li>
    <li><b>Whole-block method (state, tx-level).</b> Two blocks with n and 2n units; Δ of total trace rows, so witness reveal and post-state-root work are included. Tries are made mainnet-deep with filler leaves (15 siblings per level: 7 full branch levels for accounts, 6 for storage) and the witness is pruned to the touched paths, as geth would ship it. Filler branch nodes are full 16-way (532 B) — pessimistic for the bottom levels of mainnet tries.</li>
    <li><b>Worst-case operands.</b> 256-bit operands for arithmetic, dividend 256 / divisor 255-bit for DIV/MOD, exponent with 255 bits set for EXP/MODEXP, KECCAK256 up to 8 KB with memory pre-expanded (per-byte cost plateaus), cold/warm variants for state, distinct salts/targets where repetition would warm them, precompile inputs validated in-block (a verifier tx reverts unless the call succeeds and, where defined, returns the expected value).</li>
    <li><b>Gas.</b> Exact per-tx gas from receipts (Osaka rules: EIP-7883 modexp, EIP-7825 16.7M tx cap, EIP-7623 calldata floor).</li>
  </ul>
</div></section>

<section id="charts"><div class="wrap block">
  <h2>Cycles per gas by group</h2>
  <p class="prose">Dashed lines: the real-block average ({BLOCK_AVG}) and 3× it. Hover for exact values; the legend toggles the two series.</p>
  {''.join(chart_for_group(g) for g in GROUP_ORDER)}
</div></section>

<section id="mismatch"><div class="wrap block">
  <h2>Gas-schedule mismatch (&gt;3× the block average)</h2>
  <p class="prose">{len(mismatch)} configurations charge less than a third of what jeth needs per gas relative to an average block. "est. c/g after" applies a per-class factor (curve inlines ≈ 20×, keccak-f rework ≈ 5×, sha/blake inlines ≈ 6×, bigint inlines ≈ 3×, interpreter work ≈ 2×) — estimates, not measurements. Profiles (<code>jeth profile --rows</code>) back the attributions: cold 24 KB code = 54% <code>analyze_legacy</code> + 42% keccak; deep SLOAD = 78% keccak; warm CALL = 19% <code>Evm::run_frame</code> + 18% memcpy + 7% <code>load_acc_and_calc_gas</code> + 9% journal.</p>
  <div class="tblwrap card reveal"><div class="table-scroll">{table(mismatch, mm_cols)}</div></div>
</div></section>

<section id="full"><div class="wrap block">
  <h2>All measured configurations</h2>
  <p class="prose">Click a column header to sort. "c/g op" = glue subtracted; "c/g loop" = as executed. Rows tagged whole-block include witness reveal and post-root work.</p>
  <div class="tblwrap card reveal"><div class="table-scroll">{table(sorted(rows, key=lambda r: -(r["op_cg"] or 0)), full_cols, cls='tbl sortable')}</div></div>
</div></section>

<section id="caveats"><div class="wrap block">
  <h2>Not measured, and caveats</h2>
  <ul class="prose">
    <li>BLOBHASH (needs a type-3 tx; 3-gas index op, expected ≈ CALLVALUE), EIP-7702 authorization lists and access-list prewarming (same reveal work as cold access at 1,900–2,400 gas), RETURN/REVERT/STOP/INVALID only via CALL differences, PUSH4–19/21–31 (interpolated), DUP/SWAP beyond the sampled depths, straight-line PUSH0 runs into a deep stack (nonlinear ≈25k-row fixed cost, excluded; PUSH0 is taken from the PUSH0+POP pair), memory expansion in the quadratic regime (cheap per gas by construction), SELFDESTRUCT with a funded account, CREATE landing in a deep trie (use CALL/cold-new-value-deep7 as the proxy: 3.6 c/g).</li>
    <li>Whole-block deletions (SSTORE clear) over-include siblings at every level, so that row is an upper bound. Deep-trie fillers are full 16-way branches; mainnet bottom levels are sparser, so cold-access numbers are ~10–20% pessimistic.</li>
    <li>Per-tx numbers exclude witness reveal, receipt/tx-root hashing and signature verification; those are captured by the whole-block rows (a bare 21,000-gas transfer is 102k rows warm, 217k with deep cold paths).</li>
    <li>MODEXP was sampled at 11 points of the EIP-7883 formula; the worst is <code>1024-e1-1024</code> (183 c/g) because aurora-modexp pays the full Montgomery setup for one multiplication. Larger exponents amortize it (33–58 c/g).</li>
    <li>The 32 MiB input cap bounds every witness-heavy attack: ~1,230 cold 24 KB contracts, ~21k cold storage slots or ~15k cold accounts per block; beyond that the block cannot be represented at all — a liveness question separate from c/g.</li>
    <li>Scratch: <code>/tmp/opcg</code> (cases, results JSON, harness driver), journal <code>.journals/opcode-max-cg-2026-09.md</code> in the worktree. Nothing committed.</li>
  </ul>
</div></section>
</main>
<footer><div class="wrap fwrap">
  <div class="ftop"><span class="ft-title">jeth opcode maximum cycles-per-gas</span></div>
  <div class="srcs"><a href="https://me.andrew.ee/reports/jeth-opcode-max-cycles-per-gas-2026-09.csv">CSV</a><a href="https://me.andrew.ee/reports/jeth-top50-blocks-2026-09.html">top-50 blocks report</a></div>
  <p class="fmeta">Generated Sep 9, 2026 · Pika</p>
</div></footer>
<script>
document.querySelectorAll('table.sortable th').forEach((th, i) => {{
  th.style.cursor = 'pointer';
  th.addEventListener('click', () => {{
    const tb = th.closest('table').tBodies[0]; const rows = [...tb.rows];
    const num = th.dataset.sort === 'num'; const asc = th.dataset.asc === '1'; th.dataset.asc = asc ? '0' : '1';
    const val = r => {{ const t = r.cells[i].textContent.trim().replace(/,/g, ''); if (!num) return t; const m = t.match(/^-?[\\d.]+/); let v = m ? parseFloat(m[0]) : -Infinity; if (/B$/.test(t)) v *= 1e9; else if (/M$/.test(t)) v *= 1e6; else if (/k$/.test(t)) v *= 1e3; return v; }};
    rows.sort((a, b) => {{ const x = val(a), y = val(b); return (num ? x - y : String(x).localeCompare(String(y))) * (asc ? 1 : -1); }});
    rows.forEach(r => tb.appendChild(r));
  }});
}});
</script>
'''
sk = (SK / 'skeleton.html').read_text()
out = sk.replace('<!-- TITLE -->', 'jeth — maximum cycles-per-gas by opcode and precompile').replace('<!-- TAGS -->', 'jolt, jeth, benchmark').replace('<!-- CONTENT -->', content)
OUT.write_text(out)
with open(CSV, 'w', newline='') as fh:
    w = csv.writer(fh)
    w.writerow(['name', 'group', 'method', 'ok', 'units', 'op_gas', 'op_rows', 'op_cg', 'unit_gas', 'unit_rows', 'unit_cg', 'glue_rows', 'glue_gas', 'witness_bytes_per_unit', 'bound', 'note'])
    for r in A['rows']:
        w.writerow([r['name'], r['group'], r['method'], r['ok'], r['units'], r['op_gas'], round(r['op_rows'], 1), None if r['op_cg'] is None else round(r['op_cg'], 3), r['unit_gas'], round(r['unit_rows'], 1), None if r['unit_cg'] is None else round(r['unit_cg'], 3), round(r['glue_rows'], 1), r['glue_gas'], r.get('witness_bytes_per_unit'), bound(r), r['note']])
print('wrote', OUT, CSV, 'rows', len(rows), 'mismatch', len(mismatch))
