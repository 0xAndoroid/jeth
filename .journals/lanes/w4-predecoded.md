---
tags: [jeth, benchmark]
---
# Wave 4: predecoded dispatch gate

**KILL candidate #3 on the residual budget gate.** Best budget-fitting prefix:
270 execution-weighted entries, 23.94 MB side table, 93.41% execution coverage;
**10.87M modeled net rows saved on 781**, below the 12M requirement.

Exact dynamic counts plus explicit replacement-cost model, **not an implemented
speedup**. No instruction stream, constant pool, gas batching, stack-check
changes, or #6 riders retained. Both gate decisions are documentation only.

## Residual PUSH + gas gate (781)

| Execution-weighted prefix | Side table MB | Executed-op coverage | PUSH net M | Gas net M | Combined M |
|---|---:|---:|---:|---:|---:|
| Top 100 | 11.35 | 79.75% | 7.130 | 2.409 | 9.540 |
| Top 200 | 20.06 | 90.69% | 7.819 | 2.740 | 10.558 |
| Top 270 | 23.94 | 93.41% | 8.048 | 2.819 | 10.867 |
| All 383 active library entries | 28.21 | 94.59% | 8.169 | 2.851 | 11.020 |

Rows/coverage measured on unchanged guest code. Ranking uses gate-block execution
counts, deliberately favoring the candidate; no training-window selection or
artifact was built. Even all active library entries, with no size cap, fall below
12M in this model. Misses: 96,969 executed ops (5.41%); unchanged witness path.

### Truly removable PUSH work

PUSH0–32 cost 17,624,748 rows; PUSH0's 389,101 rows have no immediate to predecode.
PUSH1–32: **17,235,647 rows / 421,577 calls**. Exact per-function PC attribution
matches per-call assembly. Minimum retained work per successful call:

```text
stack check                    3 rows
stack destination / length     5 rows
PC load / advance / store      3 rows
four limb stores               4 rows
return                         1 row
retained before operand loads 16 rows
aligned operand loads          ceil(N / 8) rows
```

Thus ideal removable work before lookup is **9,999,379 rows**, not 17.6M.
Of that, 9,596,927 lies in library-covered execution. Examples:

| PUSH | Calls | Current rows/call | Replacement before lookup | Removable rows |
|---|---:|---:|---:|---:|
| 1 | 181,232 | 20 | 17 | 543,696 |
| 2 | 178,257 | 26 | 17 | 1,604,313 |
| 4 | 26,418 | 50 | 17 | 871,794 |
| 20 | 12,944 | 195 | 19 | 2,278,144 |
| 32 | 12,371 | 316 | 20 | 3,661,816 |

Model: four extra lookup rows (load precomputed address bias, fallback branch,
shift raw PC, add bias); limb loads already counted. Keep raw PUSH1 because its
three-row saving cannot pay four lookup rows. PUSH0 remains unchanged. No lookup
cost is charged to either excluded opcode: favorable to the candidate.

### Gas model and sensitivity

Keep raw opcode fetch and the existing handler table. One u64 side-table slot
per padded raw-code byte: block-start slots hold packed gas/end metadata; PUSH
immediate slots hold aligned limbs. Table size = `8 * sum(raw_len + 33)`;
8-alignment follows directly. No sparse-index lookup or code-PC translation.

```text
N = executed opcodes; B = basic-block entries
C = GAS / CALL-family / CREATE-family / SSTORE executions
J = JUMP + JUMPI executions
PUSH net = sum(push_calls[n] * max(0, push_rows[n] - 16 - ceil(n/8) - 4))
gas net  = (5 - 2) * N - 12 * B - 6 * C - J
```

Two recurring rows: reload block-end pointer after mutable handler call, compare
current PC. Twelve entry rows: address + aligned metadata load (3), extract gas
and end offset (3), debit/check gas (4), set next block-end pointer (2). Six-row
correction allowance: add/subtract future prepaid gas around sensitive handlers;
correction-table access omitted. One jump-state store charged per JUMP/JUMPI.
Block boundaries: entry, JUMPDEST, and instruction after terminator; PUSH payloads
excluded. Call suspension/resumption does not create another block in this model.

All covered code: `N=1,696,140`, `B=169,066`, `C=7,929`, `J=161,395`.
Gas gross 8,480,700 → recurring checks 3,392,280 → block-entry work 2,028,792 →
corrections 47,574 → jump state 161,395 = **2,850,659 net**.

Sensitivity favorable to candidate: reduce entry cost to eight rows, remove all
correction/jump costs, ignore artifact cap and initialization. All covered code
then reaches **11,905,075** combined rows; top 270 reaches **11,739,016**. These
are model bounds under stated costs, not a universal impossibility proof. No
artifact/ELF setup measurement exists: no side table was built.

## SELF baseline and diagnostic parity

Base `85ce0d0`. Native validation 3/3; exact profile totals match the baseline.

| Block | SELF rows | Keccak permutations | Gas |
|---|---:|---:|---:|
| 25905781 | 938,512,897 | 121,206 | 44,227,079 |
| 25905786 | 461,937,742 | 61,356 | 26,354,048 |
| 25905788 | 148,643,438 | 19,861 | 6,217,605 |

All hashes/gas agree with wave 3. Permutations are proven-pass totals; compute
advice counters are excluded. No guest code or hashing changes.

## Exact dispatch cost

Host-only per-PC trace-row attribution; guest unchanged.

| Block | EVM instructions | Hot-loop rows | Handler-symbol rows | Ideal LD-fetch saving ceiling |
|---|---:|---:|---:|---:|
| 25905781 | 1,793,109 | 41,241,507 | 42,526,451 | 5,379,327 |
| 25905786 | 971,527 | 22,345,121 | 22,967,420 | 2,914,581 |
| 25905788 | 248,739 | 5,720,988 | 5,824,296 | 746,217 |

The loop accounts for 97.0% of `MainnetHandler::execution` on 781: the earlier
42.5M symbol estimate did not overstate dispatch. Normal cost is **23 rows/op**:

| Component | Rows/op | 781 rows |
|---|---:|---:|
| Bytecode pointer + opcode fetch + PC advance/store | 7 | 12,551,763 |
| Instruction-table address | 2 | 3,586,218 |
| Static gas load, subtract, store, check | 5 | 8,965,545 |
| Handler pointer, arguments, indirect call | 4 | 7,172,436 |
| Continue flag + branch | 5 | 8,965,545 |

788 has one static-gas failure, skipping nine normal-tail rows:
`23 * 248,739 - 9 = 5,720,988`. Indirect calls remain with predecoding.

Jolt source: `crates/jolt-program/src/expand/memory/shared.rs` at `628713fd4`.
`LBU = 4`, `LHU/LWU = 5`, `LD = 1` expanded rows. Narrow aligned loads still
need lane extraction and an alignment assertion. The LD ceiling is an analytic
bound, **not an implemented speedup**. The residual gate above separates
retained PUSH work and gas-bookkeeping costs.
Upstream-relevant: alignment assertions make halfword/word token fetch more
expensive than byte fetch on this pin.

## Artifact and ELF sizes

| Quantity | Bytes / count |
|---|---:|
| Existing index + code + jump tables | 30,682,033 bytes |
| Original code, all 3,000 entries | 27,073,904 bytes |
| Executable legacy entries / delegation entries | 2,922 / 78 |
| Legacy instructions / PUSH instructions | 15,508,293 / 4,086,044 |
| 2-byte opcodes + declared immediates, no alignment | 42,588,894 bytes |
| 2-byte opcodes + 8-aligned, limb-rounded immediates | 81,939,968 bytes |
| Baseline ELF / same code with profile symbols | 32,635,632 / 33,981,760 bytes |
| Candidate artifact / executable ELF growth | 0 / 0 bytes |

The initial 8.3 MB assumption described a smaller development library. Parent
ruling at 18:06 ET allowed an execution-weighted subset with +24 MB stream cap,
other entries retaining analyzed-library fallback. No subset or side table was
built; no setup-time delta exists. The precise census above excludes delegation
payloads; the preliminary all-entry scan counted 952 extra pseudo-instructions.

## Gates and reproduction

- Release workspace nextest with `jeth-host/secp-inline`: **14/14**, zero skipped,
  including existing raw-code hash and revm-analysis parity for every entry.
- Existing production library rebuilt twice using source blocks 25905701–25905780:
  `index.bin`, `codes.bin`, `jt.bin`, `manifest.json` byte-identical each time.
- Native / SELF traces / exact profiles: **3/3** each; no regression. No trusted runs.
- No new stream parity test: no stream exists. Future derived metadata must be
  re-derived per entry; consensus checks only catch observable divergence.
- Source probes removed; documentation-only branch. Inputs, witnesses, block RLP
  are read-only symlinks; metadata and summaries local.

Logs, PC JSONs, census, assembly, rebuilds, and temporary source patches:
`/tmp/jeth-w4-predecoded/`. Summaries: `data/<block>/predecoded-base-self.json`.

To repeat the diagnostic, apply `dispatch-probe.patch` to `85ce0d0` in an isolated
checkout. Use `CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-w4-predecoded` and
`JOLT_PATH=/Volumes/Dev/cargo-target/jolt-cli-main/release/jolt`:

```sh
cargo build -q --message-format=short --release -p jeth-host --features secp-inline
export JETH_PC_ROWS=/tmp/jeth-w4-predecoded/781-base-pcs.json
"$CARGO_TARGET_DIR/release/jeth" profile --input data/25905781/input.bin --rows --top 100
```

Repeat for 786/788. Build/profile calls acquire `/tmp/jeth-w3-cargo.lock`; write
branch + shell PID into `owner`, remove one's own marker and `rmdir` on release.
Each PC JSON value is `[rows, executions]`. `base-execution.s` identifies the
unchanged ELF loop at `0x800f891a..=0x800f894c`, opcode fetch `0x800f891e`.

Residual probe: `residual-probe.patch`; `781-push-pcs.json` includes all PUSH
handler PCs; `.evm.json` counts executed raw-code addresses at opcode fetch.
ELF CODES base `0x8050ac90` plus index offsets maps addresses to code hashes.
All matched active entries are legacy; aggregate opcode count equals 1,793,109.
`push-symbols.json`, `push-*.s`, `analyze-push.py`, `push-analysis.json`, and
`residual-budget.json` reproduce the residual cost tables. PUSH0 is excluded
from immediate savings. The residual diagnostic again totals 938,512,897 rows
and 121,206 proven-pass permutations. Probes removed after capture.
