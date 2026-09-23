#!/usr/bin/env python3
"""Assemble the multi-block (jeth merge) measurement ledger: per-run trace
summaries, native tx counts, merge fidelity, a linear rows-vs-gas fit and the
200M/400M/600M-gas extrapolation (padding + prove-time at assumed throughput).

Usage:
  uv run python scripts/merged_summary.py --results DIR --native DIR \
      --merged-dir /Volumes/Dev/jeth-inputs/merged --baseline-json PATH \
      [--banked banked-hashes.txt] [--profiles DIR] --out summary.json [--md out.md]

`--results` holds `<name>.trace-summary.json` captured from `jeth trace` (names:
`widened-<first block>`, `<block>`, `N<n>`); `--native` holds `native-<name>.log`
from `jeth run-native`; `--profiles` may hold `<name>.agg.json` from
`aggregate_markers.py agg` plus `compare-*.json` from `aggregate_markers.py compare`.
"""

import argparse
import glob
import json
import math
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aggregate_markers import parse_trace_log  # noqa: E402

FIRST_BLOCK = 25905781
BLOCKS = list(range(FIRST_BLOCK, FIRST_BLOCK + 19))
TEN_BLOCK_SET = BLOCKS[:10]
MERGED_NS = list(range(2, 20))
TRACE_CEILINGS = {"2^24 (max_trace_length default)": 2**24, "2^29": 2**29, "2^30": 2**30}
THROUGHPUTS = {"10M cycles/s": 10e6, "20M cycles/s": 20e6}
SLOT_SECONDS = 12.0


def load_json(path):
    with open(path) as f:
        return json.load(f)


def native_info(path):
    if not os.path.exists(path):
        return {}
    text = open(path).read()
    out = {}
    m = re.search(r"block (\d+): (\d+) txs, (\d+) gas \(header\)", text)
    if m:
        out.update(block=int(m.group(1)), txs=int(m.group(2)), header_gas=int(m.group(3)))
    m = re.search(r"block_hash: (0x[0-9a-f]+)", text)
    if m:
        out["block_hash"] = m.group(1)
    m = re.search(r"validation passed in ([0-9.]+)(m?s)", text)
    if m:
        secs = float(m.group(1)) / (1000 if m.group(2) == "ms" else 1)
        out["native_seconds"] = secs
    return out


def run_record(name, results, native, banked):
    summ = load_json(os.path.join(results, f"{name}.trace-summary.json"))
    nat = native_info(os.path.join(native, f"native-{name.replace('widened-', '')}.log"))
    rec = {
        "name": name,
        "trace_rows_total": summ["trace_rows_total"],
        "gas_used": summ["gas_used"],
        "cycles_per_gas": summ["trace_rows_total"] / summ["gas_used"],
        "block_hash": summ["block_hash"],
        "guest_panicked": summ["guest_panicked"],
        "wall_seconds": summ["wall_seconds"],
        "txs": nat.get("txs"),
        "native_block_hash": nat.get("block_hash"),
        "native_hash_matches": (nat.get("block_hash") == summ["block_hash"]) if nat.get("block_hash") else None,
    }
    if banked and name.replace("widened-", "") in banked:
        b = banked[name.replace("widened-", "")]
        rec["banked_block_hash"] = b["hash"]
        rec["banked_hash_matches"] = b["hash"] == summ["block_hash"]
        rec["banked_rows_2026_09_09"] = b["rows"]
        rec["rows_delta_vs_banked"] = summ["trace_rows_total"] - b["rows"]
    return rec


def least_squares(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    a = sxy / sxx
    b = my - a * mx
    ss_res = sum((y - (a * x + b)) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - my) ** 2 for y in ys)
    return {"a_rows_per_gas": a, "b_rows": b, "r2": 1 - ss_res / ss_tot, "n": n}


def next_pow2(n):
    return 1 << (int(n) - 1).bit_length()


def extrapolate(gas, fit, merged):
    rows_fit = fit["a_rows_per_gas"] * gas + fit["b_rows"]
    nearest = min(merged, key=lambda r: abs(r["gas_used"] - gas))
    pad = next_pow2(rows_fit)
    out = {
        "gas": gas,
        "rows_fit": rows_fit,
        "cycles_per_gas_fit": rows_fit / gas,
        "nearest_measured": {
            "name": nearest["name"],
            "gas_used": nearest["gas_used"],
            "trace_rows_total": nearest["trace_rows_total"],
            "cycles_per_gas": nearest["cycles_per_gas"],
        },
        "padded_rows": pad,
        "padded_log2": int(math.log2(pad)),
        "padding_waste_pct": 100 * (pad - rows_fit) / pad,
        "chunks": {k: math.ceil(rows_fit / v) for k, v in TRACE_CEILINGS.items()},
        "prove_seconds_padded": {k: pad / v for k, v in THROUGHPUTS.items()},
        "prove_seconds_unpadded": {k: rows_fit / v for k, v in THROUGHPUTS.items()},
        "slot_fraction_padded": {k: pad / v / SLOT_SECONDS for k, v in THROUGHPUTS.items()},
    }
    return out


def gas_weighted(records):
    rows = sum(r["trace_rows_total"] for r in records)
    gas = sum(r["gas_used"] for r in records)
    return {"rows": rows, "gas": gas, "cycles_per_gas": rows / gas, "n": len(records)}


def fidelity(merged_dir, n):
    meta = load_json(os.path.join(merged_dir, f"{FIRST_BLOCK}-N{n}", "merge-meta.json"))
    tot = {}
    for entry in meta["fidelity"].values():
        for k, v in entry.items():
            if isinstance(v, int):
                tot[k] = tot.get(k, 0) + v
    src_gas = sum(s["gas_used"] for s in meta["sources"])
    return {
        "n": n,
        "tx_count": meta["tx_count"],
        "gas_used_total": meta["gas_used_total"],
        "gas_limit": meta["gas_limit"],
        "source_gas_sum": src_gas,
        "gas_retained_pct": 100 * meta["gas_used_total"] / src_gas,
        "source_txs": tot.get("txs"),
        "dropped": tot.get("dropped"),
        "status_changed": tot.get("status_changed"),
        "gas_changed_status_unchanged": tot.get("gas_changed"),
        "unchanged": tot.get("unchanged"),
        "input_bin_bytes": meta["input_bin_bytes"],
        "block_rlp_bytes": meta["block_rlp_bytes"],
        "witness": meta["witness"],
        "passes": meta["passes"],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--native", required=True)
    ap.add_argument("--merged-dir", required=True)
    ap.add_argument("--baseline-json", required=True, help="unchanged-tree trace summary of the first block")
    ap.add_argument("--banked")
    ap.add_argument("--trace-logs", help="dir with trace-<name>.log (keccak census + jolt phase markers)")
    ap.add_argument("--profiles")
    ap.add_argument("--out", required=True)
    ap.add_argument("--md")
    args = ap.parse_args()

    banked = {}
    if args.banked:
        for line in open(args.banked):
            b, h, rows = line.split()
            banked[b] = {"hash": h, "rows": int(rows)}

    def attach_census(rec, name):
        if not args.trace_logs:
            return
        path = os.path.join(args.trace_logs, f"trace-{name}.log")
        if os.path.exists(path):
            c = parse_trace_log(path)
            rec["keccak_census"] = {k: c.get(k) for k in ("perms", "calls", "bytes")}
            rec["jolt_markers"] = c.get("jolt_markers")

    singles = []
    for b in BLOCKS:
        name = f"widened-{b}" if b == FIRST_BLOCK else str(b)
        rec = run_record(name, args.results, args.native, banked)
        rec["block"] = b
        attach_census(rec, name)
        singles.append(rec)
    merged = []
    for n in MERGED_NS:
        rec = run_record(f"N{n}", args.results, args.native, None)
        rec["n"] = n
        rec["fidelity"] = fidelity(args.merged_dir, n)
        attach_census(rec, f"N{n}")
        const = singles[:n]
        rec["constituents"] = gas_weighted(const)
        if rec.get("keccak_census") and all(c.get("keccak_census") for c in const):
            segs = ("sigs", "pre_reveal_glue", "reveal", "execution", "post_root", "tail_glue", "total")
            rec["keccak_perms_vs_constituents"] = {
                seg: {
                    "singles_sum": sum(c["keccak_census"]["perms"][seg] for c in const),
                    "merged": rec["keccak_census"]["perms"][seg],
                }
                for seg in segs
            }
            for v in rec["keccak_perms_vs_constituents"].values():
                v["delta"] = v["merged"] - v["singles_sum"]
        if rec.get("jolt_markers") and all(c.get("jolt_markers") for c in const):
            rec["phase_rows_vs_constituents"] = {}
            for ph in ("deserialize", "sig_verify", "witness_reveal", "post_root", "validation"):
                ssum = sum(c["jolt_markers"].get(ph, 0) for c in const)
                m = rec["jolt_markers"].get(ph, 0)
                rec["phase_rows_vs_constituents"][ph] = {"singles_sum": ssum, "merged": m, "delta": m - ssum}
            # execution + glue = validation - reveal - post_root
            def exec_glue(j):
                return j.get("validation", 0) - j.get("witness_reveal", 0) - j.get("post_root", 0)
            ssum = sum(exec_glue(c["jolt_markers"]) for c in const)
            m = exec_glue(rec["jolt_markers"])
            rec["phase_rows_vs_constituents"]["execution_plus_glue"] = {"singles_sum": ssum, "merged": m, "delta": m - ssum}
        rec["constituent_rows_gas_normalized"] = rec["constituents"]["cycles_per_gas"] * rec["gas_used"]
        rec["delta_rows_vs_constituent_sum"] = rec["trace_rows_total"] - rec["constituents"]["rows"]
        rec["delta_cg_vs_constituents_pct"] = 100 * (rec["cycles_per_gas"] / rec["constituents"]["cycles_per_gas"] - 1)
        merged.append(rec)

    baseline = load_json(args.baseline_json)
    widened = singles[0]
    fit = least_squares([r["gas_used"] for r in merged], [r["trace_rows_total"] for r in merged])
    fit_singles = least_squares([r["gas_used"] for r in singles], [r["trace_rows_total"] for r in singles])
    gw10 = gas_weighted(singles[:10])
    gw19 = gas_weighted(singles)

    profiles = {}
    if args.profiles:
        for path in sorted(glob.glob(os.path.join(args.profiles, "*.agg.json"))):
            profiles[os.path.basename(path)[: -len(".agg.json")]] = load_json(path)
        for path in sorted(glob.glob(os.path.join(args.profiles, "compare-*.json"))):
            profiles[os.path.basename(path)[: -len(".json")]] = load_json(path)

    summary = {
        "generated": "jeth measurement lane — multi-block synthetic inputs (2026-09-18)",
        "toolchain": {
            "jolt_cli": "/Volumes/Dev/cargo-target/jolt-cli-amber-nolane/release/jolt (jolt-amber-nolane @ a0d7b74baa)",
            "variant": "validate_block (self-verifying, committed input, no trusted digests)",
            "guest_input_region": "128 MiB (was 32 MiB)",
        },
        "step0": {
            "unchanged_tree_rows": baseline["trace_rows_total"],
            "unchanged_tree_cycles_per_gas": baseline["cycles_per_gas"],
            "widened_tree_rows": widened["trace_rows_total"],
            "rows_delta_widened_minus_unchanged": widened["trace_rows_total"] - baseline["trace_rows_total"],
            "block_hash": baseline["block_hash"],
        },
        "singles": singles,
        "merged": merged,
        "gas_weighted_single": {"ten_block_set": gw10, "nineteen_block_set": gw19},
        "fit_merged_rows_vs_gas": fit,
        "fit_singles_rows_vs_gas": fit_singles,
        "extrapolation": {str(g): extrapolate(g, fit, merged) for g in (200_000_000, 400_000_000, 600_000_000)},
        "assumptions": {
            "prove_throughput_source": "a16z Lattice/Jolt post 2026-09-09: >10M cycles/s on a MacBook GPU; 20M cycles/s = 2x headroom case",
            "padding": "trace length padded to the next power of two (single proof); chunk counts = ceil(rows / ceiling)",
            "slot_seconds": SLOT_SECONDS,
        },
        "profiles": profiles,
    }
    with open(args.out, "w") as f:
        json.dump(summary, f, indent=1)
    if args.md:
        with open(args.md, "w") as f:
            f.write(render_md(summary))
    print(f"→ {args.out}")


def fmt(n):
    return f"{n:,.0f}"


def render_md(s):
    L = []
    st = s["step0"]
    L.append(f"STEP 0: unchanged {fmt(st['unchanged_tree_rows'])} rows ({st['unchanged_tree_cycles_per_gas']:.4f} c/g) → widened {fmt(st['widened_tree_rows'])} (Δ {st['rows_delta_widened_minus_unchanged']:+,})\n")
    L.append("| block | gas | txs | rows | c/g | hash = banked | Δ rows vs 2026-09-09 |\n|---|---:|---:|---:|---:|---|---:|")
    for r in s["singles"]:
        L.append(f"| {r['block']} | {fmt(r['gas_used'])} | {r['txs']} | {fmt(r['trace_rows_total'])} | {r['cycles_per_gas']:.4f} | {r.get('banked_hash_matches', 'native ok' if r['native_hash_matches'] else '?')} | {r.get('rows_delta_vs_banked', '')} |")
    g10, g19 = s["gas_weighted_single"]["ten_block_set"], s["gas_weighted_single"]["nineteen_block_set"]
    L.append(f"| gas-weighted 10 | {fmt(g10['gas'])} | | {fmt(g10['rows'])} | {g10['cycles_per_gas']:.4f} | | |")
    L.append(f"| gas-weighted 19 | {fmt(g19['gas'])} | | {fmt(g19['rows'])} | {g19['cycles_per_gas']:.4f} | | |\n")
    L.append("| N | txs | gas | rows | c/g | Σ constituents rows | Σ c/g | Δ rows | Δ c/g % | wall s |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in s["merged"]:
        c = r["constituents"]
        L.append(f"| {r['n']} | {r['txs']} | {fmt(r['gas_used'])} | {fmt(r['trace_rows_total'])} | {r['cycles_per_gas']:.4f} | {fmt(c['rows'])} | {c['cycles_per_gas']:.4f} | {r['delta_rows_vs_constituent_sum']:+,} | {r['delta_cg_vs_constituents_pct']:+.2f}% | {r['wall_seconds']:.0f} |")
    f = s["fit_merged_rows_vs_gas"]
    L.append(f"\nfit (merged N=2..19): rows = {f['a_rows_per_gas']:.4f} · gas + {fmt(f['b_rows'])}  (R² = {f['r2']:.5f})")
    fs = s["fit_singles_rows_vs_gas"]
    L.append(f"fit (19 singles): rows = {fs['a_rows_per_gas']:.4f} · gas + {fmt(fs['b_rows'])}  (R² = {fs['r2']:.5f})\n")
    L.append("| gas | rows (fit) | c/g (fit) | nearest N (rows, c/g) | pad | waste | chunks 2^24 / 2^29 / 2^30 | prove @10M/s | prove @20M/s | slot frac @10M/s |\n|---|---:|---:|---|---|---:|---|---:|---:|---:|")
    for g, e in s["extrapolation"].items():
        nm = e["nearest_measured"]
        ch = e["chunks"]
        L.append(f"| {fmt(int(g))} | {fmt(e['rows_fit'])} | {e['cycles_per_gas_fit']:.2f} | {nm['name']} ({fmt(nm['trace_rows_total'])}, {nm['cycles_per_gas']:.2f}) | 2^{e['padded_log2']} = {fmt(e['padded_rows'])} | {e['padding_waste_pct']:.1f}% | {list(ch.values())[0]} / {list(ch.values())[1]} / {list(ch.values())[2]} | {e['prove_seconds_padded']['10M cycles/s']:.0f} s | {e['prove_seconds_padded']['20M cycles/s']:.0f} s | {e['slot_fraction_padded']['10M cycles/s']:.1f}× |")
    for r in s["merged"]:
        if r["n"] not in (6, 13, 19) or not r.get("keccak_perms_vs_constituents"):
            continue
        L.append(f"\nN={r['n']} keccak permutations (proven-pass census) and phase rows (jolt markers), Σ constituents vs merged:\n")
        L.append("| segment | Σ singles perms | merged perms | Δ | Δ % |\n|---|---:|---:|---:|---:|")
        for seg, v in r["keccak_perms_vs_constituents"].items():
            L.append(f"| {seg} | {fmt(v['singles_sum'])} | {fmt(v['merged'])} | {v['delta']:+,} | {100*v['delta']/v['singles_sum']:+.1f}% |")
        L.append("\n| phase | Σ singles rows | merged rows | Δ | Δ % |\n|---|---:|---:|---:|---:|")
        for ph, v in r["phase_rows_vs_constituents"].items():
            L.append(f"| {ph} | {fmt(v['singles_sum'])} | {fmt(v['merged'])} | {v['delta']:+,} | {100*v['delta']/v['singles_sum']:+.1f}% |")
    L.append("\n| N | source txs | kept | dropped | status_changed | gas_changed (status same) | gas retained | input MB | state nodes (dedup) | codes (dedup) |\n|---|---:|---:|---:|---:|---:|---:|---:|---|---|")
    for r in s["merged"]:
        fd = r["fidelity"]
        w = fd["witness"]
        L.append(f"| {fd['n']} | {fd['source_txs']} | {fd['tx_count']} | {fd['dropped']} | {fd['status_changed']} | {fd['gas_changed_status_unchanged']} | {fd['gas_retained_pct']:.2f}% | {fd['input_bin_bytes']/1e6:.1f} | {w['state_nodes_before_dedup']:,} → {w['state_nodes']:,} | {w['codes_before_dedup']} → {w['codes']} |")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
