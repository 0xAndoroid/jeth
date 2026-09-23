#!/usr/bin/env python3
"""Aggregate `jeth profile --rows --split-markers --json` matrices into
phase x category tables and compare a merged multi-block run against the
gas-weighted sum of its constituent single-block runs.

Usage:
  uv run python scripts/aggregate_markers.py agg PROFILE.json [--trace-log TRACE.log] [--out OUT.json]
  uv run python scripts/aggregate_markers.py compare MERGED.agg.json CONST.agg.json... [--out OUT.json]

`agg` buckets every (marker, symbol) row count into a phase (witness_reveal /
execution = per-tx markers / post_root / outside = deserialize + sig_verify +
glue) and a coarse category (keccak, mpt, memcpy, interpreter,
revm_handler_state, bytecode_analysis, sig_verify, precompiles, allocator,
deserialize, u256_ruint = EVM 256-bit arithmetic, other). Symbols are classified with the families of
`aggregate_profile.py`. With `--trace-log`, the proven-pass keccak census
(`keccak[<phase>]: calls= bytes= perms=` checkpoints) and the jolt marker
totals (deserialize / sig_verify / validation) are attached.
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aggregate_profile import classify, root_path  # noqa: E402

CATEGORIES = [
    "keccak",
    "mpt",
    "memcpy",
    "interpreter",
    "revm_handler_state",
    "bytecode_analysis",
    "sig_verify",
    "precompiles",
    "allocator",
    "deserialize",
    "u256_ruint",
    "other",
]

CATEGORY_OF_FAMILY = {
    "keccak256 inline": "keccak",
    "zeth-mpt trie": "mpt",
    "memcpy/memset/memcmp": "memcpy",
    "tx sig-verify (secp inline)": "sig_verify",
    "ecrecover precompile (secp inline)": "precompiles",
    "k256 software (EIP-7702 authority)": "precompiles",
    "bn254+kzg precompiles (arkworks)": "precompiles",
    "modexp precompile (aurora)": "precompiles",
    "sha256/ripemd precompiles": "precompiles",
    "blake2 precompile": "precompiles",
    "precompile dispatch/glue": "precompiles",
    "revm handler loop": "revm_handler_state",
    "revm frames/calls": "revm_handler_state",
    "revm host/journal/state": "revm_handler_state",
    "bytecode analysis (analyze_legacy)": "bytecode_analysis",
    "allocator (O(1))": "allocator",
    "input deserialize (postcard)": "deserialize",
    "post-state hashing glue": "mpt",
    "U256 arithmetic (ruint)": "u256_ruint",
}

# Defining-crate paths the family rules do not know about.
ROOT_OVERRIDES = [
    (re.compile(r"^jeth_core::(container|from_container|code_library)"), "deserialize"),
    (re.compile(r"^jeth_core::(recover|recovery_batch)|^jolt_inlines_secp256k1"), "sig_verify"),
    (re.compile(r"^jeth_core::(crypto|bn254)"), "precompiles"),
    (re.compile(r"^jeth_core::(walk|resolver|instrument|keccak_memo)|^nybbles::"), "mpt"),
    (re.compile(r"^jolt_platform::bump_alloc"), "allocator"),
]

PHASES = ["reveal", "execution", "post_root", "outside"]
TX_LABEL = re.compile(r"^tx\d+$")


def category(symbol: str) -> tuple[str, str]:
    root = root_path(symbol)
    for rx, cat in ROOT_OVERRIDES:
        if rx.search(root):
            return cat, root[:60]
    fam, sub = classify(symbol)
    if fam.startswith("interpreter:"):
        return "interpreter", fam.split(":", 1)[1].strip()
    cat = CATEGORY_OF_FAMILY.get(fam)
    if cat is None:
        return "other", fam
    return cat, sub if cat in ("mpt", "memcpy", "precompiles") else fam


def phase_of(label: str) -> str:
    if label == "witness_reveal":
        return "reveal"
    if label == "post_root":
        return "post_root"
    if TX_LABEL.match(label):
        return "execution"
    return "outside"


def parse_trace_log(path: str) -> dict:
    """Proven-pass keccak census + jolt marker totals from a `jeth trace` log."""
    text = open(path).read()
    census = re.findall(
        r"keccak\[(\w+)\]: calls=(\d+) bytes=(\d+) perms=(\d+)", text
    )
    # Two passes (compute_advice, then proven); the proven pass is the last
    # seven checkpoints: pre_sig, post_sig, reveal start/end, post_root
    # start/end, post_validation.
    proven = census[-7:] if len(census) >= 7 else census
    labels = [c[0] for c in proven]
    expected = [
        "pre_sig",
        "post_sig",
        "witness_reveal",
        "witness_reveal",
        "post_root",
        "post_root",
        "post_validation",
    ]
    out: dict = {"checkpoints": [
        {"label": l, "calls": int(a), "bytes": int(b), "perms": int(p)}
        for l, a, b, p in proven
    ]}
    if labels == expected:
        v = [(int(a), int(b), int(p)) for _, a, b, p in proven]

        def seg(i, j, k):
            return v[j][k] - v[i][k]

        for k, name in enumerate(("calls", "bytes", "perms")):
            out[name] = {
                "sigs": seg(0, 1, k),
                "pre_reveal_glue": seg(1, 2, k),
                "reveal": seg(2, 3, k),
                "execution": seg(3, 4, k),
                "post_root": seg(4, 5, k),
                "tail_glue": seg(5, 6, k),
                "total": v[6][k],
            }
    markers = re.findall(r'"(\w+)": \d+ RV64IMAC cycles \+ \d+ virtual instructions = (\d+) total cycles', text)
    jolt: dict = {}
    for name, total in markers:  # last occurrence = proven pass
        jolt[name] = int(total)
    out["jolt_markers"] = jolt
    m = re.search(r"trace rows \(total cycles\): (\d+)", text)
    if m:
        out["trace_rows_total"] = int(m.group(1))
    return out


def aggregate(profile_path: str, trace_log: str | None) -> dict:
    prof = json.load(open(profile_path))
    total = prof["total_rows"]
    phases = defaultdict(int)
    cats = {c: {"total": 0, "by_phase": defaultdict(int)} for c in CATEGORIES}
    subs = defaultdict(lambda: defaultdict(int))
    unattributed = defaultdict(int)
    outside_labels = defaultdict(int)
    tx_markers = 0
    for marker in prof["markers"]:
        label, rows = marker["label"], marker["rows"]
        ph = phase_of(label)
        phases[ph] += rows
        if ph == "execution":
            tx_markers += 1
        if ph == "outside":
            outside_labels[label] += rows
        listed = 0
        for entry in marker["symbols"]:
            cat, sub = category(entry["symbol"])
            n = entry["rows"]
            cats[cat]["total"] += n
            cats[cat]["by_phase"][ph] += n
            subs[cat][sub] += n
            listed += n
        unattributed[ph] += rows - listed
    unattributed_total = sum(unattributed.values())
    return {
        "input": prof["input"],
        "profile_json": profile_path,
        "total_rows": total,
        "tx_markers": tx_markers,
        "phases": {p: phases[p] for p in PHASES},
        "outside_labels": dict(outside_labels),
        "categories": {
            c: {"total": v["total"], "by_phase": {p: v["by_phase"][p] for p in PHASES}}
            for c, v in cats.items()
        },
        "subcategories": {
            c: dict(sorted(s.items(), key=lambda kv: -kv[1])[:12]) for c, s in subs.items()
        },
        "unattributed_below_cutoff": {**{p: unattributed[p] for p in PHASES}, "total": unattributed_total},
        "census": parse_trace_log(trace_log) if trace_log else None,
    }


def fmt(n: float) -> str:
    return f"{n:,.0f}"


def pct(n: float, d: float) -> str:
    return f"{100 * n / d:.2f}%" if d else "-"


def print_agg(a: dict) -> None:
    total = a["total_rows"]
    print(f"input: {a['input']}\ntotal rows: {fmt(total)} | tx markers: {a['tx_markers']}\n")
    print("| phase | rows | share |\n|---|---:|---:|")
    for p in PHASES:
        print(f"| {p} | {fmt(a['phases'][p])} | {pct(a['phases'][p], total)} |")
    print(f"| unattributed (<256-row symbols) | {fmt(a['unattributed_below_cutoff']['total'])} | {pct(a['unattributed_below_cutoff']['total'], total)} |")
    print("\n| category | rows | share | reveal | execution | post_root | outside |\n|---|---:|---:|---:|---:|---:|---:|")
    for c in CATEGORIES:
        v = a["categories"][c]
        bp = v["by_phase"]
        print(f"| {c} | {fmt(v['total'])} | {pct(v['total'], total)} | {fmt(bp['reveal'])} | {fmt(bp['execution'])} | {fmt(bp['post_root'])} | {fmt(bp['outside'])} |")
    if a.get("census") and a["census"].get("perms"):
        print("\nkeccak perms (proven pass):", json.dumps(a["census"]["perms"]))
    if a.get("census") and a["census"].get("jolt_markers"):
        print("jolt markers:", json.dumps(a["census"]["jolt_markers"]))


def compare(merged: dict, singles: list[dict]) -> dict:
    def sum_key(getter):
        return sum(getter(s) for s in singles)

    total_single = sum_key(lambda s: s["total_rows"])
    total_merged = merged["total_rows"]
    out = {
        "merged_input": merged["input"],
        "singles": [s["input"] for s in singles],
        "total_rows": {"singles_sum": total_single, "merged": total_merged, "delta": total_merged - total_single},
        "phases": {},
        "categories": {},
        "keccak_by_phase": {},
        "census_perms": {},
    }
    for p in PHASES:
        s = sum_key(lambda x: x["phases"][p])
        m = merged["phases"][p]
        out["phases"][p] = {"singles_sum": s, "merged": m, "delta": m - s}
    for c in CATEGORIES:
        s = sum_key(lambda x: x["categories"][c]["total"])
        m = merged["categories"][c]["total"]
        out["categories"][c] = {
            "singles_sum": s,
            "merged": m,
            "delta": m - s,
            "by_phase": {
                p: {
                    "singles_sum": sum_key(lambda x: x["categories"][c]["by_phase"][p]),
                    "merged": merged["categories"][c]["by_phase"][p],
                }
                for p in PHASES
            },
        }
    for p in PHASES:
        s = sum_key(lambda x: x["categories"]["keccak"]["by_phase"][p])
        m = merged["categories"]["keccak"]["by_phase"][p]
        out["keccak_by_phase"][p] = {"singles_sum": s, "merged": m, "delta": m - s}
    if merged.get("census") and merged["census"].get("perms") and all(
        s.get("census") and s["census"].get("perms") for s in singles
    ):
        for seg in ("sigs", "pre_reveal_glue", "reveal", "execution", "post_root", "tail_glue", "total"):
            s = sum_key(lambda x: x["census"]["perms"][seg])
            m = merged["census"]["perms"][seg]
            out["census_perms"][seg] = {"singles_sum": s, "merged": m, "delta": m - s}
    return out


def print_compare(c: dict) -> None:
    ts, tm = c["total_rows"]["singles_sum"], c["total_rows"]["merged"]
    print(f"merged: {c['merged_input']}\nsingles: {len(c['singles'])} runs, Σ rows {fmt(ts)} → merged {fmt(tm)} (Δ {fmt(tm - ts)}, {pct(tm - ts, ts)})\n")
    print("| category | Σ singles rows | share | merged rows | share | Δ rows | Δ % |\n|---|---:|---:|---:|---:|---:|---:|")
    for cat in CATEGORIES:
        v = c["categories"][cat]
        print(f"| {cat} | {fmt(v['singles_sum'])} | {pct(v['singles_sum'], ts)} | {fmt(v['merged'])} | {pct(v['merged'], tm)} | {fmt(v['delta'])} | {pct(v['delta'], v['singles_sum'])} |")
    print(f"| **total** | {fmt(ts)} | 100% | {fmt(tm)} | 100% | {fmt(tm - ts)} | {pct(tm - ts, ts)} |")
    print("\n| phase | Σ singles | merged | Δ rows | Δ % |\n|---|---:|---:|---:|---:|")
    for p in PHASES:
        v = c["phases"][p]
        print(f"| {p} | {fmt(v['singles_sum'])} | {fmt(v['merged'])} | {fmt(v['delta'])} | {pct(v['delta'], v['singles_sum'])} |")
    print("\n| keccak rows by phase | Σ singles | merged | Δ rows | Δ % |\n|---|---:|---:|---:|---:|")
    for p in PHASES:
        v = c["keccak_by_phase"][p]
        print(f"| {p} | {fmt(v['singles_sum'])} | {fmt(v['merged'])} | {fmt(v['delta'])} | {pct(v['delta'], v['singles_sum'])} |")
    if c["census_perms"]:
        print("\n| keccak perms (census) | Σ singles | merged | Δ | Δ % |\n|---|---:|---:|---:|---:|")
        for seg, v in c["census_perms"].items():
            print(f"| {seg} | {fmt(v['singles_sum'])} | {fmt(v['merged'])} | {fmt(v['delta'])} | {pct(v['delta'], v['singles_sum'])} |")


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("agg")
    a.add_argument("profile")
    a.add_argument("--trace-log")
    a.add_argument("--out")
    c = sub.add_parser("compare")
    c.add_argument("merged")
    c.add_argument("singles", nargs="+")
    c.add_argument("--out")
    args = ap.parse_args()
    if args.cmd == "agg":
        res = aggregate(args.profile, args.trace_log)
        print_agg(res)
    else:
        res = compare(json.load(open(args.merged)), [json.load(open(s)) for s in args.singles])
        print_compare(res)
    if args.out:
        json.dump(res, open(args.out, "w"), indent=1)
        print(f"\n→ {args.out}")


if __name__ == "__main__":
    main()
