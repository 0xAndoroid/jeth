#!/usr/bin/env python3
"""Warm-state cycle attribution: bucket a `jeth profile --rows --split-markers --json`
matrix into six categories (journal `.journals/jeth-warm-state-measure.md`).

  (a) witness verification   keccak in reveal, first-touch node authentication,
                             MPT decode / validate_at / resolve / byte-walk
  (b) warm-path state lookups revm journal + State/CacheState hashbrown, per-tx
                             commit, block finalize, SparseState::account/storage
                             fixed cost, address/slot hash memos, code lookup
  (c) EVM interpreter        dispatch, frames, stack/memory/arith ops, gas, U256,
                             bytecode analysis
  (d) precompiles + sigs     secp inline (tx sigs, ecrecover), bn254, 7702
  (e) post-state root        everything inside the `post_root` marker + hashed
                             post state
  (f) other                  deserialize, consensus glue, alloc, instrumentation,
                             unattributed memcpy/memmove

Shared symbols (`native_keccak256`, `memcpy`, `memcmp`) are split per marker
group by the return-address caller profile (`jeth profile --rows --callers-of
SYM`), each caller weighted by its own row distribution over marker groups.

Symbols are matched on their *defining item* (impl type root + trait + method),
never on generic parameters: every revm symbol carries
`State<WitnessDatabase<InstrumentedTrie>>` in its generics.

Usage:
  uv run python scripts/warm_state_buckets.py buckets SPLIT.json \
      [--callers native_keccak256=LOG] [--callers memcpy=LOG] [--callers memcmp=LOG] \
      [--storage-calls N] [--trace-rows N] [--top 8] [--json-out OUT]
  uv run python scripts/warm_state_buckets.py pertx SPLIT.json TXPROFILE.json \
      [--profile-log LOG] [--callers ...] [--top 12] [--repeat-to] [--csv OUT]
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict

HASH_RE = re.compile(r"\[[0-9a-f]{16}\]")
GROUPS = ("reveal", "tx", "post_root", "outside")
BUCKET_NAMES = {
    "a": "(a) witness verification",
    "b": "(b) warm-path state lookups",
    "c": "(c) EVM interpreter",
    "d": "(d) precompiles + signatures",
    "e": "(e) post-state root",
    "f": "(f) other",
}

# Sub-label sets used by the first-touch / repeat split (section 3 of the journal).
FIRST_TOUCH_SUBS = {
    "keccak: exec first-touch node authentication",
    "storage(): byte-walk (per DB miss)",
    "walk: validate_at / match_path (once per node)",
    "account trie: Node::get + leaf decode (per DB miss)",
    "storage leaf value decode",
    "resolver (authenticate/resolve)",
    "storage(): fixed per call (model 360 rows)",
    "account(): fixed (memo compare, storage_roots)",
    "storage_roots IndexMap probe/growth",
    "address/slot hash memo (keccak misses)",
    "address/slot hash memo",
    "code_by_hash: code library lookup",
}
REPEAT_SUBS = {
    "journal (JournalInner/JournaledAccount/Host)",
    "hashbrown: journal + cache maps",
    "State/CacheState lookup (revm State DB wrapper)",
    "per-tx commit (State::commit, CacheAccount, transitions)",
    "per-tx handler pre/post execution",
    "block finalize (bundle/reverts)",
}


def strip(sym: str) -> str:
    return HASH_RE.sub("", sym)


def group_of(label: str) -> str:
    if label.startswith("tx"):
        return "tx"
    if label == "witness_reveal":
        return "reveal"
    if label == "post_root":
        return "post_root"
    return "outside"


def _matching_gt(s: str, start: int) -> int:
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "<":
            depth += 1
        elif s[i] == ">":
            depth -= 1
            if depth == 0:
                return i
    return len(s) - 1


def _split_as(inner: str) -> tuple[str, str]:
    depth = 0
    i = 0
    while i < len(inner):
        ch = inner[i]
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        elif depth == 0 and inner.startswith(" as ", i):
            return inner[:i], inner[i + 4:]
        i += 1
    return inner, ""


def _root_of(path: str) -> str:
    path = path.replace("&mut ", "").replace("&", "").lstrip()
    cut = len(path)
    for sep in ("::<", "<"):
        k = path.find(sep)
        if k != -1:
            cut = min(cut, k)
    return path[:cut]


def parse_sym(sym: str) -> tuple[str, str]:
    """-> (text, impl): text = `root as trait ::method` of the defining item,
    impl = the impl type / fn generics with their arguments (for maps, iterators,
    drop_in_place, sorts)."""
    s = strip(sym)
    if s.startswith("<"):
        end = _matching_gt(s, 0)
        inner, rest = s[1:end], s[end + 1:]
        impl_text, trait_ = _split_as(inner)
        method = rest[2:] if rest.startswith("::") else rest
        method = _root_of(method)
        root = _root_of(impl_text)
        text = f"{root} as {_root_of(trait_)} ::{method}"
        if root == "core::ptr::drop_in_place":
            impl_text = rest
        return text, impl_text
    root = _root_of(s)
    return f"{root}  ::", s[len(root):]


# (field, regex, bucket, sub) — first match wins. field: "text" (root/trait/method),
# "impl" (impl-type or fn generics), "full" (whole stripped name).
RULES: list[tuple[str, str, str, str]] = [
    # --- instrumentation / alloc (any group) ---
    ("text", r"jeth_phase_start|jeth_phase_end|keccak_stats|cycle_track|jolt_platform::.*print|^u64 as core::fmt|^core::fmt::",
     "f", "instrumentation (census println, markers)"),
    ("text", r"bump_alloc|zeroos_allocator|RawVecInner|raw_vec|finish_grow|^alloc::alloc::", "f", "alloc"),
    # --- shared symbols without caller data ---
    ("text", r"^memcpy  ::", "f", "memcpy (no caller data)"),
    ("text", r"^memcmp  ::", "f", "memcmp (no caller data)"),
    ("text", r"^native_keccak256  ::", "f", "keccak (no caller data)"),
    ("text", r"^memset  ::", "f", "memset"),
    ("text", r"^memmove  ::|compiler_builtins", "f", "memmove/builtins"),
    # --- (a) ---
    ("text", r"^jeth_core::walk::", "a", "walk: validate_at / match_path (once per node)"),
    ("text", r"^jeth_core::zeth_trie::SparseState as tries::StatelessTrie ::storage", "a", "storage(): byte-walk (per DB miss)"),
    ("text", r"^jeth_core::resolver::", "a", "resolver (authenticate/resolve)"),
    ("text", r"::new_with_codes", "a", "witness code map build (reveal)"),
    ("impl", r"alloy_trie::account::TrieAccount", "a", "account trie: Node::get + leaf decode (per DB miss)"),
    ("text", r"^zeth_mpt::mpt::node::Node .*::get$", "a", "account trie: Node::get + leaf decode (per DB miss)"),
    ("text", r"^zeth_mpt::", "a", "MPT decode/resolve (zeth-mpt)"),
    ("text", r"^ruint::Uint as alloy_rlp::decode::Decodable", "a", "storage leaf value decode"),
    # --- (b) ---
    ("text", r"^jeth_core::zeth_trie::SparseState as tries::StatelessTrie ::account", "b", "account(): fixed (memo compare, storage_roots)"),
    ("text", r"^jeth_core::zeth_trie::SparseState as tries::StatelessTrie ::calculate_state_root", "e", "post-root materialization"),
    ("text", r"::hashed_post_state", "e", "hashed post state build"),
    ("text", r"^jeth_core::keccak_memo::", "b", "address/slot hash memo"),
    ("impl", r"FixedBytes<32usize>, \[u64; 4usize\]", "b", "storage_roots IndexMap probe/growth"),
    ("text", r"^jeth_core::code_library::", "b", "code_by_hash: code library lookup"),
    ("text", r"^jeth_core::validation::CodeMap|^jeth_core::validation::WitnessDatabase", "b", "WitnessDatabase/CodeMap glue"),
    ("text", r"^revm_handler::mainnet_handler::MainnetHandler .*::(pre_execution|post_execution|validate|reimburse|reward|load_accounts|deduct)|^revm_handler::(pre_execution|post_execution|validation)",
     "b", "per-tx handler pre/post execution"),
    ("text", r"^revm_context::journal::|^revm_context_interface::journaled_state::|^revm_context::context::Context as revm_context_interface::host::Host",
     "b", "journal (JournalInner/JournaledAccount/Host)"),
    ("text", r"as revm_database_interface::DatabaseCommit ::commit|^revm_database::states::cache::|^revm_database::states::cache_account::|^revm_database::states::transition_account::|^revm_database::states::plain_account::",
     "b", "per-tx commit (State::commit, CacheAccount, transitions)"),
    ("text", r"^revm_database::states::bundle_state::|^revm_database::states::bundle_account::|^revm_database::states::reverts::",
     "b", "block finalize (bundle/reverts)"),
    ("text", r"^revm_database::", "b", "State/CacheState lookup (revm State DB wrapper)"),
    ("impl", r"EvmStorageSlot|revm_state::Account|CacheAccount|TransitionAccount|StorageSlot|RevertToSlot|revm_bytecode::bytecode::Bytecode|ruint::Uint<256usize, 4usize>, ruint::Uint<256usize, 4usize>",
     "b", "hashbrown: journal + cache maps"),
    ("text", r"^foldhash::|^hashbrown::raw::RawTableInner", "b", "hashbrown: journal + cache maps"),
    # --- (d) ---
    ("text", r"^jeth_core::recovery_batch::|^jeth_core::recover::|^jeth_core::crypto::|^jolt_inlines_secp256k1::|^jeth_core::bn254::|jeth_ecrecover_prehash",
     "d", "secp256k1 inline: tx sigs + ecrecover"),
    ("text", r"^ark_ff|^ark_ec|^ark_bn254|^ark_bls|^ark_serialize|^ark_poly|^ark_std", "d", "bn254 pairing/mul (arkworks)"),
    ("impl", r"ark_bn254|ark_ec", "d", "bn254 pairing/mul (arkworks)"),
    ("text", r"aurora_engine_modexp|^sha2::|ripemd|blake2|^revm_precompile|^alloy_evm::precompiles", "d", "precompile dispatch + software precompiles"),
    ("text", r"^k256::|^ecdsa::|^elliptic_curve::|^primeorder::|^alloy_eip7702", "d", "EIP-7702 authority recovery"),
    ("impl", r"stateless::validation::StatelessValidationError|Iter<stateless", "d", "signing hashes + sender derivation (sig_verify)"),
    # --- (c) ---
    ("text", r"^revm_interpreter::instructions::host::", "c", "host op handlers (SLOAD/SSTORE/BALANCE/EXTCODE*/LOG)"),
    ("text", r"^revm_interpreter::instructions::contract::", "c", "CALL/CREATE op handlers"),
    ("text", r"^revm_interpreter::instructions::stack::", "c", "stack ops (PUSH/DUP/SWAP/POP)"),
    ("text", r"^revm_interpreter::instructions::memory::|shared_memory", "c", "memory ops (MLOAD/MSTORE/MCOPY/resize)"),
    ("text", r"^revm_interpreter::instructions::(arithmetic|bitwise)::", "c", "arithmetic/bitwise ops"),
    ("text", r"^revm_interpreter::instructions::control::", "c", "control ops (JUMP/JUMPI/JUMPDEST)"),
    ("text", r"^revm_interpreter::instructions::system::keccak256", "c", "KECCAK256 op glue"),
    ("text", r"^revm_interpreter::instructions::system::", "c", "system ops (CALLDATA*/RETURN/CALLER)"),
    ("text", r"^revm_interpreter::.*gas|^revm_interpreter::instructions::initial_gas", "c", "gas"),
    ("text", r"^revm_interpreter::", "c", "interpreter misc"),
    ("text", r"^revm_handler::|^revm_context::evm::|^revm_context::", "c", "handler: run loop + frames"),
    ("text", r"analyze_legacy|^revm_bytecode::", "c", "bytecode analysis (jump tables, once per code)"),
    ("text", r"^ruint::Uint  ::|^ruint::", "c", "U256 arithmetic (ruint)"),
    # --- (e) ---
    ("text", r"HashedPostState|HashedStorage|^reth_trie_common", "e", "hashed post state build"),
    ("text", r"^nybbles::|^alloy_trie::nodes::", "e", "post-root materialization"),
    ("impl", r"FixedBytes<32usize>, core::option::Option", "e", "post-root materialization"),
    # --- (f) ---
    ("text", r"^jeth_core::container::|^jeth_core::from_container|^jeth_core::decode_container|^postcard|^serde", "f", "deserialize (JEF)"),
    ("text", r"receipt_root_bloom|^alloy_trie::hash_builder|^alloy_trie::root|^alloy_consensus::|^alloy_eips|^alloy_primitives::log|bytes::buf|^alloy_rlp::header::Header ::encode|^reth_ethereum_consensus|^reth_consensus|calculate_receipt_root|calculate_transaction_root|^alloy_primitives::bloom",
     "f", "consensus glue: receipts/bloom/tx root/header"),
    ("impl", r"FixedBytes<32usize>, alloy_primitives::bits::fixed::FixedBytes<32usize>", "f", "consensus glue: receipts/bloom/tx root/header"),
    ("text", r"^jeth_core::validation::|^alloy_evm::|^reth_evm|^reth_ethereum_primitives|^reth_primitives_traits|^stateless::|^jeth_core::advice|^jeth_core::lib|^jeth_guest|validate_block",
     "f", "tx loop / executor glue"),
    ("text", r"^alloy_rlp::|^alloy_primitives::|^\[u8; 32usize\]|^ruint::Uint as alloy_rlp::encode", "f", "RLP/primitives misc"),
    ("text", r"^hashbrown::|^indexmap::", "f", "hashbrown/indexmap misc"),
    ("text", r"^core::|^alloc::", "f", "core/alloc misc"),
    ("full", r"<unknown>", "f", "unknown"),
]
COMPILED = [(f, re.compile(rx), b, s) for f, rx, b, s in RULES]


def classify(sym: str, group: str) -> tuple[str, str]:
    s = strip(sym)
    text, impl = parse_sym(sym)
    # Marker-group overrides for shared / phase-bound symbols.
    if group == "post_root":
        if re.search(r"bump_alloc|core::fmt", text):
            return "f", "alloc / instrumentation"
        if s == "native_keccak256":
            return "e", "keccak: post-root node hashing"
        return "e", "post-root materialization (decode/encode/insert)"
    if group == "reveal":
        if re.search(r"analyze_legacy|revm_bytecode", text):
            return "c", "bytecode analysis (jump tables, once per code)"
        if re.search(r"bump_alloc|core::fmt", text):
            return "f", "alloc / instrumentation"
        if s == "native_keccak256":
            return "a", "keccak: reveal (state-trie node authentication + code hashes)"
        return "a", "reveal: MPT decode/resolve + memcpy"
    if s == "memset":
        return ("c", "memset (EVM memory zeroing)") if group == "tx" else ("f", "memset")
    for field, rx, b, sub in COMPILED:
        hay = text if field == "text" else impl if field == "impl" else s
        if rx.search(hay):
            return b, sub
    return "f", "unclassified: " + text[:70]


def load_split(path: str):
    d = json.load(open(path))
    gs: dict[tuple[str, str], int] = defaultdict(int)
    per_label: dict[str, dict[str, int]] = {}
    for m in d["markers"]:
        g = group_of(m["label"])
        syms = {}
        for s in m["symbols"]:
            gs[(g, s["symbol"])] += s["rows"]
            syms[s["symbol"]] = s["rows"]
        per_label[m["label"]] = syms
    return d["total_rows"], gs, per_label


CALLER_RE = re.compile(r"^\s*([0-9.]+)%\s+(\d+)\s+(.+)$", re.M)


def load_callers(path: str) -> list[tuple[str, int]]:
    text = open(path).read()
    head = text.find("=== top")
    return [(m.group(3).strip(), int(m.group(2)))
            for m in CALLER_RE.finditer(text[head:] if head >= 0 else text)]


def own_group_dist(gs, sym: str) -> dict[str, int]:
    return {g: gs.get((g, sym), 0) for g in GROUPS}


def keccak_sub(caller: str, g: str, b: str) -> str:
    text, _ = parse_sym(caller)
    if g == "post_root":
        return "keccak: post-root node hashing"
    if g == "reveal":
        return "keccak: reveal (state-trie node authentication + code hashes)"
    if "StatelessTrie ::storage" in text or text.startswith("jeth_core::resolver"):
        return "keccak: exec first-touch node authentication"
    if text.startswith("jeth_core::keccak_memo"):
        return "address/slot hash memo (keccak misses)"
    if "instructions::system::keccak256" in text:
        return "keccak: KECCAK256 op"
    if b == "d":
        return "keccak: signing hashes / recovery transcript"
    if b == "f":
        return "keccak: consensus glue (tx/receipt roots, bloom topics)"
    if b == "e":
        return "keccak: hashed post state misses"
    return "keccak: " + BUCKET_NAMES[b]


def shared_split(gs, shared_sym: str, callers: list[tuple[str, int]]):
    """(group -> {(bucket, sub): share}) for a shared symbol, from its callers,
    each caller weighted by its own row distribution over the marker groups."""
    weights: dict[str, dict[tuple[str, str], float]] = {g: defaultdict(float) for g in GROUPS}
    for caller, rows in callers:
        dist = own_group_dist(gs, caller)
        tot = sum(dist.values())
        if tot == 0:
            dist, tot = {"tx": 1}, 1  # caller below the per-marker cutoff: assume execution phase
        for g in GROUPS:
            w = rows * dist.get(g, 0) / tot
            if w <= 0:
                continue
            b, sub = classify(caller, g)
            if shared_sym == "native_keccak256":
                sub = keccak_sub(caller, g, b)
            else:
                sub = f"{shared_sym} via {sub}"
            weights[g][(b, sub)] += w
    shares = {}
    for g in GROUPS:
        tot = sum(weights[g].values())
        shares[g] = {k: v / tot for k, v in weights[g].items()} if tot else {}
    return shares, weights


def attribute(total_rows, gs, callers_by_sym, storage_calls=0):
    """Rows per (bucket, sub, group); shared symbols split by caller shares."""
    acc: dict[tuple[str, str, str], float] = defaultdict(float)
    checks = []
    shares_by_sym = {}
    for sym, callers in callers_by_sym.items():
        shares, weights = shared_split(gs, sym, callers)
        shares_by_sym[sym] = shares
        for g in GROUPS:
            actual = gs.get((g, sym), 0)
            implied = sum(weights[g].values())
            checks.append((sym, g, actual, implied))
    for (g, sym), rows in gs.items():
        if sym in shares_by_sym:
            shares = shares_by_sym[sym][g]
            if shares:
                for (b, sub), sh in shares.items():
                    acc[(b, sub, g)] += rows * sh
                continue
        b, sub = classify(sym, g)
        acc[(b, sub, g)] += rows
    # storage(): move the modelled fixed per-call cost from (a) to (b).
    if storage_calls:
        fixed = min(360.0 * storage_calls, acc[("a", "storage(): byte-walk (per DB miss)", "tx")])
        acc[("a", "storage(): byte-walk (per DB miss)", "tx")] -= fixed
        acc[("b", "storage(): fixed per call (model 360 rows)", "tx")] += fixed
    return acc, checks


def fmt(n: float) -> str:
    return f"{int(round(n)):,}"


def print_buckets(total_rows, acc, checks, top, trace_rows=None):
    covered = sum(acc.values())
    print(f"pertx-build rows {total_rows:,}  attributed {fmt(covered)} "
          f"({100*covered/total_rows:.2f}%; rest = per-marker <256-row tail)"
          + (f"  | trace rows (no markers) {trace_rows:,}" if trace_rows else ""))
    print()
    print(f"| bucket | rows | % block | reveal | tx | post_root | outside |")
    print(f"|---|---:|---:|---:|---:|---:|---:|")
    by_bucket: dict[str, float] = defaultdict(float)
    by_bucket_group: dict[tuple[str, str], float] = defaultdict(float)
    by_sub: dict[tuple[str, str], float] = defaultdict(float)
    for (b, sub, g), rows in acc.items():
        by_bucket[b] += rows
        by_bucket_group[(b, g)] += rows
        by_sub[(b, sub)] += rows
    for b in "abcdef":
        print(f"| {BUCKET_NAMES[b]} | {fmt(by_bucket[b])} | {100*by_bucket[b]/total_rows:.2f}% | "
              + " | ".join(fmt(by_bucket_group[(b, g)]) for g in GROUPS) + " |")
    print(f"| total | {fmt(covered)} | {100*covered/total_rows:.2f}% | "
          + " | ".join(fmt(sum(by_bucket_group[(b, g)] for b in 'abcdef')) for g in GROUPS) + " |")
    print()
    for b in "abcdef":
        print(f"{BUCKET_NAMES[b]}: {fmt(by_bucket[b])} ({100*by_bucket[b]/total_rows:.2f}%)")
        subs = sorted(((s, r) for (bb, s), r in by_sub.items() if bb == b), key=lambda kv: -kv[1])
        for s, r in subs[:top]:
            print(f"    {fmt(r):>13} {100*r/total_rows:6.2f}%  {s}")
        if len(subs) > top:
            rest = sum(r for _, r in subs[top:])
            print(f"    {fmt(rest):>13} {100*rest/total_rows:6.2f}%  (+{len(subs)-top} smaller sub-lines)")
    print()
    print("shared-symbol caller reconciliation (actual rows in group vs caller-implied):")
    for sym, g, actual, implied in checks:
        if actual or implied:
            print(f"    {sym:18} {g:9} actual {fmt(actual):>12}  implied {fmt(implied):>12}")
    return by_bucket, by_sub


def base_sub(sub: str) -> str:
    """`memcpy via X` / `memcmp via X` -> X (shared-symbol rows follow their caller)."""
    for pre in ("memcpy via ", "memcmp via "):
        if sub.startswith(pre):
            return sub[len(pre):]
    return sub


def print_first_touch(total_rows, by_sub):
    folded: dict[str, float] = defaultdict(float)
    for (_b, s), r in by_sub.items():
        folded[base_sub(s)] += r
    first = {s: r for s, r in folded.items() if s in FIRST_TOUCH_SUBS}
    repeat = {s: r for s, r in folded.items() if s in REPEAT_SUBS}
    once = {s: r for s, r in folded.items()
            if s.startswith("keccak: reveal") or s.startswith("reveal:") or "witness code map" in s}
    print()
    print("| class | rows | % block | sub-lines |")
    print("|---|---:|---:|---|")
    for name, d in (("block-once reveal (a)", once), ("first touch per distinct key/node (a+b)", first),
                    ("repeat per access / per tx (b)", repeat)):
        tot = sum(d.values())
        subs = ", ".join(f"{s} {fmt(r)}" for s, r in sorted(d.items(), key=lambda kv: -kv[1]))
        print(f"| {name} | {fmt(tot)} | {100*tot/total_rows:.2f}% | {subs} |")


def cmd_buckets(args):
    total_rows, gs, _ = load_split(args.split)
    callers = {}
    for spec in args.callers or []:
        sym, path = spec.split("=", 1)
        callers[sym] = load_callers(path)
    acc, checks = attribute(total_rows, gs, callers, args.storage_calls)
    _, by_sub = print_buckets(total_rows, acc, checks, args.top, args.trace_rows)
    print_first_touch(total_rows, by_sub)
    if args.json_out:
        out = defaultdict(dict)
        for (b, sub, g), rows in acc.items():
            out[b][f"{sub} [{g}]"] = rows
        json.dump({"total_rows": total_rows, "buckets": out}, open(args.json_out, "w"), indent=1)


CENSUS_RE = re.compile(r"^keccak\[(tx\d+)\]: calls=(\d+) bytes=(\d+) perms=(\d+)", re.M)


def load_tx_perms(profile_log: str) -> dict[str, int]:
    """Per-tx keccak permutations from the census lines (start and end print)."""
    seen: dict[str, list[int]] = defaultdict(list)
    for m in CENSUS_RE.finditer(open(profile_log).read()):
        seen[m.group(1)].append(int(m.group(4)))
    # pass 1 (compute_advice ELF) prints the same labels first: use the last pair (proven pass).
    return {k: v[-1] - v[-2] for k, v in seen.items() if len(v) >= 2}


def cmd_pertx(args):
    total_rows, gs, per_label = load_split(args.split)
    txp = json.load(open(args.txprofile))
    callers = {}
    for spec in args.callers or []:
        sym, path = spec.split("=", 1)
        callers[sym] = load_callers(path)
    shares = {sym: shared_split(gs, sym, c)[0]["tx"] for sym, c in callers.items()}
    perms = load_tx_perms(args.profile_log) if args.profile_log else {}
    meta = {f"tx{t['index']:04d}": t for t in txp["txs"]}
    rows_out = []
    for label, syms in per_label.items():
        if not label.startswith("tx"):
            continue
        b_rows: dict[str, float] = defaultdict(float)
        sub_rows: dict[str, float] = defaultdict(float)
        for sym, rows in syms.items():
            if sym in shares and shares[sym]:
                for (b, sub), sh in shares[sym].items():
                    b_rows[b] += rows * sh
                    sub_rows[sub] += rows * sh
            else:
                b, sub = classify(sym, "tx")
                b_rows[b] += rows
                sub_rows[sub] += rows
        t = meta.get(label, {})
        folded: dict[str, float] = defaultdict(float)
        for s_, r_ in sub_rows.items():
            folded[base_sub(s_)] += r_
        first = sum(r for s, r in folded.items() if s in FIRST_TOUCH_SUBS)
        repeat = sum(r for s, r in folded.items() if s in REPEAT_SUBS)
        rows_out.append({
            "tx": label, "cycles": t.get("cycles", sum(syms.values())), "gas": t.get("gas_used", 0),
            "to": (t.get("to") or "(create)"), "selector": t.get("selector") or "-", "type": t.get("tx_type"),
            "perms": perms.get(label), "first_touch": first, "repeat": repeat,
            "validate_at": folded.get("walk: validate_at / match_path (once per node)", 0),
            "storage_walk": folded.get("storage(): byte-walk (per DB miss)", 0)
            + folded.get("storage(): fixed per call (model 360 rows)", 0),
            "auth_keccak": folded.get("keccak: exec first-touch node authentication", 0),
            **{f"b_{b}": b_rows[b] for b in "abcdef"},
        })
    rows_out.sort(key=lambda r: -r["cycles"])
    exec_total = sum(r["cycles"] for r in rows_out)
    hdr = "| # | cycles | gas | c/g | first-touch (a+b) | of which auth keccak | repeat (b) | (c) EVM | (d) precomp | to | selector |"
    print(hdr)
    print("|" + "---|" * 11)
    for r in rows_out[: args.top]:
        cg = r["cycles"] / r["gas"] if r["gas"] else 0
        print(f"| {r['tx'][2:]} | {fmt(r['cycles'])} | {r['gas']:,} | {cg:.1f} | {fmt(r['first_touch'])} ({100*r['first_touch']/r['cycles']:.0f}%) | "
              f"{fmt(r['auth_keccak'])} | {fmt(r['repeat'])} ({100*r['repeat']/r['cycles']:.0f}%) | {fmt(r['b_c'])} | {fmt(r['b_d'])} | "
              f"{r['to'][:10]}… | {r['selector']} |")
    print(f"\nexecution-phase totals: {fmt(exec_total)} rows in {len(rows_out)} txs; "
          f"first-touch {fmt(sum(r['first_touch'] for r in rows_out))}, repeat {fmt(sum(r['repeat'] for r in rows_out))}")
    if args.repeat_to:
        # Same-(to, selector) chains in block order: is the later tx cheaper?
        by_key: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for r in rows_out:
            by_key[(r["to"], r["selector"])].append(r)
        print("\n| to | selector | n | order → c/g | order → first-touch rows | order → repeat rows |")
        print("|---|---|---:|---|---|---|")
        chains = [(k, sorted(v, key=lambda r: r["tx"])) for k, v in by_key.items() if len(v) >= 2 and k[0] != "(create)"]
        chains.sort(key=lambda kv: -sum(r["cycles"] for r in kv[1]))
        for (to, sel), v in chains[: args.top]:
            cg = " → ".join(f"{r['cycles']/r['gas']:.1f}" if r["gas"] else "-" for r in v)
            ft = " → ".join(fmt(r["first_touch"]) for r in v)
            rp = " → ".join(fmt(r["repeat"]) for r in v)
            print(f"| {to[:12]}… | {sel} | {len(v)} | {cg} | {ft} | {rp} |")
    if args.csv:
        import csv
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
            w.writeheader()
            w.writerows(rows_out)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = p.add_subparsers(dest="cmd", required=True)
    b = sp.add_parser("buckets")
    b.add_argument("split")
    b.add_argument("--callers", action="append", metavar="SYM=LOG")
    b.add_argument("--storage-calls", type=int, default=0)
    b.add_argument("--trace-rows", type=int)
    b.add_argument("--top", type=int, default=8)
    b.add_argument("--json-out")
    b.set_defaults(fn=cmd_buckets)
    t = sp.add_parser("pertx")
    t.add_argument("split")
    t.add_argument("txprofile")
    t.add_argument("--profile-log")
    t.add_argument("--callers", action="append", metavar="SYM=LOG")
    t.add_argument("--top", type=int, default=12)
    t.add_argument("--repeat-to", action="store_true")
    t.add_argument("--csv")
    t.set_defaults(fn=cmd_pertx)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
