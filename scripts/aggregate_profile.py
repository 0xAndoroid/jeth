#!/usr/bin/env python3
"""Aggregate `jeth profile --rows` output into component families.

Usage: uv run python scripts/aggregate_profile.py /tmp/jeth-prof-<block>-rows.log

Parses the ranked symbol table (exact trace-row attribution) and buckets each
symbol into a component family (keccak inline, memcpy, zeth-mpt, revm
interpreter opcode families, precompile backends, allocator, ...). Prints a
two-level table: family -> total rows/share, plus the top symbols inside.
"""

import re
import sys
from collections import defaultdict

# (family, subkey) classification rules, first match wins. Order matters.
RULES: list[tuple[str, str, str]] = [
    # (regex, family, sub)
    (r"native_keccak256", "keccak256 inline", "keccak-f + absorb"),
    (r"^memcpy$", "memcpy/memset/memcmp", "memcpy"),
    (r"^memset$", "memcpy/memset/memcmp", "memset"),
    (r"^memcmp$", "memcpy/memset/memcmp", "memcmp"),
    (r"jeth_core.*recover::inline_verify", "tx sig-verify (secp inline)", "ecdsa_verify"),
    (r"jeth_core.*recover::", "tx sig-verify (secp inline)", "recover misc"),
    (r"jeth_core.*crypto::", "ecrecover precompile (secp inline)", "jolt crypto"),
    (r"^k256::", "k256 software (EIP-7702 authority)", "k256"),
    (r"^ecdsa::|^elliptic_curve::|^primeorder::", "k256 software (EIP-7702 authority)", "ecdsa/ec"),
    (r"ark_ff|ark_ec|ark_bn254|ark_bls|ark_serialize|ark_poly", "bn254+kzg precompiles (arkworks)", "ark"),
    (r"revm_precompile.*bn254", "bn254+kzg precompiles (arkworks)", "revm bn254 glue"),
    (r"revm_precompile.*kzg", "bn254+kzg precompiles (arkworks)", "revm kzg glue"),
    (r"aurora_engine_modexp", "modexp precompile (aurora)", "modexp"),
    (r"^sha2::|revm_precompile.*hash", "sha256/ripemd precompiles", "sha256"),
    (r"ripemd", "sha256/ripemd precompiles", "ripemd160"),
    (r"revm_precompile.*blake2|blake2", "blake2 precompile", "blake2"),
    (r"revm_precompile", "precompile dispatch/glue", "revm_precompile misc"),
    (r"zeth_mpt.*Node.*decode", "zeth-mpt trie", "Node::decode"),
    (r"zeth_mpt.*resolve_digests", "zeth-mpt trie", "resolve_digests"),
    (r"zeth_mpt.*rlp_encoded|zeth_mpt.*NodeRef.*encode|zeth_mpt.*rlp", "zeth-mpt trie", "encode/rlp"),
    (r"zeth_mpt.*memoize", "zeth-mpt trie", "memoize"),
    (r"zeth_mpt.*nibs|zeth_mpt.*nibbles|zeth_mpt.*prefix_nibs", "zeth-mpt trie", "nibbles"),
    (r"zeth_mpt", "zeth-mpt trie", "other zeth-mpt"),
    (r"drop_in_place.*zeth_mpt|drop_in_place.*mpt::node", "zeth-mpt trie", "node drops"),
    (r"jeth_core.*zeth_trie", "zeth-mpt trie", "SparseState glue"),
    (r"^tries::", "zeth-mpt trie", "tries glue"),
    (r"instructions::stack::push", "interpreter: PUSH", "push"),
    (r"instructions::stack::dup", "interpreter: DUP", "dup"),
    (r"instructions::stack::swap|Stack.*exchange", "interpreter: SWAP", "swap"),
    (r"instructions::stack::pop", "interpreter: POP", "pop"),
    (r"instructions::memory::mstore", "interpreter: MSTORE/MLOAD/MCOPY", "mstore"),
    (r"instructions::memory::mload", "interpreter: MSTORE/MLOAD/MCOPY", "mload"),
    (r"instructions::memory::mcopy|instructions::memory", "interpreter: MSTORE/MLOAD/MCOPY", "mcopy/other"),
    (r"instructions::arithmetic", "interpreter: arithmetic/bitwise", "arithmetic"),
    (r"instructions::bitwise", "interpreter: arithmetic/bitwise", "bitwise"),
    (r"instructions::control", "interpreter: control (JUMP/JUMPI)", "control"),
    (r"instructions::system::keccak256", "interpreter: KECCAK256 op glue", "keccak op"),
    (r"instructions::system", "interpreter: system (CALLDATA/RETURN)", "system"),
    (r"instructions::host|host::sload|host::sstore|Host>::sload|Host>::sstore|sload|sstore",
     "revm host/journal/state", "sload/sstore"),
    (r"instructions::contract", "revm frames/calls", "call/create ops"),
    (r"revm_interpreter.*gas|::gas::", "interpreter: gas accounting", "gas"),
    (r"revm_interpreter", "interpreter: dispatch/misc", "interpreter misc"),
    (r"revm_bytecode.*analyze_legacy", "bytecode analysis (analyze_legacy)", "analyze_legacy"),
    (r"revm_bytecode", "bytecode analysis (analyze_legacy)", "bytecode misc"),
    (r"MainnetHandler.*execution|Handler>::execution", "revm handler loop", "Handler::execution"),
    (r"frame_init|EthFrame|FrameTr|frame::", "revm frames/calls", "frame init/run"),
    (r"revm_handler", "revm handler loop", "handler misc"),
    (r"JournalInner|journal|Journaled", "revm host/journal/state", "journal"),
    (r"revm_database|CacheAccount|load_cache_account|BundleState|bundle",
     "revm host/journal/state", "state/bundle"),
    (r"revm_context|revm_state", "revm host/journal/state", "context/state"),
    (r"revm_primitives|revm\[", "revm host/journal/state", "revm misc"),
    (r"zeroos_allocator|allocator", "allocator (O(1))", "alloc/dealloc/realloc"),
    (r"postcard", "input deserialize (postcard)", "postcard"),
    (r"serde", "input deserialize (postcard)", "serde"),
    (r"alloy_rlp", "RLP decode/encode (alloy)", "alloy-rlp"),
    (r"alloy_consensus.*crypto", "k256 software (EIP-7702 authority)", "alloy crypto glue"),
    (r"alloy_consensus|alloy_eips", "consensus checks + tx envelope", "alloy-consensus"),
    (r"reth_ethereum_consensus|validate_block_post_execution", "consensus checks + tx envelope", "post-exec checks"),
    (r"alloy_trie|reth_trie|HashedPostState", "post-state hashing glue", "hashed post state"),
    (r"alloy_primitives.*[Uu]int|^ruint::", "U256 arithmetic (ruint)", "ruint"),
    (r"alloy_primitives|alloy_evm", "alloy primitives misc", "alloy misc"),
    (r"indexmap|hashbrown", "hashmaps (indexmap/hashbrown)", "maps"),
    (r"drop_in_place", "drops/alloc misc", "drop_in_place"),
    (r"RawVec|raw_vec|^alloc::.*[Vv]ec", "drops/alloc misc", "vec grow"),
    (r"^stateless::", "stateless validation glue", "stateless"),
    (r"reth_", "stateless validation glue", "reth misc"),
    (r"^core::|^alloc::|compiler_builtins", "core/alloc misc", "core"),
    (r"<unknown>", "unknown", "unknown"),
]

COMPILED = [(re.compile(rx), fam, sub) for rx, fam, sub in RULES]

# First crate-qualified path in the demangled name = the defining crate of the
# impl type (for `<A as B>::m`, A's crate). Cutting at the first `<`/`>` strips
# generic parameters, which otherwise pollute substring classification (e.g.
# MainnetHandler<... tries::WitnessDbError ...> must not classify as `tries`).
ROOT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\[[0-9a-f]+\]::([A-Za-z0-9_:]*)")


def root_path(sym: str) -> str:
    """Symbol -> `crate::ungeneric::path` of the defining item."""
    if sym.startswith("core[") or "drop_in_place" in sym:
        # drop_in_place::<T>: classify by the dropped type T instead.
        inner = ROOT_RE.findall(sym)
        for crate, path in inner:
            if crate not in ("core", "alloc"):
                return f"drop_in_place {crate}::{path}"
        return sym
    m = ROOT_RE.search(sym)
    if m:
        return f"{m.group(1)}::{m.group(2)}"
    return sym  # extern "C" symbols: native_keccak256, memcpy, ...


def classify(sym: str) -> tuple[str, str]:
    root = root_path(sym)
    for rx, fam, sub in COMPILED:
        if rx.search(root):
            return fam, sub
    return "unclassified", root[:70]


def main(path: str) -> None:
    text = open(path).read()
    total_m = re.search(r"done: (\d+) real instrs, (\d+) trace rows", text)
    total_rows = int(total_m.group(2)) if total_m else 0

    rows_re = re.compile(r"^\s*([0-9.]+)%\s+(\d+)\s+(.+)$", re.M)
    fams: dict[str, int] = defaultdict(int)
    subs: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    parsed = 0
    for m in rows_re.finditer(text):
        rows, sym = int(m.group(2)), m.group(3).strip()
        fam, sub = classify(sym)
        fams[fam] += rows
        subs[fam][sub] += rows
        parsed += rows

    print(f"total rows: {total_rows:,} | attributed in top-N: {parsed:,} "
          f"({100*parsed/total_rows:.1f}%)\n")
    print(f"{'rows':>14} {'share':>7}  family")
    print("-" * 78)
    for fam, rows in sorted(fams.items(), key=lambda kv: -kv[1]):
        print(f"{rows:>14,} {100*rows/total_rows:>6.2f}%  {fam}")
        for sub, srows in sorted(subs[fam].items(), key=lambda kv: -kv[1])[:6]:
            print(f"{srows:>14,} {100*srows/total_rows:>6.2f}%      - {sub}")
    tail = total_rows - parsed
    print(f"{tail:>14,} {100*tail/total_rows:>6.2f}%  (below top-N cutoff)")


if __name__ == "__main__":
    main(sys.argv[1])
