"""Prune a full-trie witness.json to the paths of touched keys (mimics geth's execution witness)."""
import json, sys
from Crypto.Hash import keccak as K
def keccak(b): return K.new(digest_bits=256, data=bytes(b)).digest()

def rlp_decode(b, pos=0):
    x = b[pos]
    if x < 0x80: return b[pos:pos+1], pos + 1
    if x < 0xb8: l = x - 0x80; return b[pos+1:pos+1+l], pos + 1 + l
    if x < 0xc0:
        ll = x - 0xb7; l = int.from_bytes(b[pos+1:pos+1+ll], 'big'); return b[pos+1+ll:pos+1+ll+l], pos + 1 + ll + l
    if x < 0xf8:
        l = x - 0xc0; end = pos + 1 + l; items = []; p = pos + 1
        while p < end: it, p = rlp_decode(b, p); items.append(it)
        return items, end
    ll = x - 0xf7; l = int.from_bytes(b[pos+1:pos+1+ll], 'big'); end = pos + 1 + ll + l; items = []; p = pos + 1 + ll
    while p < end: it, p = rlp_decode(b, p); items.append(it)
    return items, end

def nibbles(key): 
    out = []
    for byte in key: out += [byte >> 4, byte & 0xf]
    return out

def decode_path(enc):
    flag = enc[0] >> 4
    nibs = nibbles(enc)
    nibs = nibs[2:] if flag in (0, 2) else nibs[1:]
    return nibs, flag >= 2  # (nibbles, is_leaf)

def walk(nodes, root_hash, key, used, siblings=False):
    """Collect hashes of nodes on the path of `key` (32-byte hashed key). Returns leaf value or None."""
    node = nodes.get(root_hash)
    if node is None: return None
    path = nibbles(key)
    while True:
        used.add(keccak(node))
        items, _ = rlp_decode(node)
        if len(items) == 17:
            if not path: return items[16]
            child = items[path[0]]; path = path[1:]
            if siblings:
                for ch in items[:16]:
                    if isinstance(ch, (bytes, bytearray)) and len(ch) == 32 and bytes(ch) in nodes:
                        used.add(bytes(ch))
            if child == b'': return None
        elif len(items) == 2:
            nibs, is_leaf = decode_path(items[0])
            if is_leaf:
                return items[1] if nibs == path else None
            if path[:len(nibs)] != nibs: return None
            path = path[len(nibs):]; child = items[1]
        else:
            raise ValueError('bad node')
        if isinstance(child, list):
            # inline child: re-encode not needed; it is part of the parent bytes. Continue walking within.
            node = None
            # Inline nodes are < 32 bytes; only leaves/short ext can be inline. Handle by decoding directly.
            return _walk_inline(child, path)
        if len(child) == 32:
            node = nodes.get(bytes(child))
            if node is None: return None  # unresolved (should not happen with a full witness)
        else:
            raise ValueError('unexpected child ref')

def _walk_inline(items, path):
    if len(items) == 17:
        if not path: return items[16]
        child = items[path[0]]
        if child == b'': return None
        return _walk_inline(child, path[1:]) if isinstance(child, list) else None
    nibs, is_leaf = decode_path(items[0])
    if is_leaf: return items[1] if nibs == path else None
    if path[:len(nibs)] != nibs: return None
    return _walk_inline(items[1], path[len(nibs):]) if isinstance(items[1], list) else None

def prune(witness_path, touched_accounts, touched_storage, siblings=False):
    """touched_accounts: list of 20-byte addresses (bytes); touched_storage: {address_bytes: [slot_int,...]}"""
    w = json.load(open(witness_path))
    nodes = {}
    for h in w['state']:
        b = bytes.fromhex(h[2:]); nodes[keccak(b)] = b
    root = bytes.fromhex(w['state'][0][2:]); root_hash = keccak(root)
    used = set()
    acct_leaf = {}
    for a in touched_accounts:
        acct_leaf[a] = walk(nodes, root_hash, keccak(a), used)
    for a, slots in touched_storage.items():
        leaf = acct_leaf.get(a) or walk(nodes, root_hash, keccak(a), used)
        if leaf is None: continue
        fields, _ = rlp_decode(leaf)
        sroot = bytes(fields[2])
        if sroot not in nodes: continue
        for s in slots:
            walk(nodes, sroot, keccak(int(s).to_bytes(32, 'big')), used, siblings=siblings)
    kept = [w['state'][0]] + [h for h in w['state'][1:] if keccak(bytes.fromhex(h[2:])) in used]
    before = len(w['state']); w['state'] = kept
    json.dump(w, open(witness_path, 'w'))
    return before, len(kept), sum(len(h) // 2 - 1 for h in kept)
