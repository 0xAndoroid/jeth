//! §4.2 execution-phase byte-walks: authenticated reads straight off raw
//! witness RLP — no node materialization, no allocation, no mutation.
//!
//! A walk consumes one advice hint per trie level, authenticates the located
//! witness entry (`keccak == digest`, memoized in [`WitnessResolver`]), and
//! parses just enough of the entry to pick the next child. The guest extracts
//! every branch nibble from its own key — advice only locates bytes (INV-W1);
//! `None` derives only from authenticated content (INV-W2).
//!
//! Parity (L6 / INV-W6): on FIRST authentication of an entry the whole node is
//! validated against `Node::decode`'s exact grammar (canonical RLP via
//! `alloy_rlp::Header`, 17/2 item shapes, empty branch value, ≥2 children,
//! recursive inline-child validation, HP flag ≤ 3 with the even-path pad
//! nibble deliberately UNchecked — upstream is lax there, exact-length
//! consumption). The verdict + node kind is memoized (2 bits/entry). One
//! documented narrowing: a bare-string witness entry (`0x80` / digest-for-
//! digest) panics the walk where the eager build resolved-to-Null or kept a
//! stub — refusal-only divergence, unreachable from digest-anchored mainnet
//! state; the native gate runs this same code so guest/native always agree.
//!
//! Inline children (any list first byte, incl. long-form `0xf8+` — INV-W5) are
//! walked in place on the parent's bytes: no advice call, no digest check
//! (bytes already authenticated).

use alloy_primitives::B256;
use alloy_rlp::Header;
use core::ops::Range;

/// Node kind memo values (2 bits per witness entry in `WitnessResolver`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub(crate) enum NodeKind {
    Unvalidated = 0,
    Branch = 1,
    Extension = 2,
    Leaf = 3,
}

impl NodeKind {
    #[inline(always)]
    pub(crate) fn from_bits(bits: u64) -> Self {
        match bits & 3 {
            1 => NodeKind::Branch,
            2 => NodeKind::Extension,
            3 => NodeKind::Leaf,
            _ => NodeKind::Unvalidated,
        }
    }
}

/// One walk step's outcome within an authenticated entry.
pub(crate) enum Step {
    /// Continue at a child digest (bytes copied out of the parent).
    Digest(B256),
    /// Authenticated absence (empty child / path divergence) — exclusion.
    Absent,
    /// Leaf hit: value = RLP string payload at this range of the entry bytes.
    Value(Range<usize>),
}

#[inline(always)]
pub(crate) fn key_nibble(key: &B256, d: usize) -> u8 {
    let b = key[d >> 1];
    if d & 1 == 0 {
        b >> 4
    } else {
        b & 0xf
    }
}

/// Skip one RLP item (header + payload). Canonicality is [`Header::decode`]'s.
#[inline(always)]
fn skip_item(p: &mut &[u8]) -> alloy_rlp::Result<()> {
    let h = Header::decode(p)?;
    // Single bytes (< 0x80) are their own payload; decode does not advance.
    *p = &p[h.payload_length..];
    Ok(())
}

/// Full `Node::decode`-parity validation of one node encoding, advancing `r`
/// past it. Recurses into inline (list) children. Returns the node kind.
fn validate_at(r: &mut &[u8]) -> alloy_rlp::Result<NodeKind> {
    let h = Header::decode(r)?;
    if !h.list {
        // As an inline child this is handled at the item site (empty/digest);
        // as a top-level walk entry a bare string is unusable (see module docs).
        return Err(alloy_rlp::Error::Custom("bare string node in walk"));
    }
    if h.payload_length > r.len() {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    let (mut p, rest) = r.split_at(h.payload_length);
    *r = rest;

    // First pass: count items to pick the grammar (2 vs 17).
    let mut probe = p;
    let mut items = 0usize;
    while !probe.is_empty() {
        skip_item(&mut probe)?;
        items += 1;
        if items > 17 {
            return Err(alloy_rlp::Error::Custom("unexpected list length"));
        }
    }
    match items {
        17 => {
            let mut children = 0usize;
            for i in 0..17usize {
                let before = p;
                let ih = Header::decode(&mut p)?;
                if ih.list {
                    if i == 16 {
                        return Err(alloy_rlp::Error::Custom("branch node with value"));
                    }
                    // Inline child (INV-W5): full recursive validation.
                    let mut child = &before[..before.len() - p.len() + ih.payload_length];
                    p = &p[ih.payload_length..];
                    validate_at(&mut child)?;
                    children += 1;
                } else {
                    match ih.payload_length {
                        0 => {}
                        32 if i < 16 => {
                            p = &p[32..];
                            children += 1;
                        }
                        _ if i == 16 => {
                            return Err(alloy_rlp::Error::Custom("branch node with value"));
                        }
                        _ => return Err(alloy_rlp::Error::UnexpectedLength),
                    }
                }
            }
            if children < 2 {
                return Err(alloy_rlp::Error::Custom("branch node without two children"));
            }
            Ok(NodeKind::Branch)
        }
        2 => {
            // item 0: compact HP path (string, non-empty, flag nibble <= 3).
            let ph = Header::decode(&mut p)?;
            if ph.list {
                return Err(alloy_rlp::Error::UnexpectedString);
            }
            if ph.payload_length == 0 {
                return Err(alloy_rlp::Error::InputTooShort);
            }
            let flag = p[0] >> 4;
            if flag > 3 {
                return Err(alloy_rlp::Error::Custom("node is not an extension or leaf"));
            }
            p = &p[ph.payload_length..];
            let is_leaf = flag >= 2;
            // item 1
            let before = p;
            let vh = Header::decode(&mut p)?;
            if is_leaf {
                // value must be a string (Bytes::decode parity); contents are
                // not validated here — exactly like the eager decode.
                if vh.list {
                    return Err(alloy_rlp::Error::UnexpectedList);
                }
                Ok(NodeKind::Leaf)
            } else {
                // extension child: digest or inline node that must be a branch.
                if vh.list {
                    let mut child = &before[..before.len() - p.len() + vh.payload_length];
                    if validate_at(&mut child)? != NodeKind::Branch {
                        return Err(alloy_rlp::Error::Custom(
                            "extension node with invalid child",
                        ));
                    }
                } else if vh.payload_length != 32 {
                    return Err(alloy_rlp::Error::Custom(
                        "extension node with invalid child",
                    ));
                }
                Ok(NodeKind::Extension)
            }
        }
        _ => Err(alloy_rlp::Error::Custom("unexpected list length")),
    }
}

/// Validate a complete top-level witness entry (exact consumption — the
/// `decode_exact` parity) and return its kind for the memo.
pub(crate) fn validate_entry(bytes: &[u8]) -> alloy_rlp::Result<NodeKind> {
    let mut r = bytes;
    let kind = validate_at(&mut r)?;
    if !r.is_empty() {
        return Err(alloy_rlp::Error::UnexpectedLength);
    }
    Ok(kind)
}

/// Classify an (already-validated) inline node span: item count + HP flag.
fn classify(span: &[u8]) -> NodeKind {
    let mut r = span;
    let h = Header::decode(&mut r).expect("validated");
    let mut p = &r[..h.payload_length];
    let mut items = 0usize;
    let first = p;
    while !p.is_empty() {
        skip_item(&mut p).expect("validated");
        items += 1;
    }
    if items == 17 {
        NodeKind::Branch
    } else {
        let mut q = first;
        let ph = Header::decode(&mut q).expect("validated");
        debug_assert!(!ph.list && ph.payload_length > 0);
        if q[0] >> 4 >= 2 {
            NodeKind::Leaf
        } else {
            NodeKind::Extension
        }
    }
}

/// Compare the compact HP path at `compact` against key nibbles starting at
/// `depth`. Returns the nibble count on a full prefix match, `None` on any
/// divergence or if fewer than `plen` key nibbles remain.
#[inline]
fn match_path(compact: &[u8], key: &B256, depth: usize, require_exhaust: bool) -> Option<usize> {
    let odd = compact[0] >> 4 & 1 == 1;
    let plen = if odd {
        2 * compact.len() - 1
    } else {
        2 * (compact.len() - 1)
    };
    if plen > 64 - depth || (require_exhaust && plen != 64 - depth) {
        return None;
    }
    let mut d = depth;
    if odd {
        if compact[0] & 0xf != key_nibble(key, d) {
            return None;
        }
        d += 1;
    }
    // Fast path: after the optional odd first nibble, if `d` is byte-aligned
    // the rest is a straight byte compare (HP was designed for this) — always
    // the case for leaves (remainder parity == depth parity).
    let body = &compact[1..];
    if d & 1 == 0 {
        if body != &key[d / 2..d / 2 + body.len()] {
            return None;
        }
    } else {
        for (j, &b) in body.iter().enumerate() {
            let n0 = d + 2 * j;
            if b >> 4 != key_nibble(key, n0) || b & 0xf != key_nibble(key, n0 + 1) {
                return None;
            }
        }
    }
    Some(plen)
}

/// Walk one authenticated entry from `depth`, following inline children in
/// place, until it yields a digest / absence / value (spans index into
/// `entry`). `kind` is the entry's memoized kind.
pub(crate) fn walk_entry(entry: &[u8], top_kind: NodeKind, key: &B256, depth: &mut usize) -> Step {
    let mut span = entry;
    let mut kind = top_kind;
    loop {
        let mut p = span;
        let h = Header::decode(&mut p).expect("validated");
        p = &p[..h.payload_length];
        match kind {
            NodeKind::Branch => {
                if *depth == 64 {
                    return Step::Absent; // exhausted key at a branch (node.rs:92-98 parity)
                }
                let nib = key_nibble(key, *depth) as usize;
                *depth += 1;
                for _ in 0..nib {
                    skip_item(&mut p).expect("validated");
                }
                let before = p;
                let ih = Header::decode(&mut p).expect("validated");
                if ih.list {
                    // INV-W5: inline child — continue on the parent's bytes.
                    span = &before[..before.len() - p.len() + ih.payload_length];
                    kind = classify(span);
                    continue;
                }
                match ih.payload_length {
                    0 => return Step::Absent, // authenticated-empty ⇒ exclusion
                    32 => return Step::Digest(B256::from_slice(&p[..32])),
                    _ => unreachable!("validated"),
                }
            }
            NodeKind::Extension => {
                let ph = Header::decode(&mut p).expect("validated");
                let compact = &p[..ph.payload_length];
                p = &p[ph.payload_length..];
                let Some(plen) = match_path(compact, key, *depth, false) else {
                    return Step::Absent; // authenticated divergence ⇒ exclusion
                };
                *depth += plen;
                let before = p;
                let vh = Header::decode(&mut p).expect("validated");
                if vh.list {
                    span = &before[..before.len() - p.len() + vh.payload_length];
                    kind = classify(span);
                    continue;
                }
                debug_assert_eq!(vh.payload_length, 32);
                return Step::Digest(B256::from_slice(&p[..32]));
            }
            NodeKind::Leaf => {
                let ph = Header::decode(&mut p).expect("validated");
                let compact = &p[..ph.payload_length];
                p = &p[ph.payload_length..];
                if match_path(compact, key, *depth, true).is_none() {
                    return Step::Absent;
                }
                let vh = Header::decode(&mut p).expect("validated");
                let start = p.as_ptr() as usize - entry.as_ptr() as usize;
                return Step::Value(start..start + vh.payload_length);
            }
            NodeKind::Unvalidated => unreachable!("kind memoized before walking"),
        }
    }
}
