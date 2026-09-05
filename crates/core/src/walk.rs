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
use alloy_rlp::EMPTY_STRING_CODE;
use core::ops::Range;
use zeth_mpt::{decode_header, le_words_32};

/// RLP header byte of a digest item (32-byte string) and the item's length.
const DIGEST_ITEM_PREFIX: u8 = EMPTY_STRING_CODE + 32;
const DIGEST_ITEM_LENGTH: usize = 33;

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
    /// Continue at a child digest: its four little-endian words, gathered from
    /// the parent's bytes ([`le_words_32`]).
    Digest([u64; 4]),
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

/// Header of the RLP item at the start of `p`: `(is_list, header length,
/// payload length)`, validated exactly like [`Header::decode`] (the general
/// arm is its local twin [`decode_header`]). Fast paths for the two dominant branch items, which cannot fail:
/// `0x80` is the empty string and `0xa0` a 32-byte string whose payload is
/// present when `p` holds the whole item.
#[inline(always)]
fn item_header(p: &[u8]) -> alloy_rlp::Result<(bool, usize, usize)> {
    match p.first() {
        None => Err(alloy_rlp::Error::InputTooShort),
        Some(&EMPTY_STRING_CODE) => Ok((false, 1, 0)),
        Some(&DIGEST_ITEM_PREFIX) if p.len() >= DIGEST_ITEM_LENGTH => Ok((false, 1, 32)),
        Some(_) => {
            let mut q = p;
            let h = decode_header(&mut q)?;
            Ok((h.list, p.len() - q.len(), h.payload_length))
        }
    }
}

/// Skip one RLP item (header + payload). Canonicality is [`Header::decode`]'s.
#[inline(always)]
fn skip_item(p: &mut &[u8]) -> alloy_rlp::Result<()> {
    let (_, hlen, plen) = item_header(p)?;
    *p = &p[hlen + plen..];
    Ok(())
}

/// Branch child slot rule (items 0..16): empty, a digest, or an inline node
/// (INV-W5: full recursive validation of exactly that item). Returns the
/// number of children the item contributes.
#[inline(always)]
fn validate_branch_child(item: &[u8], list: bool, plen: usize) -> alloy_rlp::Result<usize> {
    if list {
        let mut child = item;
        validate_at(&mut child)?;
        Ok(1)
    } else {
        match plen {
            0 => Ok(0),
            32 => Ok(1),
            _ => Err(alloy_rlp::Error::UnexpectedLength),
        }
    }
}

/// Full `Node::decode`-parity validation of one node encoding, advancing `r`
/// past it. Recurses into inline (list) children. Returns the node kind.
///
/// Single pass over the items: the count decides the grammar (2 vs 17), so
/// items 0 and 1 are checked after the scan while items 2.. are checked as
/// branch slots on the spot (with three or more items nothing but a 17-item
/// branch can validate). The accepted set is exactly `Node::decode`'s; when
/// several defects coexist the reported error is the first one met in this
/// order rather than `decode_raw`'s header-scan-first order.
fn validate_at(r: &mut &[u8]) -> alloy_rlp::Result<NodeKind> {
    let h = decode_header(r)?;
    if !h.list {
        // As an inline child this is handled at the item site (empty/digest);
        // as a top-level walk entry a bare string is unusable (see module docs).
        return Err(alloy_rlp::Error::Custom("bare string node in walk"));
    }
    // `decode_header` checked `r.len() >= payload_length`.
    let (mut p, rest) = r.split_at(h.payload_length);
    *r = rest;

    // (item, is_list, payload length) of items 0 and 1.
    let mut first: [(&[u8], bool, usize); 2] = [(&[], false, 0); 2];
    let mut items = 0usize;
    let mut children = 0usize;
    while !p.is_empty() {
        let (list, hlen, plen) = item_header(p)?;
        let (item, rest) = p.split_at(hlen + plen);
        p = rest;
        match items {
            0 | 1 => first[items] = (item, list, plen),
            2..=15 => children += validate_branch_child(item, list, plen)?,
            16 => {
                if list || plen != 0 {
                    return Err(alloy_rlp::Error::Custom("branch node with value"));
                }
            }
            _ => return Err(alloy_rlp::Error::Custom("unexpected list length")),
        }
        items += 1;
    }
    match items {
        17 => {
            for (item, list, plen) in first {
                children += validate_branch_child(item, list, plen)?;
            }
            if children < 2 {
                return Err(alloy_rlp::Error::Custom("branch node without two children"));
            }
            Ok(NodeKind::Branch)
        }
        2 => {
            // item 0: compact HP path (string, non-empty, flag nibble <= 3).
            let (path, path_list, plen) = first[0];
            if path_list {
                return Err(alloy_rlp::Error::UnexpectedString);
            }
            if plen == 0 {
                return Err(alloy_rlp::Error::InputTooShort);
            }
            let flag = path[path.len() - plen] >> 4;
            if flag > 3 {
                return Err(alloy_rlp::Error::Custom("node is not an extension or leaf"));
            }
            let is_leaf = flag >= 2;
            // item 1
            let (value, value_list, vlen) = first[1];
            if is_leaf {
                // value must be a string (Bytes::decode parity); contents are
                // not validated here — exactly like the eager decode.
                if value_list {
                    return Err(alloy_rlp::Error::UnexpectedList);
                }
                Ok(NodeKind::Leaf)
            } else {
                // extension child: digest or inline node that must be a branch.
                if value_list {
                    let mut child = value;
                    if validate_at(&mut child)? != NodeKind::Branch {
                        return Err(alloy_rlp::Error::Custom(
                            "extension node with invalid child",
                        ));
                    }
                } else if vlen != 32 {
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
    let h = decode_header(&mut r).expect("validated");
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
        let ph = decode_header(&mut q).expect("validated");
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
        let h = decode_header(&mut p).expect("validated");
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
                let (list, hlen, plen) = item_header(p).expect("validated");
                if list {
                    // INV-W5: inline child — continue on the parent's bytes.
                    span = &p[..hlen + plen];
                    kind = classify(span);
                    continue;
                }
                match plen {
                    0 => return Step::Absent, // authenticated-empty ⇒ exclusion
                    32 => return Step::Digest(le_words_32(&p[hlen..])),
                    _ => unreachable!("validated"),
                }
            }
            NodeKind::Extension => {
                let ph = decode_header(&mut p).expect("validated");
                let compact = &p[..ph.payload_length];
                p = &p[ph.payload_length..];
                let Some(plen) = match_path(compact, key, *depth, false) else {
                    return Step::Absent; // authenticated divergence ⇒ exclusion
                };
                *depth += plen;
                let before = p;
                let vh = decode_header(&mut p).expect("validated");
                if vh.list {
                    span = &before[..before.len() - p.len() + vh.payload_length];
                    kind = classify(span);
                    continue;
                }
                debug_assert_eq!(vh.payload_length, 32);
                return Step::Digest(le_words_32(p));
            }
            NodeKind::Leaf => {
                let ph = decode_header(&mut p).expect("validated");
                let compact = &p[..ph.payload_length];
                p = &p[ph.payload_length..];
                if match_path(compact, key, *depth, true).is_none() {
                    return Step::Absent;
                }
                let vh = decode_header(&mut p).expect("validated");
                let start = p.as_ptr() as usize - entry.as_ptr() as usize;
                return Step::Value(start..start + vh.payload_length);
            }
            NodeKind::Unvalidated => unreachable!("kind memoized before walking"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use alloy_rlp::Header;

    /// `item_header` agrees with `Header::decode` (header/payload lengths, list
    /// flag, or error) on every 1-byte item, every 33-byte item prefix,
    /// truncated digest items and long-form headers.
    #[test]
    fn item_header_matches_header_decode() {
        fn via_header(p: &[u8]) -> alloy_rlp::Result<(bool, usize, usize)> {
            let mut q = p;
            let h = Header::decode(&mut q)?;
            Ok((h.list, p.len() - q.len(), h.payload_length))
        }
        let mut cases: Vec<Vec<u8>> = vec![vec![]];
        for b in 0..=255u8 {
            cases.push(vec![b]);
            let mut item = vec![b];
            item.extend((0..32u8).map(|i| i.wrapping_mul(7)));
            cases.push(item.clone());
            item.truncate(20);
            cases.push(item);
        }
        cases.push(vec![0xb8, 0x38]);
        cases.push(vec![0xb8, 0x37]);
        cases.push(vec![0xb9, 0x00, 0x40]);
        cases.push(vec![0xf9, 0x01, 0x00]);
        let mut long = vec![0xf8, 0x40];
        long.resize(2 + 0x40, 0x80);
        cases.push(long);
        for case in &cases {
            assert_eq!(item_header(case), via_header(case), "{case:02x?}");
        }
    }

    fn digest_item(seed: u8) -> Vec<u8> {
        let mut v = vec![0xa0];
        v.extend((0..32u8).map(|i| i.wrapping_mul(seed).wrapping_add(seed)));
        v
    }

    fn list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.concat();
        let mut out = Vec::new();
        Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut out);
        out.extend_from_slice(&payload);
        out
    }

    fn branch(children: &[(usize, Vec<u8>)], value: Vec<u8>) -> Vec<u8> {
        let mut items = vec![vec![EMPTY_STRING_CODE]; 17];
        for (i, child) in children {
            items[*i] = child.clone();
        }
        items[16] = value;
        list(&items)
    }

    /// The walk validator accepts exactly the list encodings `Node::decode`
    /// accepts (bare strings are the documented narrowing) and reports the
    /// kind the grammar implies.
    #[test]
    fn validate_entry_matches_node_decode() {
        let leaf = list(&[vec![0x83, 0x20, 0x12, 0x34], vec![0x82, 0xab, 0xcd]]);
        let mut long_value = vec![0xb8, 0x40];
        long_value.extend(core::iter::repeat_n(0x11u8, 0x40));
        let long_leaf = list(&[vec![0x82, 0x20, 0x12], long_value]);
        let inline_branch = branch(&[(1, digest_item(3)), (2, digest_item(4))], vec![0x80]);
        let mut path32 = vec![0xa0, 0x20];
        path32.extend(core::iter::repeat_n(0x77u8, 31));
        let cases: Vec<(Vec<u8>, Option<NodeKind>)> = vec![
            (vec![0xc0], None),
            (vec![0x81, 0x05], None),
            (vec![0xf9, 0x00, 0x10, 0x80], None),
            (vec![0xc2, 0x80], None),
            (
                branch(&[(0, digest_item(1)), (5, digest_item(2))], vec![0x80]),
                Some(NodeKind::Branch),
            ),
            (
                branch(&[(0, digest_item(1)), (5, leaf.clone())], vec![0x80]),
                Some(NodeKind::Branch),
            ),
            (
                branch(
                    &[(0, digest_item(1)), (7, inline_branch.clone())],
                    vec![0x80],
                ),
                Some(NodeKind::Branch),
            ),
            (
                branch(&[(15, digest_item(1)), (7, leaf.clone())], vec![0x80]),
                Some(NodeKind::Branch),
            ),
            (branch(&[(0, digest_item(1))], vec![0x80]), None),
            (
                branch(&[(0, leaf.clone()), (1, digest_item(2))], vec![0x01]),
                None,
            ),
            (
                branch(
                    &[(0, digest_item(1)), (5, digest_item(2))],
                    vec![0x81, 0x05],
                ),
                None,
            ),
            (
                branch(&[(0, digest_item(1)), (5, digest_item(2))], vec![0xc0]),
                None,
            ),
            (
                branch(&[(0, digest_item(1)), (5, digest_item(2))], leaf.clone()),
                None,
            ),
            (
                branch(
                    &[(3, vec![0x82, 0x01, 0x02]), (5, digest_item(2))],
                    vec![0x80],
                ),
                None,
            ),
            (
                branch(&[(3, vec![0x02]), (5, digest_item(2))], vec![0x80]),
                None,
            ),
            (
                branch(&[(3, vec![0xc0]), (5, digest_item(2))], vec![0x80]),
                None,
            ),
            (
                branch(&[(0, vec![0xc0]), (5, digest_item(2))], vec![0x80]),
                None,
            ),
            (
                branch(&[(3, vec![0x81, 0x05]), (5, digest_item(2))], vec![0x80]),
                None,
            ),
            (
                branch(
                    &[(3, digest_item(2)[..20].to_vec()), (5, digest_item(2))],
                    vec![0x80],
                ),
                None,
            ),
            (
                branch(
                    &[(1, vec![0x82, 0x01, 0x02]), (5, digest_item(2))],
                    vec![0x80],
                ),
                None,
            ),
            (leaf.clone(), Some(NodeKind::Leaf)),
            (long_leaf, Some(NodeKind::Leaf)),
            (list(&[path32, digest_item(9)]), Some(NodeKind::Leaf)),
            (
                list(&[vec![0x1f], digest_item(2)]),
                Some(NodeKind::Extension),
            ),
            (
                list(&[vec![0x00], digest_item(2)]),
                Some(NodeKind::Extension),
            ),
            (
                list(&[vec![0x00], inline_branch.clone()]),
                Some(NodeKind::Extension),
            ),
            (list(&[vec![0x00], leaf.clone()]), None),
            (list(&[vec![0x00], vec![0x80]]), None),
            (list(&[vec![0x00], vec![0x83, 1, 2, 3]]), None),
            (list(&[vec![0x81, 0x40], digest_item(2)]), None),
            (list(&[vec![0x80], digest_item(2)]), None),
            (list(&[vec![0xc1, 0x20], digest_item(2)]), None),
            (
                list(&[vec![0x82, 0x20, 0x12], vec![0xc2, 0xab, 0xcd]]),
                None,
            ),
            (list(&[vec![0x82, 0x20, 0x12], vec![0x81, 0x05]]), None),
            (list(&[vec![0x82, 0x20, 0x12]]), None),
            (
                list(&[vec![0x82, 0x20, 0x12], vec![0x80], vec![0x80]]),
                None,
            ),
            (list(&[vec![0xa0, 0x20]]), None),
        ];
        for (case, kind) in &cases {
            for trailing in [0usize, 1] {
                let mut bytes = case.clone();
                bytes.extend(core::iter::repeat_n(0x80u8, trailing));
                let decodes = zeth_mpt::Trie::from_rlp([&bytes]).is_ok();
                let got = validate_entry(&bytes);
                assert_eq!(got.is_ok(), decodes, "{bytes:02x?}: {got:?}");
                if trailing == 0 {
                    assert_eq!(got.ok(), *kind, "{bytes:02x?}");
                }
            }
        }
    }
}
