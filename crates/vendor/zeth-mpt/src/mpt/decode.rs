// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Zero-copy node decoder: nodes decode straight into their final slots,
//! leaf values are views into the witness bytes, and list payloads are
//! scanned in place instead of through alloy's `PayloadView`.
use super::{
    children::{Children, Slot},
    memoize::Memoization,
    node::{Digest, Node},
    rlp::{DIGEST_ITEM_PREFIX, DIGEST_RLP_LENGTH},
};
use alloc::boxed::Box;
use alloy_primitives::{Bytes, B256};
use alloy_rlp::{Header, EMPTY_STRING_CODE};
use alloy_trie::Nibbles;
use core::{mem::MaybeUninit, ptr::read_volatile};

impl<M: Memoization> Node<M> {
    /// Decode `bytes` — the authenticated encoding of the [`Node::Digest`]
    /// stub `*self` — straight into this node's slot, so the resolved node is
    /// never moved (`*self = node` would copy the whole node).
    ///
    /// Requires `*self` to be `Node::Digest(*digest)` (checked by
    /// `debug_assert` only; a violation overwrites a resource-owning node
    /// without dropping it — a leak, not UB). On `Ok`, `*self` is the decoded
    /// node (possibly itself a `Digest`); on `Err`, `*self` is the original
    /// stub again.
    pub(super) fn decode_stub_in_place(
        &mut self,
        digest: &Digest,
        bytes: &Bytes,
    ) -> alloy_rlp::Result<()> {
        debug_assert!(matches!(self, Node::Digest(d) if d == digest));
        // SAFETY: `MaybeUninit<Node<M>>` has the layout of `Node<M>`, and a
        // `Node::Digest` owns no resources, so its bytes may be overwritten
        // without a drop. `decode_node_zc_exact_into` keeps the slot either
        // untouched or holding a fully valid `Node` at every point (whole-value
        // `MaybeUninit::write`s; the branch arm then mutates the written node
        // in place through `&mut Node` and resets it to `Node::Null` on
        // failure), and on `Err` leaves it untouched or `Node::Null` — so
        // `*self` is a valid, drop-safe node at every panic point and on both
        // result paths.
        let slot = unsafe { &mut *(self as *mut Self as *mut MaybeUninit<Self>) };
        let result = decode_node_zc_exact_into(bytes, slot);
        if result.is_err() {
            *self = Node::Digest(*digest);
        }
        result
    }
}

/// Zero-copy node decode. Same grammar and validation as the reference
/// `Decodable` impl (kept as a test oracle in `tests`), except leaf values
/// become [`Bytes::slice_ref`] views into `source` — the RLP-encoded node
/// bytes that `buf` points into — instead of allocated copies.
///
/// Out-param form: the string/leaf/extension arms write `out` once at the arm
/// end; the branch arm writes the empty branch first and decodes the children
/// into its slots in place (`Children` is never moved), reassigning
/// `Node::Null` on failure. Digest children are stored inline in their
/// [`Slot`]; other children are decoded straight into their final heap slot
/// (`Box::new_uninit`), deleting the by-value move chain (return → `?` →
/// `Box::new`, each a whole-node copy).
///
/// List payloads are scanned in place instead of through
/// `Header::decode_raw`'s `PayloadView` `Vec` (allocation + 3 grows + 17
/// pushes per branch): pass 1 ([`count_items`]) validates every item header
/// in order and yields the item count exactly like `decode_raw`, pass 2
/// re-derives the item boundaries with the same [`item_len`] while decoding
/// (the count decides the grammar, so boundaries cannot be consumed on the
/// fly: a 33-byte leaf path item is indistinguishable from a digest item
/// until the count is known).
///
/// Contract: on `Ok(())`, `out` holds the decoded node. On `Err`, `out` is
/// either untouched or holds the resource-free [`Node::Null`] (a branch whose
/// children failed to decode is dropped and replaced) — never partially
/// written. At every panic point `out` is untouched or holds a valid node.
fn decode_node_zc_into<M: Memoization>(
    source: &Bytes,
    buf: &mut &[u8],
    out: &mut MaybeUninit<Node<M>>,
) -> alloy_rlp::Result<()> {
    let h = decode_header(buf)?;
    // `decode_header` checked `buf.len() >= payload_length`.
    let (payload, rest) = buf.split_at(h.payload_length);
    *buf = rest;
    if !h.list {
        // if the node is not a list, it must be empty or a digest
        return match payload.len() {
            0 => {
                out.write(Node::Null);
                Ok(())
            }
            32 => {
                out.write(Node::Digest(Digest(B256::from_slice(payload))));
                Ok(())
            }
            _ => Err(alloy_rlp::Error::UnexpectedLength),
        };
    }
    match count_items(payload)? {
        // branch node: 17-item node [ v0 ... v15, value ]
        17 => {
            // Write the empty branch first and decode the children into
            // its slots, so the 640-byte `Children` is never moved.
            let node = out.write(Node::Branch(Children::default(), M::default()));
            let Node::Branch(children, _) = &mut *node else {
                unreachable!()
            };
            let filled = decode_branch_children(source, payload, children);
            if filled.is_err() {
                *node = Node::Null; // drops the partial branch
            }
            filled
        }
        // leaf or extension node: 2-item node [ encodedPath, v ]
        // they are distinguished by a flag in the first nibble of the encodedPath
        2 => {
            // pass 1 validated both item headers, so this cannot fail
            let (mut encode_path, v) = payload.split_at(item_len(payload)?);
            let (path, is_leaf) = decode_path(&mut encode_path)?;
            if is_leaf {
                let value = decode_string(&mut &v[..])?;
                out.write(Node::Leaf(path, source.slice_ref(value), M::default()));
                Ok(())
            } else {
                let mut child = Box::<Node<M>>::new_uninit();
                decode_child_into(source, v, &mut child)?;
                // SAFETY: `Ok` return above ⇒ the callee wrote a fully
                // initialized `Node` into the slot.
                let child = unsafe { child.assume_init() };
                if !matches!(*child, Node::Branch(..) | Node::Digest(..)) {
                    return Err(alloy_rlp::Error::Custom(
                        "extension node with invalid child",
                    ));
                }
                out.write(Node::Extension(path, child, M::default()));
                Ok(())
            }
        }
        _ => Err(alloy_rlp::Error::Custom("unexpected list length")),
    }
}

/// [`Header::decode`] with the long-form length read byte-wise: alloy copies
/// the 1–8 length bytes into a zero-padded `[u8; 8]` and byte-swaps it
/// (`static_left_pad` + `from_be_bytes` — a `memcpy` call and a swap per
/// long header, ~80 rows on riscv64imac); here each byte is one `lbu` folded
/// into the accumulator. Same checks in the same order, same errors, same
/// buffer advance (a single byte below `0x80` is its own payload and does not
/// advance).
#[inline(always)]
pub fn decode_header(buf: &mut &[u8]) -> alloy_rlp::Result<Header> {
    let Some(&b) = buf.first() else {
        return Err(alloy_rlp::Error::InputTooShort);
    };
    let (list, payload_length) = match b {
        0..=0x7f => (false, 1),
        EMPTY_STRING_CODE..=0xb7 => {
            *buf = &buf[1..];
            let payload_length = (b - EMPTY_STRING_CODE) as usize;
            if payload_length == 1 {
                match buf.first() {
                    None => return Err(alloy_rlp::Error::InputTooShort),
                    Some(&next) if next < EMPTY_STRING_CODE => {
                        return Err(alloy_rlp::Error::NonCanonicalSingleByte)
                    }
                    Some(_) => {}
                }
            }
            (false, payload_length)
        }
        0xb8..=0xbf | 0xf8..=0xff => {
            *buf = &buf[1..];
            let list = b >= 0xf8;
            let len_of_len = (b - if list { 0xf7 } else { 0xb7 }) as usize;
            if buf.len() < len_of_len {
                return Err(alloy_rlp::Error::InputTooShort);
            }
            let (len_bytes, rest) = buf.split_at(len_of_len);
            *buf = rest;
            if len_bytes[0] == 0 {
                return Err(alloy_rlp::Error::LeadingZero);
            }
            let mut len = 0u64;
            for &x in len_bytes {
                len = (len << 8) | x as u64;
            }
            let payload_length =
                usize::try_from(len).map_err(|_| alloy_rlp::Error::Custom("Input too big"))?;
            if payload_length < 56 {
                return Err(alloy_rlp::Error::NonCanonicalSize);
            }
            (list, payload_length)
        }
        0xc0..=0xf7 => {
            *buf = &buf[1..];
            (true, (b - 0xc0) as usize)
        }
    };
    if buf.len() < payload_length {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    Ok(Header {
        list,
        payload_length,
    })
}

/// `Header::decode_bytes(buf, false)` on top of [`decode_header`]: the payload
/// of a string item, advancing `buf` past it.
#[inline(always)]
fn decode_string<'a>(buf: &mut &'a [u8]) -> alloy_rlp::Result<&'a [u8]> {
    let h = decode_header(buf)?;
    if h.list {
        return Err(alloy_rlp::Error::UnexpectedList);
    }
    let (payload, rest) = buf.split_at(h.payload_length);
    *buf = rest;
    Ok(payload)
}

/// Header + payload length of the RLP item at the start of the non-empty
/// `p`, validated exactly like [`Header::decode`] — the general arm calls
/// its local twin [`decode_header`]; the two fast paths cover the dominant branch items and cannot
/// fail: `0x80` is the empty string (payload 0) and `0xa0` a 32-byte string
/// whose payload is present when `p` holds the whole item.
#[inline(always)]
fn item_len(p: &[u8]) -> alloy_rlp::Result<usize> {
    debug_assert!(!p.is_empty());
    match p[0] {
        EMPTY_STRING_CODE => Ok(1),
        DIGEST_ITEM_PREFIX if p.len() >= DIGEST_RLP_LENGTH => Ok(DIGEST_RLP_LENGTH),
        _ => {
            let mut q = p;
            let h = decode_header(&mut q)?;
            Ok(p.len() - q.len() + h.payload_length)
        }
    }
}

/// Number of RLP items in a list payload; every item header is decoded and
/// validated in order, first error wins — the item scan of
/// `Header::decode_raw` without its `Vec`.
#[inline(always)]
fn count_items(mut p: &[u8]) -> alloy_rlp::Result<usize> {
    let mut n = 0usize;
    while !p.is_empty() {
        p = &p[item_len(p)?..];
        n += 1;
    }
    Ok(n)
}

/// Decode the 16 child items of the 17-item branch payload `p` straight into
/// `children` (the slots of a freshly written empty [`Node::Branch`]); item
/// 16 must be the empty value. Digest items — the dominant child kind — land
/// inline as [`Slot::Digest`] (a tag and four aligned `sd`, no allocation);
/// other items are decoded into a fresh heap node. Every slot is written only
/// once its item is fully decoded, so the branch is a valid node at every
/// point; children decoded before an `Err` stay owned by it.
fn decode_branch_children<M: Memoization>(
    source: &Bytes,
    mut p: &[u8],
    children: &mut Children<M>,
) -> alloy_rlp::Result<()> {
    let mut count = 0usize;
    for slot in children.iter_mut() {
        // pass 1 counted exactly 17 validated items over `p`
        let (item, rest) = p.split_at(item_len(p)?);
        p = rest;
        if item == [EMPTY_STRING_CODE] {
            continue;
        }
        if is_digest_item(item) {
            slot.fill_digest(digest_item(item));
        } else {
            let mut child = Box::<Node<M>>::new_uninit();
            decode_node_zc_into(source, &mut &item[..], &mut child)?;
            // SAFETY: `Ok` return above ⇒ the callee wrote a fully initialized
            // `Node` into the slot. On `Err`, `?` drops the `Box<MaybeUninit<..>>`
            // without reading it; the slot is untouched or `Node::Null`, so
            // nothing leaks.
            *slot = Slot::from_child(unsafe { child.assume_init() });
        }
        count += 1;
    }
    // the 17th item is the value, which this MPT never carries
    if p != [EMPTY_STRING_CODE] {
        return Err(alloy_rlp::Error::Custom("branch node with value"));
    }
    if count < 2 {
        return Err(alloy_rlp::Error::Custom("branch node without two children"));
    }
    Ok(())
}

/// Decode one child item (a complete RLP item, as cut by the parent's list
/// scan) into `out`. Digest items take the word-gather fast path; everything
/// else goes through the general decoder. Same contract as
/// [`decode_node_zc_into`].
#[inline(always)]
fn decode_child_into<M: Memoization>(
    source: &Bytes,
    item: &[u8],
    out: &mut MaybeUninit<Node<M>>,
) -> alloy_rlp::Result<()> {
    if is_digest_item(item) {
        out.write(Node::Digest(digest_item(item)));
        Ok(())
    } else {
        decode_node_zc_into(source, &mut &item[..], out)
    }
}

/// Whether `item` is `0xa0` + 32 bytes: a 32-byte string can only be encoded
/// this way, and `Header::decode` on `0xa0` applies no canonicality condition.
#[inline(always)]
fn is_digest_item(item: &[u8]) -> bool {
    item.len() == DIGEST_RLP_LENGTH && item[0] == DIGEST_ITEM_PREFIX
}

/// The digest of the `0xa0` + 32 bytes item `item`: exactly the
/// [`Node::Digest`] payload [`decode_node_zc_into`] yields for it, without the
/// recursive call and the `memcpy(32)` of `B256::from_slice` — the 32 bytes
/// at `item[1..]` are gathered word-wise ([`le_words_32`]) and land as four
/// aligned `sd`s in the 8-aligned [`Digest`].
#[inline(always)]
fn digest_item(item: &[u8]) -> Digest {
    debug_assert!(is_digest_item(item));
    Digest::from_le_limbs(le_words_32(&item[1..]))
}

/// The 32 bytes at `bytes[..32]` (any alignment) as four little-endian words
/// (word `i` = bytes `8i..8i+8`), gathered from the aligned machine words
/// containing them: 4 `ld` when `bytes` is 8-aligned, else 5 `ld` + shift/or
/// — never a sub-word access, never an unaligned one (Jolt expands every
/// `lbu` into 3 trace rows and traps on misaligned `ld`; `read_unaligned`
/// lowers to byte loads on riscv64imac).
///
/// # Safety of the containing-word reads
/// Every word read holds at least one live byte of `bytes[..32]` (word 0
/// holds byte 0, the last word holds byte 31), and by the flat-RAM argument
/// of the guest `mem.rs` overrides — Jolt guest RAM is flat and
/// word-granular; natively the containing word lies in the same allocation
/// granule / page — the aligned word containing a live byte is readable.
/// Every load address is a multiple of 8 by construction.
#[inline(always)]
pub fn le_words_32(bytes: &[u8]) -> [u64; 4] {
    assert!(bytes.len() >= 32);
    let src = bytes.as_ptr() as usize;
    let so = src & 7;
    let base = (src & !7) as *const u64;
    unsafe {
        let w0 = u64::from_le(read_volatile(base));
        let w1 = u64::from_le(read_volatile(base.add(1)));
        let w2 = u64::from_le(read_volatile(base.add(2)));
        let w3 = u64::from_le(read_volatile(base.add(3)));
        if so == 0 {
            [w0, w1, w2, w3]
        } else {
            let w4 = u64::from_le(read_volatile(base.add(4)));
            let sr = (8 * so) as u32;
            let sl = 64 - sr;
            [
                (w0 >> sr) | (w1 << sl),
                (w1 >> sr) | (w2 << sl),
                (w2 >> sr) | (w3 << sl),
                (w3 >> sr) | (w4 << sl),
            ]
        }
    }
}

/// [`decode_node_zc_into`] over the whole buffer, mirroring `alloy_rlp::decode_exact`.
///
/// Contract: on `Ok`, `out` holds the decoded node. On `Err`, `out` is either
/// untouched or holds [`Node::Null`] (inherited from [`decode_node_zc_into`],
/// plus the trailing-bytes refusal of a complete decode) — never partially
/// written, so a caller may alias `out` with a live `&mut Node<M>` slot
/// ([`Node::decode_stub_in_place`]).
pub(super) fn decode_node_zc_exact_into<M: Memoization>(
    source: &Bytes,
    out: &mut MaybeUninit<Node<M>>,
) -> alloy_rlp::Result<()> {
    let mut buf = source.as_ref();
    decode_node_zc_into(source, &mut buf, out)?;
    if !buf.is_empty() {
        // SAFETY: `Ok` return above ⇒ `out` is fully initialized. Drop it and
        // leave a resource-free node behind for aliasing callers.
        unsafe { out.assume_init_drop() };
        out.write(Node::Null);
        return Err(alloy_rlp::Error::UnexpectedLength);
    }
    Ok(())
}

#[inline]
fn decode_path(buf: &mut &[u8]) -> alloy_rlp::Result<(Nibbles, bool)> {
    let compact = decode_string(buf)?;
    if compact.is_empty() {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    let (is_leaf, odd_len) = match compact[0] >> 4 {
        0b0000 => (false, false),
        0b0001 => (false, true),
        0b0010 => (true, false),
        0b0011 => (true, true),
        _ => return Err(alloy_rlp::Error::Custom("node is not an extension or leaf")),
    };
    // Strip the HP prefix: for odd length, the first nibble of the key is in the low nibble
    // of the first byte; for even length, skip the first byte entirely.
    let nibbles = if odd_len {
        let first = compact[0] & 0x0f;
        let mut n = Nibbles::from_nibbles_unchecked([first]);
        n.extend(&Nibbles::unpack(&compact[1..]));
        n
    } else {
        Nibbles::unpack(&compact[1..])
    };
    Ok((nibbles, is_leaf))
}

#[cfg(test)]
mod tests {
    use super::{super::memoize::Cache, *};
    use alloc::{vec, vec::Vec};
    use alloy_rlp::{Decodable, PayloadView};

    /// Reference decoder (upstream zeth-mpt's `Decodable` impl, scanning
    /// through `Header::decode_raw` into allocated values): the oracle the
    /// zero-copy decoder is checked against.
    impl<M: Memoization> Decodable for Node<M> {
        fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
            match Header::decode_raw(buf)? {
                // if the node is not a list, it must be empty or a digest
                PayloadView::String(payload) => match payload.len() {
                    0 => Ok(Node::Null),
                    32 => Ok(Node::Digest(Digest(B256::from_slice(payload)))),
                    _ => Err(alloy_rlp::Error::UnexpectedLength),
                },
                PayloadView::List(items) => match items.len() {
                    // branch node: 17-item node [ v0 ... v15, value ]
                    17 => {
                        let mut children = Children::default();
                        for (i, child_rlp) in items.iter().enumerate() {
                            if child_rlp != &[EMPTY_STRING_CODE] {
                                if i == 16 {
                                    return Err(alloy_rlp::Error::Custom("branch node with value"));
                                } else {
                                    children
                                        .insert(i as u8, Node::decode(&mut &child_rlp[..])?.into());
                                }
                            }
                        }
                        if children.len() < 2 {
                            return Err(alloy_rlp::Error::Custom(
                                "branch node without two children",
                            ));
                        }

                        Ok(Node::Branch(children, M::default()))
                    }
                    // leaf or extension node: 2-item node [ encodedPath, v ]
                    // they are distinguished by a flag in the first nibble of the encodedPath
                    2 => {
                        let [mut encode_path, mut v] = items.as_slice() else {
                            unreachable!()
                        };
                        let (path, is_leaf) = decode_path(&mut encode_path)?;
                        if is_leaf {
                            Ok(Node::Leaf(path, Bytes::decode(&mut v)?, M::default()))
                        } else {
                            let node = Node::decode(&mut v)?;
                            if !matches!(node, Node::Branch(..) | Node::Digest(..)) {
                                return Err(alloy_rlp::Error::Custom(
                                    "extension node with invalid child",
                                ));
                            }
                            Ok(Node::Extension(path, node.into(), M::default()))
                        }
                    }
                    _ => Err(alloy_rlp::Error::Custom("unexpected list length")),
                },
            }
        }
    }

    /// `item_len` agrees with `Header::decode` (length or error) on every
    /// 1-byte item, every 33-byte item prefix, truncated digest items and
    /// long-form headers.
    #[test]
    fn item_len_matches_header_decode() {
        fn via_header(p: &[u8]) -> alloy_rlp::Result<usize> {
            let mut q = p;
            let h = Header::decode(&mut q)?;
            Ok(p.len() - q.len() + h.payload_length)
        }
        let mut cases: Vec<Vec<u8>> = Vec::new();
        for b in 0..=255u8 {
            cases.push(vec![b]);
            let mut item = vec![b];
            item.extend((0..32u8).map(|i| i.wrapping_mul(7)));
            cases.push(item.clone());
            item.truncate(20);
            cases.push(item);
        }
        cases.push(vec![0xa0, 0x00]);
        cases.push(vec![0xb8, 0x38]);
        cases.push(vec![0xb8, 0x37]);
        cases.push(vec![0xb9, 0x00, 0x40]);
        cases.push(vec![0xf8, 0x40]);
        cases.push(vec![0xf9, 0x01, 0x00]);
        let mut long = vec![0xf8, 0x40];
        long.resize(2 + 0x40, 0x80);
        cases.push(long);
        for case in &cases {
            assert_eq!(item_len(case), via_header(case), "{case:02x?}");
        }
    }

    /// The zero-copy decoder agrees with the `Decodable` impl (which scans
    /// through `Header::decode_raw`) on nodes, errors and trailing bytes.
    #[test]
    fn zc_decode_matches_decodable_impl() {
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
        let leaf = list(&[vec![0x83, 0x20, 0x12, 0x34], vec![0x82, 0xab, 0xcd]]);
        let mut long_leaf_value = vec![0xb8, 0x40];
        long_leaf_value.extend(core::iter::repeat_n(0x11u8, 0x40));
        let long_leaf = list(&[vec![0x82, 0x20, 0x12], long_leaf_value]);
        let inline_branch = branch(&[(1, digest_item(3)), (2, digest_item(4))], vec![0x80]);
        let mut path32 = vec![0xa0, 0x20];
        path32.extend(core::iter::repeat_n(0x77u8, 31));
        let cases: Vec<Vec<u8>> = vec![
            vec![0x80],
            digest_item(1),
            vec![0x83, 1, 2, 3],
            vec![0xc0],
            vec![0x05],
            vec![0x81, 0x05],
            vec![0xb8, 0x05],
            vec![0xb9, 0x00, 0x40],
            branch(&[(0, digest_item(1)), (5, digest_item(2))], vec![0x80]),
            branch(&[(0, digest_item(1)), (5, leaf.clone())], vec![0x80]),
            branch(
                &[(0, digest_item(1)), (7, inline_branch.clone())],
                vec![0x80],
            ),
            branch(&[(0, digest_item(1))], vec![0x80]),
            branch(&[(0, digest_item(1)), (5, digest_item(2))], vec![0x01]),
            branch(
                &[(0, digest_item(1)), (5, digest_item(2))],
                vec![0x81, 0x05],
            ),
            branch(
                &[(3, vec![0x82, 0x01, 0x02]), (5, digest_item(2))],
                vec![0x80],
            ),
            branch(&[(3, vec![0x02]), (5, digest_item(2))], vec![0x80]),
            branch(&[(3, vec![0xc0]), (5, digest_item(2))], vec![0x80]),
            branch(&[(3, vec![0x81, 0x05]), (5, digest_item(2))], vec![0x80]),
            branch(
                &[(3, digest_item(2)[..20].to_vec()), (5, digest_item(2))],
                vec![0x80],
            ),
            leaf.clone(),
            long_leaf,
            list(&[path32, digest_item(9)]),
            list(&[vec![0x1f], digest_item(2)]),
            list(&[vec![0x00], digest_item(2)]),
            list(&[vec![0x00], inline_branch.clone()]),
            list(&[vec![0x00], leaf.clone()]),
            list(&[vec![0x00], vec![0x80]]),
            list(&[vec![0x81, 0x40], digest_item(2)]),
            list(&[vec![0x80], digest_item(2)]),
            list(&[vec![0xc1, 0x20], digest_item(2)]),
            list(&[vec![0x82, 0x20, 0x12], vec![0xc2, 0xab, 0xcd]]),
            list(&[vec![0x82, 0x20, 0x12], vec![0x81, 0x05]]),
            list(&[vec![0x82, 0x20, 0x12]]),
            list(&[vec![0x82, 0x20, 0x12], vec![0x80], vec![0x80]]),
            list(&[vec![0xa0, 0x20]]),
            vec![0xf9, 0x00, 0x10, 0x80],
            vec![0xc2, 0x80],
        ];
        for case in &cases {
            for trailing in [0usize, 1] {
                let mut bytes = case.clone();
                bytes.extend(core::iter::repeat_n(0x80u8, trailing));
                let source = Bytes::from(bytes);
                let expected = alloy_rlp::decode_exact::<Node<Cache>>(&source);
                let mut slot = MaybeUninit::<Node<Cache>>::uninit();
                let got = decode_node_zc_exact_into(&source, &mut slot);
                match (expected, got) {
                    (Ok(node), Ok(())) => {
                        assert_eq!(unsafe { slot.assume_init() }, node, "{source}")
                    }
                    (Err(e), Err(g)) => assert_eq!(e, g, "{source}"),
                    (e, g) => panic!("{source}: expected {e:?}, got {g:?}"),
                }
            }
        }
    }

    /// `decode_header` agrees with `Header::decode` (header or error, and the
    /// buffer advance) for every first byte over a range of tails: short and
    /// long lengths with and without their payload, leading zeros,
    /// non-canonical sizes, truncated length fields.
    #[test]
    fn decode_header_matches_alloy() {
        let tails: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0x05],
            vec![0x7f],
            vec![0x80],
            vec![0x37],
            vec![0x38],
            vec![0x00, 0x40],
            vec![0x01, 0x00],
            vec![0x01, 0x00, 0x00],
            vec![0xff; 8],
            vec![0x01; 9],
        ];
        for b in 0..=255u8 {
            for tail in &tails {
                for payload in [0usize, 1, 55, 56, 300] {
                    let mut bytes = vec![b];
                    bytes.extend_from_slice(tail);
                    bytes.extend(core::iter::repeat_n(0x11u8, payload));
                    let mut ours = &bytes[..];
                    let mut theirs = &bytes[..];
                    let got = decode_header(&mut ours);
                    let want = Header::decode(&mut theirs);
                    assert_eq!(got, want, "{bytes:02x?}");
                    assert_eq!(ours.len(), theirs.len(), "{bytes:02x?}");
                }
            }
        }
    }

    /// Word gather is byte-exact for every source alignment.
    #[test]
    fn le_words_32_matches_from_le_bytes() {
        let bytes: Vec<u8> = (0..48u8)
            .map(|i| i.wrapping_mul(29).wrapping_add(5))
            .collect();
        for so in 0..8 {
            let got = le_words_32(&bytes[so..]);
            for (i, w) in got.iter().enumerate() {
                let mut chunk = [0u8; 8];
                chunk.copy_from_slice(&bytes[so + 8 * i..so + 8 * i + 8]);
                assert_eq!(*w, u64::from_le_bytes(chunk), "so={so} i={i}");
            }
        }
    }

    /// The digest fast path yields the general decoder's node for every
    /// source alignment.
    #[test]
    fn digest_fast_path_matches_generic_decode() {
        let mut digest = [0u8; 32];
        for (i, b) in digest.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        for so in 0..8 {
            let mut buf = vec![0xeeu8; so];
            buf.push(DIGEST_ITEM_PREFIX);
            buf.extend_from_slice(&digest);
            buf.extend_from_slice(&[0xdd; 9]);
            let source = Bytes::from(buf);
            let item = &source[so..so + DIGEST_RLP_LENGTH];
            assert!(is_digest_item(item));
            let fast = digest_item(item);
            let mut slow = MaybeUninit::<Node<Cache>>::uninit();
            decode_node_zc_into(&source, &mut &item[..], &mut slow).unwrap();
            let slow = unsafe { slow.assume_init() };
            assert_eq!(Node::<Cache>::Digest(fast), slow, "so={so}");
            assert_eq!(fast.0.as_slice(), digest, "so={so}");
        }
    }
}
