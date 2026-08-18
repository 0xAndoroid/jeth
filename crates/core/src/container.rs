//! JEF v1: aligned, length-prefixed guest input with no host-provided offsets.
//!
//! Variable records use `u32 len | 4-byte alignment pad | bytes | trailing pad`.
//! The extra word keeps every borrowed node, code, and header 8-aligned; this is
//! required by the guest's word-at-a-time trie paths.

use alloc::{vec, vec::Vec};
use core::fmt;

pub const MAGIC: u32 = u32::from_le_bytes(*b"JEF1");
pub const VERSION: u16 = 1;
pub const FLAGS: u16 = 0;
pub const SIGNER_SIZE: usize = 72;

// The fields named by the format occupy 36 bytes. Four trailing reserved bytes
// keep the first section 8-aligned.
pub const HEADER_SIZE: usize = 40;

const MAGIC_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 4;
const FLAGS_OFFSET: usize = 6;
const TOTAL_LEN_OFFSET: usize = 8;
const STATE_COUNT_OFFSET: usize = 12;
const CODE_COUNT_OFFSET: usize = 16;
const HEADER_COUNT_OFFSET: usize = 20;
const SIGNER_COUNT_OFFSET: usize = 24;
const LIBRARY_ID_OFFSET: usize = 28;
const RESERVED_OFFSET: usize = 36;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerError {
    Truncated,
    InvalidPadding,
    Misaligned,
    InvalidMagic,
    InvalidVersion,
    InvalidFlags,
    InvalidLength,
    InvalidCount,
    InvalidBlockRlp,
    TooLarge,
}

impl fmt::Display for ContainerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated JEF input",
            Self::InvalidPadding => "invalid JEF alignment prefix",
            Self::Misaligned => "misaligned JEF input",
            Self::InvalidMagic => "invalid JEF magic",
            Self::InvalidVersion => "unsupported JEF version",
            Self::InvalidFlags => "unsupported JEF flags",
            Self::InvalidLength => "invalid JEF length",
            Self::InvalidCount => "invalid JEF count",
            Self::InvalidBlockRlp => "invalid block RLP",
            Self::TooLarge => "JEF input exceeds v1 limits",
        })
    }
}

pub struct ContainerView<'a> {
    pub block_rlp: &'a [u8],
    pub signers: &'a [[u8; SIGNER_SIZE]],
    pub state: Vec<&'a [u8]>,
    pub codes: Vec<&'a [u8]>,
    pub headers: Vec<&'a [u8]>,
    pub library_id_lo: u64,
}

pub struct ContainerReader<'a> {
    bytes: &'a [u8],
    header_start: usize,
    cursor: usize,
}

impl<'a> ContainerReader<'a> {
    pub fn read(bytes: &'a [u8]) -> Result<ContainerView<'a>, ContainerError> {
        let pad_len = *bytes.first().ok_or(ContainerError::Truncated)? as usize;
        if pad_len > 7 {
            return Err(ContainerError::InvalidPadding);
        }
        let header_start = 1usize
            .checked_add(pad_len)
            .ok_or(ContainerError::InvalidLength)?;
        if bytes.len() < header_start + HEADER_SIZE {
            return Err(ContainerError::Truncated);
        }
        if !(bytes.as_ptr() as usize + header_start).is_multiple_of(8) {
            return Err(ContainerError::Misaligned);
        }

        let mut reader = Self {
            bytes,
            header_start,
            cursor: header_start + HEADER_SIZE,
        };

        if reader.header_u32(MAGIC_OFFSET)? != MAGIC {
            return Err(ContainerError::InvalidMagic);
        }
        if reader.header_u16(VERSION_OFFSET)? != VERSION {
            return Err(ContainerError::InvalidVersion);
        }
        if reader.header_u16(FLAGS_OFFSET)? != FLAGS {
            return Err(ContainerError::InvalidFlags);
        }
        if reader.header_u32(RESERVED_OFFSET)? != 0 {
            return Err(ContainerError::InvalidFlags);
        }

        let total_len = reader.header_u32(TOTAL_LEN_OFFSET)? as usize;
        if total_len != bytes.len() - header_start {
            return Err(ContainerError::InvalidLength);
        }

        let state_count = reader.header_u32(STATE_COUNT_OFFSET)? as usize;
        let code_count = reader.header_u32(CODE_COUNT_OFFSET)? as usize;
        let header_count = reader.header_u32(HEADER_COUNT_OFFSET)? as usize;
        let signer_count = reader.header_u32(SIGNER_COUNT_OFFSET)? as usize;
        let library_id_lo = reader.header_u32(LIBRARY_ID_OFFSET)? as u64
            | ((reader.header_u32(LIBRARY_ID_OFFSET + 4)? as u64) << 32);

        let block_len = reader.read_u64()?;
        let block_len = usize::try_from(block_len).map_err(|_| ContainerError::InvalidLength)?;
        let block_rlp = reader.take(block_len)?;
        reader.align_cursor()?;

        let signer_bytes = signer_count
            .checked_mul(SIGNER_SIZE)
            .ok_or(ContainerError::InvalidCount)?;
        let signer_data = reader.take(signer_bytes)?;
        if !(signer_data.as_ptr() as usize).is_multiple_of(8) {
            return Err(ContainerError::Misaligned);
        }
        let signers = unsafe {
            core::slice::from_raw_parts(
                signer_data.as_ptr().cast::<[u8; SIGNER_SIZE]>(),
                signer_count,
            )
        };

        let state = reader.read_records(state_count)?;
        let codes = reader.read_records(code_count)?;
        let headers = reader.read_records(header_count)?;
        if reader.cursor != bytes.len() {
            return Err(ContainerError::InvalidLength);
        }

        Ok(ContainerView {
            block_rlp,
            signers,
            state,
            codes,
            headers,
            library_id_lo,
        })
    }

    fn header_u16(&self, offset: usize) -> Result<u16, ContainerError> {
        self.read_u16_at(self.header_start + offset)
    }

    fn header_u32(&self, offset: usize) -> Result<u32, ContainerError> {
        self.read_u32_at(self.header_start + offset)
    }

    fn read_u16_at(&self, offset: usize) -> Result<u16, ContainerError> {
        let end = offset
            .checked_add(core::mem::size_of::<u16>())
            .ok_or(ContainerError::InvalidLength)?;
        if end > self.bytes.len() {
            return Err(ContainerError::Truncated);
        }
        let ptr = unsafe { self.bytes.as_ptr().add(offset) };
        if !(ptr as usize).is_multiple_of(core::mem::align_of::<u16>()) {
            return Err(ContainerError::Misaligned);
        }
        Ok(u16::from_le(unsafe { ptr.cast::<u16>().read() }))
    }

    fn read_u32_at(&self, offset: usize) -> Result<u32, ContainerError> {
        let end = offset
            .checked_add(core::mem::size_of::<u32>())
            .ok_or(ContainerError::InvalidLength)?;
        if end > self.bytes.len() {
            return Err(ContainerError::Truncated);
        }
        let ptr = unsafe { self.bytes.as_ptr().add(offset) };
        if !(ptr as usize).is_multiple_of(core::mem::align_of::<u32>()) {
            return Err(ContainerError::Misaligned);
        }
        Ok(u32::from_le(unsafe { ptr.cast::<u32>().read() }))
    }

    fn read_u64(&mut self) -> Result<u64, ContainerError> {
        let end = self
            .cursor
            .checked_add(core::mem::size_of::<u64>())
            .ok_or(ContainerError::InvalidLength)?;
        if end > self.bytes.len() {
            return Err(ContainerError::Truncated);
        }
        let ptr = unsafe { self.bytes.as_ptr().add(self.cursor) };
        if !(ptr as usize).is_multiple_of(core::mem::align_of::<u64>()) {
            return Err(ContainerError::Misaligned);
        }
        self.cursor = end;
        Ok(u64::from_le(unsafe { ptr.cast::<u64>().read() }))
    }

    fn read_u32(&mut self) -> Result<u32, ContainerError> {
        let value = self.read_u32_at(self.cursor)?;
        self.cursor += core::mem::size_of::<u32>();
        Ok(value)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ContainerError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(ContainerError::InvalidLength)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(ContainerError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }

    fn align_cursor(&mut self) -> Result<(), ContainerError> {
        let relative = self
            .cursor
            .checked_sub(self.header_start)
            .ok_or(ContainerError::InvalidLength)?;
        let padding = (8 - relative % 8) % 8;
        self.cursor = self
            .cursor
            .checked_add(padding)
            .ok_or(ContainerError::InvalidLength)?;
        if self.cursor > self.bytes.len() {
            return Err(ContainerError::Truncated);
        }
        Ok(())
    }

    fn read_records(&mut self, count: usize) -> Result<Vec<&'a [u8]>, ContainerError> {
        let remaining = self.bytes.len() - self.cursor;
        if count > remaining / 8 {
            return Err(ContainerError::InvalidCount);
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let len = self.read_u32()? as usize;
            self.take(4)?;
            if !(self.bytes.as_ptr() as usize + self.cursor).is_multiple_of(8) {
                return Err(ContainerError::Misaligned);
            }
            records.push(self.take(len)?);
            self.align_cursor()?;
        }
        Ok(records)
    }
}

#[cfg(feature = "std")]
pub struct ContainerWriter;

#[cfg(feature = "std")]
impl ContainerWriter {
    pub fn write(
        block_rlp: &[u8],
        signers: &[crate::UncompressedPublicKey],
        witness: &crate::ExecutionWitness,
        stream_start: u64,
        library_id_lo: u64,
    ) -> Result<Vec<u8>, ContainerError> {
        let state_count = count_u32(witness.state.len())?;
        let code_count = count_u32(witness.codes.len())?;
        let header_count = count_u32(witness.headers.len())?;
        let signer_count = count_u32(signers.len())?;

        let mut body = vec![0; HEADER_SIZE];
        body.extend_from_slice(
            &u64::try_from(block_rlp.len())
                .map_err(|_| ContainerError::TooLarge)?
                .to_le_bytes(),
        );
        body.extend_from_slice(block_rlp);
        align_body(&mut body);

        for signer in signers {
            body.extend_from_slice(&signer.0);
            body.resize(body.len() + SIGNER_SIZE - signer.0.len(), 0);
        }
        for record in &witness.state {
            write_record(&mut body, record)?;
        }
        for record in &witness.codes {
            write_record(&mut body, record)?;
        }
        for record in &witness.headers {
            write_record(&mut body, record)?;
        }

        let total_len = count_u32(body.len())?;
        put_u32(&mut body, MAGIC_OFFSET, MAGIC);
        put_u16(&mut body, VERSION_OFFSET, VERSION);
        put_u16(&mut body, FLAGS_OFFSET, FLAGS);
        put_u32(&mut body, TOTAL_LEN_OFFSET, total_len);
        put_u32(&mut body, STATE_COUNT_OFFSET, state_count);
        put_u32(&mut body, CODE_COUNT_OFFSET, code_count);
        put_u32(&mut body, HEADER_COUNT_OFFSET, header_count);
        put_u32(&mut body, SIGNER_COUNT_OFFSET, signer_count);
        put_u32(&mut body, LIBRARY_ID_OFFSET, library_id_lo as u32);
        put_u32(
            &mut body,
            LIBRARY_ID_OFFSET + 4,
            (library_id_lo >> 32) as u32,
        );

        let mut pad_len = 0usize;
        for _ in 0..3 {
            let payload_len = 1 + pad_len + body.len();
            let varint_len = postcard_varint_len(payload_len);
            let next = (8 - ((stream_start as usize + varint_len + 1) % 8)) % 8;
            if next == pad_len {
                break;
            }
            pad_len = next;
        }
        let payload_len = 1 + pad_len + body.len();
        let varint_len = postcard_varint_len(payload_len);
        if !(stream_start as usize + varint_len + 1 + pad_len).is_multiple_of(8) {
            return Err(ContainerError::InvalidPadding);
        }

        let mut output = Vec::with_capacity(payload_len);
        output.push(pad_len as u8);
        output.resize(1 + pad_len, 0);
        output.extend_from_slice(&body);
        Ok(output)
    }
}

#[cfg(feature = "std")]
fn count_u32(value: usize) -> Result<u32, ContainerError> {
    u32::try_from(value).map_err(|_| ContainerError::TooLarge)
}

#[cfg(feature = "std")]
fn align_body(body: &mut Vec<u8>) {
    let padding = (8 - body.len() % 8) % 8;
    body.resize(body.len() + padding, 0);
}

#[cfg(feature = "std")]
fn write_record(body: &mut Vec<u8>, record: &[u8]) -> Result<(), ContainerError> {
    body.extend_from_slice(&count_u32(record.len())?.to_le_bytes());
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(record);
    align_body(body);
    Ok(())
}

#[cfg(feature = "std")]
fn put_u16(body: &mut [u8], offset: usize, value: u16) {
    body[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "std")]
fn put_u32(body: &mut [u8], offset: usize, value: u32) {
    body[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "std")]
fn postcard_varint_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::Bytes;

    #[test]
    fn round_trip_and_alignment() {
        let block = [0xc0];
        let signers = [crate::UncompressedPublicKey([7; 65])];
        let witness = crate::ExecutionWitness {
            state: vec![Bytes::from_static(&[1, 2, 3]), Bytes::new()],
            codes: vec![Bytes::from_static(&[4, 5])],
            keys: vec![Bytes::from_static(&[99])],
            headers: vec![Bytes::from_static(&[6])],
        };
        let stream_start = 0x1000;
        let encoded = ContainerWriter::write(&block, &signers, &witness, stream_start, 0).unwrap();
        let wrapped = postcard::to_stdvec(&encoded).unwrap();
        let borrowed: &[u8] = postcard::from_bytes(&wrapped).unwrap();
        assert_eq!(
            (stream_start
                + (borrowed.as_ptr() as usize - wrapped.as_ptr() as usize) as u64
                + 1
                + borrowed[0] as u64)
                % 8,
            0
        );

        let view = ContainerReader::read(borrowed).unwrap();
        assert_eq!(view.block_rlp, block);
        assert_eq!(&view.signers[0][..65], &[7; 65]);
        assert!(view
            .state
            .iter()
            .all(|record| (record.as_ptr() as usize).is_multiple_of(8)));
        assert!(view
            .codes
            .iter()
            .all(|record| (record.as_ptr() as usize).is_multiple_of(8)));
        assert!(view
            .headers
            .iter()
            .all(|record| (record.as_ptr() as usize).is_multiple_of(8)));
        assert_eq!(view.state, [&[1, 2, 3][..], &[][..]]);
        assert_eq!(view.codes, [&[4, 5][..]]);
        assert_eq!(view.headers, [&[6][..]]);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let encoded =
            ContainerWriter::write(&[0xc0], &[], &crate::ExecutionWitness::default(), 0x1000, 0)
                .unwrap();
        let mut wrapped = postcard::to_stdvec(&encoded).unwrap();
        let start = wrapped.len() - encoded.len();
        wrapped.extend_from_slice(&[0]);
        let input = &wrapped[start..];
        assert_eq!(
            ContainerReader::read(input).err(),
            Some(ContainerError::InvalidLength)
        );
    }
}
