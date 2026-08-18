//! Program-image-committed contract bytecode and revm jump tables.

use alloy_primitives::{Bytes, B256};
use revm_bytecode::{Bytecode, JumpTable};

pub const INDEX_MAGIC: u32 = u32::from_le_bytes(*b"JCL1");
pub const INDEX_VERSION: u16 = 1;
pub const INDEX_HEADER_SIZE: usize = 16;
pub const INDEX_RECORD_SIZE: usize = 64;

pub const HASH_OFFSET: usize = 0;
pub const CODE_OFFSET_OFFSET: usize = 32;
pub const CODE_LEN_OFFSET: usize = 36;
pub const ORIGINAL_LEN_OFFSET: usize = 40;
pub const JT_OFFSET_OFFSET: usize = 44;
pub const JT_LEN_OFFSET: usize = 48;
pub const JT_BIT_LEN_OFFSET: usize = 52;
pub const KIND_OFFSET: usize = 56;
pub const RESERVED_OFFSET: usize = 60;

pub const KIND_LEGACY: u32 = 0;
pub const KIND_EIP7702: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LibraryError {
    InvalidHeader,
    InvalidLength,
    InvalidOrder,
    InvalidEntry,
    InvalidKind,
}

#[derive(Clone, Copy)]
pub struct LibraryView<'a> {
    index: &'a [u8],
    codes: &'a [u8],
    jump_tables: &'a [u8],
    count: usize,
}

#[derive(Clone, Copy)]
pub struct LibraryEntry<'a> {
    pub hash: &'a [u8; 32],
    pub code: &'a [u8],
    pub original_len: usize,
    pub jump_table: &'a [u8],
    pub jump_table_bit_len: usize,
    pub kind: u32,
}

impl<'a> LibraryView<'a> {
    pub fn new(
        index: &'a [u8],
        codes: &'a [u8],
        jump_tables: &'a [u8],
    ) -> Result<Self, LibraryError> {
        if index.len() < INDEX_HEADER_SIZE
            || read_u32(index, 0)? != INDEX_MAGIC
            || read_u16(index, 4)? != INDEX_VERSION
            || read_u16(index, 6)? as usize != INDEX_RECORD_SIZE
            || read_u32(index, 12)? != 0
        {
            return Err(LibraryError::InvalidHeader);
        }
        let count = read_u32(index, 8)? as usize;
        let expected_len = INDEX_HEADER_SIZE
            .checked_add(
                count
                    .checked_mul(INDEX_RECORD_SIZE)
                    .ok_or(LibraryError::InvalidLength)?,
            )
            .ok_or(LibraryError::InvalidLength)?;
        if index.len() != expected_len {
            return Err(LibraryError::InvalidLength);
        }
        Ok(Self {
            index,
            codes,
            jump_tables,
            count,
        })
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn entry(&self, index: usize) -> Result<LibraryEntry<'a>, LibraryError> {
        if index >= self.count {
            return Err(LibraryError::InvalidEntry);
        }
        let start = INDEX_HEADER_SIZE + index * INDEX_RECORD_SIZE;
        let record = &self.index[start..start + INDEX_RECORD_SIZE];
        let hash = record[HASH_OFFSET..HASH_OFFSET + 32]
            .try_into()
            .map_err(|_| LibraryError::InvalidEntry)?;
        let code_offset = read_u32(record, CODE_OFFSET_OFFSET)? as usize;
        let code_len = read_u32(record, CODE_LEN_OFFSET)? as usize;
        let original_len = read_u32(record, ORIGINAL_LEN_OFFSET)? as usize;
        let jump_table_offset = read_u32(record, JT_OFFSET_OFFSET)? as usize;
        let jump_table_len = read_u32(record, JT_LEN_OFFSET)? as usize;
        let jump_table_bit_len = read_u32(record, JT_BIT_LEN_OFFSET)? as usize;
        let kind = read_u32(record, KIND_OFFSET)?;
        if read_u32(record, RESERVED_OFFSET)? != 0
            || !code_offset.is_multiple_of(8)
            || !jump_table_offset.is_multiple_of(8)
            || original_len > code_len
        {
            return Err(LibraryError::InvalidEntry);
        }
        let code = checked_slice(self.codes, code_offset, code_len)?;
        let jump_table = checked_slice(self.jump_tables, jump_table_offset, jump_table_len)?;
        match kind {
            KIND_LEGACY
                if !code.is_empty()
                    && jump_table_bit_len == original_len
                    && jump_table_len == jump_table_bit_len.div_ceil(8) => {}
            KIND_LEGACY => return Err(LibraryError::InvalidEntry),
            KIND_EIP7702
                if original_len == code_len && jump_table.is_empty() && jump_table_bit_len == 0 => {
            }
            KIND_EIP7702 => return Err(LibraryError::InvalidEntry),
            _ => return Err(LibraryError::InvalidKind),
        }
        Ok(LibraryEntry {
            hash,
            code,
            original_len,
            jump_table,
            jump_table_bit_len,
            kind,
        })
    }

    pub fn lookup(&self, hash: &B256) -> Result<Option<LibraryEntry<'a>>, LibraryError> {
        let mut low = 0usize;
        let mut high = self.count;
        while low < high {
            let mid = low + (high - low) / 2;
            let entry = self.entry(mid)?;
            match entry.hash.as_slice().cmp(hash.as_slice()) {
                core::cmp::Ordering::Less => low = mid + 1,
                core::cmp::Ordering::Greater => high = mid,
                core::cmp::Ordering::Equal => return Ok(Some(entry)),
            }
        }
        Ok(None)
    }

    pub fn validate(&self) -> Result<(), LibraryError> {
        let mut previous: Option<&[u8; 32]> = None;
        for index in 0..self.count {
            let entry = self.entry(index)?;
            if previous.is_some_and(|hash| hash >= entry.hash) {
                return Err(LibraryError::InvalidOrder);
            }
            previous = Some(entry.hash);
        }
        Ok(())
    }
}

impl LibraryView<'static> {
    pub fn lookup_bytecode(&self, hash: &B256) -> Option<Bytecode> {
        let entry = self.lookup(hash).ok()??;
        let bytes = Bytes::from_static(entry.code);
        match entry.kind {
            KIND_LEGACY => Some(Bytecode::new_analyzed(
                bytes,
                entry.original_len,
                JumpTable::from_static_slice(entry.jump_table, entry.jump_table_bit_len),
            )),
            KIND_EIP7702 => Bytecode::new_eip7702_raw(bytes).ok(),
            _ => None,
        }
    }
}

fn checked_slice(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8], LibraryError> {
    let end = offset.checked_add(len).ok_or(LibraryError::InvalidLength)?;
    bytes.get(offset..end).ok_or(LibraryError::InvalidLength)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, LibraryError> {
    Ok(u16::from_le_bytes(
        checked_slice(bytes, offset, 2)?
            .try_into()
            .map_err(|_| LibraryError::InvalidLength)?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, LibraryError> {
    Ok(u32::from_le_bytes(
        checked_slice(bytes, offset, 4)?
            .try_into()
            .map_err(|_| LibraryError::InvalidLength)?,
    ))
}

#[cfg(feature = "code-library")]
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/code_library.rs"));
}

#[cfg(feature = "code-library")]
pub const LIBRARY_ID: [u8; 32] = embedded::LIBRARY_ID;
#[cfg(not(feature = "code-library"))]
pub const LIBRARY_ID: [u8; 32] = [0; 32];

pub const LIBRARY_ID_LO: u64 = u64::from_le_bytes([
    LIBRARY_ID[0],
    LIBRARY_ID[1],
    LIBRARY_ID[2],
    LIBRARY_ID[3],
    LIBRARY_ID[4],
    LIBRARY_ID[5],
    LIBRARY_ID[6],
    LIBRARY_ID[7],
]);

#[cfg(feature = "code-library")]
pub fn embedded() -> LibraryView<'static> {
    LibraryView::new(
        embedded::LIBRARY_INDEX,
        embedded::LIBRARY_CODES,
        embedded::LIBRARY_JUMP_TABLES,
    )
    .expect("embedded code library")
}

#[cfg(feature = "code-library")]
pub fn lookup(hash: &B256) -> Option<Bytecode> {
    embedded().lookup_bytecode(hash)
}

#[cfg(not(feature = "code-library"))]
pub fn lookup(_hash: &B256) -> Option<Bytecode> {
    None
}

#[cfg(feature = "code-library")]
pub fn append_raw_codes(codes: &mut alloc::vec::Vec<Bytes>) {
    let library = embedded();
    codes.extend((0..library.len()).map(|index| {
        let entry = library.entry(index).expect("embedded code-library entry");
        Bytes::from_static(&entry.code[..entry.original_len])
    }));
}

#[cfg(not(feature = "code-library"))]
pub fn append_raw_codes(_codes: &mut alloc::vec::Vec<Bytes>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn rejects_unsorted_index() {
        let mut index = vec![0; INDEX_HEADER_SIZE + 2 * INDEX_RECORD_SIZE];
        index[0..4].copy_from_slice(&INDEX_MAGIC.to_le_bytes());
        index[4..6].copy_from_slice(&INDEX_VERSION.to_le_bytes());
        index[6..8].copy_from_slice(&(INDEX_RECORD_SIZE as u16).to_le_bytes());
        index[8..12].copy_from_slice(&2u32.to_le_bytes());
        for i in 0..2 {
            let record = INDEX_HEADER_SIZE + i * INDEX_RECORD_SIZE;
            index[record + CODE_LEN_OFFSET..record + CODE_LEN_OFFSET + 4]
                .copy_from_slice(&1u32.to_le_bytes());
        }
        let library = LibraryView::new(&index, &[0], &[]).unwrap();
        assert_eq!(library.validate(), Err(LibraryError::InvalidOrder));
    }

    #[cfg(feature = "code-library")]
    #[test]
    fn embedded_entries_match_revm_analysis() {
        let library = embedded();
        library.validate().unwrap();
        for index in 0..library.len() {
            let entry = library.entry(index).unwrap();
            let raw = Bytes::copy_from_slice(&entry.code[..entry.original_len]);
            assert_eq!(alloy_primitives::keccak256(&raw), B256::from(*entry.hash));
            let expected = Bytecode::new_raw(raw);
            let actual = library
                .lookup_bytecode(&B256::from(*entry.hash))
                .expect("entry lookup");
            assert_eq!(actual.kind(), expected.kind());
            assert_eq!(actual.original_byte_slice(), expected.original_byte_slice());
            assert_eq!(actual.bytes_slice(), expected.bytes_slice());
            assert_eq!(actual.legacy_jump_table(), expected.legacy_jump_table());
        }
    }
}
