//! Extract `chrome_seed` from a Chromium `resources.pak`.
//!
//! Every Chromium build embeds a 64-byte HMAC seed inside `resources.pak`
//! (`DataPack` v5 format). This module parses the pak header, walks the
//! resource entries, and returns the first entry whose length is exactly
//! [`SEED_LEN`] bytes.
//!
//! # Layout summary (`DataPack` v5)
//!
//! | Offset | Type  | Meaning                          |
//! |-------:|-------|----------------------------------|
//! | 0      | `u32` | version (must be 5)              |
//! | 4      | `u32` | encoding (unused here)           |
//! | 8      | `u16` | `resource_count`                 |
//! | 10     | `u16` | `alias_count`                    |
//! | 12+    | `[u16 id, u32 offset]` × (`resource_count` + 1) | entry table with a sentinel |
//! | ...    | `u8`  | resource data                    |
//!
//! The entry table is followed by `alias_count` four-byte alias records; the
//! first resource offset must begin at or after both tables.
//!
//! Each resource's length is derived from the difference between its offset
//! and the next entry's offset.

use std::fs;
use std::io;
use std::path::Path;

use crate::SecPrefError;

/// Length in bytes of the `chrome_seed` embedded in `resources.pak`.
pub const SEED_LEN: usize = 64;

const DATAPACK_VERSION: u32 = 5;
const HEADER_LEN: usize = 12;
const ENTRY_LEN: usize = 6; // u16 resource_id + u32 offset
const ALIAS_LEN: usize = 4; // u16 resource_id + u16 target resource index

/// Read the seed from a `resources.pak` file on disk.
///
/// # Errors
///
/// Returns [`SecPrefError::Io`] if the file cannot be read;
/// [`SecPrefError::InvalidPak`] if the header is wrong or the file is
/// truncated; [`SecPrefError::SeedNotFound`] if no 64-byte resource exists.
pub fn extract_seed_from_pak(pak_path: impl AsRef<Path>) -> Result<Vec<u8>, SecPrefError> {
    let data = fs::read(pak_path)?;
    extract_seed_from_pak_bytes(&data)
}

/// Extract the seed given the raw bytes of a `resources.pak`.
///
/// Useful for testing, or for callers that have already mapped the file.
///
/// # Errors
///
/// Same as [`extract_seed_from_pak`] apart from I/O.
pub fn extract_seed_from_pak_bytes(data: &[u8]) -> Result<Vec<u8>, SecPrefError> {
    if data.len() < HEADER_LEN {
        return Err(SecPrefError::InvalidPak(
            "resources.pak too small for DataPack v5 header".into(),
        ));
    }

    let version = u32::from_le_bytes(data[0..4].try_into().expect("checked len ≥ 12"));
    if version != DATAPACK_VERSION {
        return Err(SecPrefError::InvalidPak(format!(
            "expected DataPack version {DATAPACK_VERSION}, got {version}"
        )));
    }

    let encoding = u32::from_le_bytes(data[4..8].try_into().expect("checked len ≥ 12"));
    if encoding > 2 {
        return Err(SecPrefError::InvalidPak(format!(
            "invalid DataPack encoding {encoding}"
        )));
    }

    let resource_count =
        u16::from_le_bytes(data[8..10].try_into().expect("checked len ≥ 12")) as usize;
    let alias_count =
        u16::from_le_bytes(data[10..12].try_into().expect("checked len ≥ 12")) as usize;

    // +1 sentinel entry gives every real entry a "next offset" to subtract.
    let total_entries = resource_count
        .checked_add(1)
        .ok_or_else(|| SecPrefError::InvalidPak("resource_count + 1 overflows usize".into()))?;
    let entries_bytes = total_entries
        .checked_mul(ENTRY_LEN)
        .ok_or_else(|| SecPrefError::InvalidPak("entry table size overflows usize".into()))?;
    let alias_bytes = alias_count
        .checked_mul(ALIAS_LEN)
        .ok_or_else(|| SecPrefError::InvalidPak("alias table size overflows usize".into()))?;
    let data_start = HEADER_LEN
        .checked_add(entries_bytes)
        .and_then(|size| size.checked_add(alias_bytes))
        .ok_or_else(|| SecPrefError::InvalidPak("DataPack table size overflows usize".into()))?;
    if data.len() < data_start {
        return Err(SecPrefError::InvalidPak(
            "resources.pak truncated: not enough entry or alias data".into(),
        ));
    }

    for i in 0..resource_count {
        let base = HEADER_LEN + i * ENTRY_LEN;
        let offset = u32::from_le_bytes(
            data[base + 2..base + 6]
                .try_into()
                .expect("bounded by entries_bytes"),
        ) as usize;
        let next_base = HEADER_LEN + (i + 1) * ENTRY_LEN;
        let next_offset = u32::from_le_bytes(
            data[next_base + 2..next_base + 6]
                .try_into()
                .expect("bounded by entries_bytes (+ sentinel)"),
        ) as usize;

        if offset < data_start {
            return Err(SecPrefError::InvalidPak(format!(
                "resource {i} offset points inside DataPack tables"
            )));
        }
        if next_offset < offset {
            return Err(SecPrefError::InvalidPak(format!(
                "resource offsets are not monotonic at entry {i}"
            )));
        }
        if next_offset > data.len() {
            return Err(SecPrefError::InvalidPak(
                "resource offset exceeds file size".into(),
            ));
        }

        let len = next_offset - offset;
        if len == SEED_LEN {
            return Ok(data[offset..next_offset].to_vec());
        }
    }

    Err(SecPrefError::SeedNotFound)
}

// Compatibility with older names — some downstream consumers use these.
#[doc(hidden)]
pub fn extract_seed(pak_path: &Path) -> io::Result<Vec<u8>> {
    extract_seed_from_pak(pak_path).map_err(|e| match e {
        SecPrefError::Io(io_err) => io_err,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic `DataPack` v5 containing a single 64-byte
    /// resource. Used to unit-test the extractor without a real Chromium pak.
    #[allow(clippy::cast_possible_truncation)]
    fn synthetic_pak_with_seed(seed: &[u8; SEED_LEN]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&DATAPACK_VERSION.to_le_bytes()); // version
        buf.extend_from_slice(&0u32.to_le_bytes()); // encoding
        buf.extend_from_slice(&1u16.to_le_bytes()); // resource_count = 1
        buf.extend_from_slice(&0u16.to_le_bytes()); // alias_count = 0
        // 2 entries (1 real + 1 sentinel).
        let data_start = u32::try_from(HEADER_LEN + 2 * ENTRY_LEN).unwrap();
        let data_end = data_start + SEED_LEN as u32;
        // entry 0: id=1, offset=data_start
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&data_start.to_le_bytes());
        // sentinel: id=0, offset=data_end
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&data_end.to_le_bytes());
        buf.extend_from_slice(seed);
        buf
    }

    #[test]
    fn extract_from_synthetic_pak() {
        let seed = [0xAB; SEED_LEN];
        let pak = synthetic_pak_with_seed(&seed);
        let recovered = extract_seed_from_pak_bytes(&pak).unwrap();
        assert_eq!(recovered, seed);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut pak = vec![0u8; HEADER_LEN];
        pak[0..4].copy_from_slice(&4u32.to_le_bytes()); // v4, not v5
        let err = extract_seed_from_pak_bytes(&pak).unwrap_err();
        assert!(matches!(err, SecPrefError::InvalidPak(_)));
    }

    #[test]
    fn rejects_truncated_header() {
        let pak = vec![5u8, 0, 0, 0]; // just the version, nothing else
        let err = extract_seed_from_pak_bytes(&pak).unwrap_err();
        assert!(matches!(err, SecPrefError::InvalidPak(_)));
    }

    #[test]
    fn rejects_unknown_encoding() {
        let mut pak = vec![0u8; HEADER_LEN];
        pak[0..4].copy_from_slice(&DATAPACK_VERSION.to_le_bytes());
        pak[4..8].copy_from_slice(&3u32.to_le_bytes());
        let err = extract_seed_from_pak_bytes(&pak).unwrap_err();
        assert!(matches!(err, SecPrefError::InvalidPak(_)));
    }

    #[test]
    fn rejects_resource_offset_inside_alias_table() {
        let seed = [0xAB; SEED_LEN];
        let mut pak = synthetic_pak_with_seed(&seed);
        pak[10..12].copy_from_slice(&1u16.to_le_bytes());
        let err = extract_seed_from_pak_bytes(&pak).unwrap_err();
        assert!(matches!(err, SecPrefError::InvalidPak(_)));
    }

    #[test]
    fn rejects_descending_resource_offsets() {
        let seed = [0xAB; SEED_LEN];
        let mut pak = synthetic_pak_with_seed(&seed);
        let data_start = u32::try_from(HEADER_LEN + 2 * ENTRY_LEN).unwrap();
        pak[20..24].copy_from_slice(&(data_start - 1).to_le_bytes());
        let err = extract_seed_from_pak_bytes(&pak).unwrap_err();
        assert!(matches!(err, SecPrefError::InvalidPak(_)));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn returns_seed_not_found_when_no_64byte_resource() {
        // synthetic pak with a 32-byte resource → no seed
        let mut buf = Vec::new();
        buf.extend_from_slice(&DATAPACK_VERSION.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        let data_start = (HEADER_LEN + 2 * ENTRY_LEN) as u32;
        let data_end = data_start + 32;
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&data_start.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&data_end.to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]);
        let err = extract_seed_from_pak_bytes(&buf).unwrap_err();
        assert!(matches!(err, SecPrefError::SeedNotFound));
    }
}
