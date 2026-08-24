//! Extract `chrome_seed` from a Chromium `resources.pak`.
//!
//! Branded Chromium builds embed a 64-byte HMAC seed as the named
//! `IDR_PREF_HASH_SEED_BIN` resource in `resources.pak` (`DataPack` v5 format).
//! Resource IDs are generated per build, so the exact extraction APIs require
//! the caller to supply the ID from the matching generated resources header.
//! Compatibility helpers accept a pak only when it contains exactly one
//! 64-byte candidate; they reject ambiguous packs rather than choosing by
//! table order.
//!
//! # Layout summary (`DataPack` v5)
//!
//! | Offset | Type  | Meaning                          |
//! |-------:|-------|----------------------------------|
//! | 0      | `u32` | version (must be 5)              |
//! | 4      | `u8`  | encoding                         |
//! | 5      | `[u8; 3]` | padding                     |
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
/// truncated; [`SecPrefError::SeedNotFound`] if no 64-byte resource exists;
/// [`SecPrefError::AmbiguousSeedCandidates`] if multiple candidates exist.
pub fn extract_seed_from_pak(pak_path: impl AsRef<Path>) -> Result<Vec<u8>, SecPrefError> {
    let data = fs::read(pak_path)?;
    extract_seed_from_pak_bytes(&data)
}

/// Extract the unique 64-byte seed candidate from raw `resources.pak` bytes.
///
/// Prefer [`extract_seed_from_pak_resource_bytes`] when the matching Chromium
/// resource ID is known. This compatibility helper never chooses the first of
/// multiple candidates.
///
/// # Errors
///
/// Same as [`extract_seed_from_pak`] apart from I/O.
pub fn extract_seed_from_pak_bytes(data: &[u8]) -> Result<Vec<u8>, SecPrefError> {
    let pack = parse_data_pack(data)?;
    let candidates: Vec<&ResourceEntry> = pack
        .resources
        .iter()
        .filter(|entry| entry.end - entry.offset == SEED_LEN)
        .collect();
    match candidates.as_slice() {
        [] => Err(SecPrefError::SeedNotFound),
        [entry] => Ok(data[entry.offset..entry.end].to_vec()),
        _ => Err(SecPrefError::AmbiguousSeedCandidates(
            candidates.iter().map(|entry| entry.id).collect(),
        )),
    }
}

/// Read Chromium's named preference-hash seed from a pak on disk.
///
/// `resource_id` must be the `IDR_PREF_HASH_SEED_BIN` value generated for the
/// exact target build.
///
/// # Errors
///
/// Returns an I/O error, a `DataPack` validation error,
/// [`SecPrefError::SeedResourceNotFound`], or
/// [`SecPrefError::InvalidSeedLength`].
pub fn extract_seed_from_pak_resource(
    pak_path: impl AsRef<Path>,
    resource_id: u16,
) -> Result<Vec<u8>, SecPrefError> {
    let data = fs::read(pak_path)?;
    extract_seed_from_pak_resource_bytes(&data, resource_id)
}

/// Extract Chromium's named preference-hash seed from raw pak bytes.
///
/// Resolves both direct `DataPack` entries and aliases. `resource_id` must be the
/// `IDR_PREF_HASH_SEED_BIN` value generated for the exact target build.
///
/// # Errors
///
/// Returns a `DataPack` validation error,
/// [`SecPrefError::SeedResourceNotFound`], or
/// [`SecPrefError::InvalidSeedLength`].
pub fn extract_seed_from_pak_resource_bytes(
    data: &[u8],
    resource_id: u16,
) -> Result<Vec<u8>, SecPrefError> {
    let pack = parse_data_pack(data)?;
    let entry = pack
        .resources
        .iter()
        .find(|entry| entry.id == resource_id)
        .or_else(|| {
            pack.aliases
                .iter()
                .find(|alias| alias.id == resource_id)
                .and_then(|alias| pack.resources.get(alias.target_index))
        })
        .ok_or(SecPrefError::SeedResourceNotFound(resource_id))?;
    let length = entry.end - entry.offset;
    if length != SEED_LEN {
        return Err(SecPrefError::InvalidSeedLength {
            resource_id,
            actual: length,
        });
    }
    Ok(data[entry.offset..entry.end].to_vec())
}

#[derive(Debug)]
struct DataPack {
    resources: Vec<ResourceEntry>,
    aliases: Vec<AliasEntry>,
}

#[derive(Debug)]
struct ResourceEntry {
    id: u16,
    offset: usize,
    end: usize,
}

#[derive(Debug)]
struct AliasEntry {
    id: u16,
    target_index: usize,
}

fn parse_data_pack(data: &[u8]) -> Result<DataPack, SecPrefError> {
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

    let encoding = data[4];
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

    let mut resources = Vec::with_capacity(resource_count);
    for i in 0..resource_count {
        let base = HEADER_LEN + i * ENTRY_LEN;
        let id = u16::from_le_bytes(
            data[base..base + 2]
                .try_into()
                .expect("bounded by entries_bytes"),
        );
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

        if resources.iter().any(|entry: &ResourceEntry| entry.id == id) {
            return Err(SecPrefError::InvalidPak(format!(
                "duplicate resource ID {id}"
            )));
        }
        resources.push(ResourceEntry {
            id,
            offset,
            end: next_offset,
        });
    }

    let aliases = parse_aliases(data, HEADER_LEN + entries_bytes, alias_count, &resources)?;

    Ok(DataPack { resources, aliases })
}

fn parse_aliases(
    data: &[u8],
    alias_start: usize,
    alias_count: usize,
    resources: &[ResourceEntry],
) -> Result<Vec<AliasEntry>, SecPrefError> {
    let mut aliases = Vec::with_capacity(alias_count);
    for i in 0..alias_count {
        let base = alias_start + i * ALIAS_LEN;
        let id = u16::from_le_bytes(
            data[base..base + 2]
                .try_into()
                .expect("bounded by alias_bytes"),
        );
        let target_index = u16::from_le_bytes(
            data[base + 2..base + 4]
                .try_into()
                .expect("bounded by alias_bytes"),
        ) as usize;
        if target_index >= resources.len() {
            return Err(SecPrefError::InvalidPak(format!(
                "alias resource {id} targets missing entry index {target_index}"
            )));
        }
        if resources.iter().any(|entry| entry.id == id)
            || aliases.iter().any(|alias: &AliasEntry| alias.id == id)
        {
            return Err(SecPrefError::InvalidPak(format!(
                "duplicate resource or alias ID {id}"
            )));
        }
        aliases.push(AliasEntry { id, target_index });
    }
    Ok(aliases)
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

    #[allow(clippy::cast_possible_truncation)]
    fn synthetic_pak(resources: &[(u16, &[u8])], aliases: &[(u16, u16)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&DATAPACK_VERSION.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&(resources.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(aliases.len() as u16).to_le_bytes());

        let mut offset =
            (HEADER_LEN + (resources.len() + 1) * ENTRY_LEN + aliases.len() * ALIAS_LEN) as u32;
        for (id, payload) in resources {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&offset.to_le_bytes());
            offset += payload.len() as u32;
        }
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&offset.to_le_bytes());
        for (id, target_index) in aliases {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&target_index.to_le_bytes());
        }
        for (_, payload) in resources {
            buf.extend_from_slice(payload);
        }
        buf
    }

    fn synthetic_pak_with_seed(seed: &[u8; SEED_LEN]) -> Vec<u8> {
        synthetic_pak(&[(1, seed)], &[])
    }

    #[test]
    fn extract_from_synthetic_pak() {
        let seed = [0xAB; SEED_LEN];
        let pak = synthetic_pak_with_seed(&seed);
        let recovered = extract_seed_from_pak_bytes(&pak).unwrap();
        assert_eq!(recovered, seed);
    }

    #[test]
    fn rejects_ambiguous_length_only_seed_selection() {
        let first = [0x11; SEED_LEN];
        let second = [0x22; SEED_LEN];
        let pak = synthetic_pak(&[(10, &first), (20, &second)], &[]);

        let error = extract_seed_from_pak_bytes(&pak).unwrap_err();
        assert!(matches!(
            error,
            SecPrefError::AmbiguousSeedCandidates(ids) if ids == vec![10, 20]
        ));
    }

    #[test]
    fn extracts_exact_named_resource_and_alias() {
        let unrelated = [0x11; SEED_LEN];
        let seed = [0x22; SEED_LEN];
        let pak = synthetic_pak(&[(10, &unrelated), (20, &seed)], &[(30, 1)]);

        assert_eq!(
            extract_seed_from_pak_resource_bytes(&pak, 20).unwrap(),
            seed
        );
        assert_eq!(
            extract_seed_from_pak_resource_bytes(&pak, 30).unwrap(),
            seed
        );
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
    fn ignores_v5_header_padding_bytes() {
        let seed = [0xAB; SEED_LEN];
        let mut pak = synthetic_pak_with_seed(&seed);
        pak[5..8].copy_from_slice(&[0xAA, 0xBB, 0xCC]);

        assert_eq!(extract_seed_from_pak_bytes(&pak).unwrap(), seed);
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
