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
//! Chromium uses a compact layout with a 12-byte header, `u16` counts and
//! resource IDs, six-byte resource entries, and four-byte aliases. Microsoft
//! Edge packs observed in the wild use a wide layout with a 16-byte header,
//! `u32` counts and IDs, eight-byte entries, and eight-byte aliases. Both
//! layouts store `u32` resource offsets and end the resource table with a
//! sentinel entry.
//!
//! The parser validates both layouts and accepts one only when it is the unique
//! structurally valid interpretation. The first resource offset must begin at
//! or after the entry and alias tables.
//!
//! Each resource's length is derived from the difference between its offset
//! and the next entry's offset.

use std::fs;
use std::io;
use std::path::Path;

use crate::SecPrefError;

/// Length in bytes of the `chrome_seed` embedded in `resources.pak`.
pub const SEED_LEN: usize = 64;

/// A direct 64-byte `DataPack` resource that may be tested as a seed candidate.
#[derive(Clone, PartialEq, Eq)]
pub struct SeedResource {
    id: u32,
    bytes: [u8; SEED_LEN],
}

impl SeedResource {
    /// Direct `DataPack` resource ID.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Borrow the 64 resource bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.bytes
    }

    #[cfg(test)]
    pub(crate) const fn new_for_test(id: u32, bytes: [u8; SEED_LEN]) -> Self {
        Self { id, bytes }
    }
}

impl std::fmt::Debug for SeedResource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SeedResource")
            .field("id", &self.id)
            .field("length", &SEED_LEN)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

const DATAPACK_VERSION: u32 = 5;
const COMPACT_HEADER_LEN: usize = 12;
const COMPACT_ENTRY_LEN: usize = 6;
const COMPACT_ALIAS_LEN: usize = 4;
const WIDE_HEADER_LEN: usize = 16;
const WIDE_ENTRY_LEN: usize = 8;
const WIDE_ALIAS_LEN: usize = 8;

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

/// Enumerate every direct 64-byte resource as a policy-resolution candidate.
///
/// This function does not choose a seed. Callers should pass the returned
/// resources to [`crate::profile::resolve_profile_policy`], which proves a
/// unique candidate against the target profile. Aliases are not repeated
/// because they point at the same direct payload.
///
/// # Errors
///
/// Returns [`SecPrefError::InvalidPak`] when the `DataPack` is malformed or its
/// compact/wide layout is ambiguous.
pub fn seed_resources_from_pak_bytes(data: &[u8]) -> Result<Vec<SeedResource>, SecPrefError> {
    let pack = parse_data_pack(data)?;
    Ok(pack
        .resources
        .iter()
        .filter(|entry| entry.end - entry.offset == SEED_LEN)
        .map(|entry| SeedResource {
            id: entry.id,
            bytes: data[entry.offset..entry.end]
                .try_into()
                .expect("filtered to the fixed seed length"),
        })
        .collect())
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
    resource_id: u32,
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
    resource_id: u32,
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
    id: u32,
    offset: usize,
    end: usize,
}

#[derive(Debug)]
struct AliasEntry {
    id: u32,
    target_index: usize,
}

#[derive(Clone, Copy, Debug)]
enum DataPackLayout {
    Compact,
    Wide,
}

impl DataPackLayout {
    const fn header_len(self) -> usize {
        match self {
            Self::Compact => COMPACT_HEADER_LEN,
            Self::Wide => WIDE_HEADER_LEN,
        }
    }

    const fn entry_len(self) -> usize {
        match self {
            Self::Compact => COMPACT_ENTRY_LEN,
            Self::Wide => WIDE_ENTRY_LEN,
        }
    }

    const fn alias_len(self) -> usize {
        match self {
            Self::Compact => COMPACT_ALIAS_LEN,
            Self::Wide => WIDE_ALIAS_LEN,
        }
    }

    fn counts(self, data: &[u8]) -> (usize, usize) {
        match self {
            Self::Compact => (
                u16::from_le_bytes(data[8..10].try_into().expect("checked compact header"))
                    as usize,
                u16::from_le_bytes(data[10..12].try_into().expect("checked compact header"))
                    as usize,
            ),
            Self::Wide => (
                u32::from_le_bytes(data[8..12].try_into().expect("checked wide header")) as usize,
                u32::from_le_bytes(data[12..16].try_into().expect("checked wide header")) as usize,
            ),
        }
    }

    fn entry(self, data: &[u8], base: usize) -> (u32, usize) {
        match self {
            Self::Compact => (
                u16::from_le_bytes(data[base..base + 2].try_into().expect("bounded entry")).into(),
                u32::from_le_bytes(data[base + 2..base + 6].try_into().expect("bounded entry"))
                    as usize,
            ),
            Self::Wide => (
                u32::from_le_bytes(data[base..base + 4].try_into().expect("bounded entry")),
                u32::from_le_bytes(data[base + 4..base + 8].try_into().expect("bounded entry"))
                    as usize,
            ),
        }
    }

    fn alias(self, data: &[u8], base: usize) -> (u32, usize) {
        match self {
            Self::Compact => (
                u16::from_le_bytes(data[base..base + 2].try_into().expect("bounded alias")).into(),
                u16::from_le_bytes(data[base + 2..base + 4].try_into().expect("bounded alias"))
                    as usize,
            ),
            Self::Wide => (
                u32::from_le_bytes(data[base..base + 4].try_into().expect("bounded alias")),
                u32::from_le_bytes(data[base + 4..base + 8].try_into().expect("bounded alias"))
                    as usize,
            ),
        }
    }
}

fn parse_data_pack(data: &[u8]) -> Result<DataPack, SecPrefError> {
    if data.len() < COMPACT_HEADER_LEN {
        return Err(SecPrefError::InvalidPak(
            "resources.pak too small for DataPack v5 header".into(),
        ));
    }

    let version = u32::from_le_bytes(data[0..4].try_into().expect("checked compact header"));
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

    let compact = parse_layout(data, DataPackLayout::Compact);
    let wide = parse_layout(data, DataPackLayout::Wide);
    match (compact, wide) {
        (Ok(pack), Err(_)) | (Err(_), Ok(pack)) => Ok(pack),
        (Ok(_), Ok(_)) => Err(SecPrefError::InvalidPak(
            "ambiguous DataPack v5 table layout".into(),
        )),
        (Err(compact_error), Err(wide_error)) => Err(SecPrefError::InvalidPak(format!(
            "invalid compact and wide DataPack v5 layouts (compact: {compact_error}; wide: {wide_error})"
        ))),
    }
}

fn parse_layout(data: &[u8], layout: DataPackLayout) -> Result<DataPack, String> {
    let header_len = layout.header_len();
    if data.len() < header_len {
        return Err(format!("file too small for {layout:?} header"));
    }
    let entry_len = layout.entry_len();
    let alias_len = layout.alias_len();
    let (resource_count, alias_count) = layout.counts(data);

    // +1 sentinel entry gives every real entry a "next offset" to subtract.
    let total_entries = resource_count
        .checked_add(1)
        .ok_or_else(|| "resource_count + 1 overflows usize".to_owned())?;
    let entries_bytes = total_entries
        .checked_mul(entry_len)
        .ok_or_else(|| "entry table size overflows usize".to_owned())?;
    let alias_bytes = alias_count
        .checked_mul(alias_len)
        .ok_or_else(|| "alias table size overflows usize".to_owned())?;
    let data_start = header_len
        .checked_add(entries_bytes)
        .and_then(|size| size.checked_add(alias_bytes))
        .ok_or_else(|| "DataPack table size overflows usize".to_owned())?;
    if data.len() < data_start {
        return Err("not enough entry or alias data".into());
    }

    let mut resources = Vec::with_capacity(resource_count);
    for i in 0..resource_count {
        let base = header_len + i * entry_len;
        let (id, offset) = layout.entry(data, base);
        let next_base = header_len + (i + 1) * entry_len;
        let (_, next_offset) = layout.entry(data, next_base);

        if offset < data_start {
            return Err(format!("resource {i} offset points inside DataPack tables"));
        }
        if next_offset < offset {
            return Err(format!("resource offsets are not monotonic at entry {i}"));
        }
        if next_offset > data.len() {
            return Err("resource offset exceeds file size".into());
        }

        if resources.iter().any(|entry: &ResourceEntry| entry.id == id) {
            return Err(format!("duplicate resource ID {id}"));
        }
        resources.push(ResourceEntry {
            id,
            offset,
            end: next_offset,
        });
    }

    let aliases = parse_aliases(
        data,
        header_len + entries_bytes,
        alias_count,
        &resources,
        layout,
    )?;

    Ok(DataPack { resources, aliases })
}

fn parse_aliases(
    data: &[u8],
    alias_start: usize,
    alias_count: usize,
    resources: &[ResourceEntry],
    layout: DataPackLayout,
) -> Result<Vec<AliasEntry>, String> {
    let mut aliases = Vec::with_capacity(alias_count);
    for i in 0..alias_count {
        let base = alias_start + i * layout.alias_len();
        let (id, target_index) = layout.alias(data, base);
        if target_index >= resources.len() {
            return Err(format!(
                "alias resource {id} targets missing entry index {target_index}"
            ));
        }
        if resources.iter().any(|entry| entry.id == id)
            || aliases.iter().any(|alias: &AliasEntry| alias.id == id)
        {
            return Err(format!("duplicate resource or alias ID {id}"));
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

        let mut offset = (COMPACT_HEADER_LEN
            + (resources.len() + 1) * COMPACT_ENTRY_LEN
            + aliases.len() * COMPACT_ALIAS_LEN) as u32;
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

    #[allow(clippy::cast_possible_truncation)]
    fn synthetic_wide_pak(resources: &[(u32, &[u8])], aliases: &[(u32, u32)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&DATAPACK_VERSION.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&(resources.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(aliases.len() as u32).to_le_bytes());

        let mut offset = (WIDE_HEADER_LEN
            + (resources.len() + 1) * WIDE_ENTRY_LEN
            + aliases.len() * WIDE_ALIAS_LEN) as u32;
        for (id, payload) in resources {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&offset.to_le_bytes());
            offset += payload.len() as u32;
        }
        buf.extend_from_slice(&0u32.to_le_bytes());
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
    fn enumerates_all_direct_seed_candidates_without_exposing_bytes_in_debug() {
        let first = [0x11; SEED_LEN];
        let second = [0x22; SEED_LEN];
        let pak = synthetic_pak(&[(10, &first), (20, &[0x33; 8]), (30, &second)], &[(40, 2)]);

        let resources = seed_resources_from_pak_bytes(&pak).unwrap();
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0].id(), 10);
        assert_eq!(resources[0].as_bytes(), &first);
        assert_eq!(resources[1].id(), 30);
        assert_eq!(resources[1].as_bytes(), &second);
        assert!(format!("{:?}", resources[0]).contains("[REDACTED]"));
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
    fn extracts_wide_resource_and_alias_above_u16_range() {
        let unrelated = [0x11; 17];
        let seed = [0x22; SEED_LEN];
        // IDs mirror the range observed in Edge 151 resources.pak, while the
        // payload is synthetic and contains no vendor resource data.
        let pak = synthetic_wide_pak(&[(65_554, &unrelated), (65_840, &seed)], &[(70_001, 1)]);

        assert_eq!(extract_seed_from_pak_bytes(&pak).unwrap(), seed);
        assert_eq!(
            extract_seed_from_pak_resource_bytes(&pak, 65_840).unwrap(),
            seed
        );
        assert_eq!(
            extract_seed_from_pak_resource_bytes(&pak, 70_001).unwrap(),
            seed
        );
    }

    #[test]
    fn rejects_out_of_range_wide_alias_target() {
        let seed = [0x22; SEED_LEN];
        let pak = synthetic_wide_pak(&[(65_840, &seed)], &[(70_001, 1)]);

        assert!(matches!(
            extract_seed_from_pak_bytes(&pak),
            Err(SecPrefError::InvalidPak(_))
        ));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut pak = vec![0u8; COMPACT_HEADER_LEN];
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
        let mut pak = vec![0u8; COMPACT_HEADER_LEN];
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
        let data_start = u32::try_from(COMPACT_HEADER_LEN + 2 * COMPACT_ENTRY_LEN).unwrap();
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
        let data_start = (COMPACT_HEADER_LEN + 2 * COMPACT_ENTRY_LEN) as u32;
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
