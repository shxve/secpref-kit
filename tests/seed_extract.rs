//! Seed extraction against synthetic `DataPack` v5 fixtures.

#![allow(clippy::cast_possible_truncation)]

use secpref_kit::{
    extract_seed_from_pak_bytes, extract_seed_from_pak_resource_bytes, SecPrefError, SEED_LEN,
};

const HEADER_LEN: usize = 12;
const ENTRY_LEN: usize = 6;
const DATAPACK_VERSION: u32 = 5;

fn synthetic_pak_with_resource(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&DATAPACK_VERSION.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // encoding
    buf.extend_from_slice(&1u16.to_le_bytes()); // resource_count = 1
    buf.extend_from_slice(&0u16.to_le_bytes()); // alias_count = 0
    let data_start = (HEADER_LEN + 2 * ENTRY_LEN) as u32;
    let data_end = data_start + payload.len() as u32;
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&data_start.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&data_end.to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

#[test]
fn extracts_64_byte_seed_from_single_resource() {
    let seed = [0xC3u8; SEED_LEN];
    let pak = synthetic_pak_with_resource(&seed);
    let out = extract_seed_from_pak_bytes(&pak).unwrap();
    assert_eq!(out, seed);
}

#[test]
fn extracts_seed_by_exact_resource_id() {
    let seed = [0xC3u8; SEED_LEN];
    let pak = synthetic_pak_with_resource(&seed);
    let out = extract_seed_from_pak_resource_bytes(&pak, 1).unwrap();
    assert_eq!(out, seed);
}

#[test]
fn exact_resource_id_must_exist() {
    let seed = [0xC3u8; SEED_LEN];
    let pak = synthetic_pak_with_resource(&seed);
    let error = extract_seed_from_pak_resource_bytes(&pak, 99).unwrap_err();
    assert!(matches!(error, SecPrefError::SeedResourceNotFound(99)));
}

#[test]
fn seed_not_found_when_resource_wrong_length() {
    let pak = synthetic_pak_with_resource(&[0u8; 32]);
    let err = extract_seed_from_pak_bytes(&pak).unwrap_err();
    assert!(matches!(err, SecPrefError::SeedNotFound));
}

#[test]
fn wrong_version_rejected() {
    let mut pak = vec![0u8; HEADER_LEN];
    pak[0..4].copy_from_slice(&4u32.to_le_bytes());
    let err = extract_seed_from_pak_bytes(&pak).unwrap_err();
    assert!(matches!(err, SecPrefError::InvalidPak(_)));
}

#[test]
fn truncated_header_rejected() {
    let err = extract_seed_from_pak_bytes(&[5u8]).unwrap_err();
    assert!(matches!(err, SecPrefError::InvalidPak(_)));
}
