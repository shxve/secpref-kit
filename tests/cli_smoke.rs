//! End-to-end CLI integration tests.
//!
//! Exercises the `secpref` binary via `assert_cmd` — proves the CLI is a
//! true thin wrapper (outputs match library test vectors byte-for-byte)
//! and that I/O plumbing (atomic writes, JSON round-trips, exit codes)
//! behaves the way DESIGN.md §4.3 specifies.
//!
//! `#![cfg(feature = "cli")]` — this file only compiles + runs when the
//! `cli` feature is enabled (which is also when the binary itself is
//! built via its `required-features = ["cli"]` gate). Run with:
//!
//! ```sh
//! cargo test --features cli
//! ```

#![cfg(feature = "cli")]

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use base64::Engine as _;
use predicates::prelude::*;
use serde_json::{json, Value};
use tempfile::TempDir;

// ---------------- fixtures ----------------

/// Handle to the `secpref` binary cargo built for us.
fn secpref() -> Command {
    Command::cargo_bin("secpref").expect("secpref binary should be built with --features cli")
}

/// Write a minimal valid `manifest.json` into `dir`.
fn write_manifest(dir: &Path, name: &str) {
    fs::write(
        dir.join("manifest.json"),
        format!(r#"{{"name":"{name}","version":"1.0.0","manifest_version":3}}"#),
    )
    .expect("write manifest.json");
}

/// Create a temporary "profile" directory with an empty `Secure Preferences`.
fn empty_prefs_dir() -> TempDir {
    let td = TempDir::new().expect("tempdir");
    fs::write(td.path().join("Secure Preferences"), "{}").expect("write empty prefs");
    td
}

/// Build a synthetic `DataPack` v5 file containing a single 64-byte resource
/// (the seed). Mirrors the helper in `src/seed.rs` tests.
fn synthetic_pak_with_seed(seed: &[u8; 64]) -> Vec<u8> {
    const HEADER_LEN: usize = 12;
    const ENTRY_LEN: usize = 6;
    let mut buf = Vec::new();
    buf.extend_from_slice(&5u32.to_le_bytes()); // version 5
    buf.extend_from_slice(&0u32.to_le_bytes()); // encoding
    buf.extend_from_slice(&1u16.to_le_bytes()); // resource_count
    buf.extend_from_slice(&0u16.to_le_bytes()); // alias_count
    let data_start = u32::try_from(HEADER_LEN + 2 * ENTRY_LEN).unwrap();
    let data_end = data_start + u32::try_from(seed.len()).unwrap();
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&data_start.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&data_end.to_le_bytes());
    buf.extend_from_slice(seed);
    buf
}

// ---------------- seed extract ----------------

#[test]
fn seed_extract_hex() {
    let td = TempDir::new().unwrap();
    let pak = td.path().join("resources.pak");
    let seed = [0xABu8; 64];
    fs::write(&pak, synthetic_pak_with_seed(&seed)).unwrap();

    secpref()
        .args(["seed", "extract", "--pak"])
        .arg(&pak)
        .assert()
        .success()
        .stdout(format!("{}\n", hex::encode_upper(seed)));
}

#[test]
fn seed_extract_raw_bytes() {
    let td = TempDir::new().unwrap();
    let pak = td.path().join("resources.pak");
    let seed = [0xCDu8; 64];
    fs::write(&pak, synthetic_pak_with_seed(&seed)).unwrap();

    let output = secpref()
        .args(["seed", "extract", "--raw", "--pak"])
        .arg(&pak)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(output, seed.to_vec());
}

#[test]
fn seed_extract_missing_pak_errors() {
    secpref()
        .args(["seed", "extract", "--pak", "/nonexistent/resources.pak"])
        .assert()
        .failure();
}

// ---------------- mac compute / super ----------------

#[test]
fn mac_compute_matches_pinned_library_vector() {
    // Same vector as the library's `mac::tests::mac_empty_seed_empty_sid_bool_true`.
    // Any drift here means the CLI serializer or arg-passing broke.
    secpref()
        .args([
            "mac", "compute",
            "--seed", "",
            "--sid", "",
            "--path", "extensions.ui.developer_mode",
            "--value", "true",
        ])
        .assert()
        .success()
        .stdout("F1323889EA777F2EB3E23F3E2CFCB59D3FAFCB8DE80104742CBF2A9E44046ED9\n");
}

#[test]
fn mac_compute_object_value_with_seed_and_sid_matches_library() {
    // Mirrors library `mac_known_seed_with_sid_and_object_value` test.
    let seed_hex = hex::encode([b'A'; 64]);
    secpref()
        .args([
            "mac", "compute",
            "--seed", &seed_hex,
            "--sid", "S-1-5-21-123",
            "--path", "extensions.settings.testid",
            "--value", r#"{"key1":"value1","key2":42}"#,
        ])
        .assert()
        .success()
        .stdout("B33251DEB592061EDBCE92A14F009D37181A0F9F5B64605CC01764E1CAE12471\n");
}

#[test]
fn mac_super_produces_64_char_hex() {
    let output = secpref()
        .args([
            "mac", "super",
            "--seed", &hex::encode([0x42u8; 64]),
            "--sid", "sid",
            "--macs", r#"{"extensions":{"settings":{"abc":"DEF"}}}"#,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8(output).unwrap();
    let line = s.trim();
    assert_eq!(line.len(), 64);
    assert!(line.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn mac_compute_rejects_invalid_json_value() {
    secpref()
        .args([
            "mac", "compute",
            "--seed", "",
            "--sid", "",
            "--path", "p",
            "--value", "{not valid json",
        ])
        .assert()
        .failure();
}

// ---------------- ext-id derive ----------------

#[test]
#[cfg(not(target_os = "windows"))]
fn ext_id_derive_from_path_linux_pinned() {
    // Mirrors library `ext_id::tests::derive_from_path_linux_is_deterministic`.
    secpref()
        .args(["ext-id", "derive", "--path", "/tmp/test_extension"])
        .assert()
        .success()
        .stdout("abkadfbcnpenojlncdmkijflkbadnmeb\n");
}

#[test]
fn ext_id_derive_from_key_pinned() {
    // Mirrors library `ext_id::tests::derive_from_key_matches_known_vector`.
    let key = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
    secpref()
        .args(["ext-id", "derive", "--key"])
        .arg(&key)
        .assert()
        .success()
        .stdout("pfkfpnecnbgkcadachjiopgondajjhjl\n");
}

#[test]
fn ext_id_derive_requires_exactly_one_source() {
    secpref()
        .args(["ext-id", "derive"])
        .assert()
        .failure();
}

#[test]
fn ext_id_derive_rejects_bad_base64_key() {
    secpref()
        .args(["ext-id", "derive", "--key", "!!!not-base64!!!"])
        .assert()
        .failure();
}

// ---------------- prefs full round-trip ----------------

#[test]
fn prefs_install_verify_list_uninstall_roundtrip() {
    let profile = empty_prefs_dir();
    let ext = TempDir::new().unwrap();
    write_manifest(ext.path(), "Roundtrip");

    let seed_hex = hex::encode([0x11u8; 64]);
    let sid = "S-1-5-21-999-1";

    // -- install --
    let install_out = secpref()
        .args(["prefs", "install", "--profile"])
        .arg(profile.path())
        .args(["--ext"])
        .arg(ext.path())
        .args(["--seed", &seed_hex, "--sid", sid])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let install_str = String::from_utf8(install_out).unwrap();
    assert!(
        install_str.starts_with("installed "),
        "unexpected install stdout: {install_str}"
    );
    let ext_id = install_str
        .split_whitespace()
        .nth(1)
        .expect("install output should be `installed <ext_id> (mac ...)`")
        .to_string();
    assert_eq!(ext_id.len(), 32);

    // -- verify (passes) --
    secpref()
        .args(["prefs", "verify", "--profile"])
        .arg(profile.path())
        .args(["--ext-id", &ext_id, "--seed", &seed_hex, "--sid", sid])
        .assert()
        .success();

    // -- list --json (one entry) --
    let list_json = secpref()
        .args(["prefs", "list", "--json", "--profile"])
        .arg(profile.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let parsed: Value = serde_json::from_slice(&list_json).unwrap();
    let arr = parsed.as_array().expect("list --json should emit a JSON array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0].get("id").and_then(Value::as_str), Some(ext_id.as_str()));
    assert_eq!(arr[0].get("name").and_then(Value::as_str), Some("Roundtrip"));
    assert_eq!(arr[0].get("enabled").and_then(Value::as_bool), Some(true));

    // -- uninstall --
    secpref()
        .args(["prefs", "uninstall", "--profile"])
        .arg(profile.path())
        .args(["--ext-id", &ext_id, "--seed", &seed_hex, "--sid", sid])
        .assert()
        .success();

    // -- list --json (empty) --
    let empty_list = secpref()
        .args(["prefs", "list", "--json", "--profile"])
        .arg(profile.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let empty_parsed: Value = serde_json::from_slice(&empty_list).unwrap();
    assert!(empty_parsed.as_array().unwrap().is_empty());
}

// ---------------- prefs verify exit codes ----------------

#[test]
fn prefs_verify_wrong_seed_exits_1() {
    let profile = empty_prefs_dir();
    let ext = TempDir::new().unwrap();
    write_manifest(ext.path(), "WrongSeed");

    let install_seed = hex::encode([0x22u8; 64]);
    let sid = "S-1-5-21-100";

    // install with one seed
    let install_out = secpref()
        .args(["prefs", "install", "--profile"])
        .arg(profile.path())
        .args(["--ext"])
        .arg(ext.path())
        .args(["--seed", &install_seed, "--sid", sid])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let ext_id = String::from_utf8(install_out)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string();

    // verify with a DIFFERENT seed — DESIGN.md §4.3 says exit 1 = mismatch
    let wrong_seed = hex::encode([0xFFu8; 64]);
    secpref()
        .args(["prefs", "verify", "--profile"])
        .arg(profile.path())
        .args([
            "--ext-id", &ext_id,
            "--seed", &wrong_seed,
            "--sid", sid,
        ])
        .assert()
        .code(1);
}

#[test]
fn prefs_verify_missing_extension_exits_2() {
    let profile = empty_prefs_dir();
    let seed_hex = hex::encode([0x33u8; 64]);

    // DESIGN.md §4.3: exit 2 = missing extension
    secpref()
        .args(["prefs", "verify", "--profile"])
        .arg(profile.path())
        .args([
            "--ext-id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--seed", &seed_hex,
            "--sid", "S-1-5-21-1",
        ])
        .assert()
        .code(2);
}

// ---------------- prefs backup + strip-encrypted-hashes ----------------

#[test]
fn prefs_install_backup_writes_backup_file() {
    let profile = empty_prefs_dir();
    let ext = TempDir::new().unwrap();
    write_manifest(ext.path(), "Backupable");
    let backup_dir = TempDir::new().unwrap();

    let seed_hex = hex::encode([0x44u8; 64]);
    secpref()
        .args(["prefs", "install", "--profile"])
        .arg(profile.path())
        .args(["--ext"])
        .arg(ext.path())
        .args(["--seed", &seed_hex, "--sid", "S-1-5-21-B", "--backup"])
        .arg(backup_dir.path())
        .assert()
        .success()
        // backup path is logged to stderr per handler
        .stderr(predicate::str::contains("backup: "));

    let entries: Vec<_> = fs::read_dir(backup_dir.path())
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(entries.len(), 1, "expected exactly one backup file");
    let entry_path = entries[0].path();
    let name = entry_path.file_name().unwrap().to_string_lossy().into_owned();
    let ext_is_bak = entry_path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("bak"));
    assert!(
        name.starts_with("Secure Preferences.") && ext_is_bak,
        "unexpected backup filename: {name}"
    );
}

#[test]
fn prefs_strip_encrypted_hashes_removes_recursively() {
    let profile = TempDir::new().unwrap();
    let path = profile.path().join("Secure Preferences");
    fs::write(
        &path,
        json!({
            "protection": {
                "macs": {
                    "settings_encrypted_hash": "DEADBEEF",
                    "extensions": {
                        "settings_encrypted_hash": "CAFEBABE",
                        "settings": {
                            "abcdefghijklmnopqrstuvwxyzabcdef_encrypted_hash": "F00DF00D"
                        }
                    }
                }
            },
            "keep_this": "yes"
        })
        .to_string(),
    )
    .unwrap();

    secpref()
        .args(["prefs", "strip-encrypted-hashes", "--profile"])
        .arg(profile.path())
        .assert()
        .success();

    let after = fs::read_to_string(&path).unwrap();
    assert!(!after.contains("_encrypted_hash"));
    assert!(after.contains("\"keep_this\":\"yes\""));
}

// ---------------- SID (non-Windows guard) ----------------

#[test]
#[cfg(not(windows))]
fn sid_current_errors_on_non_windows() {
    secpref()
        .args(["sid", "current"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("Windows-only"));
}

#[test]
#[cfg(not(windows))]
fn sid_current_flag_errors_on_non_windows() {
    // --sid-current inside a `mac compute` should also fail on non-Windows.
    secpref()
        .args([
            "mac", "compute",
            "--seed", "",
            "--sid-current",
            "--path", "p",
            "--value", "true",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("Windows-only"));
}

// ---------------- arg-group correctness ----------------

#[test]
fn seed_source_arg_group_is_required() {
    // Neither --seed nor --pak
    secpref()
        .args([
            "mac", "compute",
            "--sid", "sid",
            "--path", "p",
            "--value", "true",
        ])
        .assert()
        .failure();
}

#[test]
fn seed_source_arg_group_is_exclusive() {
    // Both --seed AND --pak → clap should reject before we get to logic
    secpref()
        .args([
            "mac", "compute",
            "--seed", "00",
            "--pak", "/nowhere/resources.pak",
            "--sid", "sid",
            "--path", "p",
            "--value", "true",
        ])
        .assert()
        .failure();
}

#[test]
fn sid_source_arg_group_is_required() {
    // Neither --sid nor --sid-current
    secpref()
        .args([
            "mac", "compute",
            "--seed", "",
            "--path", "p",
            "--value", "true",
        ])
        .assert()
        .failure();
}
