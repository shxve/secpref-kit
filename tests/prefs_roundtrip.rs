//! End-to-end round-trip: install → verify → uninstall.

use secpref_kit::{manifest, prefs, resolve_ext_id};
use serde_json::json;

const SEED: [u8; 64] = [0x42; 64];
const SID: &str = "S-1-5-21-1234-5678-9012-1001";

#[test]
fn install_flow_produces_valid_macs() {
    let mut prefs_json = json!({});

    // Fake manifest → deterministic ext-id.
    let m = manifest::parse_str(
        r#"{"name": "Test", "version": "0.1.0", "permissions": ["cookies"]}"#,
    )
    .unwrap();
    let ext_path = "/tmp/some/ext";
    let ext_id = resolve_ext_id(m.key.as_deref(), ext_path).into_id();
    let settings = manifest::build_default_settings(&m, ext_path);

    // Install + developer mode + encrypted-hash bypass + super-MAC.
    let ext_mac =
        prefs::add_extension(&mut prefs_json, &ext_id, settings, &SEED, SID).unwrap();
    assert_eq!(ext_mac.len(), 64);

    prefs::enable_developer_mode(&mut prefs_json, &SEED, SID);
    prefs::strip_encrypted_hashes(&mut prefs_json);
    let super_mac = prefs::recompute_super_mac(&mut prefs_json, &SEED, SID);
    assert_eq!(super_mac.len(), 64);

    // Verify.
    let verdict = prefs::verify_extension(&prefs_json, &ext_id, &SEED, SID).unwrap();
    assert!(
        verdict.all_valid(),
        "expected all MACs valid after install: {verdict:?}"
    );
}

#[test]
fn tampered_extension_fails_verify() {
    let mut prefs_json = json!({});
    let ext_id = "abcdefghijklmnopqrstuvwxyzabcdef";
    prefs::add_extension(
        &mut prefs_json,
        ext_id,
        json!({"state": 1}),
        &SEED,
        SID,
    )
    .unwrap();
    prefs::enable_developer_mode(&mut prefs_json, &SEED, SID);
    prefs::recompute_super_mac(&mut prefs_json, &SEED, SID);

    // Tamper: change the settings blob without recomputing the MAC.
    if let Some(s) = prefs_json
        .get_mut("extensions")
        .and_then(|e| e.get_mut("settings"))
        .and_then(|s| s.get_mut(ext_id))
    {
        *s = json!({"state": 0});
    }

    let verdict = prefs::verify_extension(&prefs_json, ext_id, &SEED, SID).unwrap();
    assert!(!verdict.ext_mac_valid, "tampered extension should fail MAC check");
}

#[test]
fn uninstall_removes_settings_and_macs() {
    let mut prefs_json = json!({});
    let ext_id = "abcdefghijklmnopqrstuvwxyzabcdef";
    prefs::add_extension(
        &mut prefs_json,
        ext_id,
        json!({"state": 1}),
        &SEED,
        SID,
    )
    .unwrap();

    prefs::remove_extension(&mut prefs_json, ext_id).unwrap();

    assert!(prefs::list_extensions(&prefs_json).is_empty());
}

#[test]
fn uninstall_unknown_extension_errors() {
    let mut prefs_json = json!({"extensions": {"settings": {}}});
    let err = prefs::remove_extension(&mut prefs_json, "not-installed").unwrap_err();
    assert!(matches!(err, secpref_kit::SecPrefError::ExtensionNotFound(_)));
}
