//! Deterministic HMAC test vectors.
//!
//! These vectors are pinned so future changes to canonicalisation, JSON
//! serialisation, or hex encoding are caught by CI. Match Chromium's
//! observed behaviour and the vectors used by upstream `Silent_Chrome`.

use secpref_kit::{compute_mac, compute_super_mac};
use serde_json::{json, Value};

#[test]
fn mac_boolean_true_no_key_no_sid() {
    // The canonical "no chrome_seed" / "no SID" fingerprint that Chromium
    // itself computes for a fresh install of Chrome's `developer_mode = true`
    // preference. Value pinned from upstream references.
    let mac = compute_mac(b"", "", "extensions.ui.developer_mode", &Value::Bool(true));
    assert_eq!(
        mac,
        "F1323889EA777F2EB3E23F3E2CFCB59D3FAFCB8DE80104742CBF2A9E44046ED9"
    );
}

#[test]
fn mac_object_value_with_seed_and_sid() {
    let seed = [b'A'; 64];
    let value = json!({"key1": "value1", "key2": 42});
    let mac = compute_mac(&seed, "S-1-5-21-123", "extensions.settings.testid", &value);
    assert_eq!(
        mac,
        "B33251DEB592061EDBCE92A14F009D37181A0F9F5B64605CC01764E1CAE12471"
    );
}

#[test]
fn insertion_order_is_significant() {
    // Two objects with the same keys but different insertion order MUST
    // produce different MACs — this is the whole reason we depend on
    // `serde_json`'s `preserve_order`.
    let a: Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
    let seed = [b'K'; 64];
    let mac_a = compute_mac(&seed, "sid", "x", &a);
    let mac_b = compute_mac(&seed, "sid", "x", &b);
    assert_ne!(
        mac_a, mac_b,
        "insertion order must affect MAC — check preserve_order feature"
    );
}

#[test]
fn super_mac_is_deterministic_over_same_input() {
    let seed = [b'S'; 64];
    let macs = json!({
        "extensions": {
            "settings": {"abcdefghijklmnopqrstuvwxyzabcdef": "AAAA"},
            "ui": {"developer_mode": "BBBB"}
        }
    });
    let a = compute_super_mac(&seed, "sid", &macs);
    let b = compute_super_mac(&seed, "sid", &macs);
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
}

#[test]
fn different_devices_produce_different_macs() {
    let seed = [b'K'; 64];
    let v = json!({"state": 1});
    let a = compute_mac(&seed, "S-1-5-21-A", "extensions.settings.id", &v);
    let b = compute_mac(&seed, "S-1-5-21-B", "extensions.settings.id", &v);
    assert_ne!(a, b);
}

#[test]
fn preserves_false_and_zero_in_value() {
    // False and 0 are meaningful — Chromium's canonicaliser preserves them.
    // A MAC over `{"x": false}` must differ from one over `{}` (which
    // canonicalises to the empty object → dropped).
    let seed = [b'Z'; 64];
    let a = compute_mac(&seed, "sid", "p", &json!({"x": false}));
    let b = compute_mac(&seed, "sid", "p", &json!({}));
    assert_ne!(a, b);
}
