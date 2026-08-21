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
fn dictionary_insertion_order_is_not_significant() {
    // Chromium's base::Value::Dict is sorted, so equivalent dictionaries must
    // produce the same MAC regardless of input insertion order.
    let a: Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
    let seed = [b'K'; 64];
    let mac_a = compute_mac(&seed, "sid", "x", &a);
    let mac_b = compute_mac(&seed, "sid", "x", &b);
    assert_eq!(
        mac_a, mac_b,
        "dictionary keys must be sorted before MAC computation"
    );
}

#[test]
fn chromium_dictionary_canonicalization_vector() {
    let seed = [b'K'; 64];
    let value: Value = serde_json::from_str(
        r#"{"z":0,"a":{"drop":{},"keep":"","nil":null},"list":[{},[],{"b":2,"a":1}]}"#,
    )
    .unwrap();
    let mac = compute_mac(&seed, "sid", "x", &value);
    assert_eq!(
        mac,
        "AE4E565D29D086B6B2ED99695605946A19F2975369BED631AA2A98F71F325B05"
    );
}

#[test]
fn super_mac_uses_sorted_dictionary_serialization() {
    let seed = [b'K'; 64];
    let macs: Value = serde_json::from_str(r#"{"z":"ZZZZ","a":"AAAA"}"#).unwrap();
    assert_eq!(
        compute_super_mac(&seed, "sid", &macs),
        "4ECF5F1F64B2BF53C78EF5CB954F1322BFEFC70DFCA0C7BAF2B917D010F01A88"
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
