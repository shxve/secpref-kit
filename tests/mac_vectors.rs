//! Deterministic HMAC test vectors.
//!
//! These vectors are pinned so future changes to canonicalisation, JSON
//! serialisation, or hex encoding are caught by CI. Match Chromium's
//! observed behaviour and the vectors used by upstream `Silent_Chrome`.

use secpref_kit::{compute_absent_mac, compute_absent_mac_bytes, compute_mac, compute_super_mac};
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
fn absent_preference_has_no_serialized_value_bytes() {
    let mac = compute_absent_mac(b"", "", "missing.pref");
    assert_eq!(
        mac,
        "7716107AF54B6DDD4A298E0E357ECB129C896C8DF706362730CC57277C685793"
    );
    assert_ne!(mac, compute_mac(b"", "", "missing.pref", &Value::Null));
    assert_ne!(
        mac,
        compute_mac(b"", "", "missing.pref", &Value::String(String::new()))
    );
}

#[test]
fn absent_preference_raw_bytes_match_pinned_hex() {
    let seed = [b'K'; 64];
    let hex = compute_absent_mac(&seed, "S-1-5-21-123", "extensions.settings.absent");
    let bytes = compute_absent_mac_bytes(&seed, "S-1-5-21-123", "extensions.settings.absent");
    assert_eq!(
        hex,
        "EE99E5BC40BBBF69703914693BFBA4800B3E66C978F6A5A7BFF742930007C5AF"
    );
    assert_eq!(
        bytes,
        [
            0xEE, 0x99, 0xE5, 0xBC, 0x40, 0xBB, 0xBF, 0x69, 0x70, 0x39, 0x14, 0x69, 0x3B, 0xFB,
            0xA4, 0x80, 0x0B, 0x3E, 0x66, 0xC9, 0x78, 0xF6, 0xA5, 0xA7, 0xBF, 0xF7, 0x42, 0x93,
            0x00, 0x07, 0xC5, 0xAF,
        ]
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
