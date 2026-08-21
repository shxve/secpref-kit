//! HMAC-SHA256 primitives Chromium uses for Secure Preferences integrity.
//!
//! Two MACs matter:
//!
//! 1. **Per-value MAC** ([`compute_mac`]): `HMAC-SHA256(seed, device_id || path || canonical(value))`
//!    stored under `protection.macs.<dot-separated-path>`.
//! 2. **Super-MAC** ([`compute_super_mac`]): `HMAC-SHA256(seed, device_id || compact_json(macs))`
//!    stored at `protection.super_mac`, covering the entire `protection.macs`
//!    dictionary.
//!
//! Both are uppercase hex (64 characters, 32 bytes).
//!
//! The canonicalisation rules for the `value` in per-value MACs (implemented
//! by [`canonicalize`] + [`strip_empties`]) mirror Chromium's `JSONWriter`:
//! insertion-order keys (requires `serde_json` `preserve_order`), no
//! whitespace, empty containers / nulls stripped, `<` escaped as `<`.
//! Get any of those wrong and the MAC will not match what the browser
//! computes on load.

use std::fmt::Write;

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute a per-preference MAC as uppercase hex.
///
/// `HMAC-SHA256(seed, device_id || pref_path || canonicalize(value))` → 64 hex chars.
///
/// - `seed` — 64-byte `chrome_seed` from `resources.pak` (see [`crate::seed`]).
/// - `device_id` — Chromium's machine-scoped identifier (the machine SID on
///   Windows). Pass `""` for Linux or the raw MAC used in test vectors.
/// - `pref_path` — dotted preference path (e.g.
///   `extensions.settings.abcdefgh...`).
/// - `value` — the exact JSON value stored at that path.
///
/// # Examples
///
/// ```
/// use secpref_kit::compute_mac;
/// use serde_json::Value;
///
/// let mac = compute_mac(b"", "", "extensions.ui.developer_mode", &Value::Bool(true));
/// assert_eq!(mac, "F1323889EA777F2EB3E23F3E2CFCB59D3FAFCB8DE80104742CBF2A9E44046ED9");
/// ```
#[must_use]
pub fn compute_mac(seed: &[u8], device_id: &str, pref_path: &str, value: &Value) -> String {
    let canonical = canonicalize(value);
    let message = format!("{device_id}{pref_path}{canonical}");
    hmac_hex(seed, message.as_bytes())
}

/// Compute the `super_mac` over the entire `protection.macs` sub-tree.
///
/// `HMAC-SHA256(seed, device_id || compact_json(macs))` → 64 hex chars.
///
/// The `macs` value should be a JSON object whose nested structure mirrors
/// every path that has a per-value MAC (e.g. `{"extensions":{"settings":{"<id>":"<hex>"}, "ui":{"developer_mode":"<hex>"}}}`).
///
/// Ordering: the sub-tree is serialised with `serde_json` (which — with
/// `preserve_order` enabled — writes keys in insertion order). Chromium
/// itself does not sort here; matching insertion order is the correctness
/// requirement.
#[must_use]
pub fn compute_super_mac(seed: &[u8], device_id: &str, macs: &Value) -> String {
    let macs_json = serde_json::to_string(macs).expect("macs serialization");
    let message = format!("{device_id}{macs_json}");
    hmac_hex(seed, message.as_bytes())
}

/// Compute a per-preference MAC as raw bytes (32 bytes).
///
/// Same input as [`compute_mac`]; useful when the caller wants the bytes
/// directly (comparison against a stored value, custom encoding, ...).
#[must_use]
pub fn compute_mac_bytes(seed: &[u8], device_id: &str, pref_path: &str, value: &Value) -> [u8; 32] {
    let canonical = canonicalize(value);
    let message = format!("{device_id}{pref_path}{canonical}");
    hmac_bytes(seed, message.as_bytes())
}

/// Compute the super-MAC as raw bytes (32 bytes).
#[must_use]
pub fn compute_super_mac_bytes(seed: &[u8], device_id: &str, macs: &Value) -> [u8; 32] {
    let macs_json = serde_json::to_string(macs).expect("macs serialization");
    let message = format!("{device_id}{macs_json}");
    hmac_bytes(seed, message.as_bytes())
}

/// Serialize a JSON value for HMAC input following Chromium's `JSONWriter`
/// conventions:
///
/// 1. Compact (no whitespace).
/// 2. Insertion-order keys — relies on `serde_json`'s `preserve_order`
///    feature (enabled by this crate).
/// 3. Strip empty objects/arrays/strings and nulls (preserve `false` and `0`).
/// 4. Replace `<` with `<` (Chromium escapes it to prevent XSS if the
///    JSON is ever embedded in HTML).
#[must_use]
pub fn canonicalize(value: &Value) -> String {
    let mut v = value.clone();
    strip_empties(&mut v);
    let json = serde_json::to_string(&v).expect("JSON serialization");
    json.replace('<', "\\u003C")
}

/// Recursively remove keys whose values are empty objects, empty arrays,
/// empty strings, or null. Preserves `false` and `0` — those are meaningful
/// values Chromium keeps.
///
/// Run twice at each object level so that stripping an inner empty object
/// which then empties its parent is caught on the second pass.
pub fn strip_empties(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let keys_to_remove: Vec<String> = map
                .iter()
                .filter_map(|(k, v)| if is_empty(v) { Some(k.clone()) } else { None })
                .collect();
            for k in &keys_to_remove {
                map.swap_remove(k);
            }
            for v in map.values_mut() {
                strip_empties(v);
            }
            let keys_to_remove: Vec<String> = map
                .iter()
                .filter_map(|(k, v)| if is_empty(v) { Some(k.clone()) } else { None })
                .collect();
            for k in &keys_to_remove {
                map.swap_remove(k);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                strip_empties(item);
            }
            arr.retain(|v| !is_empty(v));
        }
        _ => {}
    }
}

fn is_empty(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.is_empty(),
        Value::Array(arr) => arr.is_empty(),
        Value::String(s) => s.is_empty(),
        Value::Null => true,
        _ => false,
    }
}

fn hmac_bytes(seed: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

fn hmac_hex(seed: &[u8], message: &[u8]) -> String {
    let bytes = hmac_bytes(seed, message);
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in &bytes {
        let _ = write!(hex, "{byte:02X}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mac_empty_seed_empty_sid_bool_true() {
        let mac = compute_mac(b"", "", "extensions.ui.developer_mode", &Value::Bool(true));
        assert_eq!(
            mac,
            "F1323889EA777F2EB3E23F3E2CFCB59D3FAFCB8DE80104742CBF2A9E44046ED9"
        );
    }

    #[test]
    fn mac_known_seed_with_sid_and_object_value() {
        let seed = [b'A'; 64];
        let value = json!({"key1": "value1", "key2": 42});
        let mac = compute_mac(&seed, "S-1-5-21-123", "extensions.settings.testid", &value);
        assert_eq!(
            mac,
            "B33251DEB592061EDBCE92A14F009D37181A0F9F5B64605CC01764E1CAE12471"
        );
    }

    #[test]
    fn mac_bytes_matches_hex() {
        let seed = [b'K'; 64];
        let value = json!({"state": 1});
        let hex = compute_mac(&seed, "sid", "path", &value);
        let bytes = compute_mac_bytes(&seed, "sid", "path", &value);
        assert_eq!(hex.len(), 64);
        assert_eq!(bytes.len(), 32);
        let mut recoded = String::new();
        for b in &bytes {
            let _ = write!(recoded, "{b:02X}");
        }
        assert_eq!(hex, recoded);
    }

    #[test]
    fn strip_empties_preserves_false_and_zero() {
        let mut v = json!({
            "keep": 42,
            "keep_false": false,
            "keep_zero": 0,
            "drop_empty_obj": {},
            "drop_empty_arr": [],
            "drop_empty_str": "",
            "drop_null": null,
            "nested": {"inner_keep": "yes", "inner_drop": {}}
        });
        strip_empties(&mut v);
        assert!(v.get("keep").is_some());
        assert!(v.get("keep_false").is_some());
        assert!(v.get("keep_zero").is_some());
        assert!(v.get("drop_empty_obj").is_none());
        assert!(v.get("drop_empty_arr").is_none());
        assert!(v.get("drop_empty_str").is_none());
        assert!(v.get("drop_null").is_none());
        let nested = v.get("nested").unwrap();
        assert!(nested.get("inner_keep").is_some());
        assert!(nested.get("inner_drop").is_none());
    }

    #[test]
    fn canonicalize_escapes_angle_bracket() {
        let v = json!({"host": "<all_urls>"});
        let c = canonicalize(&v);
        assert!(c.contains("\\u003C"));
        assert!(!c.contains('<'));
    }
}
