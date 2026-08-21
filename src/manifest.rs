//! Extension manifest parsing and `extensions.settings` blob construction.
//!
//! This module is more opinionated than the rest of the crate — it produces
//! a `settings` object that matches what Chromium writes for a sideloaded
//! unpacked extension. If a consumer needs a different shape, build the
//! `serde_json::Value` themselves and pass it to
//! [`crate::prefs::add_extension`] directly.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::SecPrefError;

/// Windows FILETIME offset for Unix epoch, in microseconds.
///
/// Chromium stores `first_install_time` / `last_update_time` as decimal
/// strings of Windows FILETIME microseconds since 1601-01-01. Non-Windows
/// callers can still generate valid values with this offset.
const FILETIME_EPOCH_OFFSET_US: u64 = 11_644_473_600_000_000;

/// A parsed extension manifest.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Manifest {
    /// The raw parsed JSON of `manifest.json`.
    pub raw: Value,
    /// The extension name.
    pub name: String,
    /// The extension version.
    pub version: String,
    /// Requested API permissions (`permissions` field).
    pub permissions: Vec<String>,
    /// Requested host permissions (`host_permissions` field).
    pub host_permissions: Vec<String>,
    /// Base64-encoded public key, if present. Used to derive a stable ID.
    pub key: Option<String>,
    /// Service worker script path, if this is an MV3 extension.
    pub service_worker: Option<String>,
}

/// Parse `manifest.json` from an extension directory.
///
/// # Errors
///
/// I/O errors reading the file, or [`SecPrefError::Json`] if the manifest is
/// not valid JSON.
pub fn parse(dir: &Path) -> Result<Manifest, SecPrefError> {
    let manifest_path = dir.join("manifest.json");
    let content = std::fs::read_to_string(&manifest_path)?;
    parse_str(&content)
}

/// Parse a manifest from an in-memory string.
///
/// # Errors
///
/// [`SecPrefError::Json`] if the input is not valid JSON.
pub fn parse_str(json_str: &str) -> Result<Manifest, SecPrefError> {
    let raw: Value = serde_json::from_str(json_str)?;

    let name = raw
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    let version = raw
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("1.0")
        .to_string();

    let permissions = extract_string_array(&raw, "permissions");
    let host_permissions = extract_string_array(&raw, "host_permissions");

    let key = raw.get("key").and_then(Value::as_str).map(String::from);

    let service_worker = raw
        .get("background")
        .and_then(|bg| bg.get("service_worker"))
        .and_then(Value::as_str)
        .map(String::from);

    Ok(Manifest {
        raw,
        name,
        version,
        permissions,
        host_permissions,
        key,
        service_worker,
    })
}

/// Build the `extensions.settings.<id>` JSON blob for a sideloaded extension.
///
/// Produces the shape Chromium writes for an **unpacked** extension in
/// developer mode (state=1, location=4). Consumers can override any field
/// by mutating the returned `Value` before passing it to
/// [`crate::prefs::add_extension`].
#[must_use]
pub fn build_default_settings(manifest: &Manifest, ext_path: &str) -> Value {
    let now = filetime_now();

    let all_permissions: Vec<Value> = manifest
        .permissions
        .iter()
        .map(|s| Value::String(s.clone()))
        .collect();

    let all_hosts: Vec<Value> = manifest
        .host_permissions
        .iter()
        .map(|s| Value::String(s.clone()))
        .collect();

    let mut settings = json!({
        "account_extension_type": 0,
        "active_permissions": {
            "api": all_permissions,
            "explicit_host": all_hosts,
            "manifest_permissions": [],
            "scriptable_host": []
        },
        "commands": {},
        "content_settings": [],
        "creation_flags": 38,
        "first_install_time": now,
        "from_bookmark": false,
        "from_webstore": false,
        "granted_permissions": {
            "api": all_permissions,
            "explicit_host": all_hosts,
            "manifest_permissions": [],
            "scriptable_host": []
        },
        "incognito": true,
        "incognito_content_settings": [],
        "incognito_preferences": {},
        "last_update_time": now,
        "location": 4,
        "manifest": manifest.raw,
        "newAllowFileAccess": true,
        "path": ext_path,
        "preferences": {},
        "regular_only_preferences": {},
        "state": 1,
        "was_installed_by_default": false,
        "was_installed_by_oem": false,
        "withholding_permissions": false
    });

    if manifest.service_worker.is_some() {
        settings["service_worker_registration_info"] =
            json!({ "version": manifest.version });
    }

    settings
}

fn filetime_now() -> String {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock");
    #[allow(clippy::cast_possible_truncation)]
    let micros = since_epoch.as_micros() as u64;
    let filetime = micros + FILETIME_EPOCH_OFFSET_US;
    filetime.to_string()
}

fn extract_string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_manifest() {
        let json = r#"{"name": "Hello", "version": "1.2.3", "permissions": ["cookies"]}"#;
        let m = parse_str(json).unwrap();
        assert_eq!(m.name, "Hello");
        assert_eq!(m.version, "1.2.3");
        assert_eq!(m.permissions, vec!["cookies".to_string()]);
        assert!(m.key.is_none());
        assert!(m.service_worker.is_none());
    }

    #[test]
    fn parse_extracts_mv3_service_worker() {
        let json = r#"{
            "name": "SW",
            "version": "0.1",
            "background": {"service_worker": "worker.js", "type": "module"}
        }"#;
        let m = parse_str(json).unwrap();
        assert_eq!(m.service_worker.as_deref(), Some("worker.js"));
    }

    #[test]
    fn build_default_settings_populates_manifest_and_path() {
        let m = parse_str(r#"{"name": "N", "version": "1.0"}"#).unwrap();
        let s = build_default_settings(&m, "/opt/ext");
        assert_eq!(s.get("path").and_then(Value::as_str), Some("/opt/ext"));
        assert_eq!(s.get("state").and_then(Value::as_i64), Some(1));
        assert_eq!(s.get("location").and_then(Value::as_i64), Some(4));
        assert!(s.get("manifest").is_some());
    }
}
