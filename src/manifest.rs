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
    /// Chromium manifest version (`2` or `3`).
    pub manifest_version: u64,
    /// The extension name.
    pub name: String,
    /// The extension version.
    pub version: String,
    /// Requested permission strings from the `permissions` field. This may
    /// include Manifest V2 host patterns, which settings construction separates
    /// from API permissions.
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

    if !raw.is_object() {
        return Err(SecPrefError::InvalidManifest(
            "manifest root must be an object".into(),
        ));
    }

    let manifest_version = raw
        .get("manifest_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            SecPrefError::InvalidManifest("missing integer `manifest_version`".into())
        })?;
    if !matches!(manifest_version, 2 | 3) {
        return Err(SecPrefError::InvalidManifest(format!(
            "unsupported `manifest_version` {manifest_version}"
        )));
    }
    if manifest_version == 2 && raw.get("host_permissions").is_some() {
        return Err(SecPrefError::InvalidManifest(
            "`host_permissions` is available only in Manifest V3".into(),
        ));
    }

    let name = raw
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| SecPrefError::InvalidManifest("missing non-empty string `name`".into()))?
        .to_string();

    let version = raw
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| SecPrefError::InvalidManifest("missing non-empty string `version`".into()))?
        .to_string();

    let permissions = extract_string_array(&raw, "permissions")?;
    let host_permissions = extract_string_array(&raw, "host_permissions")?;

    let key = match raw.get("key") {
        Some(Value::String(key)) => Some(key.clone()),
        Some(_) => {
            return Err(SecPrefError::InvalidManifest(
                "`key` must be a string".into(),
            ));
        }
        None => None,
    };

    let service_worker = raw
        .get("background")
        .and_then(|bg| bg.get("service_worker"))
        .and_then(Value::as_str)
        .map(String::from);

    Ok(Manifest {
        raw,
        manifest_version,
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
/// Produces a conservative current shape for an **unpacked** extension at
/// location 4. Chromium reloads unpacked manifests from disk, so the record
/// deliberately does not cache the manifest or service-worker lifecycle state.
/// Consumers can override any field by mutating the returned `Value` before passing it to
/// [`crate::prefs::add_extension`].
#[must_use]
pub fn build_default_settings(manifest: &Manifest, ext_path: &str) -> Value {
    let now = filetime_now();

    let api_permissions: Vec<Value> = manifest
        .permissions
        .iter()
        .filter(|permission| !is_host_permission(permission))
        .map(|s| Value::String(s.clone()))
        .collect();

    let explicit_hosts: Vec<Value> = manifest
        .permissions
        .iter()
        .filter(|permission| is_host_permission(permission))
        .chain(manifest.host_permissions.iter())
        .map(|s| Value::String(s.clone()))
        .collect();

    json!({
        "active_permissions": {
            "api": api_permissions,
            "explicit_host": explicit_hosts,
            "manifest_permissions": [],
            "scriptable_host": []
        },
        "commands": {},
        "content_settings": [],
        "creation_flags": 38,
        "disable_reasons": [],
        "first_install_time": now,
        "from_webstore": false,
        "granted_permissions": {
            "api": api_permissions,
            "explicit_host": explicit_hosts,
            "manifest_permissions": [],
            "scriptable_host": []
        },
        "incognito_content_settings": [],
        "incognito_preferences": {},
        "last_update_time": now,
        "location": 4,
        "path": ext_path,
        "preferences": {},
        "regular_only_preferences": {},
        "was_installed_by_default": false,
        "was_installed_by_oem": false,
        "withholding_permissions": false
    })
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

fn extract_string_array(value: &Value, key: &str) -> Result<Vec<String>, SecPrefError> {
    let Some(raw) = value.get(key) else {
        return Ok(Vec::new());
    };
    let array = raw
        .as_array()
        .ok_or_else(|| SecPrefError::InvalidManifest(format!("`{key}` must be an array")))?;
    array
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            entry.as_str().map(String::from).ok_or_else(|| {
                SecPrefError::InvalidManifest(format!(
                    "`{key}[{index}]` must be a string; parameterized dictionary permissions are not supported"
                ))
            })
        })
        .collect()
}

fn is_host_permission(permission: &str) -> bool {
    permission == "<all_urls>" || permission.contains("://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_manifest() {
        let json = r#"{"manifest_version": 3, "name": "Hello", "version": "1.2.3", "permissions": ["cookies"]}"#;
        let m = parse_str(json).unwrap();
        assert_eq!(m.name, "Hello");
        assert_eq!(m.version, "1.2.3");
        assert_eq!(m.manifest_version, 3);
        assert_eq!(m.permissions, vec!["cookies".to_string()]);
        assert!(m.key.is_none());
        assert!(m.service_worker.is_none());
    }

    #[test]
    fn parse_extracts_mv3_service_worker() {
        let json = r#"{
            "manifest_version": 3,
            "name": "SW",
            "version": "0.1",
            "background": {"service_worker": "worker.js", "type": "module"}
        }"#;
        let m = parse_str(json).unwrap();
        assert_eq!(m.service_worker.as_deref(), Some("worker.js"));
    }

    #[test]
    fn build_default_settings_uses_current_unpacked_shape() {
        let m = parse_str(r#"{"manifest_version": 3, "name": "N", "version": "1.0"}"#).unwrap();
        let s = build_default_settings(&m, "/opt/ext");
        assert_eq!(s.get("path").and_then(Value::as_str), Some("/opt/ext"));
        assert_eq!(s.get("location").and_then(Value::as_i64), Some(4));
        assert!(s.get("manifest").is_none());
        assert!(s.get("service_worker_registration_info").is_none());
        assert_eq!(s.get("disable_reasons"), Some(&json!([])));
    }

    #[test]
    fn rejects_missing_required_fields() {
        assert!(matches!(
            parse_str(r#"{"name":"N","version":"1"}"#),
            Err(SecPrefError::InvalidManifest(_))
        ));
        assert!(matches!(
            parse_str(r#"{"manifest_version":3,"name":"","version":"1"}"#),
            Err(SecPrefError::InvalidManifest(_))
        ));
    }

    #[test]
    fn rejects_malformed_permission_entries_instead_of_dropping_them() {
        let error = parse_str(
            r#"{"manifest_version":3,"name":"N","version":"1","permissions":["tabs",42]}"#,
        )
        .unwrap_err();
        assert!(matches!(error, SecPrefError::InvalidManifest(_)));
    }

    #[test]
    fn rejects_non_string_manifest_key() {
        let error =
            parse_str(r#"{"manifest_version":3,"name":"N","version":"1","key":42}"#).unwrap_err();
        assert!(matches!(error, SecPrefError::InvalidManifest(_)));
    }

    #[test]
    fn rejects_mv2_host_permissions_field() {
        let error = parse_str(
            r#"{"manifest_version":2,"name":"N","version":"1","host_permissions":["https://example.test/*"]}"#,
        )
        .unwrap_err();
        assert!(matches!(error, SecPrefError::InvalidManifest(_)));
    }

    #[test]
    fn mv2_host_patterns_are_written_as_explicit_hosts() {
        let manifest = parse_str(
            r#"{"manifest_version":2,"name":"N","version":"1","permissions":["tabs","https://example.test/*","<all_urls>"]}"#,
        )
        .unwrap();
        let settings = build_default_settings(&manifest, "/opt/ext");

        assert_eq!(settings["active_permissions"]["api"], json!(["tabs"]));
        assert_eq!(
            settings["active_permissions"]["explicit_host"],
            json!(["https://example.test/*", "<all_urls>"])
        );
    }
}
