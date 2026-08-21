//! Chromium extension ID derivation.
//!
//! Two paths:
//!
//! 1. **From manifest `key`** — stable across install locations. The `key` is
//!    a base64-encoded public key; ID = SHA-256(decoded key) → first 32 hex
//!    nibbles mapped to `[a-p]`.
//! 2. **From on-disk path** — used when the extension has no `key`. On
//!    Windows, path bytes are UTF-16-LE encoded before hashing (matches
//!    Chromium's behaviour). On non-Windows targets, UTF-8 bytes.
//!
//! Chrome maps hex nibbles `0x0..0xF` to letters `a..p` — a 16-letter subset
//! of the alphabet chosen so extension IDs are case-insensitive and
//! filename-safe.

use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::SecPrefError;

/// Canonicalize an extension directory and return both its path and UTF-8 form.
///
/// Chromium hashes and stores the absolute, normalized path for unpacked
/// extensions. Keeping the string and filesystem path together prevents the
/// manifest reader, ID derivation, and stored settings from disagreeing.
pub fn canonical_extension_path(path: impl AsRef<Path>) -> Result<(PathBuf, String), SecPrefError> {
    let canonical = dunce::canonicalize(path.as_ref()).map_err(|error| {
        SecPrefError::InvalidExtensionPath(format!("{}: {error}", path.as_ref().display()))
    })?;
    let string = canonical.to_str().ok_or_else(|| {
        SecPrefError::InvalidExtensionPath(format!(
            "{} cannot be represented as UTF-8",
            canonical.display()
        ))
    })?;
    Ok((canonical.clone(), string.to_owned()))
}

/// The 32-character Chromium extension ID.
///
/// The variant tells the caller which derivation path produced the ID —
/// useful for diagnostics but the ID string itself is what Chrome uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtId {
    /// Derived from a manifest `key` (stable — survives path changes).
    FromKey(String),
    /// Derived from the extension's on-disk path (changes if the folder moves).
    FromPath(String),
}

impl ExtId {
    /// The 32-character `[a-p]` ID.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::FromKey(id) | Self::FromPath(id) => id,
        }
    }

    /// Consume and return the ID string.
    #[must_use]
    pub fn into_id(self) -> String {
        match self {
            Self::FromKey(id) | Self::FromPath(id) => id,
        }
    }

    /// `true` if this ID came from a manifest `key` (stable across paths).
    #[must_use]
    pub fn is_stable(&self) -> bool {
        matches!(self, Self::FromKey(_))
    }
}

/// Derive an extension ID from a manifest `key` (base64-encoded public key).
///
/// Produces a stable ID regardless of on-disk location.
///
/// # Errors
///
/// Returns [`SecPrefError::InvalidManifestKey`] if the input is not valid
/// standard-alphabet base64.
pub fn derive_from_key(base64_key: &str) -> Result<String, SecPrefError> {
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(base64_key)
        .map_err(|e| SecPrefError::InvalidManifestKey(e.to_string()))?;
    let digest = Sha256::digest(&key_bytes);
    Ok(nibbles_to_id(&digest))
}

/// Derive an extension ID from the extension's absolute path.
///
/// Uses UTF-16-LE encoding on Windows targets (matches Chromium), UTF-8
/// bytes elsewhere.
#[must_use]
pub fn derive_from_path(path: &str) -> String {
    let bytes: Vec<u8> = if cfg!(target_os = "windows") {
        path.encode_utf16().flat_map(u16::to_le_bytes).collect()
    } else {
        path.as_bytes().to_vec()
    };
    let digest = Sha256::digest(&bytes);
    nibbles_to_id(&digest)
}

/// Resolve the extension ID: prefer manifest key (stable), fall back to path.
///
/// If `manifest_key` is `Some` and decodes as valid base64, returns
/// [`ExtId::FromKey`]. Otherwise returns [`ExtId::FromPath`].
#[must_use]
pub fn resolve(manifest_key: Option<&str>, ext_path: &str) -> ExtId {
    match manifest_key {
        Some(key) => match derive_from_key(key) {
            Ok(id) => ExtId::FromKey(id),
            Err(_) => ExtId::FromPath(derive_from_path(ext_path)),
        },
        None => ExtId::FromPath(derive_from_path(ext_path)),
    }
}

/// Map the first 16 bytes of a SHA-256 digest to Chrome's `[a-p]` alphabet.
///
/// Emits exactly 32 characters (each byte contributes two nibbles → two
/// letters).
fn nibbles_to_id(digest: &[u8]) -> String {
    digest
        .iter()
        .take(16)
        .flat_map(|byte| [byte >> 4, byte & 0x0F])
        .map(|nibble| char::from(b'a' + nibble))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nibbles_to_id_maps_hex_to_alphabet() {
        let digest = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        assert_eq!(nibbles_to_id(&digest), "abcdefghijklmnopabcdefghijklmnop");
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn derive_from_path_linux_is_deterministic() {
        assert_eq!(
            derive_from_path("/tmp/test_extension"),
            "abkadfbcnpenojlncdmkijflkbadnmeb"
        );
    }

    #[test]
    fn derive_from_key_matches_known_vector() {
        // Deterministic pseudo-random 64-byte "public key" (base64 of 64 zero
        // bytes). We compute the expected ID once and pin it.
        let key = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let id = derive_from_key(&key).unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| (b'a'..=b'p').contains(&b)));
        // Pin the actual value so future changes to the primitive are caught.
        assert_eq!(id, "pfkfpnecnbgkcadachjiopgondajjhjl");
    }

    #[test]
    fn derive_from_key_rejects_invalid_base64() {
        let err = derive_from_key("not!base64!").unwrap_err();
        assert!(matches!(err, SecPrefError::InvalidManifestKey(_)));
    }

    #[test]
    fn resolve_prefers_key_over_path() {
        let key = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let id = resolve(Some(&key), "/some/path");
        assert!(id.is_stable());
    }

    #[test]
    fn resolve_falls_back_to_path_when_key_invalid() {
        let id = resolve(Some("not_base64"), "/some/path");
        assert!(!id.is_stable());
    }

    #[test]
    fn resolve_uses_path_when_no_key() {
        let id = resolve(None, "/some/path");
        assert!(!id.is_stable());
    }
}
