//! Crate error type.

use thiserror::Error;

/// Errors returned by this crate.
///
/// Non-exhaustive to allow additional variants in future minor releases without
/// breaking downstream `match` arms.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecPrefError {
    /// The `resources.pak` header was invalid or the file was truncated.
    #[error("invalid resources.pak: {0}")]
    InvalidPak(String),

    /// No 64-byte resource was found in the pak; the seed is not present.
    #[error("chrome_seed not found in resources.pak")]
    SeedNotFound,

    /// I/O error reading a file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parse or serialize error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// The manifest key was not valid base64.
    #[error("invalid manifest key: {0}")]
    InvalidManifestKey(String),

    /// The extension manifest was valid JSON but not a valid Chromium manifest.
    #[error("invalid extension manifest: {0}")]
    InvalidManifest(String),

    /// The extension path could not be canonicalized or represented as UTF-8.
    #[error("invalid extension path: {0}")]
    InvalidExtensionPath(String),

    /// A required JSON field was not the expected shape.
    #[error("unexpected JSON shape at `{path}`: {reason}")]
    UnexpectedShape {
        /// The dotted JSON path that failed to match.
        path: String,
        /// Human-readable reason.
        reason: String,
    },

    /// The named extension was not found in Secure Preferences.
    #[error("extension `{0}` not found in extensions.settings")]
    ExtensionNotFound(String),

    /// Windows SID lookup failed (Windows-only variant, but emitted only
    /// from `#[cfg(windows)]` code paths — safe to `match` on all platforms).
    #[error("windows SID lookup failed: {0}")]
    SidLookup(String),
}
