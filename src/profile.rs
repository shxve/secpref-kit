//! Adaptive, read-only Secure Preferences policy resolution.
//!
//! This module proves legacy integrity policy from values supplied by the
//! caller. It performs no browser discovery, filesystem I/O, process control,
//! restart validation, or rollback. A proven legacy policy is not proof that a
//! current browser will accept a modified profile.

use std::fmt;

use serde_json::Value;

use crate::{mac, seed::SeedResource};

const MAX_SEED_CANDIDATES: usize = 1_024;

/// Provenance for a seed candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SeedSource {
    /// The zero-length seed observed in some Chromium-family builds.
    Empty,
    /// A 64-byte direct resource from a parsed `DataPack`.
    DataPackResource(u32),
    /// Bytes supplied explicitly by the caller.
    CallerProvided,
}

/// A possible legacy preference-hash seed.
#[derive(Clone, PartialEq, Eq)]
pub struct SeedCandidate {
    source: SeedSource,
    bytes: Vec<u8>,
}

impl SeedCandidate {
    /// Construct the zero-length seed candidate.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            source: SeedSource::Empty,
            bytes: Vec::new(),
        }
    }

    /// Construct a candidate from a parsed 64-byte `DataPack` resource.
    #[must_use]
    pub fn from_resource(resource: &SeedResource) -> Self {
        Self {
            source: SeedSource::DataPackResource(resource.id()),
            bytes: resource.as_bytes().to_vec(),
        }
    }

    /// Construct a caller-provided candidate.
    ///
    /// Chromium-family evidence currently uses either zero or 64 bytes, but
    /// HMAC accepts arbitrary key lengths and this constructor deliberately
    /// leaves policy to the caller.
    #[must_use]
    pub fn provided(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            source: SeedSource::CallerProvided,
            bytes: bytes.into(),
        }
    }

    /// Return the candidate's non-secret provenance.
    #[must_use]
    pub const fn source(&self) -> SeedSource {
        self.source
    }

    /// Borrow the seed bytes for an explicit follow-up calculation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for SeedCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SeedCandidate")
            .field("source", &self.source)
            .field("length", &self.bytes.len())
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Dotted preference paths required for extension-record operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreferenceLayout {
    records_path: Vec<String>,
}

impl PreferenceLayout {
    /// Chromium's common `extensions.settings` record layout.
    #[must_use]
    pub fn standard() -> Self {
        Self::from_extension_store("settings")
    }

    /// Opera's observed `extensions.opsettings` record layout.
    #[must_use]
    pub fn opera() -> Self {
        Self::from_extension_store("opsettings")
    }

    fn from_extension_store(store: &str) -> Self {
        Self {
            records_path: vec!["extensions".into(), store.into()],
        }
    }

    /// Path to the extension-record dictionary.
    #[must_use]
    pub fn records_path(&self) -> &[String] {
        &self.records_path
    }

    /// Mirrored path to the legacy MAC dictionary.
    #[must_use]
    pub fn legacy_macs_path(&self) -> Vec<String> {
        let mut path = vec!["protection".into(), "macs".into()];
        path.extend(self.records_path.iter().cloned());
        path
    }

    /// Dotted preference path for one extension record.
    #[must_use]
    pub fn extension_path(&self, extension_id: &str) -> String {
        format!("{}.{}", self.records_path.join("."), extension_id)
    }
}

/// Aggregate encrypted-integrity signals observed in the supplied profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct IntegrityTopology {
    /// Number of dictionary keys ending in `_encrypted_hash` below
    /// `protection.macs`.
    pub encrypted_hash_branches: usize,
    /// Whether `protection.super_encrypted_hash` is present.
    pub has_super_encrypted_hash: bool,
}

impl IntegrityTopology {
    /// Whether any encrypted-integrity state was observed.
    #[must_use]
    pub const fn has_encrypted_integrity(self) -> bool {
        self.encrypted_hash_branches > 0 || self.has_super_encrypted_hash
    }
}

/// Aggregate, privacy-safe proof for one winning seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LegacyProof {
    /// Number of stored legacy leaves checked.
    pub checked_leaves: usize,
    /// Number of stored legacy leaves that matched.
    pub matched_leaves: usize,
    /// Whether the stored super-MAC matched.
    pub super_mac_matched: bool,
}

/// A seed selected by complete profile proof.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedSeed {
    source: SeedSource,
    bytes: Vec<u8>,
}

impl ResolvedSeed {
    /// Non-secret provenance of the winning seed.
    #[must_use]
    pub const fn source(&self) -> SeedSource {
        self.source
    }

    /// Borrow the winning seed for subsequent in-memory operations.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ResolvedSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSeed")
            .field("source", &self.source)
            .field("length", &self.bytes.len())
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// An evidence-bearing, legacy-integrity profile policy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedProfilePolicy {
    /// Structurally discovered extension-record layout.
    pub layout: PreferenceLayout,
    /// Seed selected by complete legacy proof.
    pub seed: ResolvedSeed,
    /// Aggregate leaf and super-MAC proof.
    pub proof: LegacyProof,
    /// Encrypted-integrity state observed but not reproduced by this crate.
    pub integrity_topology: IntegrityTopology,
}

/// Privacy-safe diagnostics for a non-proven resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolutionEvidence {
    /// Number of distinct seed byte strings tested.
    pub seed_candidates: usize,
    /// Number of correlated extension-record layouts discovered.
    pub layouts: usize,
    /// Number of stored legacy leaves available.
    pub checked_leaves: usize,
    /// Best leaf-match count achieved by any candidate.
    pub best_leaf_matches: usize,
    /// Number of candidates matching every leaf and the super-MAC.
    pub complete_seed_matches: usize,
    /// Whether a string `protection.super_mac` was present.
    pub super_mac_present: bool,
}

/// A malformed profile condition that prevents resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileIssue {
    /// The root value was not a dictionary.
    RootNotObject,
    /// A required dictionary existed with another JSON type.
    WrongShape {
        /// Dotted path of the invalid value.
        path: String,
    },
    /// A stored legacy leaf was not a hexadecimal MAC string.
    InvalidMacLeaf,
    /// The caller supplied an unreasonable number of candidates.
    TooManySeedCandidates {
        /// Actual candidate count.
        count: usize,
        /// Enforced upper bound.
        maximum: usize,
    },
}

/// Result of adaptive profile-policy resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyResolution {
    /// Exactly one layout and seed passed complete legacy proof.
    Proven(ResolvedProfilePolicy),
    /// Multiple layouts or seed byte strings remained valid.
    Ambiguous(ResolutionEvidence),
    /// The profile lacked enough evidence for a mutation-capable proof.
    InsufficientEvidence(ResolutionEvidence),
    /// Evidence existed, but no supplied seed passed complete proof.
    NoMatch(ResolutionEvidence),
    /// The profile could not be interpreted safely.
    InvalidProfile(ProfileIssue),
}

/// Resolve legacy Secure Preferences policy from caller-supplied data.
///
/// A [`PolicyResolution::Proven`] result requires one structurally correlated
/// extension-record layout, one distinct seed matching every legacy leaf, and
/// a matching stored super-MAC. It does not prove browser restart acceptance.
#[must_use]
pub fn resolve_profile_policy(
    secure_preferences: &Value,
    device_id: &str,
    seed_candidates: &[SeedCandidate],
) -> PolicyResolution {
    if !secure_preferences.is_object() {
        return PolicyResolution::InvalidProfile(ProfileIssue::RootNotObject);
    }
    if seed_candidates.len() > MAX_SEED_CANDIDATES {
        return PolicyResolution::InvalidProfile(ProfileIssue::TooManySeedCandidates {
            count: seed_candidates.len(),
            maximum: MAX_SEED_CANDIDATES,
        });
    }

    let layouts = match discover_layouts(secure_preferences) {
        Ok(layouts) => layouts,
        Err(issue) => return PolicyResolution::InvalidProfile(issue),
    };
    let macs = match value_at_checked(secure_preferences, &["protection", "macs"]) {
        Ok(Some(macs)) if macs.is_object() => macs,
        Ok(Some(_)) => {
            return PolicyResolution::InvalidProfile(ProfileIssue::WrongShape {
                path: "protection.macs".into(),
            });
        }
        Ok(None) => {
            return PolicyResolution::InsufficientEvidence(ResolutionEvidence {
                seed_candidates: distinct_candidates(seed_candidates).len(),
                layouts: layouts.len(),
                checked_leaves: 0,
                best_leaf_matches: 0,
                complete_seed_matches: 0,
                super_mac_present: false,
            });
        }
        Err(issue) => return PolicyResolution::InvalidProfile(issue),
    };

    let mut leaves = Vec::new();
    if let Err(issue) = collect_mac_leaves(macs, &mut Vec::new(), &mut leaves) {
        return PolicyResolution::InvalidProfile(issue);
    }

    let stored_super = secure_preferences
        .get("protection")
        .and_then(|value| value.get("super_mac"))
        .and_then(Value::as_str);
    let unique_candidates = distinct_candidates(seed_candidates);
    let mut best_leaf_matches = 0;
    let mut winners = Vec::new();

    for candidate in &unique_candidates {
        let leaf_matches = leaves
            .iter()
            .filter(|leaf| leaf_matches_policy(secure_preferences, leaf, candidate, device_id))
            .count();
        best_leaf_matches = best_leaf_matches.max(leaf_matches);
        let super_matches = stored_super.is_some_and(|stored| {
            mac::compute_super_mac(candidate.as_bytes(), device_id, macs)
                .eq_ignore_ascii_case(stored)
        });
        if !leaves.is_empty() && leaf_matches == leaves.len() && super_matches {
            winners.push(*candidate);
        }
    }

    let evidence = ResolutionEvidence {
        seed_candidates: unique_candidates.len(),
        layouts: layouts.len(),
        checked_leaves: leaves.len(),
        best_leaf_matches,
        complete_seed_matches: winners.len(),
        super_mac_present: stored_super.is_some(),
    };

    if layouts.is_empty()
        || leaves.is_empty()
        || unique_candidates.is_empty()
        || stored_super.is_none()
    {
        return PolicyResolution::InsufficientEvidence(evidence);
    }
    if layouts.len() != 1 || winners.len() > 1 {
        return PolicyResolution::Ambiguous(evidence);
    }
    let Some(winner) = winners.first() else {
        return PolicyResolution::NoMatch(evidence);
    };

    PolicyResolution::Proven(ResolvedProfilePolicy {
        layout: layouts[0].clone(),
        seed: ResolvedSeed {
            source: winner.source(),
            bytes: winner.as_bytes().to_vec(),
        },
        proof: LegacyProof {
            checked_leaves: leaves.len(),
            matched_leaves: leaves.len(),
            super_mac_matched: true,
        },
        integrity_topology: integrity_topology(secure_preferences, macs),
    })
}

#[derive(Debug)]
struct MacLeaf<'a> {
    path: Vec<String>,
    stored_mac: &'a str,
}

fn distinct_candidates(candidates: &[SeedCandidate]) -> Vec<&SeedCandidate> {
    let mut distinct = Vec::new();
    for candidate in candidates {
        if !distinct
            .iter()
            .any(|existing: &&SeedCandidate| existing.as_bytes() == candidate.as_bytes())
        {
            distinct.push(candidate);
        }
    }
    distinct
}

fn discover_layouts(root: &Value) -> Result<Vec<PreferenceLayout>, ProfileIssue> {
    let Some(extension_stores) = object_at(root, &["extensions"])? else {
        return Ok(Vec::new());
    };
    let Some(mac_stores) = object_at(root, &["protection", "macs", "extensions"])? else {
        return Ok(Vec::new());
    };

    let mut layouts = Vec::new();
    for (store, records) in extension_stores {
        if store.ends_with("_encrypted_hash") {
            continue;
        }
        let known_store = store == "settings" || store == "opsettings";
        let Some(record_map) = records.as_object() else {
            if known_store {
                return Err(ProfileIssue::WrongShape {
                    path: format!("extensions.{store}"),
                });
            }
            continue;
        };
        let Some(mac_value) = mac_stores.get(store) else {
            continue;
        };
        let Some(mac_map) = mac_value.as_object() else {
            if known_store {
                return Err(ProfileIssue::WrongShape {
                    path: format!("protection.macs.extensions.{store}"),
                });
            }
            continue;
        };
        let correlated = record_map.iter().any(|(id, record)| {
            record.is_object()
                && mac_map
                    .get(id)
                    .and_then(Value::as_str)
                    .is_some_and(is_stored_mac)
        });
        if known_store || correlated {
            layouts.push(PreferenceLayout::from_extension_store(store));
        }
    }
    Ok(layouts)
}

fn object_at<'a>(
    root: &'a Value,
    path: &[&str],
) -> Result<Option<&'a serde_json::Map<String, Value>>, ProfileIssue> {
    let Some(value) = value_at_checked(root, path)? else {
        return Ok(None);
    };
    value
        .as_object()
        .map(Some)
        .ok_or_else(|| ProfileIssue::WrongShape {
            path: path.join("."),
        })
}

fn value_at_checked<'a>(root: &'a Value, path: &[&str]) -> Result<Option<&'a Value>, ProfileIssue> {
    let mut current = root;
    let mut traversed = Vec::new();
    for key in path {
        traversed.push(*key);
        let Some(current_object) = current.as_object() else {
            return Err(ProfileIssue::WrongShape {
                path: traversed[..traversed.len() - 1].join("."),
            });
        };
        let Some(next) = current_object.get(*key) else {
            return Ok(None);
        };
        current = next;
    }
    Ok(Some(current))
}

fn collect_mac_leaves<'a>(
    value: &'a Value,
    prefix: &mut Vec<String>,
    leaves: &mut Vec<MacLeaf<'a>>,
) -> Result<(), ProfileIssue> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                if key.ends_with("_encrypted_hash") {
                    continue;
                }
                prefix.push(key.clone());
                collect_mac_leaves(nested, prefix, leaves)?;
                prefix.pop();
            }
            Ok(())
        }
        Value::String(stored_mac) if is_stored_mac(stored_mac) => {
            leaves.push(MacLeaf {
                path: prefix.clone(),
                stored_mac,
            });
            Ok(())
        }
        _ => Err(ProfileIssue::InvalidMacLeaf),
    }
}

fn is_stored_mac(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn leaf_matches_policy(
    root: &Value,
    leaf: &MacLeaf<'_>,
    candidate: &SeedCandidate,
    device_id: &str,
) -> bool {
    let dotted_path = leaf.path.join(".");
    let computed = match value_at(root, &leaf.path) {
        Some(value) => mac::compute_mac(candidate.as_bytes(), device_id, &dotted_path, value),
        None => mac::compute_absent_mac(candidate.as_bytes(), device_id, &dotted_path),
    };
    computed.eq_ignore_ascii_case(leaf.stored_mac)
}

fn value_at<'a>(root: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut current = root;
    for key in path {
        current = current.get(key)?;
    }
    Some(current)
}

fn integrity_topology(root: &Value, macs: &Value) -> IntegrityTopology {
    IntegrityTopology {
        encrypted_hash_branches: count_encrypted_hash_keys(macs),
        has_super_encrypted_hash: root
            .get("protection")
            .and_then(|value| value.get("super_encrypted_hash"))
            .is_some(),
    }
}

fn count_encrypted_hash_keys(value: &Value) -> usize {
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(key, nested)| {
                usize::from(key.ends_with("_encrypted_hash")) + count_encrypted_hash_keys(nested)
            })
            .sum(),
        Value::Array(values) => values.iter().map(count_encrypted_hash_keys).sum(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::SEED_LEN;

    const EXTENSION_ID: &str = "abcdefghijklmnopabcdefghijklmnop";

    fn proven_profile(layout: &PreferenceLayout, seed: &[u8], device_id: &str) -> Value {
        let record = json!({"location": 4, "state": 1});
        let record_path = layout.extension_path(EXTENSION_ID);
        let record_mac = mac::compute_mac(seed, device_id, &record_path, &record);
        let absent_path = "browser.absent_test";
        let absent_mac = mac::compute_absent_mac(seed, device_id, absent_path);

        let mut root = json!({
            "browser": {},
            "protection": {
                "macs": {
                    "browser": {"absent_test": absent_mac}
                }
            }
        });
        let store = &layout.records_path()[1];
        root["extensions"][store][EXTENSION_ID] = record;
        root["protection"]["macs"]["extensions"][store][EXTENSION_ID] = Value::String(record_mac);
        let super_mac = mac::compute_super_mac(seed, device_id, &root["protection"]["macs"]);
        root["protection"]["super_mac"] = Value::String(super_mac);
        root
    }

    #[test]
    fn resolves_standard_layout_and_empty_seed() {
        let profile = proven_profile(&PreferenceLayout::standard(), b"", "device");
        let candidates = [
            SeedCandidate::provided([7u8; SEED_LEN]),
            SeedCandidate::empty(),
        ];

        let PolicyResolution::Proven(policy) =
            resolve_profile_policy(&profile, "device", &candidates)
        else {
            panic!("expected proven policy");
        };
        assert_eq!(policy.layout, PreferenceLayout::standard());
        assert_eq!(policy.seed.source(), SeedSource::Empty);
        assert_eq!(policy.proof.checked_leaves, 2);
    }

    #[test]
    fn resolves_opera_layout_and_resource_seed() {
        let seed = [0x42; SEED_LEN];
        let mut profile = proven_profile(&PreferenceLayout::opera(), &seed, "device");
        profile["protection"]["macs"]["extensions"]["opsettings_encrypted_hash"][EXTENSION_ID] =
            Value::String("E".repeat(84));
        profile["protection"]["super_encrypted_hash"] = Value::String("opaque".into());
        let super_mac = mac::compute_super_mac(&seed, "device", &profile["protection"]["macs"]);
        profile["protection"]["super_mac"] = Value::String(super_mac);
        let resource = SeedResource::new_for_test(65_840, seed);
        let candidates = [
            SeedCandidate::empty(),
            SeedCandidate::from_resource(&resource),
        ];

        let PolicyResolution::Proven(policy) =
            resolve_profile_policy(&profile, "device", &candidates)
        else {
            panic!("expected proven policy");
        };
        assert_eq!(policy.layout, PreferenceLayout::opera());
        assert_eq!(policy.seed.source(), SeedSource::DataPackResource(65_840));
        assert_eq!(policy.proof.checked_leaves, 2);
        assert!(policy.integrity_topology.has_encrypted_integrity());
    }

    #[test]
    fn rejects_wrong_device_without_guessing() {
        let profile = proven_profile(&PreferenceLayout::standard(), b"", "right-device");
        let resolution =
            resolve_profile_policy(&profile, "wrong-device", &[SeedCandidate::empty()]);
        assert!(matches!(resolution, PolicyResolution::NoMatch(_)));
    }

    #[test]
    fn duplicate_seed_bytes_are_one_candidate() {
        let profile = proven_profile(&PreferenceLayout::standard(), b"", "device");
        let candidates = [SeedCandidate::empty(), SeedCandidate::provided(Vec::new())];
        let PolicyResolution::Proven(policy) =
            resolve_profile_policy(&profile, "device", &candidates)
        else {
            panic!("expected duplicate bytes to deduplicate");
        };
        assert_eq!(policy.seed.source(), SeedSource::Empty);
    }

    #[test]
    fn reports_ambiguous_record_layouts() {
        let mut profile = proven_profile(&PreferenceLayout::standard(), b"", "device");
        profile["extensions"]["opsettings"] = json!({});
        profile["protection"]["macs"]["extensions"]["opsettings"] = json!({});
        let super_mac = mac::compute_super_mac(b"", "device", &profile["protection"]["macs"]);
        profile["protection"]["super_mac"] = Value::String(super_mac);

        let PolicyResolution::Ambiguous(evidence) =
            resolve_profile_policy(&profile, "device", &[SeedCandidate::empty()])
        else {
            panic!("expected layout ambiguity");
        };
        assert_eq!(evidence.layouts, 2);
    }

    #[test]
    fn scalar_extension_mac_is_a_leaf_not_a_record_layout() {
        let mut profile = proven_profile(&PreferenceLayout::standard(), b"", "device");
        profile["extensions"]["blocklist"] = json!({});
        profile["protection"]["macs"]["extensions"]["blocklist"] = Value::String(mac::compute_mac(
            b"",
            "device",
            "extensions.blocklist",
            &json!({}),
        ));
        let super_mac = mac::compute_super_mac(b"", "device", &profile["protection"]["macs"]);
        profile["protection"]["super_mac"] = Value::String(super_mac);

        let PolicyResolution::Proven(policy) =
            resolve_profile_policy(&profile, "device", &[SeedCandidate::empty()])
        else {
            panic!("expected scalar branch to remain a legacy leaf");
        };
        assert_eq!(policy.layout, PreferenceLayout::standard());
        assert_eq!(policy.proof.checked_leaves, 3);
    }

    #[test]
    fn reports_missing_super_mac_as_insufficient() {
        let mut profile = proven_profile(&PreferenceLayout::standard(), b"", "device");
        profile["protection"]
            .as_object_mut()
            .unwrap()
            .swap_remove("super_mac");
        assert!(matches!(
            resolve_profile_policy(&profile, "device", &[SeedCandidate::empty()]),
            PolicyResolution::InsufficientEvidence(_)
        ));
    }

    #[test]
    fn rejects_wrong_intermediate_shape() {
        let profile = json!({
            "extensions": {"settings": {}},
            "protection": false
        });
        assert!(matches!(
            resolve_profile_policy(&profile, "device", &[SeedCandidate::empty()]),
            PolicyResolution::InvalidProfile(ProfileIssue::WrongShape { path })
                if path == "protection"
        ));
    }

    #[test]
    fn debug_output_redacts_seed_bytes() {
        let candidate = SeedCandidate::provided(vec![0xAA; SEED_LEN]);
        let debug = format!("{candidate:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("170"));
    }
}
