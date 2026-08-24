# secpref-kit

Rust library for Chromium's legacy Secure Preferences HMAC model.
[`SilentChrome`](https://github.com/shxve/SilentChrome) integrates it into a
complete browser-aware tool and serves as the reference consumer.

## Capabilities

- Compute present-value MACs, explicit absent-preference MACs, and the top-level
  `super_mac`.
- Parse compact Chromium and wide-ID Edge DataPack v5 `resources.pak` files,
  then extract `chrome_seed` by the build-matched `IDR_PREF_HASH_SEED_BIN`
  resource ID, by a unique-candidate compatibility check, or enumerate all
  64-byte resources for profile-proven resolution.
- Resolve a legacy seed and standard/Opera extension-record layout from the
  target profile itself by requiring one candidate to match every stored MAC
  leaf and the unfiltered-tree `super_mac`. Parallel `*_encrypted_hash`
  branches are reported as topology, not misclassified as legacy leaves.
- Canonicalize extension paths and derive extension IDs.
- Parse manifests and build unpacked-extension settings.
- Add, remove, list, and verify extension preference entries.
- Resolve Chromium's Windows machine-specific device ID.

The library mutates in-memory JSON. Browser discovery, process coordination,
CLI design, and write policy belong to consumers such as SilentChrome.

`verify_extension` checks internal consistency of the legacy MAC family only.
It does not validate encrypted hashes or establish that a current Chromium
build will retain and activate a modified extension record.

Chromium treats a preference absent from the JSON document differently from a
present JSON `null` or empty string. Use `compute_absent_mac` (or
`compute_absent_mac_bytes`) for that case; do not synthesize a JSON value.

Adaptive resolution is intentionally browser-name agnostic:

```rust
use secpref_kit::{resolve_profile_policy, PolicyResolution, SeedCandidate};

# let secure_preferences = serde_json::json!({});
# let device_id = "S-1-5-21-...";
let candidates = vec![SeedCandidate::empty()];
match resolve_profile_policy(&secure_preferences, device_id, &candidates) {
    PolicyResolution::Proven(policy) => {
        // The seed matched every legacy leaf and the stored super_mac.
        // Browser restart acceptance remains the consumer's responsibility.
        let _layout = policy.layout;
    }
    other => println!("profile policy is not proven: {other:?}"),
}
```

Use `seed_resources_from_pak_bytes` plus `SeedCandidate::from_resource` to add
every direct 64-byte DataPack resource to the candidate set. Seed bytes are
redacted from the library's `Debug` output.

## Library

```rust
use secpref_kit::{manifest, prefs, resolve_ext_id};

let seed = [0u8; 64];
let device_id = "S-1-5-21-1234-5678-9012";
let path = "/absolute/path/to/extension";
let manifest = manifest::parse_str(
    r#"{"manifest_version":3,"name":"Example","version":"1.0.0"}"#,
)?;
let id = resolve_ext_id(manifest.key.as_deref(), path)?.into_id();
let settings = manifest::build_default_settings(&manifest, path);

let mut data = serde_json::json!({});
prefs::add_extension(&mut data, &id, settings, &seed, device_id)?;
prefs::enable_developer_mode(&mut data, &seed, device_id)?;
prefs::strip_encrypted_hashes(&mut data)?;
prefs::recompute_super_mac(&mut data, &seed, device_id)?;
assert!(prefs::verify_extension(&data, &id, &seed, device_id)?.all_valid());
# Ok::<(), secpref_kit::SecPrefError>(())
```

After `resolve_profile_policy` succeeds, the `prefs::*_with_layout` functions
apply the same in-memory operations to a discovered layout such as Opera's
`extensions.opsettings`. The original functions remain standard-layout
compatibility wrappers.

## Development

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

See [DESIGN.md](./DESIGN.md) for the ownership boundary and correctness rules.
Use only on systems you own or are explicitly authorized to test.
