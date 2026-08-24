# secpref-kit

Rust library for Chromium's legacy Secure Preferences HMAC model.
[`SilentChrome`](https://github.com/shxve/SilentChrome) integrates it into a
complete browser-aware tool and serves as the reference consumer.

## Capabilities

- Compute per-value MACs and the top-level `super_mac`.
- Parse compact Chromium and wide-ID Edge DataPack v5 `resources.pak` files,
  then extract `chrome_seed` by the build-matched `IDR_PREF_HASH_SEED_BIN`
  resource ID or by a unique-candidate compatibility check.
- Canonicalize extension paths and derive extension IDs.
- Parse manifests and build unpacked-extension settings.
- Add, remove, list, and verify extension preference entries.
- Resolve Chromium's Windows machine-specific device ID.

The library mutates in-memory JSON. Browser discovery, process coordination,
CLI design, and write policy belong to consumers such as SilentChrome.

`verify_extension` checks internal consistency of the legacy MAC family only.
It does not validate encrypted hashes or establish that a current Chromium
build will retain and activate a modified extension record.

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
