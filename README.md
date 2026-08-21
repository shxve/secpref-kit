# secpref-kit

Rust toolkit for the Chromium **Secure Preferences** integrity model. Read,
list, verify, and manipulate the per-value HMACs, top-level `super_mac`, and
extension entries Chromium writes to protect its preferences file. Ships with
extension-ID derivation, `resources.pak` seed extraction, and the
`_encrypted_hash` sub-tree removal that triggers Chromium's self-healing
fallback.

Extracted from — and consumed by — [`shxve/SilentChrome`][silentchrome] as the
authoritative implementation of the primitive that project's CLI installs on
top of. Suitable for both offensive tooling and blue-team integrity auditing
(compute expected MACs, compare against observed).

[silentchrome]: https://github.com/shxve/SilentChrome

## What this crate does

- `compute_mac(seed, sid, pref_path, value) -> String` — per-value MAC (uppercase hex).
- `compute_super_mac(seed, sid, macs) -> String` — MAC over the whole `protection.macs` sub-tree.
- `derive_from_key(base64_key) -> String` — stable extension ID from a manifest `key`.
- `derive_from_path(path) -> String` — extension ID from an on-disk path.
- `extract_seed_from_pak(&Path) -> Vec<u8>` — pull the 64-byte `chrome_seed` from `resources.pak`.
- `prefs::add_extension` / `remove_extension` / `enable_developer_mode` /
  `strip_encrypted_hashes` / `recompute_super_mac` / `verify_extension` — higher-level operations on a `serde_json::Value`.
- `manifest::parse` + `build_default_settings` — read a manifest, build the
  `extensions.settings.<id>` blob Chromium expects for a sideloaded unpacked
  extension.

## What this crate does NOT do

- **No filesystem I/O in the primitives.** Consumers `serde_json::to_string`
  the mutated `Value` and write it back atomically. This keeps the library
  testable and lets the consumer pick their own backup / temp-file / rename
  strategy.
- **No registry or NMH install.** For that, see the future `nmh-install` crate.
- **No CLI.** Use [`SilentChrome`][silentchrome].
- **No browser process management.** Consumer knows when the browser is safe
  to write against.

## Quick tour

```rust
use secpref_kit::{compute_mac, compute_super_mac, derive_from_path, prefs, manifest, resolve_ext_id};
use serde_json::json;

// --- Low-level MAC ---------------------------------------------------------
let seed = [0u8; 64];               // real callers: extract_seed_from_pak(...)
let sid = "S-1-5-21-1234-5678-9012-1001";
let ext_id = derive_from_path("/tmp/my-ext");
let path = format!("extensions.settings.{ext_id}");
let value = json!({"state": 1, "location": 4});
let mac = compute_mac(&seed, sid, &path, &value);   // uppercase hex, 64 chars

// --- Full add-extension flow ----------------------------------------------
let mut prefs_json = json!({});
let m = manifest::parse_str(r#"{"name":"Test","version":"0.1.0"}"#).unwrap();
let ext_path = "/tmp/my-ext";
let id = resolve_ext_id(m.key.as_deref(), ext_path).into_id();
let settings = manifest::build_default_settings(&m, ext_path);

prefs::add_extension(&mut prefs_json, &id, settings, &seed, sid).unwrap();
prefs::enable_developer_mode(&mut prefs_json, &seed, sid);
prefs::strip_encrypted_hashes(&mut prefs_json);
prefs::recompute_super_mac(&mut prefs_json, &seed, sid);

// Consumer serialises and writes:
let out = serde_json::to_string(&prefs_json).unwrap();
// std::fs::write("Secure Preferences", out).unwrap();  // atomic temp+rename recommended
# let _ = out;

// --- Defensive: verify an existing extension's MACs -----------------------
let verdict = prefs::verify_extension(&prefs_json, &id, &seed, sid).unwrap();
assert!(verdict.all_valid());
```

## Cargo features

- `default` — no non-default features. Core primitives only.

The current release does not ship a Windows-SID helper because every known
consumer already has one (in Lester's `lester-win32`, in SilentChrome's
`src/identity.rs`, etc.). If you want the SID lookup here, open an issue.

## Prior art

This primitive has been publicly documented and implemented for five years:

- **syntax-err0r**, *Silently Install Chrome Extension* (2020) — original disclosure.
- **Adlice Research**, *Secure Preferences Analysis*.
- **asaurusrex/Silent_Chrome** — upstream Python implementation.
- **KingOfTheNOPs/SilentChrome-BOF** — Cobalt Strike BOF port.
- **SpecterOps**, *Chromium Extension C2 Persistence* (2026-08-13) — current best writeup.

Publishing a clean Rust implementation neither adds nor subtracts from the
defender's detection surface. The same primitive is available in half a dozen
other public forms. What this crate adds is a **maintained, tested, MIT-licensed
Rust library** you can pull in without vendoring code from a BOF, translating
Python, or reimplementing HMAC canonicalisation for a fifth time.

## Ethical scope

The primitive lets you install a Chromium extension without user consent by
forging the file Chromium uses to detect tampering. Legitimate uses:

- **Blue-team integrity auditing.** Compute expected MACs, compare against
  what is written on disk — mismatched MACs mean either legitimate corruption
  or an adversary who forged them incorrectly.
- **Enterprise deployment tooling.** Some managed environments already
  script Secure Preferences writes; this crate does it correctly.
- **Security research** on Chromium's integrity model — this is a well-known
  primitive; understanding it well is a defence too.

Do not use it against systems you do not own or have written permission to
test. The license is MIT; the responsibility is yours.

## Development

```sh
cargo test              # 30+ unit + integration tests
cargo clippy -- -D warnings
cargo doc --open
```

## License

MIT. See [`LICENSE`](./LICENSE).
