# secpref-kit design

`secpref-kit` is an experimental Rust implementation of Chromium's legacy
Secure Preferences HMAC model. It serves library consumers without taking
ownership of browser discovery, process management, filesystem writes, or CLI
design.

## Ownership boundary

The library owns:

- Chromium JSON canonicalization and HMAC computation;
- DataPack v5 seed extraction and validation;
- extension manifest parsing, canonical path handling, and ID derivation;
- in-memory preference mutations, encrypted-hash removal, and verification;
- Chromium-compatible Windows machine-ID lookup.

Consumers own browser/profile discovery, lifecycle coordination, backup policy,
filesystem orchestration, and operator interfaces. SilentChrome is the primary
browser-aware consumer.

## Correctness decisions

1. `serde_json` uses `preserve_order` to avoid gratuitously reordering the
   stored file. MAC input is separate: dictionary keys are sorted recursively,
   matching Chromium's `base::Value::Dict` semantics.
2. Extension paths are canonicalized once and the same UTF-8 representation is
   used for manifest access, ID derivation, and stored settings.
3. DataPack parsing validates the encoding, entry table, alias table, monotonic
   offsets, and file bounds before slicing.
4. Verification recomputes MACs from the values actually stored. It checks the
   extension, both developer-mode mirrors, and the super-MAC independently.
5. Encrypted hashes may be removed before the super-MAC is recomputed to request
   legacy fallback. Current Chromium can disable that fallback, so a passing
   legacy self-check is not browser acceptance.
6. The Windows device ID follows Chromium: obtain the computer name, resolve it
   with `LookupAccountNameW`, and stringify the resulting machine SID.

## API and build policy

- Pure preference operations mutate `serde_json::Value`; filesystem helpers
  exist only where reading is intrinsic (`manifest.json`, `resources.pak`).
- Errors and externally consumed info types are non-exhaustive.
- The crate is library-only; it carries no command parser or filesystem write
  policy.
- MSRV is Rust 1.85, matching the resolved dependency floor. Dependency
  resolution remains the consuming application's responsibility.
- Unsafe code is confined to the Windows SID module and wrapped by safe APIs.

## Consumer relationship

SilentChrome depends on this crate and retains only:

- browser installation/profile/resource discovery;
- macOS and Linux identity orchestration;
- preferences-file reading and atomic replacement;
- operator-facing command output.

It must not carry duplicate crypto, DataPack, manifest, extension-ID, or
preference-integrity implementations. Its round-trip test is the consumer
contract for internal legacy-model consistency, not Chromium acceptance.

## Compatibility boundary

The crate does not generate encrypted integrity values and cannot by itself
prove that a current browser will retain or activate a modified record. Browser
acceptance requires a closed-browser write followed by restart, retention,
loading, and activation checks against the exact target build.

## Validation gates

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

Windows CI additionally compiles and exercises the machine-ID implementation.
