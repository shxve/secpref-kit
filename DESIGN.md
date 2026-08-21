# secpref-kit — Design Decisions & Milestones

Design document for `secpref-kit`. Locally-tracked while the crate is
pre-publish; will migrate to the eventual `github.com/shxve/secpref-kit`
repo when v0.3 ships. Not intended as public-facing marketing — this is
the record of *why* the crate is shaped the way it is.

Status: **pre-publish, v0.1.0 drafted**. Local at `~/dev/secpref-kit/`,
no `git init` yet, no crates.io publish. First real-world verification
comes from swapping SilentChrome and Lester onto it (Milestone M2).

---

## 1. Purpose

Provide the one correct **complete kit** for the Chromium Secure
Preferences integrity primitive — usable both as a Rust library and as
a standalone CLI. Two audiences:

- **In-house tooling** ([`shxve/SilentChrome`], private `Lester`) stops
  maintaining two independent copies of the same ~550 LOC of HMAC-SHA256
  + `resources.pak` parsing + extension-ID derivation. Both consume the
  library.
- **External consumers** (blue teams auditing preferences integrity, other
  red-team tooling, security researchers, one-off operators) get either:
  - A maintained, tested, MIT-licensed Rust **library** to link into their
    own tool, instead of vendoring code from a BOF or translating Python
    from `syntax-err0r/Silent_Chrome`.
  - Or a standalone **CLI** (`secpref`) with every primitive and every
    workflow (install / uninstall / verify / list / SID lookup / seed
    extract / MAC compute) exposed as a subcommand — no Rust knowledge
    required, scriptable from any language.

The library primitives do no I/O — that's how they stay testable and
composable. The CLI is a thin wrapper that owns the I/O and provides the
scriptable UX.

[`shxve/SilentChrome`]: https://github.com/shxve/SilentChrome

---

## 2. Scope

### In scope (library)

- HMAC-SHA256 primitives (`compute_mac`, `compute_super_mac` + `_bytes` variants).
- Chromium JSON canonicalisation (`canonicalize`, `strip_empties`) — the
  correctness dependency that makes the MACs match.
- Extension-ID derivation from a manifest `key` or an on-disk path
  (Windows UTF-16-LE, non-Windows UTF-8).
- `resources.pak` (DataPack v5) seed extraction.
- Higher-level `prefs::add_extension` / `remove_extension` /
  `enable_developer_mode` / `strip_encrypted_hashes` / `recompute_super_mac`
  / `verify_extension` / `list_extensions` operating on a `&mut serde_json::Value`.
- Extension `manifest.json` parsing + default `extensions.settings.<id>`
  blob construction for a sideloaded unpacked extension.
- **Windows SID helpers** (`sid::current_user_trimmed`, `sid::lookup_by_name`)
  — `#[cfg(windows)]`-gated, always available on Windows builds, no
  feature flag. See §3.8.

### In scope (CLI — the `secpref` binary)

Every library primitive gets a scriptable subcommand:

- `secpref seed extract --pak <path>` — pull the 64-byte seed from a `resources.pak`.
- `secpref mac compute --seed <hex> --sid <str> --path <p> --value <json>` — per-value MAC.
- `secpref mac super --seed <hex> --sid <str> --macs <json>` — top-level super-MAC.
- `secpref ext-id derive --key <base64>` / `--path <p>` — extension-ID derivation.
- `secpref sid current` / `secpref sid lookup --user <name>` — SID lookup (Windows).
- `secpref prefs install --profile <dir> --ext <path> [--seed <hex>|--pak <p>] [--sid <s>]` — full install flow on one profile.
- `secpref prefs uninstall --profile <dir> --ext-id <id> [--seed <hex>|--pak <p>] [--sid <s>]` — uninstall + super-MAC recompute.
- `secpref prefs list --profile <dir>` — enumerate installed extensions.
- `secpref prefs verify --profile <dir> --ext-id <id> [--seed <hex>|--pak <p>] [--sid <s>]` — integrity audit (blue-team use case).
- `secpref prefs strip-encrypted-hashes --profile <dir>` — force self-healing on next launch.

The CLI is scoped to **one Secure Preferences file per invocation** — it
does not do browser discovery, does not iterate profiles, does not
kill/restart browser processes. Those workflows are the SilentChrome
CLI's job. See §5.

### Out of scope (deliberately)

- **Filesystem writes in the *library* primitives.** Consumer / CLI
  picks atomic-write / backup / temp-file semantics.
- **Registry access.** NMH install goes in a separate future sibling
  crate (`nmh-install`, per the in-house integration review §6.5).
- **Browser process management** (start / stop / detect).
- **Browser discovery** (which install path, which profile, which
  browser fork). SilentChrome does this; the `secpref` CLI does not.
- **Multi-profile orchestration.** `secpref` takes one `--profile` at
  a time. Iterating a whole browser install is SilentChrome's job.

### Out of scope (permanently)

- Anything specific to non-Chromium browsers (Firefox / Safari have
  entirely different integrity models).
- ABE (App-Bound Encryption) cookie decryption. That's Chromium's `v20`
  scheme — different primitive, different crate (Lester's `lester-crypto`).
- CDP client, WebSocket transport, or anything network-side.

---

## 3. Design decisions

Each decision is recorded with its rationale so a future contributor can
see what problem it solved before proposing a change.

### 3.1 Pure library primitives; I/O lives in the CLI wrapper

**Decision.** Library primitives take input, return output. Functions like
`prefs::add_extension` mutate a `&mut serde_json::Value` in place; library
callers are responsible for reading the file, running the operations,
serialising, and writing atomically. The `secpref` CLI is a thin wrapper
that owns the I/O layer (atomic temp+rename write, optional `--backup`,
consistent error framing).

**Rationale.** Library consumers (SilentChrome + Lester + externals)
already have or want different I/O policies: SilentChrome writes a
single JSON file per profile; Lester's `lester-ext` batches multiple
pref-file mutations across profile paths, wants atomic temp-file +
rename semantics, and has its own error-handling story. Baking any I/O
policy into the library primitives would either constrain callers or
add feature flags. Pure primitives sidestep the problem; the CLI picks
one policy and owns it.

**Exceptions.** `seed::extract_seed_from_pak(path)` and
`manifest::parse(dir)` both read from disk because that's what they exist
to do; both have `_bytes` / `_str` variants that don't touch disk for
callers who mmap or preload.

### 3.2 `serde_json` `preserve_order` is a correctness requirement

**Decision.** The crate depends on `serde_json = { version = "1",
features = ["preserve_order"] }`. Downstream consumers must NOT disable
default features on `serde_json` if they want the MACs to match Chromium.

**Rationale.** Chromium's `JSONWriter` emits keys in insertion order.
The HMAC input is the emitted JSON byte-for-byte. Without
`preserve_order`, `serde_json` sorts keys alphabetically — every
non-single-key object produces the wrong MAC on the first call, silently.
Test `mac_vectors::insertion_order_is_significant` pins this: two objects
with the same keys in different order MUST produce different MACs.

### 3.3 Hand-typed API, no code generation

**Decision.** No `.pdl` files, no schema-driven code-gen. The library is
small enough that hand-typing is auditable and adding a new operation is
a diff-reviewable PR.

**Rationale.** Same reasoning as CDP-Ninja vs chromedp: the crate is
narrow (one primitive family, ~500 LOC), consumer count is small
(2 in-house, potentially handfuls externally), and every JSON shape
Chromium accepts is documented and stable for years. Code-gen would
add a build-time dependency and a whole-crate rebuild on every
`.pdl`-side change. Not worth it here.

### 3.4 `#[non_exhaustive]` on error + info types

**Decision.** `SecPrefError` and `ExtInfo` are `#[non_exhaustive]`.

**Rationale.** Downstream `match` arms should continue to compile when
we add new error variants or `ExtInfo` fields in minor releases. Trades
one line of explicit `_ =>` handling at each `match` site for the
ability to grow the enum without a major version bump.

### 3.5 No async, no runtime

**Decision.** Pure sync code. No `tokio`, no `async fn`, no futures.

**Rationale.** The primitives are all CPU-bound (HMAC, JSON, hex). The
only I/O is one `std::fs::read` for the pak file. Async here would
propagate a runtime dependency into every consumer for zero benefit.
SilentChrome and Lester are both sync-first.

### 3.6 MSRV = 1.75

**Decision.** Rust 2021 edition, minimum supported Rust version 1.75.

**Rationale.** Nothing in the crate needs anything newer. Pinning MSRV
means the crate builds on the Debian stable / RHEL 9 / Windows Server 2022
toolchains without forcing consumers to update. Bump only when a specific
language feature would materially improve the API.

### 3.7 Byte-level pinned test vectors

**Decision.** HMAC outputs and extension-ID outputs are pinned to
exact expected values in test vectors, not just "should be 64 chars"
sanity checks.

**Rationale.** The whole point of the crate is that its output matches
Chromium's expected input byte-for-byte. Every change to
canonicalisation, JSON serialisation, hex encoding, or the nibble
alphabet must be caught by CI, not shipped and discovered by a
consumer's failing MAC. Pinned vectors do that.

### 3.8 Windows SID helpers ship in v0.2 as a first-class module

**Decision.** `sid::current_user_trimmed()` and `sid::lookup_by_name(&str)`
ship in v0.2, `#[cfg(windows)]`-gated (Windows-only module, always
available on Windows builds — no feature flag). The `secpref sid current`
and `secpref sid lookup` CLI subcommands wrap them.

**Rationale.** The `secpref` CLI is a complete kit — a caller running
`secpref prefs install --profile … --ext …` from PowerShell or a batch
script without knowing their own SID would fail immediately. Requiring
external consumers to have a separate SID lookup tool (or link
`windows-sys` themselves) breaks the "standalone CLI" positioning.

`#[cfg(windows)]` rather than a `windows-sid` feature: matches Lester's
`lester-win32` and CDP-Enabler's pattern. Windows-only code is
Windows-only by build target; a feature flag would let a Linux consumer
disable it (no-op) and a Windows consumer accidentally disable it
(broken CLI). `#[cfg(windows)]` is simpler.

The in-house consumers (SilentChrome, Lester) can consume `sid::*` from
the crate instead of maintaining their own duplicates — a small
follow-on win beyond the primary Secure-Prefs dedup. Consumers that
have specific SID-handling requirements keep their own code; the
`sid::*` helpers are a convenience floor, not a mandate.

### 3.9 MIT license

**Decision.** MIT, single-license.

**Rationale.** Matches the rest of the `shxve` public offensive-tooling
crates (CDP-Ninja, MSight, teamscheck, OhClock, SilentChrome). Simplest
license for a small research library. No Apache-2.0 patent grant needed
— nothing patentable here.

### 3.10 No `unsafe` in the crate

**Decision.** Zero `unsafe` blocks in the source.

**Rationale.** The primitives are pure Rust. No FFI, no manual memory
management. If the Windows-SID helper is ever added it would need
`unsafe` for the `windows-sys` calls — that's the one place we'd
selectively `#[allow(unsafe_code)]` and gate behind a feature.

### 3.11 Extraction strategy: SilentChrome as base, Lester as edge-case source

**Decision.** The initial v0.1 implementation is lifted from
SilentChrome (already public, already clean), with rustdoc + `_bytes`
variants + `#[non_exhaustive]` error type added on top. Lester's
`lester-ext/src/secpref.rs` will be swept for edge cases missed by
SilentChrome during Milestone M2.

**Rationale.** SilentChrome's code is public and reviewed. Lester's
version is private but has been fielded against real Chrome / Edge /
Brave profiles longer. Taking SilentChrome as the base keeps the
diff-audit trivial for anyone reviewing the public repo; folding in
Lester's edge cases during M2 (when Lester is being swapped) is the
natural time to discover them.

### 3.12 `strip_encrypted_hashes` recursive by design

**Decision.** `strip_encrypted_hashes` walks the entire JSON tree, not
just the `protection.macs.extensions.settings.<id>_encrypted_hash`
location.

**Rationale.** Chromium's encrypted-hash entries appear at multiple
nesting levels (`protection.macs.settings_encrypted_hash`,
`protection.macs.extensions.settings_encrypted_hash`, and per-extension
`<id>_encrypted_hash` entries). A shallow strip would leave siblings
that would still trigger integrity failure. Recursive strip is what
triggers the self-healing fallback correctly.

### 3.13 Single crate, dual target (lib + bin), CLI feature-gated

**Decision.** One Cargo package, `secpref-kit`, that produces both a
library (`secpref_kit`) and a binary (`secpref`). The binary is behind
a `cli` feature (default off). Same pattern CDP-Ninja uses.

**Rationale.**

- **Library consumers don't pay for CLI deps.** `clap`, `anyhow`, colour
  helpers, etc. only compile when `--features cli` is set. Lester and
  SilentChrome pull `secpref-kit` with default features → zero CLI cost.
- **CLI users get a single binary.** `cargo install --features cli
  secpref-kit` installs `secpref` — one command, no extra tooling.
- **Shared code path.** The CLI is a thin wrapper over the library, so
  every behaviour the library has, the CLI has too. No drift, no
  duplicate implementations, no CLI-only features.

Cargo skeleton:

```toml
[[bin]]
name = "secpref"
path = "src/bin/secpref.rs"
required-features = ["cli"]

[features]
default = []
cli = ["dep:clap", "dep:anyhow"]

[dependencies]
clap = { version = "4", features = ["derive"], optional = true }
anyhow = { version = "1", optional = true }
```

### 3.14 CLI covers both primitives and workflows — the "kit" framing

**Decision.** The `secpref` CLI has both low-level subcommands
(`mac compute`, `seed extract`, `ext-id derive`, `sid current`) and
high-level workflow subcommands (`prefs install`, `prefs uninstall`,
`prefs verify`, `prefs list`, `prefs strip-encrypted-hashes`). Both
tiers ship in the same binary.

**Rationale.**

- **Low-level ops** enable scripted workflows in other languages
  (a Python security-audit script can shell out to `secpref mac compute
  --seed $X --sid $Y --path $Z --value $J` and get a MAC without
  linking any Rust). This is the "kit" audience — someone who wants the
  primitives, not the opinionated installer.
- **High-level ops** enable one-shot use (`secpref prefs install
  --profile /path/to/Default --ext ~/my-ext` — done). Fine for
  operators or blue teams doing point-in-time work who don't want to
  compose primitives themselves.
- **Both tiers share the library.** Every high-level subcommand is
  literally a script written in Rust over the low-level primitives —
  the same primitives external scripts can call via the low-level
  subcommands. No two implementations.

The one line the CLI does NOT cross: **it never iterates browser
installations or profiles**. That's SilentChrome's job (§5).

---

## 4. API surface

### 4.1 Library — shipped in v0.1

```
secpref_kit
├── error       // SecPrefError
├── mac         // compute_mac, compute_super_mac, canonicalize, strip_empties (+ _bytes)
├── ext_id      // derive_from_key, derive_from_path, resolve, ExtId
├── seed        // extract_seed_from_pak(_bytes), SEED_LEN
├── prefs       // add_extension, remove_extension, enable_developer_mode,
│               // strip_encrypted_hashes, recompute_super_mac,
│               // verify_extension, list_extensions, VerifyResult, ExtInfo
└── manifest    // parse, parse_str, build_default_settings, Manifest
```

Re-exports at the crate root cover the common surface
(`compute_mac`, `compute_super_mac`, `derive_from_path`,
`derive_from_key`, `resolve_ext_id`, `ExtId`, `SecPrefError`,
`SEED_LEN`, `VerifyResult`).

### 4.2 Library — added in v0.2

```
secpref_kit
└── sid         // #[cfg(windows)]
                //   current_user_trimmed() -> Result<String, SecPrefError>
                //   lookup_by_name(&str)   -> Result<String, SecPrefError>
                //   (helper types as needed: TrimmedSid newtype?)
```

Windows-only module, no feature flag. Depends on `windows-sys` for
`GetTokenInformation` / `LookupAccountNameW` / `ConvertSidToStringSidW`.

### 4.3 Binary — added in v0.2

```
src/bin/secpref.rs           // clap-derive CLI, requires --features cli
```

Subcommand tree (final v0.2 shape):

```
secpref
├── seed
│   └── extract --pak <path>                            → prints 64-byte seed (hex or --raw)
├── mac
│   ├── compute --seed <hex|@pak-path> --sid <s> --path <p> --value <json|@file>
│   └── super   --seed <hex|@pak-path> --sid <s> --macs <json|@file>
├── ext-id
│   ├── derive --key <base64>                           → 32-char ID (from manifest key)
│   └── derive --path <p>                               → 32-char ID (from on-disk path)
├── sid          # [Windows only]
│   ├── current                                         → trimmed SID string
│   └── lookup --user <name>                            → trimmed SID string
└── prefs
    ├── install   --profile <dir> --ext <path>
    │             [--seed <hex>|--pak <path>] [--sid <s>|--sid-current]
    │             [--backup <dir>] [--no-super-mac]
    ├── uninstall --profile <dir> --ext-id <id>
    │             [--seed <hex>|--pak <path>] [--sid <s>|--sid-current]
    ├── list      --profile <dir>                       → JSON or table
    ├── verify    --profile <dir> --ext-id <id>
    │             [--seed <hex>|--pak <path>] [--sid <s>|--sid-current]
    │             → exit 0 (valid) / 1 (mismatch) / 2 (missing)
    └── strip-encrypted-hashes --profile <dir>
```

Design notes on CLI ergonomics:

- **`--seed <hex>|--pak <path>`** — accept either the seed bytes directly
  (16-hex-per-byte, 128 chars total) or a path to a `resources.pak` from
  which the seed will be extracted. `--pak` is the sane default for
  interactive use; `--seed` is for scripted pipelines that cached the
  seed once.
- **`--sid <s>|--sid-current`** — either explicit SID string or "look
  it up from the current user token" via the `sid::current_user_trimmed`
  helper. `--sid-current` is Windows-only; on non-Windows the flag
  errors with a clear message.
- **`--profile <dir>`** — the directory containing `Secure Preferences`
  (e.g. `~/.config/google-chrome/Default` on Linux, `%LOCALAPPDATA%\Google\Chrome\User Data\Default` on Windows).
  Path to the profile *folder*, not the file — matches how humans
  reason about Chromium profiles.
- **`--backup <dir>`** — write a copy of the pre-modification
  `Secure Preferences` to `<dir>/Secure Preferences.<ISO8601>.bak`
  before mutating. Off by default; explicit opt-in.
- **`verify` exit codes** — 0 valid / 1 mismatch / 2 missing — scriptable
  from any shell.

### 4.4 File layout (v0.2 target)

| File | Role | LOC (est.) |
|---|---|---:|
| `src/lib.rs` | doc header + module tree + re-exports | 120 |
| `src/error.rs` | `SecPrefError` | 60 |
| `src/mac.rs` | HMAC primitives | 244 |
| `src/ext_id.rs` | extension ID derivation | 174 |
| `src/seed.rs` | seed extraction | 190 |
| `src/prefs.rs` | high-level prefs operations | 509 |
| `src/manifest.rs` | manifest parsing + build_default_settings | 221 |
| `src/sid.rs` | Windows SID helpers **(new v0.2)** | ~120 |
| `src/bin/secpref.rs` | clap-derive CLI **(new v0.2)** | ~450 |
| tests × 4 | library tests | 284 |
| tests × 2 | CLI integration tests **(new v0.2)** | ~180 |
| **Total** | | **~2,550** |

### 4.5 v0.1.0 actuals

Currently on disk (v0.1.0 draft — no SID, no bin):

| File | LOC |
|---|---:|
| `src/lib.rs` | 108 |
| `src/error.rs` | 44 |
| `src/mac.rs` | 244 |
| `src/ext_id.rs` | 174 |
| `src/seed.rs` | 190 |
| `src/prefs.rs` | 509 |
| `src/manifest.rs` | 221 |
| tests × 4 | 284 |
| **Total** | **~1,780** |

Test count: **49** (25 unit + 24 integration/doc). Clippy pedantic clean.

---

## 5. Consumer strategy

The crate ships useful only when in-house tools consume it — otherwise
it's a solo library reimplementing what those tools already have. Since
v0.2 also ships a CLI, there's a fourth "consumer" — anyone running
`secpref` directly.

### 5.1 SilentChrome relationship

**SilentChrome and `secpref` CLI coexist with different scopes.** They
do NOT compete.

| Question | `secpref` (this crate's CLI) | SilentChrome CLI |
|---|---|---|
| Scope of one invocation | One Secure Preferences file | Whole browser install (all detected browsers × all profiles) |
| Browser discovery | Never | Registry walk + install-path detection (Chrome / Edge / Brave / Chromium) |
| Profile enumeration | `--profile <dir>` supplied by caller | Iterates `User Data\Profile *`, `Default`, etc. |
| Browser process handling | Never | Kill / restart timing, awaits process exit |
| PE hardening | Standard release build | Full PE-hardening pipeline (per SilentChrome's `harden_pe.py` port) |
| Backup semantics | `--backup <dir>` opt-in | Structured backup manifest per-profile |
| Audience | Scripted pipelines, blue-team audits, one-off ops | Operators who want "just install this on all browsers" |
| Library dep | Ships the library | Consumes the library |

**Concretely:**

- `secpref prefs install --profile /path/to/Default --ext /path/to/ext`
  — direct file operation, one profile, no browser detection.
- `silent-chrome install --ext /path/to/ext` — auto-detects Chrome /
  Edge / Brave installs, iterates profiles, handles browser
  kill+relaunch timing, uses PE-hardened binary — internally calls
  `secpref_kit::prefs::add_extension` on each discovered profile.

SilentChrome remains the operator-facing "do the right thing on all
browsers" tool; `secpref` is the scriptable per-file primitive UX.

### 5.2 SilentChrome swap (v0.2, first library consumer)

**Why first.** Public → public dep, safe to iterate on the API without
private-repo coordination. Any friction in the crate's API surfaces on
this swap and is fixed before the private-repo swap.

**Delta.**

- `Cargo.toml` — add `secpref-kit = { path = "../secpref-kit" }` (path
  dep pre-publish; git dep post-M3).
- Delete `src/crypto.rs` (superseded by `secpref_kit::mac`).
- Delete `src/prefs.rs` (superseded by `secpref_kit::prefs`).
- Delete `src/ext.rs` (superseded by `secpref_kit::{ext_id, manifest}`).
- Rewire `src/main.rs` subcommands to call `secpref_kit::…` directly.
- Keep `src/browser.rs` (browser-discovery — SilentChrome's scope).
- Thin `src/identity.rs` — replace body with `secpref_kit::sid::…`
  calls (or delete entirely if unused elsewhere).

Expected diff: `-~700 / +~150` LOC.

### 5.3 Lester `lester-ext` swap (v0.2, second library consumer)

**Why second.** Confirms the API holds up against the older, more-fielded
in-house code. Any Lester-specific edge cases become v0.2 refinements.

**Delta.**

- `Lester/crates/lester-ext/Cargo.toml` — add `secpref-kit = { path = … }`.
- Delete or thin `lester-ext/src/secpref.rs` (superseded).
- Delete or thin `lester-ext/src/ext_id.rs` (superseded).
- Keep `lester-ext/src/nmh.rs` (NMH install — future `nmh-install` sibling crate).
- Keep `lester-ext/src/cleanup.rs` (uninstall orchestration — different scope).
- `Lester/crates/lester-win32/src/sid.rs` (if it exists standalone) —
  consider consuming `secpref_kit::sid` for consistency, or keep local
  if Lester's SID handling has requirements the crate helpers don't cover.
- Adapter for Lester's own error type.

Expected diff: `-~700 / +~140` LOC (includes possible `lester-win32/src/sid.rs` retire).

### 5.4 External consumers (CLI + library, v0.3+)

Once M3 lands (`crates.io` publish), external audiences can consume
the crate directly:

- **Blue teams** running `secpref prefs verify --profile X --ext-id Y
  --pak Z --sid-current` in a scheduled integrity-audit job.
- **Other red-team tooling** linking `secpref-kit` as a library instead
  of vendoring code from a BOF or translating Python.
- **Security researchers** using `secpref mac compute` /
  `secpref ext-id derive` as scriptable primitives from any language.

### 5.5 `.raw/code/` reference tree

The Lester `.raw/code/` folder holds vendored copies of Silent_Chrome
(upstream Python), SilentChrome-BOF (SpecterOps BOF), Ditto,
ChromeAlone, etc. as research reference. Nothing to update there — they
remain reference implementations, not consumers.

---

## 6. Ethical framing

Recorded in the README, restated here as the design position:

The primitive lets a caller install a Chromium extension without user
consent by forging the file Chromium uses to detect tampering. This has
been publicly documented since 2020 (`syntax-err0r` blog + multiple
subsequent implementations). Publishing a clean Rust library **does not
move the detection bar**: defenders already knew about the primitive;
attackers already had five working implementations across Python / C /
Cobalt Strike BOF / Rust.

**Legitimate uses named in README:**

- Blue-team integrity auditing: compute expected MACs, compare against
  what is written on disk. Mismatched MACs = either legitimate
  corruption or a badly-forged tamper.
- Enterprise deployment tooling that already scripts Secure Preferences
  writes; this crate does it correctly.
- Security research on Chromium's integrity model.

**Restricted uses named in README:**

- Do not use against systems you do not own or have written permission
  to test. MIT license, but responsibility is on the caller.

---

## 7. Milestones

Semver-shaped. Each milestone has an explicit exit criteria — no
milestone is "done" until every criterion is met.

### M1 — v0.1.0 (drafted, local only)

**Status:** ✅ complete as of 2026-08-20.

**Delivered:**

- Core primitives (mac, super_mac, canonicalize, strip_empties).
- Extension ID derivation (from_key, from_path, resolve).
- Seed extraction from `resources.pak` (path + bytes variants).
- Prefs manipulation (add / remove / enable_developer_mode /
  strip_encrypted_hashes / recompute_super_mac / verify / list).
- Manifest parser + `build_default_settings`.
- 49 tests, clippy pedantic clean, MIT.
- `README.md`, `LICENSE`, `DESIGN.md` (this file).

**Exit criteria (all met):**

- [x] `cargo build` clean
- [x] `cargo test` — all 49 pass
- [x] `cargo clippy --all-targets -- -D warnings` clean
- [x] `cargo doc --no-deps` builds without warnings
- [x] Pinned HMAC + extension-ID test vectors
- [x] MIT license present, `#[non_exhaustive]` on error + `ExtInfo`

**Not published to crates.io.** Local `~/dev/secpref-kit/` only. No
`git init`.

### M2 — v0.2.0 (kit completion: SID + CLI + consumer swap)

**Goal.** Complete the kit. Ship the Windows SID module and the
standalone `secpref` CLI, then swap both in-house consumers onto the
library. When M2 exits, the crate is feature-complete for its stated
purpose — only publish + polish remain.

**Work — SID module (§3.8, §4.2):**

- Add `src/sid.rs` with `current_user_trimmed()` + `lookup_by_name(&str)`.
- Add `windows-sys` as a `[target.'cfg(windows)']` dep.
- Unit tests for the SID trim helper (pure string manipulation, testable
  on Linux); integration tests behind `#[cfg(windows)]`.

**Work — CLI (§3.13, §3.14, §4.3):**

- Add `[[bin]]` + `[features] cli = [...]` sections to `Cargo.toml`.
- Author `src/bin/secpref.rs` with the subcommand tree in §4.3.
- Wire every subcommand as a thin wrapper over the library — no
  duplicate logic, no CLI-only behaviours.
- CLI integration tests using `assert_cmd` + temp fixture directories.
- README grows a "CLI usage" section with concrete examples.

**Work — consumer swaps (§5.2, §5.3):**

- Swap SilentChrome onto `secpref-kit` (path dep locally). Fix API
  friction as it surfaces.
- Diff SilentChrome's own tests against secpref-kit's — port any
  extra coverage upstream.
- Swap Lester `lester-ext` onto `secpref-kit` (path dep locally).
- Sweep Lester `lester-ext/src/secpref.rs` for edge cases not currently
  in the crate; add them + regression tests.
- Bump crate to 0.2.0 with a CHANGELOG entry per API delta.

**Exit criteria:**

- [ ] `src/sid.rs` compiles + tests pass on Windows target (via `cargo
      check --target x86_64-pc-windows-msvc` using `cargo-xwin` for
      cross-check; runtime tests on a Windows rig)
- [ ] `secpref` binary builds with `--features cli`, runs every
      subcommand happy-path from a Bash script
- [ ] CLI integration tests: `assert_cmd` coverage on `seed extract`,
      `mac compute`, `ext-id derive`, `prefs install` /
      `verify` / `list` / `uninstall`, `prefs strip-encrypted-hashes`
- [ ] SilentChrome builds + tests pass against `secpref-kit` path dep
- [ ] Lester builds + tests pass against `secpref-kit` path dep
- [ ] All 49 (+ new SID + CLI) crate tests remain green
- [ ] `SilentChrome.exe` behaviour unchanged on Chrome / Edge / Brave
      test rigs (comparison against pre-swap output)
- [ ] Lester `butil dump --strategy=extension` behaviour unchanged
- [ ] CHANGELOG.md exists

Still local, still no publish.

### M3 — v0.3.0 (public ship)

**Goal.** Crate + `secpref` binary are publishable — external consumers
can `cargo add secpref-kit` or `cargo install --features cli secpref-kit`
against real registry versions.

**Work:**

- Add real Chromium fixture paks under `tests/fixtures/` (or generate
  them from a checked-in signature) so seed extraction is tested
  against actual browsers, not just synthetic paks.
- GitHub Actions CI matrix:
  - Linux stable: `cargo test`, `cargo test --features cli`,
    `cargo clippy --all-targets --all-features -- -D warnings`,
    `cargo doc --no-deps`, `cargo audit`.
  - Windows stable: same, plus `sid::*` runtime tests.
  - MSRV (1.75): `cargo build`, `cargo build --features cli`.
- README badges (build, crates.io version, docs.rs, MIT).
- `git init`, first commit, push to `github.com/shxve/secpref-kit`.
- `cargo publish` v0.3.0 to crates.io. Two publish artefacts on
  crates.io: the library (`secpref-kit`) and — via `cargo install
  --features cli secpref-kit` — the `secpref` binary.
- SilentChrome + Lester `Cargo.toml` bumps from path dep → git dep
  (or crates.io dep once we're confident in the API).
- Public release note (single blog / gist / SpecterOps-style writeup
  is optional — the crate landing on crates.io is enough).

**Exit criteria:**

- [ ] CI green on Linux + Windows + MSRV
- [ ] Fixture paks (Chrome / Edge / Brave) verified against upstream
- [ ] Public repo `shxve/secpref-kit` exists, MIT license visible
- [ ] `secpref-kit v0.3.0` on crates.io
- [ ] `cargo install --features cli secpref-kit` produces a working
      `secpref` binary on Linux + Windows
- [ ] SilentChrome + Lester consume via git dep or crates.io dep

### M4 — v1.0.0 (stable API)

**Goal.** SemVer commitment on the API surface. External consumers can
build against 1.x without expecting breakage.

**Work:**

- Sweep for any API method still named ambiguously; rename before 1.0.
- Confirm all `#[non_exhaustive]` decisions are still correct.
- Add rustdoc `# Examples` for every public function.
- Comprehensive changelog covering 0.1 → 1.0.
- `cargo public-api` diff against v0.3 to confirm no accidental removals.

**Exit criteria:**

- [ ] Zero API changes vs latest 0.x for one full month
- [ ] docs.rs page passes internal review (every symbol documented,
      every example compiles)
- [ ] Public release announcement (blog or SpecterOps-style writeup)
- [ ] `secpref-kit v1.0.0` on crates.io

### Post-1.0 (not scheduled)

- **Additional Chromium integrity mechanisms** — IWA key distribution,
  Web App Sync integrity — if the same forger pattern generalises.
- **Companion crate `nmh-install`** (registry + NMH manifest write) —
  see in-house integration review §6.5. Not this crate; sibling crate.
  A `secpref-kit`-style CLI would live in `nmh-install` too (same
  lib+bin pattern).
- **macOS / Linux SID equivalents** — Chromium on macOS/Linux uses
  different HMAC device_id derivations (not user SID). If a consumer
  needs to forge Secure Preferences on non-Windows, this becomes an
  `identity` module with per-platform impls. Untouched until demand.

---

## 8. Non-goals for v1.0

Explicit list of things NOT to add before 1.0:

- Async API surface.
- Non-Chromium browser support (Firefox / Safari have different
  integrity models entirely).
- ABE / v10 / v20 cookie decryption.
- CDP / networking / registry / process management.
- Registry writes for NMH install (separate `nmh-install` sibling crate
  per the in-house integration review §6.5).
- Browser discovery / multi-profile orchestration (SilentChrome's job).
- `serde`-derived types for the whole Secure Preferences schema (we operate
  on `serde_json::Value` deliberately — the schema is too big and too
  version-drifty to type out).

If any of these become interesting later, they get a separate crate.

---

## 9. Open questions

Not decided as of v0.1 draft. Revisit during M2 or M3.

- **Alias naming.** Rust idiom prefers `derive_from_path` /
  `derive_from_key`. Chromium's docs call these
  `extension_id_from_public_key` / `extension_id_from_path`. Which is
  more discoverable in docs.rs search? (Current: Rust idiom wins;
  the module namespace `ext_id::` makes the meaning obvious.)

- **`Manifest` field completeness.** v0.1's `Manifest` struct exposes
  `name`, `version`, `permissions`, `host_permissions`, `key`,
  `service_worker`. Manifest V3 has many more fields (content scripts,
  action, options page, etc.). Consumers so far only need the current
  six — add more when a consumer needs them.

- **`build_default_settings` opinionated fields.** Currently hard-codes
  `state = 1`, `location = 4`, `incognito = true`, `newAllowFileAccess
  = true`, `creation_flags = 38`. Might want a builder pattern
  (`SettingsBuilder::new().state(1).incognito(false).build()`) in
  v0.2 if consumers want variations without cloning + mutating a
  returned `Value`.

- **Error variants.** Is `SecPrefError` right? Consumers might want
  finer error types per module. Revisit in M2 after both consumers have
  swapped.

- **`preserve_order` at the crate boundary.** Since `preserve_order` is
  a correctness requirement, should the crate refuse to build if it's
  disabled? Currently the crate depends on it explicitly so disabling
  is impossible — but if someone did `default-features = false, features
  = []`, MAC output would silently drift. Consider a compile-time
  assertion.

---

## 10. Change log

| Date | Change |
|---|---|
| 2026-08-20 | v0.1.0 drafted locally (extracted from SilentChrome). 49 tests, clippy clean. |
| 2026-08-20 | Renamed from `secpref-forge` to `secpref-kit` (`-forge` implied offensive-only; `-kit` reflects the read/list/verify/manipulate scope). |
| 2026-08-20 | Scope expansion: SID helpers moved from post-1.0 back to v0.2 first-class; CLI (standalone `secpref` binary) added to v0.2. §3.1 refined (I/O lives in CLI wrapper, not library). §3.8 inverted (SID ships, no feature flag, `#[cfg(windows)]`-gated). New §3.13 (single crate, dual target, CLI feature-gated) + §3.14 (CLI covers both primitives and workflows — "kit" framing). §4 restructured into 4.1 v0.1 shipped / 4.2 v0.2 SID / 4.3 v0.2 CLI / 4.4 file-layout target. §5 SilentChrome relationship refined (secpref CLI is per-file scriptable; SilentChrome remains browser-orchestrating). §7 M2 expanded to cover SID + CLI + consumer swap in one milestone. §8 non-goals pruned (CLI + windows-SID removed). |
