//! `secpref` — Chromium Secure Preferences complete-kit CLI.
//!
//! Thin wrapper over `secpref_kit`. Every subcommand is a direct call
//! into the library; no logic lives here that isn't I/O plumbing.
//!
//! Requires `--features cli`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::Value;

use secpref_kit::{
    ext_id, extract_seed_from_pak, mac, manifest, prefs, resolve_ext_id,
};

// -------------------- top-level parser --------------------

#[derive(Parser)]
#[command(
    name = "secpref",
    version,
    about = "Chromium Secure Preferences complete kit (seed / MAC / extension ID / prefs / Windows SID)",
    propagate_version = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// `resources.pak` seed operations.
    Seed {
        #[command(subcommand)]
        op: SeedOp,
    },
    /// HMAC compute (per-value and top-level super-MAC).
    Mac {
        #[command(subcommand)]
        op: MacOp,
    },
    /// Extension-ID derivation.
    #[command(name = "ext-id")]
    ExtId {
        #[command(subcommand)]
        op: ExtIdOp,
    },
    /// Windows SID helpers (Windows-only; errors on other platforms).
    Sid {
        #[command(subcommand)]
        op: SidOp,
    },
    /// `Secure Preferences` operations (per-profile).
    Prefs {
        #[command(subcommand)]
        op: PrefsOp,
    },
}

// -------------------- subcommand enums --------------------

#[derive(Subcommand)]
enum SeedOp {
    /// Extract the 64-byte `chrome_seed` from a `resources.pak`.
    Extract {
        /// Path to Chromium `resources.pak`.
        #[arg(long)]
        pak: PathBuf,
        /// Emit raw bytes to stdout instead of uppercase hex.
        #[arg(long)]
        raw: bool,
    },
}

#[derive(Subcommand)]
enum MacOp {
    /// Compute a per-value MAC.
    Compute {
        #[command(flatten)]
        seed_src: SeedSource,
        #[command(flatten)]
        sid_src: SidSource,
        /// Dotted preference path (e.g. `extensions.settings.<id>`).
        #[arg(long)]
        path: String,
        /// JSON value at that preference path.
        #[arg(long, value_parser = parse_json)]
        value: Value,
    },
    /// Compute the top-level super-MAC over a `protection.macs` sub-tree.
    Super {
        #[command(flatten)]
        seed_src: SeedSource,
        #[command(flatten)]
        sid_src: SidSource,
        /// JSON object of the `protection.macs` sub-tree.
        #[arg(long, value_parser = parse_json)]
        macs: Value,
    },
}

#[derive(Subcommand)]
enum ExtIdOp {
    /// Derive an extension ID.
    ///
    /// Exactly one of `--key` or `--path` must be supplied.
    Derive {
        /// Base64-encoded manifest key (produces stable ID).
        #[arg(long, group = "id_from")]
        key: Option<String>,
        /// Extension on-disk path (Windows: UTF-16-LE bytes hashed).
        #[arg(long, group = "id_from")]
        path: Option<String>,
    },
}

#[derive(Subcommand)]
enum SidOp {
    /// Print the current process user's SID.
    Current,
    /// Look up a user's SID by name.
    Lookup {
        /// Account name (`alice` or `CORP\alice`).
        #[arg(long)]
        user: String,
    },
}

#[derive(Subcommand)]
enum PrefsOp {
    /// Install an extension into one `Secure Preferences` file.
    Install {
        /// Profile directory (contains the `Secure Preferences` file).
        #[arg(long)]
        profile: PathBuf,
        /// Extension directory (unpacked; must contain `manifest.json`).
        #[arg(long)]
        ext: PathBuf,
        #[command(flatten)]
        seed_src: SeedSource,
        #[command(flatten)]
        sid_src: SidSource,
        /// Back up the pre-modification file into this directory.
        #[arg(long)]
        backup: Option<PathBuf>,
        /// Skip super-MAC recomputation (advanced).
        #[arg(long)]
        no_super_mac: bool,
    },
    /// Uninstall an extension.
    Uninstall {
        #[arg(long)]
        profile: PathBuf,
        /// 32-character extension ID.
        #[arg(long = "ext-id")]
        ext_id: String,
        #[command(flatten)]
        seed_src: SeedSource,
        #[command(flatten)]
        sid_src: SidSource,
    },
    /// List installed extensions.
    List {
        #[arg(long)]
        profile: PathBuf,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Verify an extension's MACs (exit 0 = valid, 1 = mismatch, 2 = missing).
    Verify {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long = "ext-id")]
        ext_id: String,
        #[command(flatten)]
        seed_src: SeedSource,
        #[command(flatten)]
        sid_src: SidSource,
    },
    /// Drop every `*_encrypted_hash` entry (force self-healing).
    #[command(name = "strip-encrypted-hashes")]
    StripEncryptedHashes {
        #[arg(long)]
        profile: PathBuf,
    },
}

// -------------------- shared arg groups --------------------

#[derive(Args)]
#[group(required = true, multiple = false)]
struct SeedSource {
    /// Seed as uppercase hex (64 bytes → 128 hex chars).
    #[arg(long)]
    seed: Option<String>,
    /// Path to a `resources.pak` from which to extract the seed.
    #[arg(long = "pak")]
    pak: Option<PathBuf>,
}

impl SeedSource {
    fn resolve(&self) -> Result<Vec<u8>> {
        if let Some(hex_str) = &self.seed {
            hex::decode(hex_str).context("--seed: not valid hex")
        } else if let Some(pak) = &self.pak {
            extract_seed_from_pak(pak).context("--pak: seed extraction failed")
        } else {
            bail!("either --seed or --pak required (clap arg-group guard)");
        }
    }
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct SidSource {
    /// Explicit SID string (e.g. `S-1-5-21-...-1001`).
    #[arg(long)]
    sid: Option<String>,
    /// Use the current process user's SID (Windows only).
    #[arg(long = "sid-current")]
    sid_current: bool,
}

impl SidSource {
    fn resolve(&self) -> Result<String> {
        if let Some(s) = &self.sid {
            return Ok(s.clone());
        }
        if self.sid_current {
            #[cfg(windows)]
            {
                return secpref_kit::sid::current_user_trimmed().map_err(Into::into);
            }
            #[cfg(not(windows))]
            {
                bail!("--sid-current is Windows-only; supply --sid explicitly");
            }
        }
        bail!("either --sid or --sid-current required (clap arg-group guard)");
    }
}

// -------------------- helpers --------------------

fn parse_json(s: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str(s)
}

fn secure_prefs_path(profile: &Path) -> PathBuf {
    profile.join("Secure Preferences")
}

fn read_prefs(path: &Path) -> Result<Value> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&content).with_context(|| format!("parsing {}", path.display()))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("secpref-tmp");
    fs::write(&tmp, bytes)
        .with_context(|| format!("writing tmp {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn timestamp() -> String {
    // No chrono dep — plain UTC epoch seconds.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    format!("{secs}")
}

// -------------------- main + handlers --------------------

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(3)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        Command::Seed { op } => handle_seed(op),
        Command::Mac { op } => handle_mac(op),
        Command::ExtId { op } => handle_ext_id(op),
        Command::Sid { op } => handle_sid(op),
        Command::Prefs { op } => handle_prefs(op),
    }
}

fn handle_seed(op: SeedOp) -> Result<ExitCode> {
    match op {
        SeedOp::Extract { pak, raw } => {
            let seed = extract_seed_from_pak(&pak)?;
            if raw {
                use std::io::Write;
                std::io::stdout().write_all(&seed).context("stdout write")?;
            } else {
                println!("{}", hex::encode_upper(&seed));
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn handle_mac(op: MacOp) -> Result<ExitCode> {
    match op {
        MacOp::Compute {
            seed_src,
            sid_src,
            path,
            value,
        } => {
            let seed = seed_src.resolve()?;
            let sid = sid_src.resolve()?;
            println!("{}", mac::compute_mac(&seed, &sid, &path, &value));
            Ok(ExitCode::SUCCESS)
        }
        MacOp::Super {
            seed_src,
            sid_src,
            macs,
        } => {
            let seed = seed_src.resolve()?;
            let sid = sid_src.resolve()?;
            println!("{}", mac::compute_super_mac(&seed, &sid, &macs));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn handle_ext_id(op: ExtIdOp) -> Result<ExitCode> {
    match op {
        ExtIdOp::Derive { key, path } => {
            let id = match (key, path) {
                (Some(k), None) => ext_id::derive_from_key(&k)?,
                (None, Some(p)) => ext_id::derive_from_path(&p),
                (Some(_), Some(_)) => bail!("pass exactly one of --key or --path"),
                (None, None) => bail!("supply --key or --path"),
            };
            println!("{id}");
            Ok(ExitCode::SUCCESS)
        }
    }
}

// `op` is consumed by the match on Windows but unused on other platforms —
// that asymmetry trips `needless_pass_by_value` on non-Windows. Allow it
// so the signature stays consistent across targets.
#[cfg_attr(not(windows), allow(clippy::needless_pass_by_value))]
fn handle_sid(op: SidOp) -> Result<ExitCode> {
    #[cfg(not(windows))]
    {
        let _ = op;
        bail!("sid subcommand is Windows-only");
    }
    #[cfg(windows)]
    match op {
        SidOp::Current => {
            println!("{}", secpref_kit::sid::current_user_trimmed()?);
            Ok(ExitCode::SUCCESS)
        }
        SidOp::Lookup { user } => {
            println!("{}", secpref_kit::sid::lookup_by_name(&user)?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn handle_prefs(op: PrefsOp) -> Result<ExitCode> {
    match op {
        PrefsOp::Install {
            profile,
            ext,
            seed_src,
            sid_src,
            backup,
            no_super_mac,
        } => install(&profile, &ext, &seed_src, &sid_src, backup.as_deref(), no_super_mac),
        PrefsOp::Uninstall {
            profile,
            ext_id,
            seed_src,
            sid_src,
        } => uninstall(&profile, &ext_id, &seed_src, &sid_src),
        PrefsOp::List { profile, json } => list(&profile, json),
        PrefsOp::Verify {
            profile,
            ext_id,
            seed_src,
            sid_src,
        } => verify(&profile, &ext_id, &seed_src, &sid_src),
        PrefsOp::StripEncryptedHashes { profile } => strip(&profile),
    }
}

fn install(
    profile: &Path,
    ext: &Path,
    seed_src: &SeedSource,
    sid_src: &SidSource,
    backup: Option<&Path>,
    no_super_mac: bool,
) -> Result<ExitCode> {
    let seed = seed_src.resolve()?;
    let sid = sid_src.resolve()?;
    let prefs_path = secure_prefs_path(profile);
    let mut prefs_json = read_prefs(&prefs_path)?;

    if let Some(bdir) = backup {
        fs::create_dir_all(bdir)
            .with_context(|| format!("creating backup dir {}", bdir.display()))?;
        let dest = bdir.join(format!("Secure Preferences.{}.bak", timestamp()));
        fs::copy(&prefs_path, &dest)
            .with_context(|| format!("backing up to {}", dest.display()))?;
        eprintln!("backup: {}", dest.display());
    }

    let m = manifest::parse(ext).with_context(|| format!("parsing manifest in {}", ext.display()))?;
    let ext_path_str = ext.display().to_string();
    let ext_id_str = resolve_ext_id(m.key.as_deref(), &ext_path_str).into_id();
    let settings = manifest::build_default_settings(&m, &ext_path_str);

    let ext_mac = prefs::add_extension(&mut prefs_json, &ext_id_str, settings, &seed, &sid)?;
    prefs::enable_developer_mode(&mut prefs_json, &seed, &sid);
    prefs::strip_encrypted_hashes(&mut prefs_json);
    if !no_super_mac {
        prefs::recompute_super_mac(&mut prefs_json, &seed, &sid);
    }

    let out = serde_json::to_string(&prefs_json)?;
    atomic_write(&prefs_path, out.as_bytes())?;
    println!("installed {ext_id_str} (mac {ext_mac})");
    Ok(ExitCode::SUCCESS)
}

fn uninstall(
    profile: &Path,
    ext_id_str: &str,
    seed_src: &SeedSource,
    sid_src: &SidSource,
) -> Result<ExitCode> {
    let seed = seed_src.resolve()?;
    let sid = sid_src.resolve()?;
    let prefs_path = secure_prefs_path(profile);
    let mut prefs_json = read_prefs(&prefs_path)?;
    prefs::remove_extension(&mut prefs_json, ext_id_str)?;
    prefs::strip_encrypted_hashes(&mut prefs_json);
    prefs::recompute_super_mac(&mut prefs_json, &seed, &sid);
    let out = serde_json::to_string(&prefs_json)?;
    atomic_write(&prefs_path, out.as_bytes())?;
    println!("uninstalled {ext_id_str}");
    Ok(ExitCode::SUCCESS)
}

fn list(profile: &Path, json: bool) -> Result<ExitCode> {
    let prefs_json = read_prefs(&secure_prefs_path(profile))?;
    let installed = prefs::list_extensions(&prefs_json);
    if json {
        let payload: Vec<Value> = installed
            .iter()
            .map(|e| {
                serde_json::json!({
                    "id":      e.id,
                    "name":    e.name,
                    "path":    e.path,
                    "version": e.version,
                    "enabled": e.enabled,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else if installed.is_empty() {
        eprintln!("(no extensions installed)");
    } else {
        for e in installed {
            println!(
                "{}  {:<3}  {:<12}  {}",
                e.id,
                if e.enabled { "on" } else { "off" },
                if e.version.is_empty() { "-" } else { &e.version },
                if e.name.is_empty() { "(unknown)" } else { &e.name },
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn verify(
    profile: &Path,
    ext_id_str: &str,
    seed_src: &SeedSource,
    sid_src: &SidSource,
) -> Result<ExitCode> {
    let seed = seed_src.resolve()?;
    let sid = sid_src.resolve()?;
    let prefs_json = read_prefs(&secure_prefs_path(profile))?;
    match prefs::verify_extension(&prefs_json, ext_id_str, &seed, &sid) {
        Ok(verdict) => {
            println!("ext_mac_valid   : {}", verdict.ext_mac_valid);
            println!("dev_mac_valid   : {}", verdict.dev_mac_valid);
            println!("super_mac_valid : {}", verdict.super_mac_valid);
            if verdict.all_valid() {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(1))
            }
        }
        Err(secpref_kit::SecPrefError::ExtensionNotFound(_)) => {
            eprintln!("extension not present in profile");
            Ok(ExitCode::from(2))
        }
        Err(other) => Err(other.into()),
    }
}

fn strip(profile: &Path) -> Result<ExitCode> {
    let prefs_path = secure_prefs_path(profile);
    let mut prefs_json = read_prefs(&prefs_path)?;
    prefs::strip_encrypted_hashes(&mut prefs_json);
    let out = serde_json::to_string(&prefs_json)?;
    atomic_write(&prefs_path, out.as_bytes())?;
    println!("encrypted-hash entries stripped");
    Ok(ExitCode::SUCCESS)
}
