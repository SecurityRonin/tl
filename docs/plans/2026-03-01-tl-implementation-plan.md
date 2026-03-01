# tl Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Rust-based TUI forensic triage tool that parses Velociraptor collections into a unified, browsable timeline in under 30 seconds.

**Architecture:** Collection abstraction layer normalizes path encodings from any triage format (Velociraptor, KAPE, raw dirs) into a unified virtual filesystem. Artifact parsers run in parallel via rayon, feeding into a BTreeMap-based timeline with entity resolution. ratatui TUI with vi keys presents the timeline-first view.

**Tech Stack:** Rust, ratatui + crossterm, mft, evtx, notatin, lnk, jumplist_parser, frnsc-prefetch, frnsc-amcache, zip, rayon, clap, chrono, nt-time, csv, serde

**Design Doc:** `docs/plans/2026-03-01-tl-design.md`

---

## Phase 1: MVP — NTFS Timeline Core

**Deliverable:** `tl <collection.zip>` opens a TUI showing every file from $MFT with 8 NTFS timestamps, timestomping detection, vi-key navigation, and CSV export.

---

### Task 1.1: Project Scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `src/lib.rs`
- Create: `.gitignore` (already exists, verify)

**Step 1: Initialize Cargo project**

```bash
cd /Users/4n6h4x0r/src/tl2
cargo init --name tl
```

**Step 2: Set up Cargo.toml with initial dependencies**

```toml
[package]
name = "tl"
version = "0.1.0"
edition = "2021"
description = "Rapid forensic triage timeline tool"

[dependencies]
# CLI
clap = { version = "4", features = ["derive"] }

# Collection handling
zip = "2"
percent-encoding = "2"

# NTFS
mft = "0.6"

# Timestamps
chrono = { version = "0.4", features = ["serde"] }
nt-time = "0.8"

# TUI
ratatui = "0.29"
crossterm = "0.28"

# Data
serde = { version = "1", features = ["derive"] }
serde_json = "1"
csv = "1"
bodyfile = "0.4"
smallvec = { version = "1", features = ["serde"] }
bitflags = "2"

# Parallelism
rayon = "1"

# Search
regex = "1"

# Error handling
anyhow = "1"
thiserror = "1"

# Logging
log = "0.4"
env_logger = "0.11"

[dev-dependencies]
tempfile = "3"
assert_cmd = "2"
predicates = "3"
```

**Step 3: Create minimal main.rs**

```rust
use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "tl", about = "Rapid forensic triage timeline")]
struct Cli {
    /// Path to collection (zip file or directory)
    collection: std::path::PathBuf,

    /// Export timeline to CSV instead of opening TUI
    #[arg(long)]
    export_csv: Option<std::path::PathBuf>,

    /// Export timeline to JSON instead of opening TUI
    #[arg(long)]
    export_json: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    println!("Opening collection: {}", cli.collection.display());
    Ok(())
}
```

**Step 4: Create lib.rs with module structure**

```rust
pub mod collection;
pub mod timeline;
pub mod parsers;
pub mod tui;
pub mod export;
```

**Step 5: Create module directories**

```bash
mkdir -p src/{collection,timeline,parsers,tui,export}
touch src/collection/mod.rs src/timeline/mod.rs src/parsers/mod.rs src/tui/mod.rs src/export/mod.rs
```

**Step 6: Verify it compiles**

```bash
cargo build
```
Expected: Compiles with warnings about unused modules.

**Step 7: Commit**

```bash
git init
git add Cargo.toml src/ .gitignore docs/
git commit -m "feat: project scaffold with module structure and dependencies"
```

---

### Task 1.2: Path Normalization

**Files:**
- Create: `src/collection/path.rs`
- Modify: `src/collection/mod.rs`
- Create: `tests/path_normalization.rs`

**Step 1: Write the failing tests**

```rust
// tests/path_normalization.rs
use tl::collection::path::{NormalizedPath, normalize_velociraptor_path, AccessorType};

#[test]
fn test_ntfs_accessor_path() {
    let raw = "uploads/ntfs/%5C%5C.%5CC%3A/$MFT";
    let norm = normalize_velociraptor_path(raw).unwrap();
    assert_eq!(norm.windows_path(), r"C:\$MFT");
    assert_eq!(norm.accessor_type(), AccessorType::Ntfs);
}

#[test]
fn test_auto_accessor_path() {
    let raw = "uploads/auto/C%3A/Windows/System32/config/SYSTEM";
    let norm = normalize_velociraptor_path(raw).unwrap();
    assert_eq!(norm.windows_path(), r"C:\Windows\System32\config\SYSTEM");
    assert_eq!(norm.accessor_type(), AccessorType::Auto);
}

#[test]
fn test_auto_accessor_user_profile() {
    let raw = "uploads/auto/C%3A/Users/4n6h4x0r/NTUSER.DAT";
    let norm = normalize_velociraptor_path(raw).unwrap();
    assert_eq!(norm.windows_path(), r"C:\Users\4n6h4x0r\NTUSER.DAT");
}

#[test]
fn test_ntfs_accessor_usnjrnl() {
    let raw = "uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J";
    let norm = normalize_velociraptor_path(raw).unwrap();
    assert_eq!(norm.windows_path(), r"C:\$Extend\$UsnJrnl:$J");
    assert_eq!(norm.accessor_type(), AccessorType::Ntfs);
}

#[test]
fn test_path_with_spaces() {
    let raw = "uploads/auto/C%3A/ProgramData/Microsoft/Windows/Start Menu/Programs/Word.lnk";
    let norm = normalize_velociraptor_path(raw).unwrap();
    assert_eq!(norm.windows_path(), r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Word.lnk");
}

#[test]
fn test_windows_old_path() {
    let raw = "uploads/auto/C%3A/Windows.old/WINDOWS/System32/config/SYSTEM";
    let norm = normalize_velociraptor_path(raw).unwrap();
    assert_eq!(norm.windows_path(), r"C:\Windows.old\WINDOWS\System32\config\SYSTEM");
}

#[test]
fn test_unknown_path_returns_none() {
    let raw = "some/random/path.txt";
    assert!(normalize_velociraptor_path(raw).is_none());
}
```

**Step 2: Run tests to verify they fail**

```bash
cargo test --test path_normalization
```
Expected: Compilation error — module doesn't exist yet.

**Step 3: Implement path normalization**

```rust
// src/collection/path.rs
use percent_encoding::percent_decode_str;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessorType {
    Ntfs,
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPath {
    windows_path: String,
    accessor: AccessorType,
    original_zip_path: String,
}

impl NormalizedPath {
    pub fn windows_path(&self) -> &str {
        &self.windows_path
    }

    pub fn accessor_type(&self) -> AccessorType {
        self.accessor.clone()
    }

    pub fn original_zip_path(&self) -> &str {
        &self.original_zip_path
    }
}

impl fmt::Display for NormalizedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.windows_path)
    }
}

/// Normalize a Velociraptor collection zip path to a Windows path.
///
/// Handles two accessor types:
/// - `uploads/ntfs/%5C%5C.%5CC%3A/...` -> `C:\...` (NTFS accessor)
/// - `uploads/auto/C%3A/...` -> `C:\...` (Auto accessor)
///
/// Returns None if the path doesn't match a known Velociraptor pattern.
pub fn normalize_velociraptor_path(zip_path: &str) -> Option<NormalizedPath> {
    if let Some(rest) = zip_path.strip_prefix("uploads/ntfs/") {
        // Decode the volume prefix: %5C%5C.%5CC%3A -> \\.\C:
        let decoded = percent_decode_str(rest).decode_utf8().ok()?;
        // Strip \\.\C: prefix and convert to C:\
        let without_prefix = decoded.strip_prefix(r"\\.\C:")?;
        let win_path = format!("C:{}", without_prefix.replace('/', r"\"));
        Some(NormalizedPath {
            windows_path: win_path,
            accessor: AccessorType::Ntfs,
            original_zip_path: zip_path.to_string(),
        })
    } else if let Some(rest) = zip_path.strip_prefix("uploads/auto/") {
        let decoded = percent_decode_str(rest).decode_utf8().ok()?;
        // decoded starts with C: or similar drive letter
        let win_path = decoded.replace('/', r"\");
        Some(NormalizedPath {
            windows_path: win_path,
            accessor: AccessorType::Auto,
            original_zip_path: zip_path.to_string(),
        })
    } else {
        None
    }
}
```

Update `src/collection/mod.rs`:

```rust
pub mod path;
```

**Step 4: Run tests**

```bash
cargo test --test path_normalization
```
Expected: All 7 tests pass.

**Step 5: Commit**

```bash
git add src/collection/ tests/
git commit -m "feat: Velociraptor path normalization with dual accessor support"
```

---

### Task 1.3: Collection Provider Trait & VelociraptorProvider

**Files:**
- Create: `src/collection/provider.rs`
- Create: `src/collection/velociraptor.rs`
- Create: `src/collection/manifest.rs`
- Modify: `src/collection/mod.rs`
- Create: `tests/velociraptor_provider.rs`

**Step 1: Write the failing test**

```rust
// tests/velociraptor_provider.rs
use std::path::Path;
use tl::collection::velociraptor::VelociraptorProvider;
use tl::collection::provider::CollectionProvider;

#[test]
fn test_open_collection_zip() {
    let zip_path = Path::new("test/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
    if !zip_path.exists() {
        eprintln!("Skipping: test collection not found at {}", zip_path.display());
        return;
    }
    let provider = VelociraptorProvider::open(zip_path).unwrap();
    let manifest = provider.discover();

    // Should find the $MFT
    assert!(manifest.has_mft());
    // Should find the $UsnJrnl
    assert!(manifest.has_usnjrnl());
    // Should find registry hives
    assert!(!manifest.registry_hives().is_empty());
    // Should find event logs
    assert!(!manifest.event_logs().is_empty());
    // Should find prefetch files
    assert!(!manifest.prefetch_files().is_empty());
    // Should find LNK files
    assert!(!manifest.lnk_files().is_empty());
}

#[test]
fn test_collection_metadata() {
    let zip_path = Path::new("test/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
    if !zip_path.exists() {
        return;
    }
    let provider = VelociraptorProvider::open(zip_path).unwrap();
    let meta = provider.metadata();
    // Hostname extracted from zip filename
    assert!(meta.hostname.contains("A380"));
}
```

**Step 2: Run tests to verify they fail**

```bash
cargo test --test velociraptor_provider
```

**Step 3: Implement the manifest types**

```rust
// src/collection/manifest.rs
use crate::collection::path::NormalizedPath;

#[derive(Debug, Default)]
pub struct ArtifactManifest {
    pub mft: Option<NormalizedPath>,
    pub mft_mirr: Option<NormalizedPath>,
    pub usnjrnl_j: Option<NormalizedPath>,
    pub usnjrnl_max: Option<NormalizedPath>,
    pub logfile: Option<NormalizedPath>,
    pub boot: Option<NormalizedPath>,
    pub secure_sds: Option<NormalizedPath>,
    pub registry_hives: Vec<RegistryHiveEntry>,
    pub event_logs: Vec<NormalizedPath>,
    pub prefetch: Vec<NormalizedPath>,
    pub lnk_files: Vec<NormalizedPath>,
    pub jump_lists_auto: Vec<NormalizedPath>,
    pub jump_lists_custom: Vec<NormalizedPath>,
    pub amcache: Vec<NormalizedPath>,
    pub recycle_bin: Vec<NormalizedPath>,
    pub scheduled_tasks: Vec<NormalizedPath>,
    pub all_paths: Vec<NormalizedPath>,
}

#[derive(Debug, Clone)]
pub struct RegistryHiveEntry {
    pub path: NormalizedPath,
    pub hive_type: RegistryHiveType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RegistryHiveType {
    System,
    Software,
    Sam,
    Security,
    Default,
    NtUser { username: String },
    UsrClass { username: String },
    Amcache,
    Other(String),
}

impl ArtifactManifest {
    pub fn has_mft(&self) -> bool { self.mft.is_some() }
    pub fn has_usnjrnl(&self) -> bool { self.usnjrnl_j.is_some() }
    pub fn registry_hives(&self) -> &[RegistryHiveEntry] { &self.registry_hives }
    pub fn event_logs(&self) -> &[NormalizedPath] { &self.event_logs }
    pub fn prefetch_files(&self) -> &[NormalizedPath] { &self.prefetch }
    pub fn lnk_files(&self) -> &[NormalizedPath] { &self.lnk_files }
}
```

**Step 4: Implement the provider trait**

```rust
// src/collection/provider.rs
use crate::collection::manifest::ArtifactManifest;
use crate::collection::path::NormalizedPath;
use anyhow::Result;
use std::io::Read;

#[derive(Debug, Clone, Default)]
pub struct CollectionMetadata {
    pub hostname: String,
    pub collection_timestamp: String,
    pub source_tool: String,
}

pub trait CollectionProvider: Send + Sync {
    fn discover(&self) -> ArtifactManifest;
    fn open_file(&self, path: &NormalizedPath) -> Result<Vec<u8>>;
    fn metadata(&self) -> CollectionMetadata;
}
```

**Step 5: Implement VelociraptorProvider**

```rust
// src/collection/velociraptor.rs
use crate::collection::manifest::*;
use crate::collection::path::*;
use crate::collection::provider::*;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use zip::ZipArchive;
use std::sync::Mutex;

pub struct VelociraptorProvider {
    zip_path: PathBuf,
    manifest: ArtifactManifest,
    meta: CollectionMetadata,
}

impl VelociraptorProvider {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open collection: {}", path.display()))?;
        let mut archive = ZipArchive::new(file)
            .context("Failed to read zip archive")?;

        let mut manifest = ArtifactManifest::default();

        // Scan all entries and classify
        for i in 0..archive.len() {
            let entry = archive.by_index(i)?;
            let zip_path = entry.name().to_string();

            if let Some(norm) = normalize_velociraptor_path(&zip_path) {
                classify_artifact(&norm, &mut manifest);
                manifest.all_paths.push(norm);
            }
        }

        // Extract metadata from filename
        let meta = extract_metadata_from_filename(path);

        Ok(Self {
            zip_path: path.to_path_buf(),
            manifest,
            meta,
        })
    }
}

impl CollectionProvider for VelociraptorProvider {
    fn discover(&self) -> ArtifactManifest {
        // Clone is acceptable here since discover is called once
        // In practice, return a reference or Arc
        // For now, rebuild from stored paths
        let mut m = ArtifactManifest::default();
        for p in &self.manifest.all_paths {
            classify_artifact(p, &mut m);
        }
        m.all_paths = self.manifest.all_paths.clone();
        m
    }

    fn open_file(&self, path: &NormalizedPath) -> Result<Vec<u8>> {
        let file = File::open(&self.zip_path)?;
        let mut archive = ZipArchive::new(file)?;
        let mut entry = archive.by_name(path.original_zip_path())?;
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn metadata(&self) -> CollectionMetadata {
        self.meta.clone()
    }
}

fn classify_artifact(path: &NormalizedPath, manifest: &mut ArtifactManifest) {
    let win = path.windows_path();
    let lower = win.to_lowercase();

    // NTFS core
    if lower.ends_with(r"\$mft") && !lower.contains("mftmirr") {
        manifest.mft = Some(path.clone());
    } else if lower.ends_with(r"\$mftmirr") {
        manifest.mft_mirr = Some(path.clone());
    } else if lower.ends_with("$usnjrnl:$j") || lower.ends_with(r"$usnjrnl%3a$j") {
        manifest.usnjrnl_j = Some(path.clone());
    } else if lower.ends_with("$usnjrnl:$max") {
        manifest.usnjrnl_max = Some(path.clone());
    } else if lower.ends_with(r"\$logfile") {
        manifest.logfile = Some(path.clone());
    } else if lower.ends_with(r"\$boot") {
        manifest.boot = Some(path.clone());
    } else if lower.ends_with("$secure:$sds") {
        manifest.secure_sds = Some(path.clone());
    }
    // Event logs
    else if lower.ends_with(".evtx") {
        manifest.event_logs.push(path.clone());
    }
    // Prefetch
    else if lower.ends_with(".pf") && lower.contains("prefetch") {
        manifest.prefetch.push(path.clone());
    }
    // LNK files
    else if lower.ends_with(".lnk") {
        manifest.lnk_files.push(path.clone());
    }
    // Jump Lists
    else if lower.ends_with(".automaticdestinations-ms") {
        manifest.jump_lists_auto.push(path.clone());
    } else if lower.ends_with(".customdestinations-ms") {
        manifest.jump_lists_custom.push(path.clone());
    }
    // Registry hives
    else if lower.ends_with("amcache.hve") {
        manifest.amcache.push(path.clone());
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::Amcache,
        });
    } else if lower.ends_with(r"\system") && lower.contains("config") {
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::System,
        });
    } else if lower.ends_with(r"\software") && lower.contains("config") {
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::Software,
        });
    } else if lower.ends_with(r"\sam") && lower.contains("config") {
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::Sam,
        });
    } else if lower.ends_with(r"\security") && lower.contains("config") {
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::Security,
        });
    } else if lower.ends_with("ntuser.dat") {
        let username = extract_username_from_path(win);
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::NtUser { username },
        });
    } else if lower.ends_with("usrclass.dat") {
        let username = extract_username_from_path(win);
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::UsrClass { username },
        });
    }
    // Recycle Bin
    else if lower.contains("$recycle.bin") && lower.contains("$i") {
        manifest.recycle_bin.push(path.clone());
    }
    // Scheduled Tasks
    else if lower.contains(r"system32\tasks\") && !lower.ends_with(r"\tasks\") {
        manifest.scheduled_tasks.push(path.clone());
    }
}

fn extract_username_from_path(win_path: &str) -> String {
    // Extract username from paths like C:\Users\<username>\NTUSER.DAT
    let parts: Vec<&str> = win_path.split('\\').collect();
    for (i, part) in parts.iter().enumerate() {
        if part.eq_ignore_ascii_case("Users") && i + 1 < parts.len() {
            return parts[i + 1].to_string();
        }
    }
    "unknown".to_string()
}

fn extract_metadata_from_filename(path: &Path) -> CollectionMetadata {
    let filename = path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    // Pattern: Collection-<hostname>-<timestamp>
    let (hostname, timestamp) = if let Some(rest) = filename.strip_prefix("Collection-") {
        // Find the timestamp part (starts with a year like 2025-)
        if let Some(idx) = rest.find("-202") {
            let host = &rest[..idx];
            let ts = &rest[idx + 1..];
            (host.to_string(), ts.to_string())
        } else {
            (rest.to_string(), String::new())
        }
    } else {
        (filename.to_string(), String::new())
    };

    CollectionMetadata {
        hostname,
        collection_timestamp: timestamp,
        source_tool: "Velociraptor".to_string(),
    }
}
```

Update `src/collection/mod.rs`:

```rust
pub mod path;
pub mod manifest;
pub mod provider;
pub mod velociraptor;
```

**Step 6: Run tests**

```bash
cargo test --test velociraptor_provider
```
Expected: All tests pass (or skip if test collection not present).

**Step 7: Commit**

```bash
git add src/collection/ tests/
git commit -m "feat: collection provider trait and Velociraptor zip reader with artifact discovery"
```

---

### Task 1.4: Timeline Model & MFT Parser Integration

**Files:**
- Create: `src/timeline/entry.rs`
- Create: `src/timeline/store.rs`
- Create: `src/parsers/mft_parser.rs`
- Modify: `src/timeline/mod.rs`
- Modify: `src/parsers/mod.rs`
- Create: `tests/mft_timeline.rs`

**Step 1: Write failing test**

```rust
// tests/mft_timeline.rs
use std::path::Path;
use tl::collection::velociraptor::VelociraptorProvider;
use tl::collection::provider::CollectionProvider;
use tl::parsers::mft_parser::parse_mft;
use tl::timeline::store::TimelineStore;

#[test]
fn test_parse_mft_from_collection() {
    let zip_path = Path::new("test/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
    if !zip_path.exists() {
        eprintln!("Skipping: test collection not found");
        return;
    }
    let provider = VelociraptorProvider::open(zip_path).unwrap();
    let manifest = provider.discover();

    let mft_path = manifest.mft.as_ref().expect("No $MFT found");
    let mft_data = provider.open_file(mft_path).unwrap();

    let mut store = TimelineStore::new();
    parse_mft(&mft_data, &mut store).unwrap();

    // A real $MFT should have thousands of entries
    assert!(store.len() > 1000, "Expected >1000 entries, got {}", store.len());

    // Check that entries have timestamps
    let first = store.entries().next().unwrap();
    assert!(first.timestamps.si_created.is_some() || first.timestamps.fn_created.is_some());
}

#[test]
fn test_timestomping_detection() {
    use tl::timeline::entry::*;
    use chrono::{NaiveDateTime, Utc, TimeZone};

    // Create an entry where SI Created < FN Created (timestomped)
    let mut ts = TimestampSet::default();
    ts.si_created = Some(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap());
    ts.fn_created = Some(Utc.with_ymd_and_hms(2025, 8, 10, 11, 0, 0).unwrap());

    let anomalies = detect_anomalies(&ts);
    assert!(anomalies.contains(AnomalyFlags::TIMESTOMPED_SI_LT_FN));
}
```

**Step 2: Run tests to verify failure**

```bash
cargo test --test mft_timeline
```

**Step 3: Implement timeline entry types**

```rust
// src/timeline/entry.rs
use bitflags::bitflags;
use chrono::{DateTime, Utc};
use serde::Serialize;
use smallvec::SmallVec;
use std::fmt;

pub type WinTimestamp = DateTime<Utc>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntityId {
    MftEntry(u64),
    Generated(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum EventType {
    FileCreate,
    FileModify,
    FileAccess,
    FileDelete,
    FileRename,
    MftEntryModify,
    Execute,
    RegistryModify,
    ServiceInstall,
    ScheduledTaskCreate,
    UserLogon,
    UserLogoff,
    ProcessCreate,
    NetworkConnection,
    BitsTransfer,
    RdpSession,
    Other(String),
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventType::FileCreate => write!(f, "CREATE"),
            EventType::FileModify => write!(f, "MOD"),
            EventType::FileAccess => write!(f, "ACC"),
            EventType::FileDelete => write!(f, "DEL"),
            EventType::FileRename => write!(f, "REN"),
            EventType::MftEntryModify => write!(f, "MFT"),
            EventType::Execute => write!(f, "EXEC"),
            EventType::RegistryModify => write!(f, "REG"),
            EventType::ServiceInstall => write!(f, "SVC"),
            EventType::ScheduledTaskCreate => write!(f, "TASK"),
            EventType::UserLogon => write!(f, "LOGON"),
            EventType::UserLogoff => write!(f, "LOGOFF"),
            EventType::ProcessCreate => write!(f, "PROC"),
            EventType::NetworkConnection => write!(f, "NET"),
            EventType::BitsTransfer => write!(f, "BITS"),
            EventType::RdpSession => write!(f, "RDP"),
            EventType::Other(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ArtifactSource {
    Mft,
    UsnJrnl,
    LogFile,
    Prefetch,
    Amcache,
    Shimcache,
    BamDam,
    UserAssist,
    Evtx(String), // channel name
    Lnk,
    JumpList,
    Shellbags,
    Registry(String), // hive name
    RecycleBin,
    ScheduledTask,
}

impl fmt::Display for ArtifactSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArtifactSource::Mft => write!(f, "MFT"),
            ArtifactSource::UsnJrnl => write!(f, "USN"),
            ArtifactSource::LogFile => write!(f, "LOG"),
            ArtifactSource::Prefetch => write!(f, "PF"),
            ArtifactSource::Amcache => write!(f, "AM"),
            ArtifactSource::Shimcache => write!(f, "SHIM"),
            ArtifactSource::BamDam => write!(f, "BAM"),
            ArtifactSource::UserAssist => write!(f, "UA"),
            ArtifactSource::Evtx(ch) => write!(f, "EVT"),
            ArtifactSource::Lnk => write!(f, "LNK"),
            ArtifactSource::JumpList => write!(f, "JL"),
            ArtifactSource::Shellbags => write!(f, "SB"),
            ArtifactSource::Registry(h) => write!(f, "REG"),
            ArtifactSource::RecycleBin => write!(f, "RB"),
            ArtifactSource::ScheduledTask => write!(f, "TSK"),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    pub struct AnomalyFlags: u32 {
        const TIMESTOMPED_SI_LT_FN     = 0b0000_0001;
        const TIMESTOMPED_ZERO_NANOS   = 0b0000_0010;
        const METADATA_BACKDATED       = 0b0000_0100;
        const NO_USN_CREATE            = 0b0000_1000;
        const LOG_GAP_DETECTED         = 0b0001_0000;
        const LOG_CLEARED              = 0b0010_0000;
        const EXECUTION_NO_PREFETCH    = 0b0100_0000;
        const HIDDEN_ADS               = 0b1000_0000;
    }
}

#[derive(Debug, Clone, Default)]
pub struct TimestampSet {
    pub si_created: Option<WinTimestamp>,
    pub si_modified: Option<WinTimestamp>,
    pub si_accessed: Option<WinTimestamp>,
    pub si_entry_modified: Option<WinTimestamp>,
    pub fn_created: Option<WinTimestamp>,
    pub fn_modified: Option<WinTimestamp>,
    pub fn_accessed: Option<WinTimestamp>,
    pub fn_entry_modified: Option<WinTimestamp>,
    pub usn_timestamp: Option<WinTimestamp>,
    pub lnk_target_created: Option<WinTimestamp>,
    pub lnk_target_modified: Option<WinTimestamp>,
    pub lnk_target_accessed: Option<WinTimestamp>,
    pub jumplist_timestamp: Option<WinTimestamp>,
    pub prefetch_last_run: Option<Vec<WinTimestamp>>,
    pub amcache_timestamp: Option<WinTimestamp>,
    pub shimcache_timestamp: Option<WinTimestamp>,
    pub evtx_timestamp: Option<WinTimestamp>,
}

#[derive(Debug, Clone, Default)]
pub struct EntryMetadata {
    pub file_size: Option<u64>,
    pub mft_entry_number: Option<u64>,
    pub mft_sequence: Option<u16>,
    pub is_directory: bool,
    pub has_ads: bool,
    pub parent_path: Option<String>,
    pub sha256: Option<String>,
    pub sha1: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TimelineEntry {
    pub entity_id: EntityId,
    pub path: String,
    pub primary_timestamp: WinTimestamp,
    pub event_type: EventType,
    pub timestamps: TimestampSet,
    pub sources: SmallVec<[ArtifactSource; 4]>,
    pub anomalies: AnomalyFlags,
    pub metadata: EntryMetadata,
}

/// Detect anomalies in a timestamp set.
pub fn detect_anomalies(ts: &TimestampSet) -> AnomalyFlags {
    let mut flags = AnomalyFlags::empty();

    // Timestomping: SI Created before FN Created
    if let (Some(si), Some(fn_c)) = (ts.si_created, ts.fn_created) {
        if si < fn_c {
            flags |= AnomalyFlags::TIMESTOMPED_SI_LT_FN;
        }
    }

    // Timestomping: zero nanoseconds in SI timestamps (tool artifact)
    if let Some(si) = ts.si_created {
        if si.timestamp_subsec_nanos() == 0 {
            // Only flag if FN has non-zero nanos
            if let Some(fn_c) = ts.fn_created {
                if fn_c.timestamp_subsec_nanos() != 0 {
                    flags |= AnomalyFlags::TIMESTOMPED_ZERO_NANOS;
                }
            }
        }
    }

    flags
}
```

**Step 4: Implement timeline store**

```rust
// src/timeline/store.rs
use crate::timeline::entry::*;
use std::collections::BTreeMap;

pub struct TimelineStore {
    /// Primary index: ordered by timestamp
    entries: Vec<TimelineEntry>,
    sorted: bool,
}

impl TimelineStore {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            sorted: false,
        }
    }

    pub fn push(&mut self, entry: TimelineEntry) {
        self.entries.push(entry);
        self.sorted = false;
    }

    pub fn sort(&mut self) {
        if !self.sorted {
            self.entries.sort_by(|a, b| a.primary_timestamp.cmp(&b.primary_timestamp));
            self.sorted = true;
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = &TimelineEntry> {
        self.entries.iter()
    }

    pub fn entries_mut(&mut self) -> &mut Vec<TimelineEntry> {
        self.sorted = false;
        &mut self.entries
    }

    pub fn get(&self, index: usize) -> Option<&TimelineEntry> {
        self.entries.get(index)
    }
}
```

Update `src/timeline/mod.rs`:

```rust
pub mod entry;
pub mod store;
```

**Step 5: Implement MFT parser**

```rust
// src/parsers/mft_parser.rs
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;
use anyhow::{Context, Result};
use mft::MftParser;
use mft::attribute::MftAttributeContent;
use chrono::{DateTime, Utc};
use std::io::Cursor;
use smallvec::smallvec;

pub fn parse_mft(data: &[u8], store: &mut TimelineStore) -> Result<()> {
    let mut parser = MftParser::from_buffer(data.to_vec())
        .context("Failed to parse $MFT")?;

    for entry_result in parser.iter_entries() {
        let entry = match entry_result {
            Ok(e) => e,
            Err(_) => continue, // Skip corrupt entries
        };

        let entry_id = entry.header.record_number;
        let is_dir = entry.is_dir();

        // Get full path
        let path = parser.get_full_path_for_entry(&entry)
            .unwrap_or_default()
            .unwrap_or_else(|| format!("[MFT Entry {}]", entry_id));

        let mut timestamps = TimestampSet::default();
        let mut has_ads = false;

        // Extract SI and FN timestamps from attributes
        for attr in entry.iter_attributes().filter_map(|a| a.ok()) {
            match attr.data {
                MftAttributeContent::AttrX10(ref si) => {
                    timestamps.si_created = Some(to_utc(si.created));
                    timestamps.si_modified = Some(to_utc(si.modified));
                    timestamps.si_accessed = Some(to_utc(si.accessed));
                    timestamps.si_entry_modified = Some(to_utc(si.mft_modified));
                }
                MftAttributeContent::AttrX30(ref fn_attr) => {
                    // Only use the first FN attribute (Win32 or Win32+DOS)
                    if timestamps.fn_created.is_none() {
                        timestamps.fn_created = Some(to_utc(fn_attr.created));
                        timestamps.fn_modified = Some(to_utc(fn_attr.modified));
                        timestamps.fn_accessed = Some(to_utc(fn_attr.accessed));
                        timestamps.fn_entry_modified = Some(to_utc(fn_attr.mft_modified));
                    }
                }
                _ => {}
            }

            // Check for ADS
            if attr.header.type_code.0 == 128 && attr.header.name.len() > 0 {
                has_ads = true;
            }
        }

        // Use SI Modified as primary timestamp (most forensically relevant)
        let primary_ts = timestamps.si_modified
            .or(timestamps.si_created)
            .or(timestamps.fn_modified)
            .unwrap_or_else(|| Utc::now());

        let anomalies = detect_anomalies(&timestamps);

        let timeline_entry = TimelineEntry {
            entity_id: EntityId::MftEntry(entry_id),
            path: path.clone(),
            primary_timestamp: primary_ts,
            event_type: if is_dir { EventType::Other("DIR".to_string()) } else { EventType::FileModify },
            timestamps,
            sources: smallvec![ArtifactSource::Mft],
            anomalies,
            metadata: EntryMetadata {
                file_size: Some(entry.header.used_entry_size as u64),
                mft_entry_number: Some(entry_id),
                mft_sequence: Some(entry.header.sequence),
                is_directory: is_dir,
                has_ads,
                parent_path: None,
                ..Default::default()
            },
        };

        store.push(timeline_entry);
    }

    store.sort();
    Ok(())
}

fn to_utc(dt: mft::DateTimeError) -> DateTime<Utc> {
    // The mft crate returns DateTime<Utc> directly in newer versions
    // Adapt based on actual crate API
    dt
}
```

Update `src/parsers/mod.rs`:

```rust
pub mod mft_parser;
```

**Step 6: Run tests**

```bash
cargo test --test mft_timeline
```

Note: The `mft` crate API may need adjustments. Check `cargo doc --open` for actual types. The `to_utc` function signature needs to match the crate's actual timestamp type. Adjust accordingly during implementation.

**Step 7: Commit**

```bash
git add src/timeline/ src/parsers/ tests/
git commit -m "feat: timeline model with MFT parser integration and timestomping detection"
```

---

### Task 1.5: TUI — Basic Timeline View

**Files:**
- Create: `src/tui/app.rs`
- Create: `src/tui/timeline_view.rs`
- Create: `src/tui/keybindings.rs`
- Modify: `src/tui/mod.rs`
- Modify: `src/main.rs`

**Step 1: Implement TUI app state**

```rust
// src/tui/app.rs
use crate::timeline::store::TimelineStore;
use crate::timeline::entry::*;

pub enum AppMode {
    Normal,
    Search,
    Filter,
    Command,
}

pub struct App {
    pub store: TimelineStore,
    pub mode: AppMode,
    pub selected_index: usize,
    pub scroll_offset: usize,
    pub detail_expanded: bool,
    pub search_query: String,
    pub search_results: Vec<usize>,
    pub search_cursor: usize,
    pub status_message: String,
    pub should_quit: bool,
    pub visible_rows: usize,
    pub hostname: String,
    pub collection_date: String,
}

impl App {
    pub fn new(store: TimelineStore, hostname: String, collection_date: String) -> Self {
        Self {
            store,
            mode: AppMode::Normal,
            selected_index: 0,
            scroll_offset: 0,
            detail_expanded: false,
            search_query: String::new(),
            search_results: Vec::new(),
            search_cursor: 0,
            status_message: String::new(),
            should_quit: false,
            visible_rows: 20,
            hostname,
            collection_date,
        }
    }

    pub fn move_down(&mut self, n: usize) {
        let max = self.store.len().saturating_sub(1);
        self.selected_index = (self.selected_index + n).min(max);
        self.ensure_visible();
    }

    pub fn move_up(&mut self, n: usize) {
        self.selected_index = self.selected_index.saturating_sub(n);
        self.ensure_visible();
    }

    pub fn goto_top(&mut self) {
        self.selected_index = 0;
        self.scroll_offset = 0;
    }

    pub fn goto_bottom(&mut self) {
        self.selected_index = self.store.len().saturating_sub(1);
        self.ensure_visible();
    }

    pub fn page_down(&mut self) {
        self.move_down(self.visible_rows / 2);
    }

    pub fn page_up(&mut self) {
        self.move_up(self.visible_rows / 2);
    }

    pub fn toggle_detail(&mut self) {
        self.detail_expanded = !self.detail_expanded;
    }

    fn ensure_visible(&mut self) {
        if self.selected_index < self.scroll_offset {
            self.scroll_offset = self.selected_index;
        }
        if self.selected_index >= self.scroll_offset + self.visible_rows {
            self.scroll_offset = self.selected_index - self.visible_rows + 1;
        }
    }

    pub fn selected_entry(&self) -> Option<&TimelineEntry> {
        self.store.get(self.selected_index)
    }
}
```

**Step 2: Implement timeline rendering**

This is the core TUI view — a ratatui Table widget showing the timeline. Implementation follows standard ratatui patterns with `Table`, `Row`, `Cell`, `Block`, and `Paragraph` widgets.

```rust
// src/tui/timeline_view.rs
use crate::tui::app::App;
use crate::timeline::entry::*;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};

pub fn render(f: &mut Frame, app: &App) {
    let chunks = if app.detail_expanded {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),   // header
                Constraint::Min(10),     // timeline table
                Constraint::Length(10),  // detail pane
                Constraint::Length(1),   // status bar
            ])
            .split(f.area())
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),   // header
                Constraint::Min(10),     // timeline table
                Constraint::Length(1),   // status bar
            ])
            .split(f.area())
    };

    render_header(f, app, chunks[0]);
    render_table(f, app, chunks[1]);

    if app.detail_expanded {
        render_detail(f, app, chunks[2]);
        render_status(f, app, chunks[3]);
    } else {
        render_status(f, app, chunks[chunks.len() - 1]);
    }
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(" tl ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" {} ", app.hostname)),
            Span::styled(format!(" {} ", app.collection_date), Style::default().fg(Color::DarkGray)),
            Span::raw(format!(" {} entries", app.store.len())),
        ]),
    ])
    .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(header, area);
}

fn render_table(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Timestamp"),
        Cell::from("Event"),
        Cell::from("Path"),
        Cell::from("Sources"),
        Cell::from("Anomaly"),
    ])
    .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    .height(1);

    let visible_height = area.height.saturating_sub(3) as usize;

    let rows: Vec<Row> = app.store.entries()
        .skip(app.scroll_offset)
        .take(visible_height)
        .enumerate()
        .map(|(i, entry)| {
            let actual_idx = app.scroll_offset + i;
            let is_selected = actual_idx == app.selected_index;

            let ts = entry.primary_timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
            let event = entry.event_type.to_string();
            let path = truncate_path(&entry.path, area.width as usize - 45);
            let sources: String = entry.sources.iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            let anomaly = if entry.anomalies.is_empty() {
                String::new()
            } else {
                format_anomalies(entry.anomalies)
            };

            let style = if is_selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else if entry.anomalies.contains(AnomalyFlags::TIMESTOMPED_SI_LT_FN) {
                Style::default().fg(Color::Red)
            } else {
                match entry.event_type {
                    EventType::Execute => Style::default().fg(Color::Yellow),
                    EventType::FileCreate => Style::default().fg(Color::Green),
                    EventType::FileDelete => Style::default().fg(Color::Red),
                    EventType::FileRename => Style::default().fg(Color::Cyan),
                    _ => Style::default(),
                }
            };

            Row::new(vec![
                Cell::from(ts),
                Cell::from(event),
                Cell::from(path),
                Cell::from(sources),
                Cell::from(anomaly),
            ]).style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(19),   // timestamp
            Constraint::Length(6),    // event
            Constraint::Min(30),     // path
            Constraint::Length(12),   // sources
            Constraint::Length(10),   // anomaly
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Timeline "));

    f.render_widget(table, area);
}

fn render_detail(f: &mut Frame, app: &App, area: Rect) {
    let content = if let Some(entry) = app.selected_entry() {
        let mut lines = vec![
            Line::from(vec![
                Span::styled("Entity: ", Style::default().fg(Color::Blue)),
                Span::raw(&entry.path),
            ]),
        ];

        // MFT info
        if let Some(mft_num) = entry.metadata.mft_entry_number {
            lines.push(Line::from(format!(
                "MFT Entry: {} | Size: {} | Dir: {}",
                mft_num,
                entry.metadata.file_size.unwrap_or(0),
                entry.metadata.is_directory,
            )));
        }

        // SI vs FN timestamps
        let si_line = format!(
            "SI: C={} M={} A={} E={}",
            fmt_ts(entry.timestamps.si_created),
            fmt_ts(entry.timestamps.si_modified),
            fmt_ts(entry.timestamps.si_accessed),
            fmt_ts(entry.timestamps.si_entry_modified),
        );
        let fn_line = format!(
            "FN: C={} M={} A={} E={}",
            fmt_ts(entry.timestamps.fn_created),
            fmt_ts(entry.timestamps.fn_modified),
            fmt_ts(entry.timestamps.fn_accessed),
            fmt_ts(entry.timestamps.fn_entry_modified),
        );
        lines.push(Line::from(si_line));
        lines.push(Line::from(fn_line));

        if !entry.anomalies.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("ANOMALIES: {}", format_anomalies(entry.anomalies)),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
        }

        lines
    } else {
        vec![Line::from("No entry selected")]
    };

    let detail = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL).title(" Detail "));
    f.render_widget(detail, area);
}

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    let status = match app.mode {
        crate::tui::app::AppMode::Search => {
            Line::from(vec![
                Span::styled("/", Style::default().fg(Color::Yellow)),
                Span::raw(&app.search_query),
            ])
        }
        _ => {
            Line::from(vec![
                Span::raw(format!(
                    " {}/{} ",
                    app.selected_index + 1,
                    app.store.len()
                )),
                Span::styled(
                    " j/k:move  /:search  Enter:detail  x:export  q:quit  ?:help ",
                    Style::default().fg(Color::DarkGray),
                ),
            ])
        }
    };
    f.render_widget(Paragraph::new(status), area);
}

fn truncate_path(path: &str, max_width: usize) -> String {
    if path.len() <= max_width {
        path.to_string()
    } else {
        format!("...{}", &path[path.len() - max_width + 3..])
    }
}

fn fmt_ts(ts: Option<chrono::DateTime<chrono::Utc>>) -> String {
    match ts {
        Some(t) => t.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "-".to_string(),
    }
}

fn format_anomalies(flags: AnomalyFlags) -> String {
    let mut parts = Vec::new();
    if flags.contains(AnomalyFlags::TIMESTOMPED_SI_LT_FN) { parts.push("STOMP"); }
    if flags.contains(AnomalyFlags::TIMESTOMPED_ZERO_NANOS) { parts.push("0NANO"); }
    if flags.contains(AnomalyFlags::HIDDEN_ADS) { parts.push("ADS"); }
    if flags.contains(AnomalyFlags::LOG_CLEARED) { parts.push("CLEAR"); }
    parts.join(" ")
}
```

**Step 3: Implement key bindings**

```rust
// src/tui/keybindings.rs
use crate::tui::app::{App, AppMode};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub fn handle_key(app: &mut App, key: KeyEvent) {
    match app.mode {
        AppMode::Normal => handle_normal_mode(app, key),
        AppMode::Search => handle_search_mode(app, key),
        _ => {}
    }
}

fn handle_normal_mode(app: &mut App, key: KeyEvent) {
    match (key.modifiers, key.code) {
        // Quit
        (_, KeyCode::Char('q')) => app.should_quit = true,

        // Movement
        (_, KeyCode::Char('j')) | (_, KeyCode::Down) => app.move_down(1),
        (_, KeyCode::Char('k')) | (_, KeyCode::Up) => app.move_up(1),
        (_, KeyCode::Char('J')) => app.move_down(10),
        (_, KeyCode::Char('K')) => app.move_up(10),
        (KeyModifiers::CONTROL, KeyCode::Char('d')) => app.page_down(),
        (KeyModifiers::CONTROL, KeyCode::Char('u')) => app.page_up(),
        (KeyModifiers::CONTROL, KeyCode::Char('f')) => {
            let n = app.visible_rows;
            app.move_down(n);
        }
        (KeyModifiers::CONTROL, KeyCode::Char('b')) => {
            let n = app.visible_rows;
            app.move_up(n);
        }
        (_, KeyCode::Char('G')) => app.goto_bottom(),
        (_, KeyCode::Char('g')) => {
            // gg = go to top (simplified: single g goes to top)
            app.goto_top();
        }

        // Detail pane
        (_, KeyCode::Enter) => app.toggle_detail(),

        // Search
        (_, KeyCode::Char('/')) => {
            app.mode = AppMode::Search;
            app.search_query.clear();
        }

        // Export (placeholder)
        (_, KeyCode::Char('x')) => {
            app.status_message = "Export: not yet implemented".to_string();
        }

        _ => {}
    }
}

fn handle_search_mode(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter => {
            // Execute search
            perform_search(app);
            app.mode = AppMode::Normal;
        }
        KeyCode::Esc => {
            app.mode = AppMode::Normal;
            app.search_query.clear();
        }
        KeyCode::Backspace => {
            app.search_query.pop();
        }
        KeyCode::Char(c) => {
            app.search_query.push(c);
        }
        _ => {}
    }
}

fn perform_search(app: &mut App) {
    let query = app.search_query.to_lowercase();
    app.search_results.clear();

    for (i, entry) in app.store.entries().enumerate() {
        if entry.path.to_lowercase().contains(&query) {
            app.search_results.push(i);
        }
    }

    if let Some(&first) = app.search_results.first() {
        app.selected_index = first;
        app.search_cursor = 0;
        app.status_message = format!("{} matches", app.search_results.len());
    } else {
        app.status_message = "No matches".to_string();
    }
}
```

Update `src/tui/mod.rs`:

```rust
pub mod app;
pub mod timeline_view;
pub mod keybindings;
```

**Step 4: Wire everything into main.rs**

```rust
// src/main.rs
use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use std::io;

use tl::collection::provider::CollectionProvider;
use tl::collection::velociraptor::VelociraptorProvider;
use tl::parsers::mft_parser;
use tl::timeline::store::TimelineStore;
use tl::tui::app::App;

#[derive(Parser)]
#[command(name = "tl", about = "Rapid forensic triage timeline")]
struct Cli {
    /// Path to collection (zip file or directory)
    collection: std::path::PathBuf,

    /// Export timeline to CSV instead of opening TUI
    #[arg(long)]
    export_csv: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    eprintln!("Opening collection: {}", cli.collection.display());

    // Open collection
    let provider = VelociraptorProvider::open(&cli.collection)
        .context("Failed to open collection")?;

    let meta = provider.metadata();
    eprintln!("Host: {} | Date: {}", meta.hostname, meta.collection_timestamp);

    let manifest = provider.discover();
    eprintln!("Artifacts found:");
    eprintln!("  $MFT: {}", manifest.has_mft());
    eprintln!("  $UsnJrnl: {}", manifest.has_usnjrnl());
    eprintln!("  Registry hives: {}", manifest.registry_hives().len());
    eprintln!("  Event logs: {}", manifest.event_logs().len());
    eprintln!("  Prefetch: {}", manifest.prefetch_files().len());
    eprintln!("  LNK files: {}", manifest.lnk_files().len());

    // Parse $MFT
    let mut store = TimelineStore::new();
    if let Some(mft_path) = &manifest.mft {
        eprintln!("Parsing $MFT...");
        let mft_data = provider.open_file(mft_path)?;
        eprintln!("  $MFT size: {} bytes", mft_data.len());
        mft_parser::parse_mft(&mft_data, &mut store)?;
        eprintln!("  {} timeline entries from $MFT", store.len());
    }

    if let Some(csv_path) = cli.export_csv {
        eprintln!("Exporting to CSV: {}", csv_path.display());
        // TODO: implement CSV export
        return Ok(());
    }

    // Launch TUI
    run_tui(store, meta.hostname, meta.collection_timestamp)
}

fn run_tui(store: TimelineStore, hostname: String, date: String) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(store, hostname, date);

    loop {
        terminal.draw(|f| {
            app.visible_rows = f.area().height.saturating_sub(6) as usize;
            tl::tui::timeline_view::render(f, &app);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                tl::tui::keybindings::handle_key(&mut app, key);
            }
        }

        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
```

**Step 5: Build and test manually**

```bash
cargo build --release
./target/release/tl test/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip
```

Expected: TUI opens showing $MFT timeline entries. j/k to navigate. Enter for detail. q to quit.

**Step 6: Commit**

```bash
git add src/ tests/
git commit -m "feat: TUI timeline view with vi keybindings and MFT parsing"
```

---

### Task 1.6: CSV Export (Bodyfile Format)

**Files:**
- Create: `src/export/csv_export.rs`
- Modify: `src/export/mod.rs`
- Modify: `src/main.rs`
- Create: `tests/csv_export.rs`

**Step 1: Write failing test**

```rust
// tests/csv_export.rs
use tl::timeline::entry::*;
use tl::timeline::store::TimelineStore;
use tl::export::csv_export::export_csv;
use chrono::Utc;
use smallvec::smallvec;
use std::io::Cursor;

#[test]
fn test_csv_export() {
    let mut store = TimelineStore::new();
    let ts = Utc::now();
    store.push(TimelineEntry {
        entity_id: EntityId::MftEntry(42),
        path: r"C:\test\file.exe".to_string(),
        primary_timestamp: ts,
        event_type: EventType::FileCreate,
        timestamps: TimestampSet::default(),
        sources: smallvec![ArtifactSource::Mft],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata::default(),
    });

    let mut buf = Vec::new();
    export_csv(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    assert!(output.contains("file.exe"));
    assert!(output.contains("CREATE"));
    assert!(output.contains("MFT"));
}
```

**Step 2: Run test to verify failure**

```bash
cargo test --test csv_export
```

**Step 3: Implement CSV export**

```rust
// src/export/csv_export.rs
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;
use anyhow::Result;
use std::io::Write;

pub fn export_csv<W: Write>(store: &TimelineStore, writer: &mut W) -> Result<()> {
    let mut wtr = csv::Writer::from_writer(writer);

    wtr.write_record(&[
        "Timestamp",
        "Event",
        "Path",
        "Sources",
        "Anomalies",
        "SI_Created",
        "SI_Modified",
        "SI_Accessed",
        "SI_EntryMod",
        "FN_Created",
        "FN_Modified",
        "FN_Accessed",
        "FN_EntryMod",
        "MFT_Entry",
        "FileSize",
        "IsDir",
    ])?;

    for entry in store.entries() {
        let sources: String = entry.sources.iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join("|");

        let anomalies: String = format!("{:?}", entry.anomalies);

        wtr.write_record(&[
            entry.primary_timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            entry.event_type.to_string(),
            entry.path.clone(),
            sources,
            anomalies,
            fmt_ts_opt(entry.timestamps.si_created),
            fmt_ts_opt(entry.timestamps.si_modified),
            fmt_ts_opt(entry.timestamps.si_accessed),
            fmt_ts_opt(entry.timestamps.si_entry_modified),
            fmt_ts_opt(entry.timestamps.fn_created),
            fmt_ts_opt(entry.timestamps.fn_modified),
            fmt_ts_opt(entry.timestamps.fn_accessed),
            fmt_ts_opt(entry.timestamps.fn_entry_modified),
            entry.metadata.mft_entry_number.map(|n| n.to_string()).unwrap_or_default(),
            entry.metadata.file_size.map(|n| n.to_string()).unwrap_or_default(),
            entry.metadata.is_directory.to_string(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

fn fmt_ts_opt(ts: Option<chrono::DateTime<chrono::Utc>>) -> String {
    ts.map(|t| t.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
        .unwrap_or_default()
}
```

Update `src/export/mod.rs`:

```rust
pub mod csv_export;
```

Wire into main.rs's CSV export path:

```rust
// In main.rs, replace the TODO
if let Some(csv_path) = cli.export_csv {
    let file = std::fs::File::create(&csv_path)?;
    let mut writer = std::io::BufWriter::new(file);
    tl::export::csv_export::export_csv(&store, &mut writer)?;
    eprintln!("Exported {} entries to {}", store.len(), csv_path.display());
    return Ok(());
}
```

**Step 4: Run test**

```bash
cargo test --test csv_export
```

**Step 5: Manual integration test**

```bash
cargo run --release -- test/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip --export-csv /tmp/tl-test.csv
head -5 /tmp/tl-test.csv
wc -l /tmp/tl-test.csv
```

**Step 6: Commit**

```bash
git add src/export/ tests/ src/main.rs
git commit -m "feat: CSV export with all timestamp columns"
```

---

## Phase 2: USN Journal + File Operations

### Task 2.1: Custom $UsnJrnl:$J Parser

**Files:**
- Create: `src/parsers/usn_parser.rs`
- Create: `tests/usn_parser.rs`
- Modify: `src/parsers/mod.rs`

This task implements a custom offline parser for USN_RECORD_V2 and V3 structures. The binary format is:

```
USN_RECORD_V2:
  Offset 0x00: RecordLength (u32)
  Offset 0x04: MajorVersion (u16) = 2
  Offset 0x06: MinorVersion (u16) = 0
  Offset 0x08: FileReferenceNumber (u64) - lower 48 bits = MFT entry, upper 16 = sequence
  Offset 0x10: ParentFileReferenceNumber (u64)
  Offset 0x18: Usn (i64) - offset in journal
  Offset 0x20: TimeStamp (i64) - Windows FILETIME
  Offset 0x28: Reason (u32) - reason flags
  Offset 0x2C: SourceInfo (u32)
  Offset 0x30: SecurityId (u32)
  Offset 0x34: FileAttributes (u32)
  Offset 0x38: FileNameLength (u16)
  Offset 0x3A: FileNameOffset (u16)
  Offset 0x3C: FileName (variable, UTF-16LE)
```

Implementation: Parse sequentially, skip zero-filled regions (journal is sparse), extract MFT reference + timestamp + reason + filename for each record. Merge into timeline by MFT entry number.

---

### Task 2.2: Merge USN Events into Timeline

Entity resolution: match USN records to existing MFT entries by MFT reference number (lower 48 bits of FileReferenceNumber). Map USN reason codes to EventType:

| USN Reason | EventType |
|-----------|-----------|
| FILE_CREATE | FileCreate |
| DATA_OVERWRITE / DATA_EXTEND / DATA_TRUNCATION | FileModify |
| RENAME_OLD_NAME / RENAME_NEW_NAME | FileRename |
| FILE_DELETE | FileDelete |
| SECURITY_CHANGE | Other("SEC") |
| CLOSE | (skip, not independently useful) |

---

## Phase 3: Execution Evidence

### Task 3.1: Prefetch Parser Integration
Integrate `frnsc-prefetch` crate. For each .pf file: extract executable name, last 8 run timestamps, run count, referenced files/directories. Create timeline entries with EventType::Execute.

### Task 3.2: Amcache Parser Integration
Integrate `frnsc-amcache` crate. Parse Amcache.hve from the collection. Extract: SHA1, publisher, install date, file path. Create timeline entries, merge with MFT by path.

### Task 3.3: Shimcache Parser (Custom)
Use `notatin` to open SYSTEM hive. Navigate to `ControlSet001\Control\Session Manager\AppCompatCache\AppCompatCache`. Parse binary value — format varies by Windows version (detect via header magic). Extract ordered list of executables with optional timestamps.

### Task 3.4: BAM/DAM Parser (Custom)
Use `notatin` to read SYSTEM hive. Navigate to `ControlSet001\Services\bam\State\UserSettings\<SID>`. Each value name is an executable path, value data is a Windows FILETIME of last execution.

---

## Phase 4: User Activity Artifacts

### Task 4.1: LNK File Parser Integration
Integrate `lnk` crate. For each .lnk file in the collection: extract target path, target timestamps (created/modified/accessed), volume serial, NetBIOS name, MAC address. Create timeline entries, merge with MFT by target path.

### Task 4.2: Jump List Parser Integration
Integrate `jumplist_parser` crate. Parse AutomaticDestinations and CustomDestinations. Map AppIDs to application names. Extract target entries with timestamps. Merge with timeline.

### Task 4.3: UserAssist Parser (Custom)
Use `notatin` to open NTUSER.DAT. Navigate to `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`. Decode ROT13 value names to get program paths. Parse binary value data: run count (offset 4), focus time (offset 12), last run FILETIME (offset 60).

### Task 4.4: Shellbag Parser (Custom)
Use `notatin` to open UsrClass.dat. Navigate to `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` and `Bags`. Parse shell item ID lists to reconstruct folder paths with timestamps.

### Task 4.5: Recycle Bin $I Parser (Custom)
Simple binary format. Header: version (u64 at offset 0), file size (u64 at offset 8), deletion timestamp (FILETIME at offset 16), original path (UTF-16LE string at offset 24+). Create FileDelete timeline entries.

### Task 4.6: MRU List Parser (Custom)
Use `notatin` to read NTUSER.DAT. Parse `RecentDocs`, `OpenSavePidlMRU`, and `Office\<version>\<app>\File MRU` keys. Extract file paths and access order.

---

## Phase 5: Registry Deep Dive

### Task 5.1: Run/RunOnce Keys
Parse from NTUSER.DAT and SOFTWARE hives. Create persistence-type timeline entries.

### Task 5.2: Services Enumeration
Parse SYSTEM hive `Services` key. Extract service name, ImagePath, start type, description.

### Task 5.3: Network Profiles
Parse SOFTWARE hive `Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`. Extract network names, first/last connected timestamps, network type.

### Task 5.4: USB Device History
Parse SYSTEM hive `Enum\USB` and `Enum\USBSTOR`. Cross-reference with setupapi.dev.log for install timestamps. Extract device serial, vendor, product, first/last connection.

### Task 5.5: System Metadata
Parse SYSTEM hive for: timezone (TimeZoneInformation), ComputerName, last shutdown time (Windows\CurrentVersion\ShutdownTime). Use timezone to correctly display all timestamps.

---

## Phase 6: Event Logs

### Task 6.1: EVTX Parser Integration
Integrate `evtx` crate. Parallel parse all .evtx files. Extract timestamp, Event ID, channel, provider, event data XML. Map key Event IDs to EventTypes.

### Task 6.2: Priority Channel Extraction
Implement Event ID -> forensic meaning mapping for: Security (logon/logoff/process), System (services/shutdown), PowerShell (script blocks), TaskScheduler, TerminalServices, BITS, Defender.

### Task 6.3: Background Streaming
Implement async EVTX parsing that streams results into the timeline store while TUI is running. Show parsing progress indicator in the TUI status bar.

---

## Phase 7: Advanced Artifacts & Anti-Forensics

### Task 7.1: $LogFile Parser (Custom)
Parse NTFS transaction log. Reference: Brian Carrier's NTFS internals, jschicht's LogFileParser. Extract operation records with timestamps.

### Task 7.2: WMI Repository Parser
Parse OBJECTS.DATA for WMI event subscriptions (persistence mechanism). Extract consumer names, filter queries, consumer scripts/commands.

### Task 7.3: BITS Database Parser
Use `ese_parser` to open qmgr.db. Extract BITS job entries: URL, local path, state, creation/modification times.

### Task 7.4: Scheduled Tasks XML Parser
Parse XML task definitions from System32/Tasks/. Extract: task name, triggers, actions (command + arguments), last run time, next run time, author.

### Task 7.5: Full Anomaly Detection Engine
Aggregate anomaly checks across all artifact types. Add: log gap detection, log clearing detection (Event ID 1102), execution without Prefetch cross-reference.

---

## Phase 8: Universal Triage & Export

### Task 8.1: KAPE Provider
Implement `KapeProvider` for KAPE-format collections (C/ directory structure, different path layout).

### Task 8.2: Raw Directory Provider
Implement `RawProvider` for loose artifact directories (someone just copied files into a folder).

### Task 8.3: JSON/JSONL Export
Full structured export with all metadata, timestamps, and anomaly flags.

### Task 8.4: HTML Report Generator
Self-contained HTML file with embedded CSS/JS. Timeline visualization, anomaly highlights, executive summary section. No external dependencies.

---

## Phase 9: Polish & Performance

### Task 9.1: Memory-Mapped I/O
Use mmap for large artifacts ($MFT, event logs) to reduce memory pressure.

### Task 9.2: Virtualized Scrolling
Implement lazy rendering for 100K+ entry timelines. Only compute visible rows.

### Task 9.3: Session Save/Restore
Save current filters, position, marks to a session file. Restore on reopening same collection.

### Task 9.4: Headless Mode
`--headless` flag: parse all artifacts, export all formats, no TUI. For CI/automation.

### Task 9.5: Configuration
Config file (~/.config/tl/config.toml) for: key bindings, color scheme, default filters, default export format.

---

## Testing Strategy

### Unit Tests
- Path normalization (all encoding variants)
- Each parser (feed known-good binary data, verify parsed output)
- Anomaly detection (construct timestamp sets, verify flags)
- Entity resolution (merge logic)

### Integration Tests
- Open real Velociraptor collection zip, parse all artifacts, verify timeline
- CSV round-trip (export, re-import, compare)
- Full pipeline: collection -> parse -> timeline -> export

### Test Data
- Primary: `test/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip` (2.35 GB)
- Standalone: `test/evtx_files.zip`, `test/lnk_files.zip`, `test/jumplist_files.zip`, `test/pf_files.zip`
- Unit: Craft minimal binary blobs for parser unit tests

### Performance Benchmarks
- $MFT parse time for 1GB MFT (target: <15s)
- Full collection parse time (target: <30s)
- TUI scroll performance at 100K entries (target: 60fps)
