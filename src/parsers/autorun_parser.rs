use anyhow::{Context, Result};
use log::{debug, warn};
use nt_hive2::{Hive, HiveParseMode, SubPath};
use smallvec::smallvec;
use std::io::Cursor;

use crate::collection::manifest::{ArtifactManifest, RegistryHiveType};
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static AUTORUN_ID_COUNTER: AtomicU64 = AtomicU64::new(0x4152_0000_0000_0000); // "AR" prefix

fn next_autorun_id() -> u64 {
    AUTORUN_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Parsed autorun entry ────────────────────────────────────────────────────

/// A parsed autorun entry from Run/RunOnce registry keys.
#[derive(Debug, Clone)]
pub struct AutorunEntry {
    pub name: String,
    pub command: String,
    pub key_path: String,
    pub hive_source: String,
    pub last_write: chrono::DateTime<chrono::Utc>,
}

// ─── Run/RunOnce key paths ───────────────────────────────────────────────────

/// Run/RunOnce paths relative to SOFTWARE hive root.
const SOFTWARE_RUN_PATHS: &[&str] = &[
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
];

/// Run/RunOnce paths relative to NTUSER.DAT hive root.
const NTUSER_RUN_PATHS: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
];

// ─── Registry Parsing ────────────────────────────────────────────────────────

/// Parse autorun entries from a registry hive.
///
/// Enumerates the specified Run/RunOnce key paths and extracts each
/// value name (autorun name) and value data (command to execute).
pub fn parse_autoruns_from_hive(
    data: &[u8],
    hive_label: &str,
    key_paths: &[&str],
) -> Result<Vec<AutorunEntry>> {
    let mut entries = Vec::new();

    let mut hive = Hive::new(
        Cursor::new(data.to_vec()),
        HiveParseMode::NormalWithBaseBlock,
    )
    .context("Failed to parse registry hive")?
    .treat_hive_as_clean();

    let root_key = hive
        .root_key_node()
        .context("Failed to get root key from hive")?;

    for path in key_paths {
        let run_key = match root_key.subpath(*path, &mut hive) {
            Ok(Some(key)) => key,
            Ok(None) => {
                debug!("Run path not found: {} in {}", path, hive_label);
                continue;
            }
            Err(e) => {
                debug!("Error accessing run path {} in {}: {}", path, hive_label, e);
                continue;
            }
        };

        let key_ref = run_key.borrow();
        let last_write = *key_ref.timestamp();

        let values = key_ref.values();
        for value in values {
            let name = value.name().to_string();

            // Skip default values
            if name.is_empty() || name == "(Default)" {
                continue;
            }

            let command = match value.value() {
                nt_hive2::RegistryValue::RegSZ(s)
                | nt_hive2::RegistryValue::RegExpandSZ(s) => s.clone(),
                _ => continue,
            };

            if command.is_empty() {
                continue;
            }

            entries.push(AutorunEntry {
                name,
                command,
                key_path: path.to_string(),
                hive_source: hive_label.to_string(),
                last_write,
            });
        }
    }

    Ok(entries)
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse autorun entries from SOFTWARE and NTUSER.DAT hives.
pub fn parse_autoruns(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    let mut total = 0u32;

    // Parse SOFTWARE hive(s)
    for hive_entry in manifest
        .registry_hives
        .iter()
        .filter(|h| h.hive_type == RegistryHiveType::Software)
    {
        let data = match provider.open_file(&hive_entry.path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read SOFTWARE hive {}: {}", hive_entry.path, e);
                continue;
            }
        };

        let autoruns = match parse_autoruns_from_hive(&data, "SOFTWARE", SOFTWARE_RUN_PATHS) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to parse autoruns from SOFTWARE: {}", e);
                continue;
            }
        };

        for ar in &autoruns {
            push_autorun_entry(ar, store);
            total += 1;
        }
    }

    // Parse NTUSER.DAT hive(s)
    for hive_entry in &manifest.registry_hives {
        let username = match &hive_entry.hive_type {
            RegistryHiveType::NtUser { username } => username.clone(),
            _ => continue,
        };

        let data = match provider.open_file(&hive_entry.path) {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    "Failed to read NTUSER.DAT for {}: {}",
                    username, e
                );
                continue;
            }
        };

        let label = format!("NTUSER.DAT ({})", username);
        let autoruns = match parse_autoruns_from_hive(&data, &label, NTUSER_RUN_PATHS) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to parse autoruns from NTUSER.DAT ({}): {}", username, e);
                continue;
            }
        };

        for ar in &autoruns {
            push_autorun_entry(ar, store);
            total += 1;
        }
    }

    debug!("Parsed {} autorun entries", total);
    Ok(())
}

/// Create a timeline entry from an autorun and push it to the store.
fn push_autorun_entry(ar: &AutorunEntry, store: &mut TimelineStore) {
    let desc = format!(
        "[Autorun:{}] {} = {} ({})",
        ar.hive_source, ar.name, ar.command, ar.key_path,
    );

    let entry = TimelineEntry {
        entity_id: EntityId::Generated(next_autorun_id()),
        path: desc,
        primary_timestamp: ar.last_write,
        event_type: EventType::RegistryModify,
        timestamps: TimestampSet::default(),
        sources: smallvec![ArtifactSource::Registry(ar.hive_source.clone())],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata::default(),
    };

    store.push(entry);
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn test_autorun_entry_creation() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = AutorunEntry {
            name: "Backdoor".to_string(),
            command: r"C:\temp\evil.exe -persist".to_string(),
            key_path: r"Microsoft\Windows\CurrentVersion\Run".to_string(),
            hive_source: "NTUSER.DAT (admin)".to_string(),
            last_write: ts,
        };
        assert_eq!(entry.name, "Backdoor");
        assert!(entry.command.contains("evil.exe"));
    }

    #[test]
    fn test_autorun_timeline_entry() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let ar = AutorunEntry {
            name: "MalwareRun".to_string(),
            command: r"powershell.exe -ep bypass -f C:\temp\p.ps1".to_string(),
            key_path: r"Microsoft\Windows\CurrentVersion\Run".to_string(),
            hive_source: "SOFTWARE".to_string(),
            last_write: ts,
        };

        let desc = format!(
            "[Autorun:{}] {} = {} ({})",
            ar.hive_source, ar.name, ar.command, ar.key_path,
        );

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_autorun_id()),
            path: desc.clone(),
            primary_timestamp: ar.last_write,
            event_type: EventType::RegistryModify,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Registry(ar.hive_source.clone())],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        assert_eq!(entry.event_type, EventType::RegistryModify);
        assert!(entry.path.contains("MalwareRun"));
        assert!(entry.path.contains("powershell"));
    }

    #[test]
    fn test_parse_autoruns_from_hive_invalid_data() {
        let empty_data = vec![0u8; 0];
        let result = parse_autoruns_from_hive(&empty_data, "SOFTWARE", &[
            r"Microsoft\Windows\CurrentVersion\Run",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_manifest_no_error() {
        use crate::collection::manifest::ArtifactManifest;
        let manifest = ArtifactManifest::default();
        let mut store = TimelineStore::new();

        struct MockProvider;
        impl CollectionProvider for MockProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                anyhow::bail!("should not be called")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let provider = MockProvider;
        let result = parse_autoruns(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }
}
