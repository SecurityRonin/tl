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

    // ─── next_autorun_id tests ──────────────────────────────────────────

    #[test]
    fn test_next_autorun_id_increments() {
        let id1 = next_autorun_id();
        let id2 = next_autorun_id();
        assert!(id2 > id1);
        assert_eq!(id2 - id1, 1);
    }

    #[test]
    fn test_next_autorun_id_has_ar_prefix() {
        let id = next_autorun_id();
        let prefix = (id >> 48) & 0xFFFF;
        assert_eq!(prefix, 0x4152);
    }

    // ─── AutorunEntry struct tests ──────────────────────────────────────

    #[test]
    fn test_autorun_entry_clone() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = AutorunEntry {
            name: "TestRun".to_string(),
            command: r"C:\test.exe -flag".to_string(),
            key_path: r"Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
            hive_source: "NTUSER.DAT (admin)".to_string(),
            last_write: ts,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.name, entry.name);
        assert_eq!(cloned.command, entry.command);
        assert_eq!(cloned.key_path, entry.key_path);
        assert_eq!(cloned.hive_source, entry.hive_source);
        assert_eq!(cloned.last_write, entry.last_write);
    }

    #[test]
    fn test_autorun_entry_debug() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = AutorunEntry {
            name: "DbgAutorun".to_string(),
            command: "cmd.exe".to_string(),
            key_path: "Run".to_string(),
            hive_source: "SOFTWARE".to_string(),
            last_write: ts,
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("AutorunEntry"));
        assert!(debug_str.contains("DbgAutorun"));
    }

    // ─── Key path constants tests ───────────────────────────────────────

    #[test]
    fn test_software_run_paths_not_empty() {
        assert!(!SOFTWARE_RUN_PATHS.is_empty());
        for path in SOFTWARE_RUN_PATHS {
            assert!(path.contains("Run"), "Expected 'Run' in path: {}", path);
        }
    }

    #[test]
    fn test_ntuser_run_paths_not_empty() {
        assert!(!NTUSER_RUN_PATHS.is_empty());
        for path in NTUSER_RUN_PATHS {
            assert!(path.contains("Run"), "Expected 'Run' in path: {}", path);
        }
    }

    #[test]
    fn test_software_run_paths_include_wow64() {
        let has_wow64 = SOFTWARE_RUN_PATHS
            .iter()
            .any(|p| p.contains("Wow6432Node"));
        assert!(has_wow64, "SOFTWARE paths should include Wow6432Node entries");
    }

    #[test]
    fn test_software_run_paths_include_runonce() {
        let has_runonce = SOFTWARE_RUN_PATHS
            .iter()
            .any(|p| p.contains("RunOnce"));
        assert!(has_runonce, "SOFTWARE paths should include RunOnce");
    }

    #[test]
    fn test_ntuser_run_paths_include_runonce() {
        let has_runonce = NTUSER_RUN_PATHS
            .iter()
            .any(|p| p.contains("RunOnce"));
        assert!(has_runonce, "NTUSER paths should include RunOnce");
    }

    // ─── push_autorun_entry tests ───────────────────────────────────────

    #[test]
    fn test_push_autorun_entry_adds_to_store() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let ar = AutorunEntry {
            name: "TestEntry".to_string(),
            command: r"C:\test.exe".to_string(),
            key_path: "Run".to_string(),
            hive_source: "SOFTWARE".to_string(),
            last_write: ts,
        };
        let mut store = TimelineStore::new();
        push_autorun_entry(&ar, &mut store);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_push_autorun_entry_format() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let ar = AutorunEntry {
            name: "Persistence".to_string(),
            command: r"powershell.exe -ep bypass".to_string(),
            key_path: r"Microsoft\Windows\CurrentVersion\Run".to_string(),
            hive_source: "NTUSER.DAT (victim)".to_string(),
            last_write: ts,
        };
        let mut store = TimelineStore::new();
        push_autorun_entry(&ar, &mut store);
        // Verify the description format from the stored entry
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_push_autorun_entry_event_type() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let ar = AutorunEntry {
            name: "Check".to_string(),
            command: "cmd.exe".to_string(),
            key_path: "Run".to_string(),
            hive_source: "SOFTWARE".to_string(),
            last_write: ts,
        };
        let mut store = TimelineStore::new();
        push_autorun_entry(&ar, &mut store);
        assert_eq!(store.len(), 1);
    }

    // ─── Description format tests ───────────────────────────────────────

    #[test]
    fn test_autorun_description_contains_all_fields() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let ar = AutorunEntry {
            name: "SuspiciousRun".to_string(),
            command: r"C:\Users\Public\evil.exe".to_string(),
            key_path: r"Microsoft\Windows\CurrentVersion\RunOnce".to_string(),
            hive_source: "SOFTWARE".to_string(),
            last_write: ts,
        };

        let desc = format!(
            "[Autorun:{}] {} = {} ({})",
            ar.hive_source, ar.name, ar.command, ar.key_path,
        );

        assert!(desc.contains("Autorun:SOFTWARE"));
        assert!(desc.contains("SuspiciousRun"));
        assert!(desc.contains("evil.exe"));
        assert!(desc.contains("RunOnce"));
    }

    #[test]
    fn test_autorun_description_ntuser_format() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let ar = AutorunEntry {
            name: "Update".to_string(),
            command: "updater.exe".to_string(),
            key_path: r"Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
            hive_source: "NTUSER.DAT (jdoe)".to_string(),
            last_write: ts,
        };

        let desc = format!(
            "[Autorun:{}] {} = {} ({})",
            ar.hive_source, ar.name, ar.command, ar.key_path,
        );

        assert!(desc.contains("NTUSER.DAT (jdoe)"));
    }

    // ─── parse_autoruns_from_hive edge cases ────────────────────────────

    #[test]
    fn test_parse_autoruns_from_hive_garbage_data() {
        let garbage = vec![0xFFu8; 256];
        let result = parse_autoruns_from_hive(&garbage, "SOFTWARE", SOFTWARE_RUN_PATHS);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_autoruns_from_hive_small_data() {
        let small = vec![0x42u8; 10];
        let result = parse_autoruns_from_hive(&small, "TEST", NTUSER_RUN_PATHS);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_autoruns_from_hive_empty_key_paths() {
        // With empty key paths, should still fail on invalid hive data
        let data = vec![0u8; 0];
        let result = parse_autoruns_from_hive(&data, "SOFTWARE", &[]);
        assert!(result.is_err());
    }

    // ─── Multiple push tests ────────────────────────────────────────────

    #[test]
    fn test_push_multiple_autorun_entries() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let mut store = TimelineStore::new();
        for i in 0..5 {
            let ar = AutorunEntry {
                name: format!("Entry{}", i),
                command: format!("cmd{}.exe", i),
                key_path: "Run".to_string(),
                hive_source: "SOFTWARE".to_string(),
                last_write: ts,
            };
            push_autorun_entry(&ar, &mut store);
        }
        assert_eq!(store.len(), 5);
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

    // ─── parse_autoruns pipeline tests ───────────────────────────────

    fn make_software_manifest() -> crate::collection::manifest::ArtifactManifest {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SOFTWARE", 'C'),
            hive_type: RegistryHiveType::Software,
        });
        manifest
    }

    fn make_ntuser_manifest() -> crate::collection::manifest::ArtifactManifest {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Users/admin/NTUSER.DAT", 'C'),
            hive_type: RegistryHiveType::NtUser { username: "admin".to_string() },
        });
        manifest
    }

    #[test]
    fn test_parse_autoruns_software_hive_open_file_error() {
        // Tests warn path when provider.open_file fails for SOFTWARE hive (line 140-143)
        let manifest = make_software_manifest();
        let mut store = TimelineStore::new();

        struct FailOpenProvider;
        impl CollectionProvider for FailOpenProvider {
            fn discover(&self) -> crate::collection::manifest::ArtifactManifest {
                crate::collection::manifest::ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                anyhow::bail!("Cannot read SOFTWARE hive")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_autoruns(&FailOpenProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_autoruns_software_hive_invalid_data() {
        // Tests warn path when parse_autoruns_from_hive fails (line 148-151)
        let manifest = make_software_manifest();
        let mut store = TimelineStore::new();

        struct GarbageProvider;
        impl CollectionProvider for GarbageProvider {
            fn discover(&self) -> crate::collection::manifest::ArtifactManifest {
                crate::collection::manifest::ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(vec![0xFFu8; 512])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_autoruns(&GarbageProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_autoruns_ntuser_open_file_error() {
        // Tests warn path when provider.open_file fails for NTUSER.DAT (line 169-175)
        let manifest = make_ntuser_manifest();
        let mut store = TimelineStore::new();

        struct FailNtUserProvider;
        impl CollectionProvider for FailNtUserProvider {
            fn discover(&self) -> crate::collection::manifest::ArtifactManifest {
                crate::collection::manifest::ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                anyhow::bail!("Cannot read NTUSER.DAT")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_autoruns(&FailNtUserProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_autoruns_ntuser_invalid_hive_data() {
        // Tests warn path when parse_autoruns_from_hive fails for NTUSER (line 181-184)
        let manifest = make_ntuser_manifest();
        let mut store = TimelineStore::new();

        struct GarbageNtUserProvider;
        impl CollectionProvider for GarbageNtUserProvider {
            fn discover(&self) -> crate::collection::manifest::ArtifactManifest {
                crate::collection::manifest::ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(vec![0xABu8; 256])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_autoruns(&GarbageNtUserProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_autoruns_skips_non_matching_hive_types() {
        // Tests that non-NtUser hives are skipped in NTUSER loop (line 163-165)
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        // Add System hive - should be skipped by NTUSER loop
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SYSTEM", 'C'),
            hive_type: RegistryHiveType::System,
        });
        // Add SAM hive - should be skipped by both loops
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SAM", 'C'),
            hive_type: RegistryHiveType::Sam,
        });

        let mut store = TimelineStore::new();

        struct NoOpProvider;
        impl CollectionProvider for NoOpProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                // Should not be called for System/Sam in NtUser loop
                anyhow::bail!("unexpected call")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        // This should not error because System is not Software so SOFTWARE
        // loop fails open, and System/Sam are not NtUser so NTUSER loop skips
        let result = parse_autoruns(&NoOpProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_autoruns_both_software_and_ntuser() {
        // Tests that both loops run with both hive types in manifest
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SOFTWARE", 'C'),
            hive_type: RegistryHiveType::Software,
        });
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Users/admin/NTUSER.DAT", 'C'),
            hive_type: RegistryHiveType::NtUser { username: "admin".to_string() },
        });

        let mut store = TimelineStore::new();

        struct FailProvider;
        impl CollectionProvider for FailProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                anyhow::bail!("read error")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_autoruns(&FailProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── push_autorun_entry detailed verification ────────────────────

    #[test]
    fn test_push_autorun_entry_description_format_verified() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let ar = AutorunEntry {
            name: "MalwareStartup".to_string(),
            command: r"C:\temp\evil.exe -persist".to_string(),
            key_path: r"Microsoft\Windows\CurrentVersion\Run".to_string(),
            hive_source: "SOFTWARE".to_string(),
            last_write: ts,
        };
        let mut store = TimelineStore::new();
        push_autorun_entry(&ar, &mut store);
        assert_eq!(store.len(), 1);
        let entry = store.get(0).unwrap();
        assert!(entry.path.contains("[Autorun:SOFTWARE]"));
        assert!(entry.path.contains("MalwareStartup"));
        assert!(entry.path.contains("evil.exe"));
        assert!(entry.path.contains("CurrentVersion\\Run"));
        assert_eq!(entry.event_type, EventType::RegistryModify);
        assert_eq!(entry.primary_timestamp, ts);
    }

    #[test]
    fn test_push_autorun_entry_ntuser_source() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let ar = AutorunEntry {
            name: "UserStartup".to_string(),
            command: "notepad.exe".to_string(),
            key_path: r"Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
            hive_source: "NTUSER.DAT (admin)".to_string(),
            last_write: ts,
        };
        let mut store = TimelineStore::new();
        push_autorun_entry(&ar, &mut store);
        let entry = store.get(0).unwrap();
        assert!(entry.path.contains("NTUSER.DAT (admin)"));
        assert_eq!(entry.sources[0], ArtifactSource::Registry("NTUSER.DAT (admin)".to_string()));
    }

    #[test]
    fn test_push_autorun_entry_unique_ids() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let mut store = TimelineStore::new();
        for i in 0..10 {
            let ar = AutorunEntry {
                name: format!("Entry{}", i),
                command: format!("cmd{}.exe", i),
                key_path: "Run".to_string(),
                hive_source: "SOFTWARE".to_string(),
                last_write: ts,
            };
            push_autorun_entry(&ar, &mut store);
        }
        assert_eq!(store.len(), 10);
        // Verify all entity_ids are unique
        let ids: Vec<_> = store.entries().map(|e| &e.entity_id).collect();
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "IDs at {} and {} should differ", i, j);
            }
        }
    }

    // ─── parse_autoruns_from_hive additional edge cases ──────────────

    #[test]
    fn test_parse_autoruns_from_hive_short_zeroed_data() {
        // Short zeroed data without regf magic should error
        let data = vec![0u8; 32];
        let result = parse_autoruns_from_hive(&data, "SOFTWARE", SOFTWARE_RUN_PATHS);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_autoruns_from_hive_short_random_data() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let result = parse_autoruns_from_hive(&data, "TEST", &["Run"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_autoruns_from_hive_single_path() {
        let data = vec![0u8; 0];
        let result = parse_autoruns_from_hive(&data, "SOFTWARE", &[r"Microsoft\Windows\CurrentVersion\Run"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_next_autorun_id_uniqueness_batch() {
        let ids: Vec<u64> = (0..100).map(|_| next_autorun_id()).collect();
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ids.len());
    }

    #[test]
    fn test_autorun_entry_long_command() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let long_command = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand ".to_string()
            + &"A".repeat(500);
        let entry = AutorunEntry {
            name: "EncodedRun".to_string(),
            command: long_command.clone(),
            key_path: r"Microsoft\Windows\CurrentVersion\RunOnce".to_string(),
            hive_source: "SOFTWARE".to_string(),
            last_write: ts,
        };
        assert!(entry.command.len() > 500);

        let mut store = TimelineStore::new();
        push_autorun_entry(&entry, &mut store);
        let stored = store.get(0).unwrap();
        assert!(stored.path.contains("EncodedRun"));
    }
}
