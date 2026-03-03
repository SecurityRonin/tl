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

static SERVICE_ID_COUNTER: AtomicU64 = AtomicU64::new(0x5356_0000_0000_0000); // "SV" prefix

fn next_service_id() -> u64 {
    SERVICE_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Parsed service entry ────────────────────────────────────────────────────

/// A parsed Windows service from the SYSTEM registry hive.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    pub name: String,
    pub image_path: String,
    pub start_type: u32,
    pub service_type: u32,
    pub last_write: chrono::DateTime<chrono::Utc>,
}

/// Convert a start type value to a human-readable string.
pub fn start_type_str(start: u32) -> &'static str {
    match start {
        0 => "Boot",
        1 => "System",
        2 => "Auto",
        3 => "Manual",
        4 => "Disabled",
        _ => "Unknown",
    }
}

// ─── Registry Parsing ────────────────────────────────────────────────────────

/// Parse services from a SYSTEM registry hive.
///
/// Enumerates `ControlSet001\Services\<name>` subkeys. For each service,
/// extracts ImagePath, Start type, Type, and the key's last-write timestamp.
/// Only returns auto-start services (Start = 0, 1, or 2) to focus on
/// persistence-relevant entries.
pub fn parse_services_from_hive(data: &[u8]) -> Result<Vec<ServiceEntry>> {
    let mut entries = Vec::new();

    let mut hive = Hive::new(
        Cursor::new(data.to_vec()),
        HiveParseMode::NormalWithBaseBlock,
    )
    .context("Failed to parse SYSTEM registry hive")?
    .treat_hive_as_clean();

    let root_key = hive
        .root_key_node()
        .context("Failed to get root key from SYSTEM hive")?;

    // Try both ControlSet001 and ControlSet002
    let control_set_paths = [
        r"ControlSet001\Services",
        r"ControlSet002\Services",
    ];

    for cs_path in &control_set_paths {
        let services_key = match root_key.subpath(*cs_path, &mut hive) {
            Ok(Some(key)) => key,
            Ok(None) => {
                debug!("Services path not found: {}", cs_path);
                continue;
            }
            Err(e) => {
                debug!("Error accessing services path {}: {}", cs_path, e);
                continue;
            }
        };

        let subkeys = match services_key.borrow().subkeys(&mut hive) {
            Ok(sk) => sk.clone(),
            Err(e) => {
                warn!("Error reading Services subkeys at {}: {}", cs_path, e);
                continue;
            }
        };

        for service_key in subkeys.iter() {
            let sk = service_key.borrow();
            let name = sk.name().to_string();

            // Get last write timestamp from the key
            let last_write = *sk.timestamp();

            let mut image_path = String::new();
            let mut start_type: u32 = 3; // Default to Manual
            let mut service_type: u32 = 0;

            let values = sk.values();
            for value in values {
                let vname = value.name();
                match vname {
                    "ImagePath" => {
                        match value.value() {
                            nt_hive2::RegistryValue::RegSZ(s)
                            | nt_hive2::RegistryValue::RegExpandSZ(s) => {
                                image_path = s.clone();
                            }
                            _ => {}
                        }
                    }
                    "Start" => {
                        if let nt_hive2::RegistryValue::RegDWord(val) = value.value() {
                            start_type = *val;
                        }
                    }
                    "Type" => {
                        if let nt_hive2::RegistryValue::RegDWord(val) = value.value() {
                            service_type = *val;
                        }
                    }
                    _ => {}
                }
            }

            // Only include auto-start services (Boot=0, System=1, Auto=2)
            if start_type > 2 {
                continue;
            }

            // Skip services without an ImagePath (drivers without binary)
            if image_path.is_empty() {
                continue;
            }

            entries.push(ServiceEntry {
                name,
                image_path,
                start_type,
                service_type,
                last_write,
            });
        }

        // Only process first successful control set
        if !entries.is_empty() {
            break;
        }
    }

    Ok(entries)
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse Windows services from SYSTEM hive and populate the timeline.
pub fn parse_services(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    let system_hives: Vec<_> = manifest
        .registry_hives
        .iter()
        .filter(|h| h.hive_type == RegistryHiveType::System)
        .collect();

    if system_hives.is_empty() {
        debug!("No SYSTEM hive found in manifest");
        return Ok(());
    }

    for hive_entry in &system_hives {
        let data = match provider.open_file(&hive_entry.path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read SYSTEM hive {}: {}", hive_entry.path, e);
                continue;
            }
        };

        debug!(
            "Parsing services from SYSTEM hive: {} ({} bytes)",
            hive_entry.path,
            data.len()
        );

        let service_entries = match parse_services_from_hive(&data) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to parse services from {}: {}", hive_entry.path, e);
                continue;
            }
        };

        debug!("Found {} auto-start services", service_entries.len());

        for svc in &service_entries {
            let desc = format!(
                "[Service:{}] {} -> {}",
                svc.name,
                start_type_str(svc.start_type),
                svc.image_path,
            );

            let entry = TimelineEntry {
                entity_id: EntityId::Generated(next_service_id()),
                path: desc,
                primary_timestamp: svc.last_write,
                event_type: EventType::ServiceInstall,
                timestamps: TimestampSet::default(),
                sources: smallvec![ArtifactSource::Registry("SYSTEM".to_string())],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
            };

            store.push(entry);
        }
    }

    Ok(()
    )
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn test_start_type_boot() {
        assert_eq!(start_type_str(0), "Boot");
    }

    #[test]
    fn test_start_type_auto() {
        assert_eq!(start_type_str(2), "Auto");
    }

    #[test]
    fn test_start_type_disabled() {
        assert_eq!(start_type_str(4), "Disabled");
    }

    #[test]
    fn test_start_type_unknown() {
        assert_eq!(start_type_str(99), "Unknown");
    }

    #[test]
    fn test_service_entry_creation() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = ServiceEntry {
            name: "MaliciousSvc".to_string(),
            image_path: r"C:\temp\backdoor.exe".to_string(),
            start_type: 2,
            service_type: 16,
            last_write: ts,
        };
        assert_eq!(entry.name, "MaliciousSvc");
        assert_eq!(start_type_str(entry.start_type), "Auto");
    }

    #[test]
    fn test_service_timeline_entry() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let svc = ServiceEntry {
            name: "EvilSvc".to_string(),
            image_path: r"C:\Windows\Temp\evil.exe -hidden".to_string(),
            start_type: 2,
            service_type: 16,
            last_write: ts,
        };

        let desc = format!(
            "[Service:{}] {} -> {} ({})",
            svc.name,
            start_type_str(svc.start_type),
            svc.image_path,
            svc.name,
        );

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_service_id()),
            path: desc.clone(),
            primary_timestamp: svc.last_write,
            event_type: EventType::ServiceInstall,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Registry("SYSTEM".to_string())],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        assert_eq!(entry.event_type, EventType::ServiceInstall);
        assert!(entry.path.contains("EvilSvc"));
        assert!(entry.path.contains("evil.exe"));
        assert!(entry.path.contains("Auto"));
    }

    #[test]
    fn test_parse_services_from_hive_returns_services() {
        // This test requires the actual parsing function
        // Use a minimal SYSTEM hive — for now test that the function exists
        // and returns Ok with empty data (graceful failure)
        let empty_data = vec![0u8; 0];
        let result = parse_services_from_hive(&empty_data);
        // Should return Err since empty data isn't a valid hive
        assert!(result.is_err());
    }

    // ─── start_type_str comprehensive tests ─────────────────────────────

    #[test]
    fn test_start_type_system() {
        assert_eq!(start_type_str(1), "System");
    }

    #[test]
    fn test_start_type_manual() {
        assert_eq!(start_type_str(3), "Manual");
    }

    #[test]
    fn test_start_type_all_values() {
        let expected = vec![
            (0, "Boot"),
            (1, "System"),
            (2, "Auto"),
            (3, "Manual"),
            (4, "Disabled"),
        ];
        for (val, name) in expected {
            assert_eq!(start_type_str(val), name, "Failed for start_type={}", val);
        }
    }

    #[test]
    fn test_start_type_large_unknown() {
        assert_eq!(start_type_str(255), "Unknown");
        assert_eq!(start_type_str(u32::MAX), "Unknown");
    }

    // ─── next_service_id tests ──────────────────────────────────────────

    #[test]
    fn test_next_service_id_increments() {
        let id1 = next_service_id();
        let id2 = next_service_id();
        assert!(id2 > id1);
        assert_eq!(id2 - id1, 1);
    }

    #[test]
    fn test_next_service_id_has_sv_prefix() {
        let id = next_service_id();
        let prefix = (id >> 48) & 0xFFFF;
        assert_eq!(prefix, 0x5356);
    }

    // ─── ServiceEntry struct tests ──────────────────────────────────────

    #[test]
    fn test_service_entry_clone() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = ServiceEntry {
            name: "TestSvc".to_string(),
            image_path: r"C:\Windows\svc.exe".to_string(),
            start_type: 2,
            service_type: 16,
            last_write: ts,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.name, entry.name);
        assert_eq!(cloned.image_path, entry.image_path);
        assert_eq!(cloned.start_type, entry.start_type);
        assert_eq!(cloned.service_type, entry.service_type);
        assert_eq!(cloned.last_write, entry.last_write);
    }

    #[test]
    fn test_service_entry_debug() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = ServiceEntry {
            name: "DebugSvc".to_string(),
            image_path: r"C:\dbg.exe".to_string(),
            start_type: 0,
            service_type: 1,
            last_write: ts,
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("ServiceEntry"));
        assert!(debug_str.contains("DebugSvc"));
    }

    // ─── ServiceEntry with various start types ──────────────────────────

    #[test]
    fn test_service_entry_boot_type() {
        let ts = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let svc = ServiceEntry {
            name: "BootDriver".to_string(),
            image_path: r"system32\drivers\boot.sys".to_string(),
            start_type: 0,
            service_type: 1,
            last_write: ts,
        };
        assert_eq!(start_type_str(svc.start_type), "Boot");
    }

    #[test]
    fn test_service_entry_system_type() {
        let ts = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let svc = ServiceEntry {
            name: "SysDriver".to_string(),
            image_path: r"system32\drivers\sys.sys".to_string(),
            start_type: 1,
            service_type: 2,
            last_write: ts,
        };
        assert_eq!(start_type_str(svc.start_type), "System");
    }

    // ─── Description formatting tests ───────────────────────────────────

    #[test]
    fn test_service_description_format() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let svc = ServiceEntry {
            name: "MySvc".to_string(),
            image_path: r"C:\svc.exe".to_string(),
            start_type: 2,
            service_type: 16,
            last_write: ts,
        };
        let desc = format!(
            "[Service:{}] {} -> {}",
            svc.name,
            start_type_str(svc.start_type),
            svc.image_path,
        );
        assert!(desc.starts_with("[Service:MySvc]"));
        assert!(desc.contains("Auto"));
        assert!(desc.contains(r"C:\svc.exe"));
    }

    #[test]
    fn test_service_description_with_boot_start() {
        let ts = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let svc = ServiceEntry {
            name: "EarlyBoot".to_string(),
            image_path: r"system32\drivers\early.sys".to_string(),
            start_type: 0,
            service_type: 1,
            last_write: ts,
        };
        let desc = format!(
            "[Service:{}] {} -> {}",
            svc.name,
            start_type_str(svc.start_type),
            svc.image_path,
        );
        assert!(desc.contains("Boot"));
    }

    // ─── parse_services_from_hive edge cases ────────────────────────────

    #[test]
    fn test_parse_services_from_hive_garbage_data() {
        let garbage = vec![0xFFu8; 256];
        let result = parse_services_from_hive(&garbage);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_services_from_hive_small_data() {
        let small = vec![0x42u8; 10];
        let result = parse_services_from_hive(&small);
        assert!(result.is_err());
    }

    // ─── Timeline entry creation ────────────────────────────────────────

    #[test]
    fn test_service_timeline_entry_event_type() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_service_id()),
            path: "[Service:Test] Auto -> test.exe".to_string(),
            primary_timestamp: ts,
            event_type: EventType::ServiceInstall,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Registry("SYSTEM".to_string())],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };
        assert_eq!(entry.event_type, EventType::ServiceInstall);
        assert_eq!(format!("{}", entry.event_type), "SVC");
    }

    #[test]
    fn test_service_timeline_entry_source() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_service_id()),
            path: "[Service:X] Boot -> driver.sys".to_string(),
            primary_timestamp: ts,
            event_type: EventType::ServiceInstall,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Registry("SYSTEM".to_string())],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };
        assert_eq!(entry.sources[0], ArtifactSource::Registry("SYSTEM".to_string()));
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
        let result = parse_services(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── parse_services pipeline tests with mock providers ───────────

    fn make_system_hive_manifest() -> crate::collection::manifest::ArtifactManifest {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SYSTEM", 'C'),
            hive_type: RegistryHiveType::System,
        });
        manifest
    }

    #[test]
    fn test_parse_services_open_file_error() {
        // Tests the warn path when provider.open_file fails (line 183-186)
        let manifest = make_system_hive_manifest();
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
                anyhow::bail!("Disk read error")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_services(&FailOpenProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_services_invalid_hive_data() {
        // Tests the warn path when parse_services_from_hive fails (line 197-200)
        let manifest = make_system_hive_manifest();
        let mut store = TimelineStore::new();

        struct GarbageDataProvider;
        impl CollectionProvider for GarbageDataProvider {
            fn discover(&self) -> crate::collection::manifest::ArtifactManifest {
                crate::collection::manifest::ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(vec![0xFFu8; 256])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_services(&GarbageDataProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_services_no_system_hive_in_manifest() {
        // Tests the debug path when no SYSTEM hives are in the manifest (line 175-178)
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        // Add a SOFTWARE hive instead of SYSTEM
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SOFTWARE", 'C'),
            hive_type: RegistryHiveType::Software,
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
                Ok(vec![])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_services(&NoOpProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_services_multiple_system_hives() {
        // Tests iterating multiple SYSTEM hive entries (line 180 loop)
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SYSTEM", 'C'),
            hive_type: RegistryHiveType::System,
        });
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/backup/SYSTEM", 'C'),
            hive_type: RegistryHiveType::System,
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
                anyhow::bail!("read error for both")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_services(&FailProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_services_from_hive_one_byte() {
        let result = parse_services_from_hive(&[0x72]); // 'r' byte
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_services_from_hive_all_zeros_small() {
        // Zeroed data does not contain valid regf magic
        let result = parse_services_from_hive(&[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_services_from_hive_random_short_data() {
        let result = parse_services_from_hive(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(result.is_err());
    }

    // ─── ServiceEntry formatting variations ──────────────────────────

    #[test]
    fn test_service_description_with_system_start() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let svc = ServiceEntry {
            name: "SysDrv".to_string(),
            image_path: r"system32\drivers\sysdrv.sys".to_string(),
            start_type: 1,
            service_type: 2,
            last_write: ts,
        };
        let desc = format!(
            "[Service:{}] {} -> {}",
            svc.name,
            start_type_str(svc.start_type),
            svc.image_path,
        );
        assert!(desc.contains("System"));
        assert!(desc.contains("SysDrv"));
    }

    #[test]
    fn test_service_entry_various_service_types() {
        let ts = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        // Service type 1 = kernel driver
        let svc1 = ServiceEntry {
            name: "KernelDrv".to_string(),
            image_path: "driver.sys".to_string(),
            start_type: 0,
            service_type: 1,
            last_write: ts,
        };
        assert_eq!(svc1.service_type, 1);

        // Service type 16 = own process
        let svc16 = ServiceEntry {
            name: "OwnProcess".to_string(),
            image_path: "svc.exe".to_string(),
            start_type: 2,
            service_type: 16,
            last_write: ts,
        };
        assert_eq!(svc16.service_type, 16);

        // Service type 32 = shared process
        let svc32 = ServiceEntry {
            name: "SharedSvc".to_string(),
            image_path: "svchost.exe -k netsvcs".to_string(),
            start_type: 2,
            service_type: 32,
            last_write: ts,
        };
        assert_eq!(svc32.service_type, 32);
    }

    #[test]
    fn test_service_timeline_entry_has_correct_source() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_service_id()),
            path: "[Service:Svc] Auto -> test.exe".to_string(),
            primary_timestamp: ts,
            event_type: EventType::ServiceInstall,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Registry("SYSTEM".to_string())],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };
        // Verify the ArtifactSource displays correctly
        assert_eq!(format!("{}", entry.sources[0]), "REG:SYSTEM");
    }

    #[test]
    fn test_service_timeline_entry_timestamps_default() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_service_id()),
            path: "test".to_string(),
            primary_timestamp: ts,
            event_type: EventType::ServiceInstall,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Registry("SYSTEM".to_string())],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };
        assert!(entry.timestamps.si_created.is_none());
        assert!(entry.timestamps.fn_created.is_none());
        assert!(entry.metadata.file_size.is_none());
    }

    #[test]
    fn test_start_type_str_boundary_5() {
        assert_eq!(start_type_str(5), "Unknown");
    }

    #[test]
    fn test_next_service_id_uniqueness_batch() {
        let ids: Vec<u64> = (0..100).map(|_| next_service_id()).collect();
        // All IDs should be unique
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ids.len());
    }

    #[test]
    fn test_parse_services_skips_non_system_hives() {
        // Manifest with only non-System hives; should be filtered out
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Users/user/NTUSER.DAT", 'C'),
            hive_type: RegistryHiveType::NtUser { username: "user".to_string() },
        });
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SAM", 'C'),
            hive_type: RegistryHiveType::Sam,
        });

        let mut store = TimelineStore::new();

        struct PanicProvider;
        impl CollectionProvider for PanicProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                panic!("Should not be called for non-System hives")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        // This should NOT panic because non-System hives are filtered out
        let result = parse_services(&PanicProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }
}
