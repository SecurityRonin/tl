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
}
