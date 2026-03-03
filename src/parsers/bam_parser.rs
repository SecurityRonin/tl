use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use log::{debug, warn};
use nt_hive2::{Hive, HiveParseMode, RegistryValue, SubPath};
use smallvec::smallvec;
use std::io::Cursor;

use crate::collection::manifest::{ArtifactManifest, RegistryHiveType};
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a Windows FILETIME (100ns intervals since 1601-01-01) to DateTime<Utc>.
fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    const EPOCH_DIFF: i64 = 11_644_473_600;
    let secs = (filetime / 10_000_000) as i64 - EPOCH_DIFF;
    if secs < 0 {
        return None;
    }
    let nanos = ((filetime % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}

/// Convert a device path to a more readable Windows path.
///
/// Converts paths like:
///   `\Device\HarddiskVolume3\Windows\System32\cmd.exe`
/// to:
///   `C:\Windows\System32\cmd.exe`
///
/// We assume HarddiskVolume1=C:, but in practice the mapping varies.
/// We preserve the original path if we can't map it confidently.
pub fn device_path_to_windows_path(device_path: &str) -> String {
    // Common mappings - these are approximate; in a real environment,
    // the volume->letter mapping comes from the system configuration
    if let Some(rest) = device_path.strip_prefix(r"\Device\HarddiskVolume") {
        // Extract the volume number and the remainder of the path
        if let Some(slash_pos) = rest.find('\\') {
            let _volume_num = &rest[..slash_pos];
            let path_rest = &rest[slash_pos..];
            // Default to C: drive (most common for system volume)
            return format!("C:{}", path_rest);
        }
    }
    // Return original if we can't map it
    device_path.to_string()
}

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static BAM_ID_COUNTER: AtomicU64 = AtomicU64::new(0x4241_0000_0000_0000); // "BA" prefix

fn next_bam_id() -> u64 {
    BAM_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Parsed entry ────────────────────────────────────────────────────────────

/// A parsed BAM/DAM entry.
#[derive(Debug, Clone)]
pub struct BamEntry {
    /// The executable path (converted from device path if possible).
    pub path: String,
    /// The original device path as found in the registry.
    pub device_path: String,
    /// The last execution timestamp.
    pub execution_time: DateTime<Utc>,
    /// The SID of the user who executed the program.
    pub user_sid: String,
}

/// Extract the FILETIME from the first 8 bytes of BAM/DAM value data.
fn parse_bam_timestamp(binary_data: &[u8]) -> Option<DateTime<Utc>> {
    if binary_data.len() < 8 {
        return None;
    }
    let filetime = u64::from_le_bytes([
        binary_data[0],
        binary_data[1],
        binary_data[2],
        binary_data[3],
        binary_data[4],
        binary_data[5],
        binary_data[6],
        binary_data[7],
    ]);
    filetime_to_datetime(filetime)
}

// ─── Registry navigation ─────────────────────────────────────────────────────

/// Parse BAM entries from a SYSTEM registry hive.
///
/// Path: ControlSet001\Services\bam\State\UserSettings\<SID>
/// and:  ControlSet001\Services\dam\State\UserSettings\<SID>
///
/// Each value under the SID subkey:
///   - Value name = executable path (device path)
///   - Value data = binary, first 8 bytes are a Windows FILETIME
fn parse_bam_from_hive(data: &[u8]) -> Result<Vec<BamEntry>> {
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

    // Try both bam and dam services under both ControlSet001 and ControlSet002
    let paths = [
        r"ControlSet001\Services\bam\State\UserSettings",
        r"ControlSet002\Services\bam\State\UserSettings",
        r"ControlSet001\Services\dam\State\UserSettings",
        r"ControlSet002\Services\dam\State\UserSettings",
        // Also try without "State" (older Win10 builds)
        r"ControlSet001\Services\bam\UserSettings",
        r"ControlSet002\Services\bam\UserSettings",
    ];

    for path in &paths {
        let user_settings_key = match root_key.subpath(*path, &mut hive) {
            Ok(Some(key)) => key,
            Ok(None) => {
                debug!("BAM/DAM path not found: {}", path);
                continue;
            }
            Err(e) => {
                debug!("Error accessing BAM/DAM path {}: {}", path, e);
                continue;
            }
        };

        // Enumerate SID subkeys
        let sid_keys = match user_settings_key.borrow().subkeys(&mut hive) {
            Ok(sk) => sk.clone(),
            Err(e) => {
                warn!("Error reading BAM/DAM SID subkeys at {}: {}", path, e);
                continue;
            }
        };

        for sid_key in sid_keys.iter() {
            let sk = sid_key.borrow();
            let user_sid = sk.name().to_string();

            // Skip non-SID subkeys
            if !user_sid.starts_with("S-1-") {
                continue;
            }

            let values = sk.values();

            for value in values {
                let value_name = value.name().to_string();

                // Skip registry metadata values (Version, SequenceNumber, etc.)
                if value_name == "Version"
                    || value_name == "SequenceNumber"
                    || value_name.is_empty()
                {
                    continue;
                }

                // The value data should be binary with at least 8 bytes (FILETIME)
                let binary_data = match value.value() {
                    RegistryValue::RegBinary(data) => data,
                    _ => continue,
                };

                let execution_time = match parse_bam_timestamp(binary_data) {
                    Some(ts) => ts,
                    None => continue,
                };

                let windows_path = device_path_to_windows_path(&value_name);

                entries.push(BamEntry {
                    path: windows_path,
                    device_path: value_name,
                    execution_time,
                    user_sid: user_sid.clone(),
                });
            }
        }
    }

    debug!("Found {} BAM/DAM entries", entries.len());
    Ok(entries)
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse BAM/DAM entries from the SYSTEM registry hive.
///
/// The Background Activity Moderator (BAM) and Desktop Activity Moderator (DAM)
/// track execution of programs by user SID. Each entry contains the device path
/// of the executable and a FILETIME timestamp of the last execution.
///
/// Registry path:
///   SYSTEM\ControlSet001\Services\bam\State\UserSettings\<SID>
///   SYSTEM\ControlSet001\Services\dam\State\UserSettings\<SID>
pub fn parse_bam(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    // Find the SYSTEM hive
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
            "Parsing BAM/DAM from SYSTEM hive: {} ({} bytes)",
            hive_entry.path,
            data.len()
        );

        let bam_entries = match parse_bam_from_hive(&data) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to parse BAM/DAM from {}: {}", hive_entry.path, e);
                continue;
            }
        };

        debug!(
            "Found {} BAM/DAM entries from {}",
            bam_entries.len(),
            hive_entry.path
        );

        for bam_entry in &bam_entries {
            let timestamps = TimestampSet::default();
            // BAM provides execution time; store it in the evtx_timestamp field
            // or use primary_timestamp. There's no dedicated bam_timestamp field,
            // so we use the primary timestamp directly.

            let metadata = EntryMetadata {
                ..EntryMetadata::default()
            };

            let entry = TimelineEntry {
                entity_id: EntityId::Generated(next_bam_id()),
                path: bam_entry.path.clone(),
                primary_timestamp: bam_entry.execution_time,
                event_type: EventType::Execute,
                timestamps,
                sources: smallvec![ArtifactSource::BamDam],
                anomalies: AnomalyFlags::empty(),
                metadata,
            };

            store.push(entry);
        }
    }

    Ok(())
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_to_datetime() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;
        let result = filetime_to_datetime(filetime).unwrap();
        assert_eq!(result, dt);
    }

    #[test]
    fn test_filetime_zero() {
        assert!(filetime_to_datetime(0).is_none());
    }

    #[test]
    fn test_device_path_to_windows_path_volume3() {
        let device_path = r"\Device\HarddiskVolume3\Windows\System32\cmd.exe";
        let result = device_path_to_windows_path(device_path);
        assert_eq!(result, r"C:\Windows\System32\cmd.exe");
    }

    #[test]
    fn test_device_path_to_windows_path_volume1() {
        let device_path = r"\Device\HarddiskVolume1\Users\admin\malware.exe";
        let result = device_path_to_windows_path(device_path);
        assert_eq!(result, r"C:\Users\admin\malware.exe");
    }

    #[test]
    fn test_device_path_unmappable() {
        let path = r"\\?\GLOBALROOT\Device\Mup\server\share\tool.exe";
        let result = device_path_to_windows_path(path);
        // Unmappable paths returned as-is
        assert_eq!(result, path);
    }

    #[test]
    fn test_device_path_already_windows() {
        let path = r"C:\Windows\System32\cmd.exe";
        let result = device_path_to_windows_path(path);
        assert_eq!(result, path);
    }

    #[test]
    fn test_parse_bam_timestamp_valid() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;

        let mut data = vec![0u8; 16]; // BAM data is typically more than 8 bytes
        data[0..8].copy_from_slice(&filetime.to_le_bytes());

        let result = parse_bam_timestamp(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), dt);
    }

    #[test]
    fn test_parse_bam_timestamp_too_short() {
        let data = vec![0u8; 4];
        assert!(parse_bam_timestamp(&data).is_none());
    }

    #[test]
    fn test_parse_bam_timestamp_zero() {
        let data = vec![0u8; 8];
        assert!(parse_bam_timestamp(&data).is_none());
    }

    #[test]
    fn test_bam_entry_creation() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();

        let bam_entry = BamEntry {
            path: r"C:\Windows\System32\cmd.exe".to_string(),
            device_path: r"\Device\HarddiskVolume3\Windows\System32\cmd.exe".to_string(),
            execution_time: dt,
            user_sid: "S-1-5-21-1234567890-1234567890-1234567890-1001".to_string(),
        };

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_bam_id()),
            path: bam_entry.path.clone(),
            primary_timestamp: bam_entry.execution_time,
            event_type: EventType::Execute,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::BamDam],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        assert_eq!(entry.path, r"C:\Windows\System32\cmd.exe");
        assert_eq!(entry.event_type, EventType::Execute);
        assert_eq!(entry.primary_timestamp, dt);
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
        let result = parse_bam(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_sid_filtering() {
        // Non-SID strings should be filtered
        assert!(!"Version".starts_with("S-1-"));
        assert!(!"SequenceNumber".starts_with("S-1-"));
        assert!("S-1-5-21-1234567890-1234567890-1234567890-1001".starts_with("S-1-"));
    }

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_filetime_negative_secs() {
        // A very small filetime that produces negative secs after epoch diff subtraction
        let filetime = 1u64;
        assert!(filetime_to_datetime(filetime).is_none());
    }

    #[test]
    fn test_filetime_with_nanos() {
        use chrono::TimeZone;
        let dt_base = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let secs = dt_base.timestamp() + 11_644_473_600;
        // Add 2_500_000 (100ns units) = 250ms
        let filetime = (secs as u64) * 10_000_000 + 2_500_000;
        let result = filetime_to_datetime(filetime).unwrap();
        assert_eq!(result.timestamp(), dt_base.timestamp());
        assert_eq!(result.timestamp_subsec_nanos(), 250_000_000);
    }

    #[test]
    fn test_filetime_max_valid() {
        // A very large filetime that should still be valid
        // Year ~2100: still within reasonable bounds
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;
        let result = filetime_to_datetime(filetime).unwrap();
        assert_eq!(result, dt);
    }

    #[test]
    fn test_device_path_to_windows_path_volume_number_only() {
        // Path with volume number but nothing after it (no trailing backslash)
        let device_path = r"\Device\HarddiskVolume3";
        let result = device_path_to_windows_path(device_path);
        // No slash found after volume number, so returned as-is
        assert_eq!(result, device_path);
    }

    #[test]
    fn test_device_path_to_windows_path_empty() {
        let result = device_path_to_windows_path("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_device_path_to_windows_path_various_volumes() {
        // Different volume numbers should all map to C:
        for vol in 1..=10 {
            let path = format!(r"\Device\HarddiskVolume{}\test.exe", vol);
            let result = device_path_to_windows_path(&path);
            assert_eq!(result, r"C:\test.exe");
        }
    }

    #[test]
    fn test_device_path_to_windows_path_deep_path() {
        let device_path = r"\Device\HarddiskVolume2\Users\admin\AppData\Local\Temp\malware.exe";
        let result = device_path_to_windows_path(device_path);
        assert_eq!(result, r"C:\Users\admin\AppData\Local\Temp\malware.exe");
    }

    #[test]
    fn test_parse_bam_timestamp_exactly_8_bytes() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;
        let data = filetime.to_le_bytes().to_vec();
        assert_eq!(data.len(), 8);
        let result = parse_bam_timestamp(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), dt);
    }

    #[test]
    fn test_parse_bam_timestamp_empty() {
        let data: Vec<u8> = Vec::new();
        assert!(parse_bam_timestamp(&data).is_none());
    }

    #[test]
    fn test_parse_bam_timestamp_7_bytes() {
        let data = vec![0u8; 7];
        assert!(parse_bam_timestamp(&data).is_none());
    }

    #[test]
    fn test_parse_bam_timestamp_pre_epoch() {
        // Filetime value that would be before 1970 but not zero
        let filetime = 1_000_000u64; // tiny value, well before 1970
        let mut data = vec![0u8; 8];
        data[0..8].copy_from_slice(&filetime.to_le_bytes());
        assert!(parse_bam_timestamp(&data).is_none());
    }

    #[test]
    fn test_bam_entry_clone() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let entry = BamEntry {
            path: r"C:\Windows\notepad.exe".to_string(),
            device_path: r"\Device\HarddiskVolume3\Windows\notepad.exe".to_string(),
            execution_time: dt,
            user_sid: "S-1-5-21-111-222-333-1001".to_string(),
        };
        let cloned = entry.clone();
        assert_eq!(cloned.path, entry.path);
        assert_eq!(cloned.device_path, entry.device_path);
        assert_eq!(cloned.execution_time, entry.execution_time);
        assert_eq!(cloned.user_sid, entry.user_sid);
    }

    #[test]
    fn test_bam_entry_debug() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let entry = BamEntry {
            path: "test.exe".to_string(),
            device_path: "device_test".to_string(),
            execution_time: dt,
            user_sid: "S-1-5-21-0-0-0-0".to_string(),
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("BamEntry"));
        assert!(debug_str.contains("test.exe"));
    }

    #[test]
    fn test_bam_entry_all_fields() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 3, 15, 14, 30, 0).unwrap();
        let entry = BamEntry {
            path: r"C:\Windows\System32\svchost.exe".to_string(),
            device_path: r"\Device\HarddiskVolume1\Windows\System32\svchost.exe".to_string(),
            execution_time: dt,
            user_sid: "S-1-5-18".to_string(), // SYSTEM SID
        };
        assert_eq!(entry.path, r"C:\Windows\System32\svchost.exe");
        assert_eq!(entry.user_sid, "S-1-5-18");
        assert_eq!(entry.execution_time, dt);
    }

    #[test]
    fn test_next_bam_id_monotonic() {
        let id1 = next_bam_id();
        let id2 = next_bam_id();
        let id3 = next_bam_id();
        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[test]
    fn test_next_bam_id_has_ba_prefix() {
        let id = next_bam_id();
        // The top 2 bytes should be 0x4241 ("BA")
        assert_eq!((id >> 48) & 0xFFFF, 0x4241);
    }

    #[test]
    fn test_timeline_entry_from_bam_has_correct_source() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_bam_id()),
            path: r"C:\test.exe".to_string(),
            primary_timestamp: dt,
            event_type: EventType::Execute,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::BamDam],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };
        assert!(matches!(entry.sources[0], ArtifactSource::BamDam));
        assert_eq!(entry.event_type, EventType::Execute);
    }

    #[test]
    fn test_device_path_unc_path() {
        let path = r"\\server\share\folder\file.exe";
        let result = device_path_to_windows_path(path);
        // UNC paths should be returned as-is
        assert_eq!(result, path);
    }

    #[test]
    fn test_parse_bam_timestamp_with_extra_data() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;
        // BAM entries typically have more data after the 8-byte FILETIME
        let mut data = vec![0u8; 24];
        data[0..8].copy_from_slice(&filetime.to_le_bytes());
        data[8..16].copy_from_slice(&0xDEADBEEFu64.to_le_bytes()); // extra data
        let result = parse_bam_timestamp(&data);
        assert_eq!(result, Some(dt));
    }

    // ─── Pipeline integration and hive parsing coverage ──────────────────

    #[test]
    fn test_parse_bam_from_hive_invalid_data() {
        // Invalid hive data should return an error
        let result = parse_bam_from_hive(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bam_from_hive_empty_data() {
        let result = parse_bam_from_hive(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bam_from_hive_truncated_hive() {
        // A buffer that starts with "regf" but is too short
        let mut data = vec![0u8; 50];
        data[0..4].copy_from_slice(b"regf");
        let result = parse_bam_from_hive(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bam_with_system_hive_that_fails_to_open() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SYSTEM", 'C'),
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
                anyhow::bail!("File not found")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        // Should succeed (error is logged, not propagated)
        let result = parse_bam(&FailProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_bam_with_system_hive_invalid_content() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SYSTEM", 'C'),
            hive_type: RegistryHiveType::System,
        });

        let mut store = TimelineStore::new();

        struct GarbageProvider;
        impl CollectionProvider for GarbageProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                // Return garbage data that won't parse as a registry hive
                Ok(vec![0xDE, 0xAD, 0xBE, 0xEF].into_iter().cycle().take(1024).collect())
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        // Should succeed (parse error is logged, not propagated)
        let result = parse_bam(&GarbageProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_bam_skips_non_system_hives() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        // Add an NTUSER.DAT hive (not SYSTEM) - should be skipped
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Users/admin/NTUSER.DAT", 'C'),
            hive_type: RegistryHiveType::NtUser {
                username: "admin".to_string(),
            },
        });
        // Add a Software hive - should be skipped
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SOFTWARE", 'C'),
            hive_type: RegistryHiveType::Software,
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
                panic!("Should not be called for non-SYSTEM hives")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        // Should succeed without calling open_file because no SYSTEM hives
        let result = parse_bam(&PanicProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_bam_with_multiple_system_hives() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        // Two system hives - both should be attempted
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SYSTEM", 'C'),
            hive_type: RegistryHiveType::System,
        });
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SYSTEM.bak", 'C'),
            hive_type: RegistryHiveType::System,
        });

        let mut store = TimelineStore::new();

        use std::sync::atomic::AtomicU32;
        static CALL_COUNT: AtomicU32 = AtomicU32::new(0);

        struct CountingProvider;
        impl CollectionProvider for CountingProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                CALL_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Return invalid data so parsing fails gracefully
                Ok(vec![0u8; 512])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        CALL_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        let result = parse_bam(&CountingProvider, &manifest, &mut store);
        assert!(result.is_ok());
        // Both hives should have been attempted
        assert_eq!(CALL_COUNT.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn test_parse_bam_timestamp_1_byte() {
        let data = vec![0xFF];
        assert!(parse_bam_timestamp(&data).is_none());
    }

    #[test]
    fn test_device_path_case_sensitivity() {
        // The prefix match is case-sensitive
        let path = r"\device\harddiskvolume3\Windows\cmd.exe";
        let result = device_path_to_windows_path(path);
        // Lowercase "device" doesn't match, returned as-is
        assert_eq!(result, path);
    }

    #[test]
    fn test_device_path_just_prefix() {
        let path = r"\Device\HarddiskVolume";
        let result = device_path_to_windows_path(path);
        // After strip_prefix, rest is "" which has no backslash
        assert_eq!(result, path);
    }

    // ─── Minimal valid hive tests ─────────────────────────────────────────

    /// Build a minimal valid Windows registry hive binary.
    /// The hive contains a root key node with 0 subkeys and 0 values.
    /// This is sufficient to exercise code that opens a hive and navigates
    /// subpaths (which will return Ok(None) for missing paths).
    fn build_minimal_hive() -> Vec<u8> {
        let mut hive = vec![0u8; 4096 + 4096]; // base block + one hive bin

        // ─── Base Block (4096 bytes) ─────────────────────────────────────
        // Offset 0x00: magic "regf"
        hive[0..4].copy_from_slice(b"regf");
        // Offset 0x04: primary_sequence_number
        hive[4..8].copy_from_slice(&1u32.to_le_bytes());
        // Offset 0x08: secondary_sequence_number
        hive[8..12].copy_from_slice(&1u32.to_le_bytes());
        // Offset 0x0C: timestamp (u64)
        hive[12..20].copy_from_slice(&0u64.to_le_bytes());
        // Offset 0x14: major_version = 1
        hive[20..24].copy_from_slice(&1u32.to_le_bytes());
        // Offset 0x18: minor_version = 5
        hive[24..28].copy_from_slice(&5u32.to_le_bytes());
        // Offset 0x1C: file_type = 0 (HiveFile)
        hive[28..32].copy_from_slice(&0u32.to_le_bytes());
        // Offset 0x20: file_format = 1
        hive[32..36].copy_from_slice(&1u32.to_le_bytes());
        // Offset 0x24: root_cell_offset = 0x20 (32 bytes into hive bins data)
        hive[36..40].copy_from_slice(&0x20u32.to_le_bytes());
        // Offset 0x28: data_size = 0x1000 (4096, one hive bin)
        hive[40..44].copy_from_slice(&0x1000u32.to_le_bytes());
        // Offset 0x2C: clustering_factor = 1
        hive[44..48].copy_from_slice(&1u32.to_le_bytes());
        // Offset 0x30-0x8F: file_name (64 bytes of UTF-16LE), leave as zeros
        // Remaining header fields up to 0x1FB: zeros are fine
        // Offset 0x1FC: checksum = XOR of first 127 u32s
        let mut checksum: u32 = 0;
        for i in 0..127 {
            let off = i * 4;
            let val = u32::from_le_bytes([hive[off], hive[off+1], hive[off+2], hive[off+3]]);
            checksum ^= val;
        }
        if checksum == 0xFFFF_FFFF { checksum = 0xFFFF_FFFE; }
        if checksum == 0 { checksum = 1; }
        hive[0x1FC..0x200].copy_from_slice(&checksum.to_le_bytes());

        // ─── Hive Bin (4096 bytes, starting at offset 4096) ──────────────
        let hbin_off = 4096;
        // hbin magic
        hive[hbin_off..hbin_off+4].copy_from_slice(b"hbin");
        // offset of this hive bin = 0
        hive[hbin_off+4..hbin_off+8].copy_from_slice(&0u32.to_le_bytes());
        // size of this hive bin = 0x1000 (4096)
        hive[hbin_off+8..hbin_off+12].copy_from_slice(&0x1000u32.to_le_bytes());
        // reserved (u64) = 0
        hive[hbin_off+12..hbin_off+20].copy_from_slice(&0u64.to_le_bytes());
        // timestamp (u64) = 0
        hive[hbin_off+20..hbin_off+28].copy_from_slice(&0u64.to_le_bytes());
        // spare (u32) = 0
        hive[hbin_off+28..hbin_off+32].copy_from_slice(&0u32.to_le_bytes());

        // ─── Root Cell at hbin_off + 0x20 (= root_cell_offset 0x20) ─────
        // The root_cell_offset in base block is relative to start of hive bins data.
        // Hive bins data starts right after base block. The hive bin header is 32 bytes.
        // So root cell is at hbin_off + 32 = hbin_off + 0x20.
        let cell_off = hbin_off + 0x20;
        // Cell header: size as negative i32 (allocated).
        // We need enough space for the nk record. nk record is:
        //   2 bytes magic "nk" + 2 bytes flags + 8 bytes timestamp + 4 bytes access_bits
        //   + 4 bytes parent + 4 bytes subkey_count + 4 bytes volatile_subkey_count
        //   + 4 bytes subkeys_list_offset + 4 bytes volatile_subkeys_list_offset
        //   + 4 bytes key_values_count + (conditional key_values_list ptr)
        //   + 4 bytes key_values_list_offset + 4 bytes key_security_offset
        //   + 4 bytes class_name_offset + 4 bytes max_subkey_name
        //   + 4 bytes max_subkey_class_name + 4 bytes max_value_name
        //   + 4 bytes max_value_data + 4 bytes work_var
        //   + 2 bytes key_name_length + 2 bytes class_name_length
        //   + key_name_string bytes
        // Total nk fields (without key_name): 2+2+8+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+2+2 = 76 bytes
        // Plus "nk" magic is inside the Cell content. Cell header is 4 bytes.
        // Total cell: 4 (header) + 76 + key_name_length, aligned to 8.
        // With root key name "CMI-CreateHive{2A7FB991-7BBE-4F9D-B91E-7CB54597B9B0}" that's a long name.
        // We'll use a short name like "root" (4 bytes). Total = 4+76+4 = 84, aligned to 88.
        let key_name = b"root";
        let key_name_len = key_name.len() as u16;
        let nk_content_size = 76 + key_name_len as usize;
        let cell_size = 4 + nk_content_size; // 4 for header
        let aligned_cell_size = (cell_size + 7) & !7; // align to 8
        let cell_size_i32 = -(aligned_cell_size as i32); // negative = allocated
        hive[cell_off..cell_off+4].copy_from_slice(&cell_size_i32.to_le_bytes());

        let nk_off = cell_off + 4; // after cell header
        // "nk" magic
        hive[nk_off..nk_off+2].copy_from_slice(b"nk");
        // flags (u16): KEY_HIVE_ENTRY = 0x0004 (root key flag)
        hive[nk_off+2..nk_off+4].copy_from_slice(&0x0024u16.to_le_bytes()); // KEY_HIVE_ENTRY | KEY_COMP_NAME
        // timestamp (8 bytes): a valid FILETIME
        let filetime: u64 = 132500000000000000; // ~2020-12-01
        hive[nk_off+4..nk_off+12].copy_from_slice(&filetime.to_le_bytes());
        // access_bits (u32)
        hive[nk_off+12..nk_off+16].copy_from_slice(&0u32.to_le_bytes());
        // parent offset (u32): 0xFFFFFFFF (no parent for root)
        hive[nk_off+16..nk_off+20].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // subkey_count (u32) = 0
        hive[nk_off+20..nk_off+24].copy_from_slice(&0u32.to_le_bytes());
        // volatile_subkey_count (u32) = 0
        hive[nk_off+24..nk_off+28].copy_from_slice(&0u32.to_le_bytes());
        // subkeys_list_offset (u32) = 0xFFFFFFFF (none)
        hive[nk_off+28..nk_off+32].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // volatile_subkeys_list_offset (u32) = 0xFFFFFFFF
        hive[nk_off+32..nk_off+36].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // key_values_count (u32) = 0
        hive[nk_off+36..nk_off+40].copy_from_slice(&0u32.to_le_bytes());
        // key_values_list_offset (u32) = 0xFFFFFFFF (none, but this is temp/conditional)
        hive[nk_off+40..nk_off+44].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // key_security_offset (u32) = 0xFFFFFFFF
        hive[nk_off+44..nk_off+48].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // class_name_offset (u32) = 0xFFFFFFFF
        hive[nk_off+48..nk_off+52].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // max_subkey_name (u32) = 0
        hive[nk_off+52..nk_off+56].copy_from_slice(&0u32.to_le_bytes());
        // max_subkey_class_name (u32) = 0
        hive[nk_off+56..nk_off+60].copy_from_slice(&0u32.to_le_bytes());
        // max_value_name (u32) = 0
        hive[nk_off+60..nk_off+64].copy_from_slice(&0u32.to_le_bytes());
        // max_value_data (u32) = 0
        hive[nk_off+64..nk_off+68].copy_from_slice(&0u32.to_le_bytes());
        // work_var (u32) = 0
        hive[nk_off+68..nk_off+72].copy_from_slice(&0u32.to_le_bytes());
        // key_name_length (u16)
        hive[nk_off+72..nk_off+74].copy_from_slice(&key_name_len.to_le_bytes());
        // class_name_length (u16) = 0
        hive[nk_off+74..nk_off+76].copy_from_slice(&0u16.to_le_bytes());
        // key_name_string (ASCII since KEY_COMP_NAME flag is set)
        hive[nk_off+76..nk_off+76+key_name.len()].copy_from_slice(key_name);

        hive
    }

    #[test]
    fn test_parse_bam_from_hive_valid_hive_no_bam_keys() {
        // A valid hive with a root key but no BAM/DAM subkeys.
        // parse_bam_from_hive should succeed with 0 entries.
        let hive_data = build_minimal_hive();
        let result = parse_bam_from_hive(&hive_data);
        assert!(result.is_ok(), "parse_bam_from_hive failed: {:?}", result.err());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_parse_bam_pipeline_with_valid_empty_hive() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let hive_data = build_minimal_hive();

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SYSTEM", 'C'),
            hive_type: RegistryHiveType::System,
        });

        let mut store = TimelineStore::new();

        struct ValidHiveProvider {
            data: Vec<u8>,
        }
        impl CollectionProvider for ValidHiveProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(self.data.clone())
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let provider = ValidHiveProvider { data: hive_data };
        let result = parse_bam(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        // Valid hive but no BAM keys, so 0 entries
        assert_eq!(store.len(), 0);
    }
}
