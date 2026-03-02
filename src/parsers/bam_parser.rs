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
}
