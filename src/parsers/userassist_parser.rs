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

// ─── Constants ───────────────────────────────────────────────────────────────

/// GUID for executable file execution tracking.
const GUID_EXE: &str = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}";

/// GUID for shortcut file execution tracking.
const GUID_SHORTCUT: &str = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}";

/// Minimum size of a UserAssist value data blob (Win7+ format: 72 bytes).
const USERASSIST_MIN_SIZE_WIN7: usize = 72;

/// Size of the older WinXP format (16 bytes).
const USERASSIST_SIZE_WINXP: usize = 16;

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

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    if offset + 8 > data.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}

/// ROT13 decode: rotate each ASCII letter by 13 positions.
///
/// Used to decode UserAssist value names, which are ROT13-encoded program paths.
pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static USERASSIST_ID_COUNTER: AtomicU64 = AtomicU64::new(0x5541_0000_0000_0000); // "UA" prefix

fn next_userassist_id() -> u64 {
    USERASSIST_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Parsed entry ────────────────────────────────────────────────────────────

/// A parsed UserAssist entry.
#[derive(Debug, Clone)]
pub struct UserAssistEntry {
    /// Decoded program path (after ROT13 decoding).
    pub path: String,
    /// Run count.
    pub run_count: u32,
    /// Focus count (Win7+).
    pub focus_count: Option<u32>,
    /// Focus time in milliseconds (Win7+).
    pub focus_time_ms: Option<u32>,
    /// Last execution timestamp.
    pub last_run_time: Option<DateTime<Utc>>,
    /// Which GUID category this came from.
    pub guid: String,
}

/// Parse a UserAssist value data blob.
///
/// Win7+ format (72 bytes):
///   - Offset 4: Run count (u32 LE)
///   - Offset 8: Focus count (u32 LE)
///   - Offset 12: Focus time in ms (u32 LE)
///   - Offset 60: Last run timestamp (FILETIME, u64 LE)
///
/// WinXP format (16 bytes):
///   - Offset 4: Run count (u32 LE)
///   - Offset 8: Last run timestamp (FILETIME, u64 LE)
pub fn parse_userassist_value(data: &[u8]) -> Option<(u32, Option<u32>, Option<u32>, Option<DateTime<Utc>>)> {
    if data.len() >= USERASSIST_MIN_SIZE_WIN7 {
        // Win7+ format
        let run_count = read_u32_le(data, 4)?;
        let focus_count = read_u32_le(data, 8);
        let focus_time = read_u32_le(data, 12);
        let last_run = read_u64_le(data, 60).and_then(filetime_to_datetime);
        Some((run_count, focus_count, focus_time, last_run))
    } else if data.len() >= USERASSIST_SIZE_WINXP {
        // WinXP format
        let run_count = read_u32_le(data, 4)?;
        let last_run = read_u64_le(data, 8).and_then(filetime_to_datetime);
        Some((run_count, None, None, last_run))
    } else {
        None
    }
}

// ─── Registry navigation ─────────────────────────────────────────────────────

/// Parse UserAssist entries from an NTUSER.DAT hive.
fn parse_userassist_from_hive(data: &[u8]) -> Result<Vec<UserAssistEntry>> {
    let mut entries = Vec::new();

    let mut hive = Hive::new(
        Cursor::new(data.to_vec()),
        HiveParseMode::NormalWithBaseBlock,
    )
    .context("Failed to parse NTUSER.DAT registry hive")?
    .treat_hive_as_clean();

    let root_key = hive
        .root_key_node()
        .context("Failed to get root key from NTUSER.DAT")?;

    let guids = [GUID_EXE, GUID_SHORTCUT];

    for guid in &guids {
        let path = format!(
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{}\Count",
            guid
        );

        let count_key = match root_key.subpath(path.as_str(), &mut hive) {
            Ok(Some(key)) => key,
            Ok(None) => {
                debug!("UserAssist path not found: {}", path);
                continue;
            }
            Err(e) => {
                debug!("Error accessing UserAssist path {}: {}", path, e);
                continue;
            }
        };

        let count_key_ref = count_key.borrow();
        let values = count_key_ref.values();

        for value in values.iter() {
            let encoded_name = value.name().to_string();

            // Skip empty or metadata values
            if encoded_name.is_empty() || encoded_name == "UEME_CTLSESSION" {
                continue;
            }

            let binary_data = match value.value() {
                RegistryValue::RegBinary(data) => data,
                _ => continue,
            };

            let (run_count, focus_count, focus_time, last_run) =
                match parse_userassist_value(binary_data) {
                    Some(v) => v,
                    None => continue,
                };

            // Decode the ROT13-encoded path
            let decoded_path = rot13(&encoded_name);

            entries.push(UserAssistEntry {
                path: decoded_path,
                run_count,
                focus_count,
                focus_time_ms: focus_time,
                last_run_time: last_run,
                guid: guid.to_string(),
            });
        }
    }

    debug!("Found {} UserAssist entries", entries.len());
    Ok(entries)
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse UserAssist entries from NTUSER.DAT registry hives.
///
/// The UserAssist key tracks program execution evidence, including:
/// - Executable file executions
/// - Shortcut file executions
/// - Run counts and focus times
/// - Last execution timestamps
///
/// Registry path:
///   NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
pub fn parse_userassist(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    // Find NTUSER.DAT hives
    let ntuser_hives: Vec<_> = manifest
        .registry_hives
        .iter()
        .filter(|h| matches!(h.hive_type, RegistryHiveType::NtUser { .. }))
        .collect();

    if ntuser_hives.is_empty() {
        debug!("No NTUSER.DAT hives found in manifest");
        return Ok(());
    }

    for hive_entry in &ntuser_hives {
        let data = match provider.open_file(&hive_entry.path) {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    "Failed to read NTUSER.DAT hive {}: {}",
                    hive_entry.path, e
                );
                continue;
            }
        };

        debug!(
            "Parsing UserAssist from NTUSER.DAT: {} ({} bytes)",
            hive_entry.path,
            data.len()
        );

        let ua_entries = match parse_userassist_from_hive(&data) {
            Ok(entries) => entries,
            Err(e) => {
                warn!(
                    "Failed to parse UserAssist from {}: {}",
                    hive_entry.path, e
                );
                continue;
            }
        };

        debug!(
            "Found {} UserAssist entries from {}",
            ua_entries.len(),
            hive_entry.path
        );

        for ua_entry in &ua_entries {
            let primary_timestamp = match ua_entry.last_run_time {
                Some(ts) => ts,
                None => continue, // Skip entries without timestamps
            };

            let entry = TimelineEntry {
                entity_id: EntityId::Generated(next_userassist_id()),
                path: ua_entry.path.clone(),
                primary_timestamp,
                event_type: EventType::Execute,
                timestamps: TimestampSet::default(),
                sources: smallvec![ArtifactSource::UserAssist],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
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
    fn test_rot13_lowercase() {
        assert_eq!(rot13("abcdefghijklmnopqrstuvwxyz"), "nopqrstuvwxyzabcdefghijklm");
    }

    #[test]
    fn test_rot13_uppercase() {
        assert_eq!(rot13("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), "NOPQRSTUVWXYZABCDEFGHIJKLM");
    }

    #[test]
    fn test_rot13_mixed() {
        // "C:\Windows\System32\cmd.exe" ROT13 encoded
        let encoded = r"P:\Jvaqbjf\Flfgrz32\pzq.rkr";
        let decoded = rot13(encoded);
        assert_eq!(decoded, r"C:\Windows\System32\cmd.exe");
    }

    #[test]
    fn test_rot13_non_alpha() {
        assert_eq!(rot13("123-456.789"), "123-456.789");
    }

    #[test]
    fn test_rot13_roundtrip() {
        let original = r"C:\Users\Admin\Desktop\malware.exe";
        let encoded = rot13(original);
        let decoded = rot13(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_parse_userassist_value_win7() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;

        let mut data = vec![0u8; 72];
        // Run count at offset 4
        data[4..8].copy_from_slice(&42u32.to_le_bytes());
        // Focus count at offset 8
        data[8..12].copy_from_slice(&10u32.to_le_bytes());
        // Focus time at offset 12
        data[12..16].copy_from_slice(&5000u32.to_le_bytes());
        // Last run time at offset 60
        data[60..68].copy_from_slice(&filetime.to_le_bytes());

        let result = parse_userassist_value(&data);
        assert!(result.is_some());

        let (run_count, focus_count, focus_time, last_run) = result.unwrap();
        assert_eq!(run_count, 42);
        assert_eq!(focus_count, Some(10));
        assert_eq!(focus_time, Some(5000));
        assert_eq!(last_run, Some(dt));
    }

    #[test]
    fn test_parse_userassist_value_winxp() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;

        let mut data = vec![0u8; 16];
        // Run count at offset 4
        data[4..8].copy_from_slice(&7u32.to_le_bytes());
        // Last run time at offset 8
        data[8..16].copy_from_slice(&filetime.to_le_bytes());

        let result = parse_userassist_value(&data);
        assert!(result.is_some());

        let (run_count, focus_count, focus_time, last_run) = result.unwrap();
        assert_eq!(run_count, 7);
        assert!(focus_count.is_none());
        assert!(focus_time.is_none());
        assert_eq!(last_run, Some(dt));
    }

    #[test]
    fn test_parse_userassist_value_too_short() {
        let data = vec![0u8; 8];
        assert!(parse_userassist_value(&data).is_none());
    }

    #[test]
    fn test_parse_userassist_value_zero_timestamp() {
        let mut data = vec![0u8; 72];
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        // Timestamp left at 0

        let result = parse_userassist_value(&data);
        assert!(result.is_some());
        let (run_count, _, _, last_run) = result.unwrap();
        assert_eq!(run_count, 1);
        assert!(last_run.is_none());
    }

    #[test]
    fn test_userassist_entry_creation() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();

        let ua_entry = UserAssistEntry {
            path: r"C:\Windows\System32\cmd.exe".to_string(),
            run_count: 42,
            focus_count: Some(10),
            focus_time_ms: Some(5000),
            last_run_time: Some(dt),
            guid: GUID_EXE.to_string(),
        };

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_userassist_id()),
            path: ua_entry.path.clone(),
            primary_timestamp: ua_entry.last_run_time.unwrap(),
            event_type: EventType::Execute,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::UserAssist],
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
        let result = parse_userassist(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_filetime_negative_secs() {
        let filetime = 1u64;
        assert!(filetime_to_datetime(filetime).is_none());
    }

    #[test]
    fn test_filetime_subsecond_precision() {
        use chrono::TimeZone;
        let dt_base = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let secs = dt_base.timestamp() + 11_644_473_600;
        // Add 3_333_333 * 100ns = ~333ms
        let filetime = (secs as u64) * 10_000_000 + 3_333_333;
        let result = filetime_to_datetime(filetime).unwrap();
        assert_eq!(result.timestamp(), dt_base.timestamp());
        assert_eq!(result.timestamp_subsec_nanos(), 333_333_300);
    }

    #[test]
    fn test_filetime_epoch_boundary() {
        use chrono::TimeZone;
        let epoch_diff: u64 = 11_644_473_600;
        let filetime = epoch_diff * 10_000_000;
        let result = filetime_to_datetime(filetime).unwrap();
        assert_eq!(result, Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap());
    }

    #[test]
    fn test_read_u32_le_valid() {
        let data = [0x78, 0x56, 0x34, 0x12, 0xFF];
        assert_eq!(read_u32_le(&data, 0), Some(0x12345678));
    }

    #[test]
    fn test_read_u32_le_out_of_bounds() {
        let data = [0x01, 0x02, 0x03];
        assert!(read_u32_le(&data, 0).is_none());
    }

    #[test]
    fn test_read_u32_le_with_offset() {
        let data = [0xAA, 0xBB, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&data, 2), Some(0x12345678));
    }

    #[test]
    fn test_read_u64_le_valid() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u64_le(&data, 0), Some(0x0807060504030201));
    }

    #[test]
    fn test_read_u64_le_out_of_bounds() {
        let data = [0u8; 7];
        assert!(read_u64_le(&data, 0).is_none());
    }

    #[test]
    fn test_read_u64_le_with_offset() {
        let data = [0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u64_le(&data, 2), Some(0x0807060504030201));
    }

    #[test]
    fn test_rot13_empty_string() {
        assert_eq!(rot13(""), "");
    }

    #[test]
    fn test_rot13_single_char_a() {
        assert_eq!(rot13("a"), "n");
    }

    #[test]
    fn test_rot13_single_char_n() {
        assert_eq!(rot13("n"), "a");
    }

    #[test]
    fn test_rot13_single_char_z() {
        assert_eq!(rot13("z"), "m");
    }

    #[test]
    fn test_rot13_single_char_m() {
        assert_eq!(rot13("m"), "z");
    }

    #[test]
    fn test_rot13_uppercase_a() {
        assert_eq!(rot13("A"), "N");
    }

    #[test]
    fn test_rot13_uppercase_z() {
        assert_eq!(rot13("Z"), "M");
    }

    #[test]
    fn test_rot13_digits_unchanged() {
        assert_eq!(rot13("0123456789"), "0123456789");
    }

    #[test]
    fn test_rot13_special_chars_unchanged() {
        assert_eq!(rot13(r"{}[]()!@#$%^&*"), r"{}[]()!@#$%^&*");
    }

    #[test]
    fn test_rot13_path_separators_preserved() {
        assert_eq!(rot13(r"\\?\"), r"\\?\");
        assert_eq!(rot13("/"), "/");
        assert_eq!(rot13(":"), ":");
    }

    #[test]
    fn test_rot13_guid_format() {
        // GUIDs in UserAssist paths are ROT13 encoded too
        // Start from the known decoded value and verify roundtrip
        let decoded_guid = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}";
        let encoded = rot13(decoded_guid);
        let roundtrip = rot13(&encoded);
        assert_eq!(roundtrip, decoded_guid);
    }

    #[test]
    fn test_rot13_realistic_userassist_path() {
        // A realistic encoded UserAssist value name
        let encoded = r"{1NP14R64-53F0-4084-N2NP-34765Q08D2O1}\Zvpebfbsg.Jvaqbjf.Rkcybere";
        let decoded = rot13(encoded);
        assert!(decoded.contains("Microsoft.Windows.Explorer"));
    }

    #[test]
    fn test_rot13_boundary_chars() {
        // Test the exact boundary characters
        assert_eq!(rot13("mM"), "zZ"); // m->z, M->Z
        assert_eq!(rot13("nN"), "aA"); // n->a, N->A
        assert_eq!(rot13("aA"), "nN"); // a->n, A->N
    }

    #[test]
    fn test_parse_userassist_value_exactly_winxp_size() {
        let mut data = vec![0u8; USERASSIST_SIZE_WINXP]; // exactly 16
        data[4..8].copy_from_slice(&5u32.to_le_bytes());
        let result = parse_userassist_value(&data);
        assert!(result.is_some());
        let (run_count, focus_count, focus_time, _) = result.unwrap();
        assert_eq!(run_count, 5);
        assert!(focus_count.is_none());
        assert!(focus_time.is_none());
    }

    #[test]
    fn test_parse_userassist_value_between_xp_and_win7() {
        // Size between 16 and 72: should use WinXP format
        let mut data = vec![0u8; 40];
        data[4..8].copy_from_slice(&3u32.to_le_bytes());
        let result = parse_userassist_value(&data);
        assert!(result.is_some());
        let (run_count, focus_count, focus_time, _) = result.unwrap();
        assert_eq!(run_count, 3);
        assert!(focus_count.is_none());
        assert!(focus_time.is_none());
    }

    #[test]
    fn test_parse_userassist_value_larger_than_win7() {
        // Larger than 72 bytes: should still use Win7 format
        let mut data = vec![0u8; 100];
        data[4..8].copy_from_slice(&99u32.to_le_bytes());
        data[8..12].copy_from_slice(&50u32.to_le_bytes());
        data[12..16].copy_from_slice(&12000u32.to_le_bytes());
        let result = parse_userassist_value(&data);
        assert!(result.is_some());
        let (run_count, focus_count, focus_time, _) = result.unwrap();
        assert_eq!(run_count, 99);
        assert_eq!(focus_count, Some(50));
        assert_eq!(focus_time, Some(12000));
    }

    #[test]
    fn test_parse_userassist_value_zero_run_count() {
        let mut data = vec![0u8; 72];
        // run_count = 0
        let result = parse_userassist_value(&data);
        assert!(result.is_some());
        let (run_count, _, _, _) = result.unwrap();
        assert_eq!(run_count, 0);
    }

    #[test]
    fn test_parse_userassist_value_max_run_count() {
        let mut data = vec![0u8; 72];
        data[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        let result = parse_userassist_value(&data);
        assert!(result.is_some());
        let (run_count, _, _, _) = result.unwrap();
        assert_eq!(run_count, u32::MAX);
    }

    #[test]
    fn test_parse_userassist_value_15_bytes() {
        // 15 bytes: less than USERASSIST_SIZE_WINXP (16) => None
        let data = vec![0u8; 15];
        assert!(parse_userassist_value(&data).is_none());
    }

    #[test]
    fn test_parse_userassist_value_empty() {
        let data: Vec<u8> = Vec::new();
        assert!(parse_userassist_value(&data).is_none());
    }

    #[test]
    fn test_userassist_entry_clone() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let entry = UserAssistEntry {
            path: r"C:\test.exe".to_string(),
            run_count: 5,
            focus_count: Some(3),
            focus_time_ms: Some(1000),
            last_run_time: Some(dt),
            guid: GUID_EXE.to_string(),
        };
        let cloned = entry.clone();
        assert_eq!(cloned.path, entry.path);
        assert_eq!(cloned.run_count, entry.run_count);
        assert_eq!(cloned.focus_count, entry.focus_count);
        assert_eq!(cloned.focus_time_ms, entry.focus_time_ms);
        assert_eq!(cloned.last_run_time, entry.last_run_time);
        assert_eq!(cloned.guid, entry.guid);
    }

    #[test]
    fn test_userassist_entry_debug() {
        let entry = UserAssistEntry {
            path: "test.exe".to_string(),
            run_count: 1,
            focus_count: None,
            focus_time_ms: None,
            last_run_time: None,
            guid: GUID_SHORTCUT.to_string(),
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("UserAssistEntry"));
        assert!(debug_str.contains("test.exe"));
    }

    #[test]
    fn test_userassist_entry_no_last_run() {
        let entry = UserAssistEntry {
            path: "calc.exe".to_string(),
            run_count: 10,
            focus_count: Some(5),
            focus_time_ms: Some(2000),
            last_run_time: None,
            guid: GUID_EXE.to_string(),
        };
        assert!(entry.last_run_time.is_none());
        assert_eq!(entry.run_count, 10);
    }

    #[test]
    fn test_next_userassist_id_monotonic() {
        let id1 = next_userassist_id();
        let id2 = next_userassist_id();
        let id3 = next_userassist_id();
        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[test]
    fn test_next_userassist_id_has_ua_prefix() {
        let id = next_userassist_id();
        assert_eq!((id >> 48) & 0xFFFF, 0x5541);
    }

    #[test]
    fn test_guid_constants() {
        assert_eq!(GUID_EXE, "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}");
        assert_eq!(GUID_SHORTCUT, "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}");
    }

    #[test]
    fn test_userassist_size_constants() {
        assert_eq!(USERASSIST_MIN_SIZE_WIN7, 72);
        assert_eq!(USERASSIST_SIZE_WINXP, 16);
    }

    #[test]
    fn test_userassist_entry_with_shortcut_guid() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 3, 1, 0, 0, 0).unwrap();
        let entry = UserAssistEntry {
            path: r"C:\Users\admin\Desktop\tool.lnk".to_string(),
            run_count: 1,
            focus_count: Some(1),
            focus_time_ms: Some(500),
            last_run_time: Some(dt),
            guid: GUID_SHORTCUT.to_string(),
        };
        assert_eq!(entry.guid, GUID_SHORTCUT);
        assert!(entry.path.ends_with(".lnk"));
    }

    #[test]
    fn test_parse_userassist_value_win7_with_zero_focus() {
        let mut data = vec![0u8; 72];
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // run_count
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // focus_count = 0
        data[12..16].copy_from_slice(&0u32.to_le_bytes()); // focus_time = 0
        let result = parse_userassist_value(&data);
        assert!(result.is_some());
        let (_, focus_count, focus_time, _) = result.unwrap();
        assert_eq!(focus_count, Some(0));
        assert_eq!(focus_time, Some(0));
    }

    #[test]
    fn test_rot13_unicode_unchanged() {
        // Non-ASCII characters should pass through unchanged
        let input = "\u{00e9}\u{00f1}\u{00fc}"; // e-acute, n-tilde, u-umlaut
        assert_eq!(rot13(input), input);
    }

    #[test]
    fn test_timeline_entry_from_userassist_source() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_userassist_id()),
            path: r"C:\Windows\System32\cmd.exe".to_string(),
            primary_timestamp: dt,
            event_type: EventType::Execute,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::UserAssist],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };
        assert!(matches!(entry.sources[0], ArtifactSource::UserAssist));
    }

    // ─── Tests targeting uncovered lines in parse_userassist_from_hive ────

    #[test]
    fn test_parse_userassist_from_hive_invalid_data() {
        // Passing garbage data should fail to parse as a registry hive
        let data = vec![0xFFu8; 256];
        let result = parse_userassist_from_hive(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_userassist_from_hive_empty_data() {
        let result = parse_userassist_from_hive(&[]);
        assert!(result.is_err());
    }

    // ─── Tests targeting uncovered lines in parse_userassist (main fn) ───

    #[test]
    fn test_parse_userassist_with_ntuser_hive_open_error() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Users/test/NTUSER.DAT", 'C'),
            hive_type: RegistryHiveType::NtUser { username: "test".to_string() },
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

        // The provider fails to open the file, should warn and continue
        let result = parse_userassist(&FailProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_userassist_with_invalid_hive_data() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Users/test/NTUSER.DAT", 'C'),
            hive_type: RegistryHiveType::NtUser { username: "test".to_string() },
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
                // Return garbage data that won't parse as a valid hive
                Ok(vec![0xDE; 64])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        // The hive is unparseable, should warn and continue
        let result = parse_userassist(&GarbageProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_userassist_skips_non_ntuser_hives() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        // Add a SYSTEM hive, not NTUSER - should be filtered out
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SYSTEM", 'C'),
            hive_type: RegistryHiveType::System,
        });
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SOFTWARE", 'C'),
            hive_type: RegistryHiveType::Software,
        });

        let mut store = TimelineStore::new();

        struct NeverCalledProvider;
        impl CollectionProvider for NeverCalledProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                panic!("open_file should not be called for non-NTUSER hives");
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        // Only NTUSER hives are processed; SYSTEM and SOFTWARE are skipped
        let result = parse_userassist(&NeverCalledProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_userassist_value_winxp_with_zero_timestamp() {
        // WinXP format with zero timestamp in FILETIME field
        let mut data = vec![0u8; 16];
        data[4..8].copy_from_slice(&3u32.to_le_bytes());
        // Timestamp bytes all zero -> filetime_to_datetime returns None
        let result = parse_userassist_value(&data);
        assert!(result.is_some());
        let (run_count, focus_count, focus_time, last_run) = result.unwrap();
        assert_eq!(run_count, 3);
        assert!(focus_count.is_none());
        assert!(focus_time.is_none());
        assert!(last_run.is_none());
    }

    #[test]
    fn test_parse_userassist_value_win7_large_values() {
        let mut data = vec![0u8; 72];
        data[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        data[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        data[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        let result = parse_userassist_value(&data);
        assert!(result.is_some());
        let (run_count, focus_count, focus_time, _) = result.unwrap();
        assert_eq!(run_count, u32::MAX);
        assert_eq!(focus_count, Some(u32::MAX));
        assert_eq!(focus_time, Some(u32::MAX));
    }

    #[test]
    fn test_read_u32_le_offset_at_exact_boundary() {
        // Data has exactly 4 bytes at offset 2 -> should succeed
        let data = [0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u32_le(&data, 2), Some(0x04030201));
        // Offset 3 leaves only 3 bytes -> should fail
        assert!(read_u32_le(&data, 3).is_none());
    }

    #[test]
    fn test_read_u64_le_offset_at_exact_boundary() {
        let data = [0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u64_le(&data, 2), Some(0x0807060504030201));
        // Offset 3 leaves only 7 bytes -> should fail
        assert!(read_u64_le(&data, 3).is_none());
    }

    #[test]
    fn test_filetime_very_large_value() {
        // Very large filetime that's still valid (far future)
        let filetime: u64 = 200_000_000_000_000_000; // year ~2434
        let result = filetime_to_datetime(filetime);
        assert!(result.is_some());
        let dt = result.unwrap();
        assert!(dt.timestamp() > 0);
    }

    #[test]
    fn test_parse_userassist_value_exactly_71_bytes() {
        // 71 bytes: less than WIN7 min (72) but more than WINXP (16) -> WinXP format
        let mut data = vec![0u8; 71];
        data[4..8].copy_from_slice(&2u32.to_le_bytes());
        let result = parse_userassist_value(&data);
        assert!(result.is_some());
        let (run_count, focus_count, focus_time, _) = result.unwrap();
        assert_eq!(run_count, 2);
        assert!(focus_count.is_none());
        assert!(focus_time.is_none());
    }

    #[test]
    fn test_parse_userassist_value_exactly_72_bytes() {
        // Exactly 72 -> WIN7 format
        let mut data = vec![0u8; 72];
        data[4..8].copy_from_slice(&10u32.to_le_bytes());
        data[8..12].copy_from_slice(&5u32.to_le_bytes());
        data[12..16].copy_from_slice(&3000u32.to_le_bytes());
        let result = parse_userassist_value(&data);
        assert!(result.is_some());
        let (run_count, focus_count, focus_time, _) = result.unwrap();
        assert_eq!(run_count, 10);
        assert_eq!(focus_count, Some(5));
        assert_eq!(focus_time, Some(3000));
    }

    #[test]
    fn test_rot13_full_alphabet_roundtrip() {
        let original = "The Quick Brown Fox Jumps Over The Lazy Dog 0123456789!@#";
        let encoded = rot13(original);
        let decoded = rot13(&encoded);
        assert_eq!(decoded, original);
        // Encoded should differ from original (at least for alpha chars)
        assert_ne!(encoded, original);
    }

    #[test]
    fn test_userassist_entry_with_none_fields() {
        let entry = UserAssistEntry {
            path: "path_only".to_string(),
            run_count: 0,
            focus_count: None,
            focus_time_ms: None,
            last_run_time: None,
            guid: String::new(),
        };
        assert_eq!(entry.path, "path_only");
        assert_eq!(entry.run_count, 0);
        assert!(entry.focus_count.is_none());
        assert!(entry.focus_time_ms.is_none());
        assert!(entry.last_run_time.is_none());
        assert!(entry.guid.is_empty());
    }
}
