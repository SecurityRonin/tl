use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use log::{debug, warn};
use nt_hive2::{CleanHive, Hive, HiveParseMode, SubPath};
use smallvec::smallvec;
use std::io::Cursor;

use crate::collection::manifest::{ArtifactManifest, RegistryHiveType};
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a Windows FILETIME (100ns intervals since 1601-01-01) to DateTime<Utc>.
#[cfg(test)]
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

/// Try to extract a folder name from a shell item ID (ItemIDList entry).
///
/// Shell items have many formats; we attempt to extract folder names from the
/// most common types:
/// - Type 0x1F: Root folder (GUID-based, e.g., "My Computer")
/// - Type 0x2F: Drive item (e.g., "C:\")
/// - Type 0x31/0x32/0x35: File entry (contains short 8.3 name and optional Unicode name)
///
/// This is a minimal implementation -- full shellbag parsing requires handling
/// dozens of shell item types (ZIP items, network items, delegate items, etc.).
pub fn extract_name_from_shell_item(data: &[u8]) -> Option<String> {
    if data.len() < 3 {
        return None;
    }

    let item_type = data[2];

    match item_type {
        // Root folder (known folder GUID)
        0x1F => {
            if data.len() >= 18 {
                // GUID at offset 4 in known format -- map to friendly names
                let guid_bytes = &data[4..20];
                let name = known_folder_name(guid_bytes);
                Some(name.to_string())
            } else {
                None
            }
        }
        // Volume/Drive item
        0x2F | 0x23 | 0x25 | 0x29 | 0x2A | 0x2E => {
            if data.len() >= 4 {
                // Drive letter typically at offset 3
                let drive_str: String = data[3..]
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as char)
                    .collect();
                if !drive_str.is_empty() {
                    Some(drive_str)
                } else {
                    None
                }
            } else {
                None
            }
        }
        // File entry items (most common shellbag type)
        0x30..=0x3F => extract_file_entry_name(data),
        // Network share items
        0x41..=0x47 | 0xC3 => {
            // Network name typically starts at offset 5
            if data.len() > 5 {
                let name: String = data[5..]
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as char)
                    .collect();
                if !name.is_empty() {
                    Some(name)
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => {
            // Unknown item type -- try to extract any ASCII string as a fallback
            extract_ascii_fallback(data)
        }
    }
}

/// Extract folder name from a file entry shell item (type 0x30-0x3F).
///
/// Format:
/// - Offset 0-1: Item size (u16 LE)
/// - Offset 2: Item type
/// - Offset 3: File size (u8, low byte)
/// - Offset 4-7: Last modified date (FAT timestamp)
/// - Offset 8-9: File attributes
/// - Offset 10+: Short name (8.3 format, null-terminated)
/// - After short name (padded to even offset): optional Unicode long name
fn extract_file_entry_name(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }

    // Extract the short (8.3) name starting at offset 14 or search for it
    let short_name_start = if data.len() > 14 {
        14
    } else {
        return None;
    };

    // Read short name
    let short_name: String = data[short_name_start..]
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect();

    // Try to find a Unicode long name after the short name
    // Scan forward past the short name and padding to find UTF-16LE data
    let short_name_end = short_name_start + short_name.len() + 1;
    // Align to even offset
    let search_start = if short_name_end % 2 == 1 {
        short_name_end + 1
    } else {
        short_name_end
    };

    // Look for a Unicode name somewhere in the remaining data
    // The Unicode long name is typically preceded by some metadata bytes
    if let Some(unicode_name) = find_unicode_name(&data[search_start..]) {
        if !unicode_name.is_empty() {
            return Some(unicode_name);
        }
    }

    if !short_name.is_empty() {
        Some(short_name)
    } else {
        None
    }
}

/// Attempt to find a Unicode (UTF-16LE) filename in the data.
fn find_unicode_name(data: &[u8]) -> Option<String> {
    // Scan for sequences that look like UTF-16LE printable characters
    // (non-null byte followed by 0x00 repeated at least 3 times)
    if data.len() < 4 {
        return None;
    }

    for start in 0..data.len().saturating_sub(4) {
        // Look for a UTF-16LE sequence: printable byte, 0x00, printable byte, 0x00
        if data[start] >= 0x20
            && data[start] < 0x7F
            && start + 1 < data.len()
            && data[start + 1] == 0x00
            && start + 2 < data.len()
            && data[start + 2] >= 0x20
            && start + 3 < data.len()
            && data[start + 3] == 0x00
        {
            // Found potential start of UTF-16LE string
            let u16_iter = data[start..]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .take_while(|&c| c != 0 && c >= 0x20 && c < 0xFFFE);

            let chars: Vec<u16> = u16_iter.collect();
            if chars.len() >= 2 {
                let name = String::from_utf16_lossy(&chars);
                if name.len() >= 2 {
                    return Some(name);
                }
            }
        }
    }

    None
}

/// Try to extract any ASCII string as a fallback for unknown item types.
fn extract_ascii_fallback(data: &[u8]) -> Option<String> {
    if data.len() < 6 {
        return None;
    }

    // Try starting at various offsets
    for offset in [3, 4, 5, 6, 8, 10, 14] {
        if offset >= data.len() {
            continue;
        }
        let s: String = data[offset..]
            .iter()
            .take_while(|&&b| b >= 0x20 && b < 0x7F)
            .map(|&b| b as char)
            .collect();
        if s.len() >= 3 {
            return Some(s);
        }
    }

    None
}

/// Map a known folder GUID to a friendly name.
fn known_folder_name(guid_bytes: &[u8]) -> &'static str {
    if guid_bytes.len() < 16 {
        return "Unknown";
    }

    // Common known folder GUIDs (as raw bytes)
    // {20D04FE0-3AEA-1069-A2D8-08002B30309D} = "My Computer"
    if guid_bytes[0] == 0xE0 && guid_bytes[1] == 0x4F && guid_bytes[2] == 0xD0 && guid_bytes[3] == 0x20 {
        return "My Computer";
    }
    // {450D8FBA-AD25-11D0-98A8-0800361B1103} = "My Documents"
    if guid_bytes[0] == 0xBA && guid_bytes[1] == 0x8F && guid_bytes[2] == 0x0D && guid_bytes[3] == 0x45 {
        return "My Documents";
    }
    // {645FF040-5081-101B-9F08-00AA002F954E} = "Recycle Bin"
    if guid_bytes[0] == 0x40 && guid_bytes[1] == 0xF0 && guid_bytes[2] == 0x5F && guid_bytes[3] == 0x64 {
        return "Recycle Bin";
    }
    // {F02C1A0D-BE21-4350-88B0-7367FC96EF3C} = "Network"
    if guid_bytes[0] == 0x0D && guid_bytes[1] == 0x1A && guid_bytes[2] == 0x2C && guid_bytes[3] == 0xF0 {
        return "Network";
    }

    "Known Folder"
}

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static SHELLBAG_ID_COUNTER: AtomicU64 = AtomicU64::new(0x5342_0000_0000_0000); // "SB" prefix

fn next_shellbag_id() -> u64 {
    SHELLBAG_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Parsed entry ────────────────────────────────────────────────────────────

/// A parsed shellbag entry.
#[derive(Debug, Clone)]
pub struct ShellbagEntry {
    /// Registry path of this shellbag key.
    pub reg_path: String,
    /// Extracted folder name (if parseable).
    pub folder_name: Option<String>,
    /// Key last-written timestamp (indicates when the folder was accessed).
    pub last_accessed: DateTime<Utc>,
}

// ─── Registry tree walking ───────────────────────────────────────────────────

/// Walk the BagMRU tree recursively and collect shellbag entries.
fn walk_bagmru(
    hive: &mut Hive<Cursor<Vec<u8>>, CleanHive>,
    key: &nt_hive2::KeyNode,
    current_path: &str,
    entries: &mut Vec<ShellbagEntry>,
) {
    // Record this key's timestamp (returns &DateTime<Utc>)
    let timestamp = Some(*key.timestamp());

    // Try to extract folder names from the numbered values
    let mut folder_names = Vec::new();
    let values = key.values();
    for value in values.iter() {
        let name = value.name().to_string();
        // Skip MRUListEx and NodeSlot values
        if name == "MRUListEx" || name == "NodeSlot" || name == "NodeSlots" {
            continue;
        }
        // Numbered values (0, 1, 2, ...) contain shell item data
        if name.chars().all(|c| c.is_ascii_digit()) {
            if let nt_hive2::RegistryValue::RegBinary(data) = value.value() {
                if let Some(name) = extract_name_from_shell_item(data) {
                    folder_names.push(name);
                }
            }
        }
    }

    if let Some(ts) = timestamp {
        let folder = folder_names.first().cloned();
        entries.push(ShellbagEntry {
            reg_path: current_path.to_string(),
            folder_name: folder,
            last_accessed: ts,
        });
    }

    // Recurse into numbered subkeys
    let subkeys = match key.subkeys(hive) {
        Ok(sk) => sk.clone(),
        Err(_) => return,
    };

    for subkey in subkeys.iter() {
        let sk = subkey.borrow();
        let subkey_name = sk.name().to_string();
        let subpath = format!(r"{}\{}", current_path, subkey_name);
        walk_bagmru(hive, &sk, &subpath, entries);
    }
}

/// Parse shellbag entries from a UsrClass.dat hive.
fn parse_shellbags_from_hive(data: &[u8]) -> Result<Vec<ShellbagEntry>> {
    let mut entries = Vec::new();

    let mut hive = Hive::new(
        Cursor::new(data.to_vec()),
        HiveParseMode::NormalWithBaseBlock,
    )
    .context("Failed to parse UsrClass.dat registry hive")?
    .treat_hive_as_clean();

    let root_key = hive
        .root_key_node()
        .context("Failed to get root key from UsrClass.dat")?;

    let bagmru_path = r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU";

    let bagmru_key = match root_key.subpath(bagmru_path, &mut hive) {
        Ok(Some(key)) => key,
        Ok(None) => {
            debug!("BagMRU path not found in UsrClass.dat");
            return Ok(entries);
        }
        Err(e) => {
            debug!("Error accessing BagMRU: {}", e);
            return Ok(entries);
        }
    };

    walk_bagmru(&mut hive, &bagmru_key.borrow(), bagmru_path, &mut entries);

    debug!("Found {} shellbag entries", entries.len());
    Ok(entries)
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse shellbag entries from UsrClass.dat registry hives.
///
/// Shellbags track folder access/browsing history. The BagMRU key under
/// UsrClass.dat contains a tree structure where each subkey represents a
/// folder that was navigated to in Explorer. The key's last-written timestamp
/// indicates when the folder was last accessed.
///
/// Registry path:
///   UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
pub fn parse_shellbags(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    // Find UsrClass.dat hives
    let usrclass_hives: Vec<_> = manifest
        .registry_hives
        .iter()
        .filter(|h| matches!(h.hive_type, RegistryHiveType::UsrClass { .. }))
        .collect();

    if usrclass_hives.is_empty() {
        debug!("No UsrClass.dat hives found in manifest");
        return Ok(());
    }

    for hive_entry in &usrclass_hives {
        let data = match provider.open_file(&hive_entry.path) {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    "Failed to read UsrClass.dat hive {}: {}",
                    hive_entry.path, e
                );
                continue;
            }
        };

        debug!(
            "Parsing Shellbags from UsrClass.dat: {} ({} bytes)",
            hive_entry.path,
            data.len()
        );

        let sb_entries = match parse_shellbags_from_hive(&data) {
            Ok(entries) => entries,
            Err(e) => {
                warn!(
                    "Failed to parse Shellbags from {}: {}",
                    hive_entry.path, e
                );
                continue;
            }
        };

        debug!(
            "Found {} Shellbag entries from {}",
            sb_entries.len(),
            hive_entry.path
        );

        for sb_entry in &sb_entries {
            let display_path = if let Some(ref folder) = sb_entry.folder_name {
                format!("[Shellbag] {} ({})", folder, sb_entry.reg_path)
            } else {
                format!("[Shellbag] {}", sb_entry.reg_path)
            };

            let entry = TimelineEntry {
                entity_id: EntityId::Generated(next_shellbag_id()),
                path: display_path,
                primary_timestamp: sb_entry.last_accessed,
                event_type: EventType::FileAccess,
                timestamps: TimestampSet::default(),
                sources: smallvec![ArtifactSource::Shellbags],
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
    fn test_extract_name_drive_item() {
        // Drive item: type 0x2F, drive letter at offset 3
        let mut data = vec![0u8; 20];
        data[0..2].copy_from_slice(&20u16.to_le_bytes()); // size
        data[2] = 0x2F; // drive item type
        data[3..7].copy_from_slice(b"C:\\\0");

        let name = extract_name_from_shell_item(&data);
        assert_eq!(name, Some(r"C:\".to_string()));
    }

    #[test]
    fn test_extract_name_file_entry() {
        // File entry: type 0x31 with a short name
        let mut data = vec![0u8; 30];
        data[0..2].copy_from_slice(&30u16.to_le_bytes()); // size
        data[2] = 0x31; // file entry type
        // Short name at offset 14
        data[14..22].copy_from_slice(b"DOCUME~1");
        data[22] = 0; // null terminator

        let name = extract_name_from_shell_item(&data);
        assert!(name.is_some());
        assert!(name.unwrap().contains("DOCUME~1"));
    }

    #[test]
    fn test_extract_name_too_short() {
        let data = vec![0u8; 2];
        assert!(extract_name_from_shell_item(&data).is_none());
    }

    #[test]
    fn test_known_folder_my_computer() {
        // {20D04FE0-3AEA-1069-A2D8-08002B30309D} in raw bytes
        let guid: [u8; 16] = [
            0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30,
            0x30, 0x9D,
        ];
        assert_eq!(known_folder_name(&guid), "My Computer");
    }

    #[test]
    fn test_known_folder_recycle_bin() {
        let guid: [u8; 16] = [
            0x40, 0xF0, 0x5F, 0x64, 0x81, 0x50, 0x1B, 0x10, 0x9F, 0x08, 0x00, 0xAA, 0x00, 0x2F,
            0x95, 0x4E,
        ];
        assert_eq!(known_folder_name(&guid), "Recycle Bin");
    }

    #[test]
    fn test_known_folder_unknown() {
        let guid = [0xFF; 16];
        assert_eq!(known_folder_name(&guid), "Known Folder");
    }

    #[test]
    fn test_shellbag_entry_creation() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();

        let sb_entry = ShellbagEntry {
            reg_path: r"BagMRU\0\1".to_string(),
            folder_name: Some("Documents".to_string()),
            last_accessed: dt,
        };

        let display_path = format!(
            "[Shellbag] {} ({})",
            sb_entry.folder_name.as_ref().unwrap(),
            sb_entry.reg_path
        );

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_shellbag_id()),
            path: display_path.clone(),
            primary_timestamp: sb_entry.last_accessed,
            event_type: EventType::FileAccess,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Shellbags],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        assert_eq!(entry.event_type, EventType::FileAccess);
        assert!(entry.path.contains("Documents"));
        assert!(entry.path.contains("BagMRU"));
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
        let result = parse_shellbags(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_find_unicode_name() {
        // Build a UTF-16LE string "test.txt"
        let mut data = vec![0u8; 4]; // some padding
        let s = "test.txt";
        let utf16: Vec<u8> = s
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&utf16);
        data.extend_from_slice(&[0, 0]); // null terminator

        let result = find_unicode_name(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "test.txt");
    }

    #[test]
    fn test_find_unicode_name_empty() {
        let data = vec![0u8; 4];
        assert!(find_unicode_name(&data).is_none());
    }

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_filetime_negative_secs() {
        // Very early date before Unix epoch => secs < 0 => None
        let filetime = 10_000_000u64;
        assert!(filetime_to_datetime(filetime).is_none());
    }

    #[test]
    fn test_extract_name_root_folder_my_computer() {
        // Root folder type 0x1F, GUID for "My Computer"
        let mut data = vec![0u8; 20];
        data[0..2].copy_from_slice(&20u16.to_le_bytes());
        data[2] = 0x1F;
        // GUID bytes at offset 4
        data[4] = 0xE0;
        data[5] = 0x4F;
        data[6] = 0xD0;
        data[7] = 0x20;
        // Fill remaining GUID bytes
        data[8..20].copy_from_slice(&[0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D]);
        let name = extract_name_from_shell_item(&data);
        assert_eq!(name, Some("My Computer".to_string()));
    }

    #[test]
    fn test_extract_name_root_folder_too_short() {
        // Root folder type 0x1F but data too short for GUID
        let mut data = vec![0u8; 10];
        data[2] = 0x1F;
        assert!(extract_name_from_shell_item(&data).is_none());
    }

    #[test]
    fn test_extract_name_drive_item_all_types() {
        // Test various drive item types
        for item_type in [0x23, 0x25, 0x29, 0x2A, 0x2E] {
            let mut data = vec![0u8; 10];
            data[0..2].copy_from_slice(&10u16.to_le_bytes());
            data[2] = item_type;
            data[3..6].copy_from_slice(b"D:\0");
            let name = extract_name_from_shell_item(&data);
            assert!(name.is_some(), "type 0x{:02X} should extract a name", item_type);
        }
    }

    #[test]
    fn test_extract_name_drive_item_empty_string() {
        let mut data = vec![0u8; 10];
        data[2] = 0x2F;
        data[3] = 0; // Immediately null
        assert!(extract_name_from_shell_item(&data).is_none());
    }

    #[test]
    fn test_extract_name_drive_item_too_short() {
        let mut data = vec![0u8; 3];
        data[2] = 0x2F;
        assert!(extract_name_from_shell_item(&data).is_none());
    }

    #[test]
    fn test_extract_name_network_share() {
        let mut data = vec![0u8; 30];
        data[0..2].copy_from_slice(&30u16.to_le_bytes());
        data[2] = 0x41; // Network share type
        data[5..20].copy_from_slice(b"\\\\SERVER\\share\0");
        let name = extract_name_from_shell_item(&data);
        assert!(name.is_some());
        assert!(name.unwrap().contains("SERVER"));
    }

    #[test]
    fn test_extract_name_network_type_c3() {
        let mut data = vec![0u8; 20];
        data[2] = 0xC3;
        data[5..16].copy_from_slice(b"NETSHARE01\0");
        let name = extract_name_from_shell_item(&data);
        assert!(name.is_some());
    }

    #[test]
    fn test_extract_name_network_too_short() {
        let mut data = vec![0u8; 5];
        data[2] = 0x41;
        assert!(extract_name_from_shell_item(&data).is_none());
    }

    #[test]
    fn test_extract_name_network_empty_name() {
        let mut data = vec![0u8; 10];
        data[2] = 0x41;
        data[5] = 0; // null immediately
        assert!(extract_name_from_shell_item(&data).is_none());
    }

    #[test]
    fn test_extract_name_unknown_type_with_ascii() {
        // Unknown type that has an ASCII string at a valid offset
        let mut data = vec![0u8; 20];
        data[2] = 0xFE; // Unknown type
        data[3..11].copy_from_slice(b"FOLDER1\0");
        let name = extract_name_from_shell_item(&data);
        assert!(name.is_some());
        assert!(name.unwrap().contains("FOLDER1"));
    }

    #[test]
    fn test_extract_name_unknown_type_too_short() {
        let mut data = vec![0u8; 5];
        data[2] = 0xFE;
        assert!(extract_name_from_shell_item(&data).is_none());
    }

    #[test]
    fn test_extract_name_unknown_type_no_ascii() {
        let mut data = vec![0u8; 20];
        data[2] = 0xFE;
        // Fill with non-printable chars at all offsets
        for b in &mut data[3..] {
            *b = 0x01; // non-printable, non-zero
        }
        assert!(extract_name_from_shell_item(&data).is_none());
    }

    #[test]
    fn test_extract_file_entry_name_too_short() {
        let mut data = vec![0u8; 11];
        data[2] = 0x31;
        assert!(extract_file_entry_name(&data).is_none());
    }

    #[test]
    fn test_extract_file_entry_name_14_bytes() {
        // data.len() <= 14 -- returns None
        let mut data = vec![0u8; 14];
        data[2] = 0x31;
        assert!(extract_file_entry_name(&data).is_none());
    }

    #[test]
    fn test_extract_file_entry_with_unicode_name() {
        // Build a file entry shell item with both short name and Unicode long name
        let mut data = vec![0u8; 80];
        data[0..2].copy_from_slice(&80u16.to_le_bytes());
        data[2] = 0x32; // file entry type
        // Short name at offset 14
        data[14..22].copy_from_slice(b"DOCUME~1");
        data[22] = 0; // null terminator
        // Padding to even offset: 14 + 8 + 1 = 23 (odd) => pad to 24
        // Put a Unicode name "Documents" after some metadata
        let unicode_name = "Documents";
        let utf16: Vec<u8> = unicode_name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let unicode_start = 30;
        data[unicode_start..unicode_start + utf16.len()].copy_from_slice(&utf16);
        // null terminator for unicode
        data[unicode_start + utf16.len()] = 0;
        data[unicode_start + utf16.len() + 1] = 0;

        let name = extract_file_entry_name(&data);
        assert!(name.is_some());
        // Should find the Unicode name "Documents" instead of "DOCUME~1"
        assert_eq!(name.unwrap(), "Documents");
    }

    #[test]
    fn test_extract_file_entry_short_name_only() {
        // File entry with short name but no valid Unicode name after it
        let mut data = vec![0u8; 30];
        data[0..2].copy_from_slice(&30u16.to_le_bytes());
        data[2] = 0x31;
        data[14..18].copy_from_slice(b"TEST");
        data[18] = 0;
        // All zeroes after short name => no Unicode found

        let name = extract_file_entry_name(&data);
        assert!(name.is_some());
        assert_eq!(name.unwrap(), "TEST");
    }

    #[test]
    fn test_extract_ascii_fallback_various_offsets() {
        // Test that extract_ascii_fallback tries multiple offsets
        let mut data = vec![0u8; 20];
        data[2] = 0xFF; // unknown type
        // Put ASCII at offset 8
        data[8..14].copy_from_slice(b"MYDIR\0");
        let result = extract_ascii_fallback(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "MYDIR");
    }

    #[test]
    fn test_extract_ascii_fallback_short_strings() {
        // All ASCII strings shorter than 3 chars => None
        let mut data = vec![0u8; 20];
        data[3] = b'A';
        data[4] = b'B';
        data[5] = 0;
        assert!(extract_ascii_fallback(&data).is_none());
    }

    #[test]
    fn test_known_folder_my_documents() {
        let guid: [u8; 16] = [
            0xBA, 0x8F, 0x0D, 0x45, 0x25, 0xAD, 0xD0, 0x11, 0x98, 0xA8, 0x08, 0x00, 0x36, 0x1B,
            0x11, 0x03,
        ];
        assert_eq!(known_folder_name(&guid), "My Documents");
    }

    #[test]
    fn test_known_folder_network() {
        let guid: [u8; 16] = [
            0x0D, 0x1A, 0x2C, 0xF0, 0x21, 0xBE, 0x50, 0x43, 0x88, 0xB0, 0x73, 0x67, 0xFC, 0x96,
            0xEF, 0x3C,
        ];
        assert_eq!(known_folder_name(&guid), "Network");
    }

    #[test]
    fn test_known_folder_too_short() {
        let guid: [u8; 10] = [0; 10];
        assert_eq!(known_folder_name(&guid), "Unknown");
    }

    #[test]
    fn test_find_unicode_name_too_short() {
        let data = vec![0u8; 3];
        assert!(find_unicode_name(&data).is_none());
    }

    #[test]
    fn test_find_unicode_name_single_char() {
        // Single UTF-16 char followed by null is too short (< 2 chars)
        let mut data = vec![0u8; 6];
        data[0] = b'A';
        data[1] = 0;
        data[2] = 0;
        data[3] = 0;
        assert!(find_unicode_name(&data).is_none());
    }

    #[test]
    fn test_next_shellbag_id_increments() {
        let id1 = next_shellbag_id();
        let id2 = next_shellbag_id();
        assert!(id2 > id1);
        assert_eq!(id1 >> 48, 0x5342);
    }

    #[test]
    fn test_shellbag_entry_no_folder_name() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let sb_entry = ShellbagEntry {
            reg_path: r"BagMRU\0".to_string(),
            folder_name: None,
            last_accessed: dt,
        };
        // Test the display path with no folder name
        let display_path = if let Some(ref folder) = sb_entry.folder_name {
            format!("[Shellbag] {} ({})", folder, sb_entry.reg_path)
        } else {
            format!("[Shellbag] {}", sb_entry.reg_path)
        };
        assert_eq!(display_path, r"[Shellbag] BagMRU\0");
    }

    #[test]
    fn test_file_entry_range_0x30_to_0x3f() {
        // All types 0x30-0x3F should go to extract_file_entry_name
        for item_type in 0x30..=0x3F {
            let mut data = vec![0u8; 30];
            data[0..2].copy_from_slice(&30u16.to_le_bytes());
            data[2] = item_type;
            data[14..19].copy_from_slice(b"FILE\0");
            let result = extract_name_from_shell_item(&data);
            // Should either find "FILE" or None, but not panic
            if let Some(name) = result {
                assert!(!name.is_empty());
            }
        }
    }

    // ─── Coverage for parse_shellbags_from_hive ─────────────────────────

    #[test]
    fn test_parse_shellbags_from_hive_empty_data() {
        let result = parse_shellbags_from_hive(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_shellbags_from_hive_garbage_data() {
        let data = vec![0xFFu8; 1024];
        let result = parse_shellbags_from_hive(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_shellbags_from_hive_too_small() {
        let data = vec![0u8; 10];
        let result = parse_shellbags_from_hive(&data);
        assert!(result.is_err());
    }

    // ─── Coverage for parse_shellbags pipeline ──────────────────────────

    #[test]
    fn test_parse_shellbags_provider_fails() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        struct FailProvider;
        impl CollectionProvider for FailProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                anyhow::bail!("disk error")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Users/admin/AppData/Local/Microsoft/Windows/UsrClass.dat", 'C'),
            hive_type: RegistryHiveType::UsrClass { username: "admin".to_string() },
        });
        let mut store = TimelineStore::new();

        let result = parse_shellbags(&FailProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_shellbags_invalid_hive_data() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        struct InvalidHiveProvider;
        impl CollectionProvider for InvalidHiveProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(vec![0xDE, 0xAD, 0xBE, 0xEF]) // Not a valid hive
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Users/admin/UsrClass.dat", 'C'),
            hive_type: RegistryHiveType::UsrClass { username: "admin".to_string() },
        });
        let mut store = TimelineStore::new();

        let result = parse_shellbags(&InvalidHiveProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_shellbags_skips_non_usrclass_hives() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        struct NeverCalledProvider;
        impl CollectionProvider for NeverCalledProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                anyhow::bail!("should not be called for non-UsrClass hives")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SYSTEM", 'C'),
            hive_type: RegistryHiveType::System,
        });
        let mut store = TimelineStore::new();

        let result = parse_shellbags(&NeverCalledProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_shellbag_entry_debug_clone() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let entry = ShellbagEntry {
            reg_path: "BagMRU\\0".to_string(),
            folder_name: Some("Documents".to_string()),
            last_accessed: dt,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.folder_name, entry.folder_name);
        assert_eq!(cloned.reg_path, entry.reg_path);
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("Documents"));
    }

    #[test]
    fn test_extract_name_root_folder_all_known_guids() {
        // Test My Documents GUID
        let mut data = vec![0u8; 20];
        data[2] = 0x1F;
        data[4..8].copy_from_slice(&[0xBA, 0x8F, 0x0D, 0x45]);
        data[8..20].copy_from_slice(&[0x25, 0xAD, 0xD0, 0x11, 0x98, 0xA8, 0x08, 0x00, 0x36, 0x1B, 0x11, 0x03]);
        assert_eq!(extract_name_from_shell_item(&data), Some("My Documents".to_string()));

        // Test Recycle Bin GUID
        let mut data2 = vec![0u8; 20];
        data2[2] = 0x1F;
        data2[4..8].copy_from_slice(&[0x40, 0xF0, 0x5F, 0x64]);
        data2[8..20].copy_from_slice(&[0x81, 0x50, 0x1B, 0x10, 0x9F, 0x08, 0x00, 0xAA, 0x00, 0x2F, 0x95, 0x4E]);
        assert_eq!(extract_name_from_shell_item(&data2), Some("Recycle Bin".to_string()));

        // Test Network GUID
        let mut data3 = vec![0u8; 20];
        data3[2] = 0x1F;
        data3[4..8].copy_from_slice(&[0x0D, 0x1A, 0x2C, 0xF0]);
        data3[8..20].copy_from_slice(&[0x21, 0xBE, 0x50, 0x43, 0x88, 0xB0, 0x73, 0x67, 0xFC, 0x96, 0xEF, 0x3C]);
        assert_eq!(extract_name_from_shell_item(&data3), Some("Network".to_string()));
    }

    #[test]
    fn test_extract_name_root_folder_unknown_guid() {
        let mut data = vec![0u8; 20];
        data[2] = 0x1F;
        // Unknown GUID
        data[4..20].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
        assert_eq!(extract_name_from_shell_item(&data), Some("Known Folder".to_string()));
    }
}
