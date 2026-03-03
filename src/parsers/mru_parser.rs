use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use log::{debug, warn};
use nt_hive2::{CleanHive, Hive, HiveParseMode, RegistryValue, SubPath};
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

/// Extract a filename from a RecentDocs value data blob.
///
/// The binary data for each numbered value in RecentDocs typically contains:
/// - A UTF-16LE filename (null-terminated)
/// - Followed by additional shell item data
///
/// We extract the first null-terminated UTF-16LE string.
pub fn extract_filename_from_recentdocs(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }

    // The data starts with a UTF-16LE filename
    let u16_iter = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
    let chars: Vec<u16> = u16_iter.take_while(|&c| c != 0).collect();

    if chars.is_empty() {
        return None;
    }

    let name = String::from_utf16_lossy(&chars);
    if name.is_empty() || !name.chars().any(|c| c.is_alphanumeric()) {
        return None;
    }

    Some(name)
}

/// Parse the MRUListEx value to get the order of entries.
///
/// MRUListEx is an array of u32 indices terminated by 0xFFFFFFFF.
pub fn parse_mrulistex(data: &[u8]) -> Vec<u32> {
    let mut indices = Vec::new();
    for chunk in data.chunks_exact(4) {
        let idx = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if idx == 0xFFFFFFFF {
            break;
        }
        indices.push(idx);
    }
    indices
}

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static MRU_ID_COUNTER: AtomicU64 = AtomicU64::new(0x4D52_0000_0000_0000); // "MR" prefix

fn next_mru_id() -> u64 {
    MRU_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Parsed entry ────────────────────────────────────────────────────────────

/// A parsed MRU list entry.
#[derive(Debug, Clone)]
pub struct MruEntry {
    /// The file/document name or path.
    pub name: String,
    /// The timestamp (key last-written) indicating when this was accessed.
    pub timestamp: DateTime<Utc>,
    /// Which MRU key this came from.
    pub source_key: String,
    /// MRU order position (0 = most recent).
    pub mru_position: usize,
}

// ─── Registry parsing ────────────────────────────────────────────────────────

/// Parse MRU entries from an NTUSER.DAT hive.
fn parse_mru_from_hive(data: &[u8]) -> Result<Vec<MruEntry>> {
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

    // Parse RecentDocs
    parse_recent_docs(&root_key, &mut hive, &mut entries);

    // Parse OpenSavePidlMRU
    parse_open_save_mru(&root_key, &mut hive, &mut entries);

    debug!("Found {} MRU entries total", entries.len());
    Ok(entries)
}

/// Parse the RecentDocs key.
///
/// Path: Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
///
/// Contains MRUListEx (order) and numbered values (0, 1, 2, ...) with
/// binary blobs containing filenames.
fn parse_recent_docs(
    root_key: &nt_hive2::KeyNode,
    hive: &mut Hive<Cursor<Vec<u8>>, CleanHive>,
    entries: &mut Vec<MruEntry>,
) {
    let path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs";

    let recent_key = match root_key.subpath(path, hive) {
        Ok(Some(key)) => key,
        Ok(None) => {
            debug!("RecentDocs path not found");
            return;
        }
        Err(e) => {
            debug!("Error accessing RecentDocs: {}", e);
            return;
        }
    };

    let key_ref = recent_key.borrow();
    let key_timestamp = Some(*key_ref.timestamp());

    // Get the MRUListEx value for ordering
    let mut mru_order: Option<Vec<u32>> = None;
    let values = key_ref.values();
    for value in values.iter() {
        if value.name().eq_ignore_ascii_case("MRUListEx") {
            if let RegistryValue::RegBinary(data) = value.value() {
                mru_order = Some(parse_mrulistex(data));
            }
            break;
        }
    }

    // Read numbered values
    for value in values.iter() {
        let name = value.name().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let index: u32 = match name.parse() {
            Ok(i) => i,
            Err(_) => continue,
        };

        let binary_data = match value.value() {
            RegistryValue::RegBinary(data) => data,
            _ => continue,
        };

        let filename = match extract_filename_from_recentdocs(binary_data) {
            Some(f) => f,
            None => continue,
        };

        // Determine MRU position
        let position = mru_order
            .as_ref()
            .and_then(|order| order.iter().position(|&i| i == index))
            .unwrap_or(index as usize);

        // Use key timestamp as access time
        if let Some(ts) = key_timestamp {
            entries.push(MruEntry {
                name: filename,
                timestamp: ts,
                source_key: "RecentDocs".to_string(),
                mru_position: position,
            });
        }
    }

    // Also recurse into extension subkeys (e.g., RecentDocs\.docx, RecentDocs\.pdf)
    let subkeys = match key_ref.subkeys(hive) {
        Ok(sk) => sk.clone(),
        Err(_) => return,
    };

    for subkey in subkeys.iter() {
        let sk = subkey.borrow();
        let ext = sk.name().to_string();
        let sub_timestamp = Some(*sk.timestamp());

        let sub_values = sk.values();
        for value in sub_values.iter() {
            let vname = value.name().to_string();
            if !vname.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            let binary_data = match value.value() {
                RegistryValue::RegBinary(data) => data,
                _ => continue,
            };

            let filename = match extract_filename_from_recentdocs(binary_data) {
                Some(f) => f,
                None => continue,
            };

            if let Some(ts) = sub_timestamp {
                entries.push(MruEntry {
                    name: filename,
                    timestamp: ts,
                    source_key: format!("RecentDocs\\{}", ext),
                    mru_position: 0,
                });
            }
        }
    }
}

/// Parse the OpenSavePidlMRU key.
///
/// Path: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
///
/// Contains extension subkeys (e.g., "docx", "pdf", "*") with MRU data.
fn parse_open_save_mru(
    root_key: &nt_hive2::KeyNode,
    hive: &mut Hive<Cursor<Vec<u8>>, CleanHive>,
    entries: &mut Vec<MruEntry>,
) {
    let path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU";

    let mru_key = match root_key.subpath(path, hive) {
        Ok(Some(key)) => key,
        Ok(None) => {
            debug!("OpenSavePidlMRU path not found");
            return;
        }
        Err(e) => {
            debug!("Error accessing OpenSavePidlMRU: {}", e);
            return;
        }
    };

    let key_ref = mru_key.borrow();

    // Enumerate extension subkeys
    let subkeys = match key_ref.subkeys(hive) {
        Ok(sk) => sk.clone(),
        Err(e) => {
            debug!("Error reading OpenSavePidlMRU subkeys: {}", e);
            return;
        }
    };

    for subkey in subkeys.iter() {
        let sk = subkey.borrow();
        let ext = sk.name().to_string();
        let sub_timestamp = Some(*sk.timestamp());

        let sub_values = sk.values();
        for value in sub_values.iter() {
            let vname = value.name().to_string();
            if !vname.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            let binary_data = match value.value() {
                RegistryValue::RegBinary(data) => data,
                _ => continue,
            };

            // OpenSavePidlMRU values contain PIDL data (ItemIDList)
            // Try to extract a filename from the blob
            let filename = match extract_filename_from_pidl(binary_data) {
                Some(f) => f,
                None => continue,
            };

            if let Some(ts) = sub_timestamp {
                entries.push(MruEntry {
                    name: filename,
                    timestamp: ts,
                    source_key: format!("OpenSavePidlMRU\\{}", ext),
                    mru_position: 0,
                });
            }
        }
    }
}

/// Attempt to extract a filename from an ItemIDList (PIDL) blob.
///
/// PIDLs are sequences of shell item IDs. We scan for what looks like
/// a filename by looking for a UTF-16LE string in the data.
fn extract_filename_from_pidl(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }

    // Strategy: scan for UTF-16LE strings that look like filenames
    // Look for a sequence of printable ASCII characters encoded in UTF-16LE
    let mut best_name: Option<String> = None;
    let mut best_len = 0;

    let mut offset = 0;
    while offset + 4 <= data.len() {
        // Look for UTF-16LE sequence: printable byte, 0x00
        if data[offset] >= 0x20
            && data[offset] < 0x7F
            && offset + 1 < data.len()
            && data[offset + 1] == 0x00
            && offset + 2 < data.len()
            && data[offset + 2] >= 0x20
            && offset + 3 < data.len()
            && data[offset + 3] == 0x00
        {
            let u16_iter = data[offset..]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .take_while(|&c| c != 0 && c >= 0x20 && c < 0xFFFE);

            let chars: Vec<u16> = u16_iter.collect();
            if chars.len() > best_len && chars.len() >= 3 {
                let name = String::from_utf16_lossy(&chars);
                // Check if it looks like a filename (contains a dot or backslash)
                if name.contains('.') || name.contains('\\') || name.contains('/') {
                    best_name = Some(name.clone());
                    best_len = chars.len();
                } else if best_name.is_none() && name.len() >= 3 {
                    best_name = Some(name);
                    best_len = chars.len();
                }
            }
            offset += 2;
        } else {
            offset += 1;
        }
    }

    best_name
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse MRU (Most Recently Used) list entries from NTUSER.DAT registry hives.
///
/// Parses the following MRU keys:
/// - RecentDocs: Recently opened documents
/// - OpenSavePidlMRU: Open/Save dialog history
///
/// These provide evidence of file access and user activity.
///
/// Registry paths:
///   NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
///   NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
pub fn parse_mru_lists(
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
        debug!("No NTUSER.DAT hives found in manifest for MRU parsing");
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
            "Parsing MRU lists from NTUSER.DAT: {} ({} bytes)",
            hive_entry.path,
            data.len()
        );

        let mru_entries = match parse_mru_from_hive(&data) {
            Ok(entries) => entries,
            Err(e) => {
                warn!(
                    "Failed to parse MRU lists from {}: {}",
                    hive_entry.path, e
                );
                continue;
            }
        };

        debug!(
            "Found {} MRU entries from {}",
            mru_entries.len(),
            hive_entry.path
        );

        for mru_entry in &mru_entries {
            let display_path = format!(
                "[MRU:{}] {}",
                mru_entry.source_key, mru_entry.name
            );

            let entry = TimelineEntry {
                entity_id: EntityId::Generated(next_mru_id()),
                path: display_path,
                primary_timestamp: mru_entry.timestamp,
                event_type: EventType::FileAccess,
                timestamps: TimestampSet::default(),
                sources: smallvec![ArtifactSource::Registry("MRU".to_string())],
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
    fn test_parse_mrulistex() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // terminator

        let order = parse_mrulistex(&data);
        assert_eq!(order, vec![3, 1, 0, 2]);
    }

    #[test]
    fn test_parse_mrulistex_empty() {
        let data: Vec<u8> = 0xFFFFFFFFu32.to_le_bytes().to_vec();
        let order = parse_mrulistex(&data);
        assert!(order.is_empty());
    }

    #[test]
    fn test_parse_mrulistex_no_terminator() {
        let mut data = Vec::new();
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        // No terminator -- should still parse what's there
        let order = parse_mrulistex(&data);
        assert_eq!(order, vec![5, 3]);
    }

    #[test]
    fn test_extract_filename_from_recentdocs() {
        // Build a RecentDocs value: UTF-16LE filename + null + more data
        let filename = "report.docx";
        let mut data: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&[0, 0]); // null terminator
        data.extend_from_slice(&[0xFF; 20]); // extra shell data

        let result = extract_filename_from_recentdocs(&data);
        assert_eq!(result, Some("report.docx".to_string()));
    }

    #[test]
    fn test_extract_filename_from_recentdocs_empty() {
        let data = vec![0, 0]; // just a null terminator
        assert!(extract_filename_from_recentdocs(&data).is_none());
    }

    #[test]
    fn test_extract_filename_from_recentdocs_too_short() {
        let data = vec![0u8; 2];
        assert!(extract_filename_from_recentdocs(&data).is_none());
    }

    #[test]
    fn test_extract_filename_from_pidl() {
        // Build a PIDL-like blob with an embedded UTF-16LE filename
        let mut data = vec![0u8; 20]; // some header data
        let filename = "document.pdf";
        let utf16: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&utf16);
        data.extend_from_slice(&[0, 0]); // null terminator
        data.extend_from_slice(&[0xFF; 10]); // extra data

        let result = extract_filename_from_pidl(&data);
        assert!(result.is_some());
        assert!(result.unwrap().contains("document.pdf"));
    }

    #[test]
    fn test_extract_filename_from_pidl_empty() {
        let data = vec![0u8; 4];
        assert!(extract_filename_from_pidl(&data).is_none());
    }

    #[test]
    fn test_mru_entry_creation() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();

        let mru_entry = MruEntry {
            name: "secret_doc.docx".to_string(),
            timestamp: dt,
            source_key: "RecentDocs".to_string(),
            mru_position: 0,
        };

        let display_path = format!("[MRU:{}] {}", mru_entry.source_key, mru_entry.name);

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_mru_id()),
            path: display_path.clone(),
            primary_timestamp: mru_entry.timestamp,
            event_type: EventType::FileAccess,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Registry("MRU".to_string())],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        assert_eq!(entry.path, "[MRU:RecentDocs] secret_doc.docx");
        assert_eq!(entry.event_type, EventType::FileAccess);
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
        let result = parse_mru_lists(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_filetime_negative_secs() {
        // A filetime that would produce negative secs after subtracting epoch diff
        // (i.e., before 1970-01-01). The EPOCH_DIFF is 11_644_473_600.
        // If filetime / 10_000_000 < EPOCH_DIFF, secs < 0 => None
        let filetime = 1u64; // way before Unix epoch
        assert!(filetime_to_datetime(filetime).is_none());
    }

    #[test]
    fn test_filetime_with_subsecond_nanos() {
        use chrono::TimeZone;
        // Build a filetime with sub-second precision
        let dt_base = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let secs = dt_base.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000 + 5_000_000; // +0.5 seconds
        let result = filetime_to_datetime(filetime).unwrap();
        assert_eq!(result.timestamp(), dt_base.timestamp());
        assert_eq!(result.timestamp_subsec_nanos(), 500_000_000);
    }

    #[test]
    fn test_filetime_boundary_exactly_epoch() {
        use chrono::TimeZone;
        // Exactly 1970-01-01 00:00:00 UTC
        let epoch_diff: u64 = 11_644_473_600;
        let filetime = epoch_diff * 10_000_000;
        let result = filetime_to_datetime(filetime).unwrap();
        assert_eq!(result, Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap());
    }

    #[test]
    fn test_parse_mrulistex_single_entry() {
        let mut data = Vec::new();
        data.extend_from_slice(&42u32.to_le_bytes());
        data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        let order = parse_mrulistex(&data);
        assert_eq!(order, vec![42]);
    }

    #[test]
    fn test_parse_mrulistex_all_zeros() {
        // Entries of value 0 are valid (index 0), terminator is 0xFFFFFFFF
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        let order = parse_mrulistex(&data);
        assert_eq!(order, vec![0, 0]);
    }

    #[test]
    fn test_parse_mrulistex_trailing_bytes_ignored() {
        // 3 bytes after valid entries (not a full chunk) should be ignored
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // trailing garbage
        let order = parse_mrulistex(&data);
        assert_eq!(order, vec![1]);
    }

    #[test]
    fn test_parse_mrulistex_empty_data() {
        let data: Vec<u8> = Vec::new();
        let order = parse_mrulistex(&data);
        assert!(order.is_empty());
    }

    #[test]
    fn test_extract_filename_from_recentdocs_unicode() {
        // Test with a filename containing unicode (Chinese characters)
        let filename = "report_\u{4e2d}\u{6587}.docx";
        let mut data: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&[0, 0]); // null terminator
        data.extend_from_slice(&[0xFF; 10]); // extra shell data

        let result = extract_filename_from_recentdocs(&data);
        assert!(result.is_some());
        assert!(result.unwrap().contains("report_"));
    }

    #[test]
    fn test_extract_filename_from_recentdocs_only_whitespace() {
        // Non-alphanumeric content should return None
        let filename = "   ";
        let mut data: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&[0, 0]);

        let result = extract_filename_from_recentdocs(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_filename_from_recentdocs_exactly_4_bytes() {
        // Exactly 4 bytes = 2 UTF-16 chars
        let filename = "AB";
        let data: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(data.len(), 4);
        let result = extract_filename_from_recentdocs(&data);
        assert_eq!(result, Some("AB".to_string()));
    }

    #[test]
    fn test_extract_filename_from_recentdocs_3_bytes() {
        // Less than 4 bytes returns None
        let data = vec![0x41, 0x00, 0x42];
        assert!(extract_filename_from_recentdocs(&data).is_none());
    }

    #[test]
    fn test_extract_filename_from_pidl_too_short() {
        let data = vec![0u8; 7]; // less than 8
        assert!(extract_filename_from_pidl(&data).is_none());
    }

    #[test]
    fn test_extract_filename_from_pidl_no_utf16_sequences() {
        // All high bytes, no valid UTF-16LE patterns
        let data = vec![0xFF; 20];
        assert!(extract_filename_from_pidl(&data).is_none());
    }

    #[test]
    fn test_extract_filename_from_pidl_with_backslash_path() {
        // A PIDL-like blob with a backslash-containing path
        let mut data = vec![0u8; 10]; // header
        let path = r"C:\Users\test\file.txt";
        let utf16: Vec<u8> = path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&utf16);
        data.extend_from_slice(&[0, 0]); // null terminator

        let result = extract_filename_from_pidl(&data);
        assert!(result.is_some());
        let name = result.unwrap();
        assert!(name.contains("Users") || name.contains("file.txt"));
    }

    #[test]
    fn test_extract_filename_from_pidl_prefers_filename_over_generic_string() {
        // Put both a short generic string and a longer filename with dot
        let mut data = vec![0u8; 10];
        // Short generic string first
        let generic = "abc";
        let utf16_gen: Vec<u8> = generic
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&utf16_gen);
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&[0xFF; 4]); // separator
        // Then a longer filename with a dot
        let filename = "important_document.pdf";
        let utf16_fn: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&utf16_fn);
        data.extend_from_slice(&[0, 0]);

        let result = extract_filename_from_pidl(&data);
        assert!(result.is_some());
        // Should prefer the longer filename-like string (contains a dot)
        let name = result.unwrap();
        assert!(name.contains("important_document.pdf"));
    }

    #[test]
    fn test_mru_entry_fields() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 3, 15, 8, 0, 0).unwrap();
        let entry = MruEntry {
            name: "budget_2025.xlsx".to_string(),
            timestamp: dt,
            source_key: "RecentDocs\\.xlsx".to_string(),
            mru_position: 3,
        };
        assert_eq!(entry.name, "budget_2025.xlsx");
        assert_eq!(entry.timestamp, dt);
        assert_eq!(entry.source_key, "RecentDocs\\.xlsx");
        assert_eq!(entry.mru_position, 3);
    }

    #[test]
    fn test_mru_entry_clone() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let entry = MruEntry {
            name: "test.txt".to_string(),
            timestamp: dt,
            source_key: "RecentDocs".to_string(),
            mru_position: 0,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.name, entry.name);
        assert_eq!(cloned.timestamp, entry.timestamp);
        assert_eq!(cloned.source_key, entry.source_key);
        assert_eq!(cloned.mru_position, entry.mru_position);
    }

    #[test]
    fn test_mru_entry_debug_format() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let entry = MruEntry {
            name: "file.doc".to_string(),
            timestamp: dt,
            source_key: "RecentDocs".to_string(),
            mru_position: 0,
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("MruEntry"));
        assert!(debug_str.contains("file.doc"));
    }

    #[test]
    fn test_next_mru_id_monotonic() {
        let id1 = next_mru_id();
        let id2 = next_mru_id();
        let id3 = next_mru_id();
        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[test]
    fn test_timeline_entry_source_is_registry_mru() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_mru_id()),
            path: "[MRU:RecentDocs] test.txt".to_string(),
            primary_timestamp: dt,
            event_type: EventType::FileAccess,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Registry("MRU".to_string())],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };
        assert!(matches!(&entry.sources[0], ArtifactSource::Registry(s) if s == "MRU"));
    }

    #[test]
    fn test_extract_filename_from_recentdocs_long_name() {
        // Test with a very long filename
        let long_name = "a".repeat(260); // MAX_PATH length
        let mut data: Vec<u8> = long_name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&[0, 0]);
        let result = extract_filename_from_recentdocs(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 260);
    }

    #[test]
    fn test_extract_filename_from_recentdocs_special_chars() {
        let filename = "report (1) - final [v2].docx";
        let mut data: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&[0xFF; 8]);
        let result = extract_filename_from_recentdocs(&data);
        assert_eq!(result, Some("report (1) - final [v2].docx".to_string()));
    }

    #[test]
    fn test_parse_mrulistex_large_indices() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xFFFFFFFEu32.to_le_bytes()); // large but not terminator
        data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // terminator
        let order = parse_mrulistex(&data);
        assert_eq!(order, vec![0xFFFFFFFE]);
    }

    #[test]
    fn test_extract_filename_from_pidl_exactly_8_bytes() {
        // Minimum valid size for pidl - all zeros => no valid UTF-16 sequences
        let data = vec![0u8; 8];
        assert!(extract_filename_from_pidl(&data).is_none());
    }

    #[test]
    fn test_extract_filename_from_pidl_forward_slash_path() {
        let mut data = vec![0u8; 10];
        let path = "home/user/notes.txt";
        let utf16: Vec<u8> = path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&utf16);
        data.extend_from_slice(&[0, 0]);

        let result = extract_filename_from_pidl(&data);
        assert!(result.is_some());
        assert!(result.unwrap().contains("notes.txt"));
    }

    // ─── Pipeline integration and hive parsing coverage ──────────────────

    #[test]
    fn test_parse_mru_from_hive_invalid_data() {
        let result = parse_mru_from_hive(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mru_from_hive_empty_data() {
        let result = parse_mru_from_hive(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mru_from_hive_truncated() {
        let mut data = vec![0u8; 50];
        data[0..4].copy_from_slice(b"regf");
        let result = parse_mru_from_hive(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mru_lists_with_ntuser_hive_that_fails_to_open() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Users/admin/NTUSER.DAT", 'C'),
            hive_type: RegistryHiveType::NtUser {
                username: "admin".to_string(),
            },
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
                anyhow::bail!("Permission denied")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_mru_lists(&FailProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_mru_lists_with_invalid_hive_content() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Users/admin/NTUSER.DAT", 'C'),
            hive_type: RegistryHiveType::NtUser {
                username: "admin".to_string(),
            },
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
                Ok(vec![0xAB; 1024])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_mru_lists(&GarbageProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_mru_lists_skips_non_ntuser_hives() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SYSTEM", 'C'),
            hive_type: RegistryHiveType::System,
        });
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SOFTWARE", 'C'),
            hive_type: RegistryHiveType::Software,
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
                panic!("Should not be called for non-NTUSER hives")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_mru_lists(&PanicProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_extract_filename_from_pidl_short_utf16_no_dot() {
        // A valid UTF-16 string with exactly 3 chars but no dot/slash
        // Should still be returned as best_name when nothing better exists
        let mut data = vec![0u8; 10]; // header
        let name = "abc";
        let utf16: Vec<u8> = name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&utf16);
        data.extend_from_slice(&[0, 0]);

        let result = extract_filename_from_pidl(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "abc");
    }

    #[test]
    fn test_extract_filename_from_pidl_2_char_string_too_short() {
        // A 2-char string should not meet the >= 3 threshold
        let mut data = vec![0u8; 10];
        let name = "ab";
        let utf16: Vec<u8> = name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&utf16);
        data.extend_from_slice(&[0, 0]);
        // Pad to ensure we don't hit other strings
        data.extend_from_slice(&[0xFF; 10]);

        let result = extract_filename_from_pidl(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_filename_from_pidl_prefers_dotted_over_generic() {
        // A shorter string with a dot should be preferred over a longer generic one
        let mut data = vec![0u8; 8]; // min header

        // First: a 4-char generic string "test" (no dot)
        let gen = "test";
        let utf16_gen: Vec<u8> = gen
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&utf16_gen);
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&[0xFF; 4]); // separator

        // Second: a 10-char filename with dot "report.doc"
        let filename = "report.doc";
        let utf16_fn: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&utf16_fn);
        data.extend_from_slice(&[0, 0]);

        let result = extract_filename_from_pidl(&data);
        assert!(result.is_some());
        let name = result.unwrap();
        // The longer filename with a dot should win
        assert!(name.contains("report.doc"));
    }

    #[test]
    fn test_extract_filename_from_pidl_all_control_chars() {
        // Data with control characters (< 0x20) interspersed - no valid UTF-16 strings
        let data = vec![0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00];
        assert!(extract_filename_from_pidl(&data).is_none());
    }

    #[test]
    fn test_extract_filename_from_recentdocs_null_at_start() {
        // Data that starts with a null terminator
        let mut data = vec![0, 0]; // null terminator immediately
        data.extend_from_slice(&[0x41, 0x00, 0x42, 0x00]); // "AB" after null
        let result = extract_filename_from_recentdocs(&data);
        assert!(result.is_none()); // Empty before null
    }

    #[test]
    fn test_parse_mru_lists_multiple_ntuser_hives() {
        use crate::collection::manifest::{ArtifactManifest, RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Users/admin/NTUSER.DAT", 'C'),
            hive_type: RegistryHiveType::NtUser {
                username: "admin".to_string(),
            },
        });
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Users/analyst/NTUSER.DAT", 'C'),
            hive_type: RegistryHiveType::NtUser {
                username: "analyst".to_string(),
            },
        });

        let mut store = TimelineStore::new();

        use std::sync::atomic::AtomicU32;
        static MRU_CALL_COUNT: AtomicU32 = AtomicU32::new(0);

        struct CountingProvider;
        impl CollectionProvider for CountingProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                MRU_CALL_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(vec![0u8; 512]) // invalid hive data
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        MRU_CALL_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        let result = parse_mru_lists(&CountingProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(MRU_CALL_COUNT.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn test_next_mru_id_has_mr_prefix() {
        let id = next_mru_id();
        assert_eq!((id >> 48) & 0xFFFF, 0x4D52);
    }

    #[test]
    fn test_extract_filename_from_recentdocs_only_non_alpha() {
        // Characters that are not alphanumeric
        let filename = "---";
        let mut data: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&[0, 0]);
        let result = extract_filename_from_recentdocs(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_filename_from_pidl_high_byte_non_zero() {
        // UTF-16LE with non-zero high bytes (non-ASCII) - these don't match
        // the printable ASCII range filter (0x20..0x7F in low byte, 0x00 in high byte)
        let data = vec![0x41, 0x01, 0x42, 0x01, 0x43, 0x01, 0x44, 0x01, 0x00, 0x00];
        // These are valid UTF-16 but won't match the scanner's ASCII heuristic
        // Result depends on whether the scanner finds them
        let _result = extract_filename_from_pidl(&data);
        // Just verify no panic
    }
}
