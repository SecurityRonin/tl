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
}
