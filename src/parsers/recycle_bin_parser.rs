use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, warn};
use smallvec::smallvec;

use crate::collection::manifest::ArtifactManifest;
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── Constants ───────────────────────────────────────────────────────────────

/// Minimum size of a $I file (header + timestamp + at least some path data).
const MIN_I_FILE_SIZE: usize = 28;

/// Maximum reasonable $I file size (1 MB).
const MAX_I_FILE_SIZE: usize = 1_000_000;

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

/// Decode a UTF-16LE byte slice into a String, stopping at the first null.
fn decode_utf16le_null_terminated(data: &[u8]) -> String {
    let u16_iter = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
    let chars: Vec<u16> = u16_iter.take_while(|&c| c != 0).collect();
    String::from_utf16_lossy(&chars)
}

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static RECYCLEBIN_ID_COUNTER: AtomicU64 = AtomicU64::new(0x5242_0000_0000_0000); // "RB" prefix

fn next_recyclebin_id() -> u64 {
    RECYCLEBIN_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Parsed entry ────────────────────────────────────────────────────────────

/// A parsed Recycle Bin $I file entry.
#[derive(Debug, Clone)]
pub struct RecycleBinEntry {
    /// Original file path before deletion.
    pub original_path: String,
    /// File size before deletion.
    pub file_size: u64,
    /// Timestamp when the file was deleted.
    pub deletion_time: DateTime<Utc>,
    /// The $I file path.
    pub i_file_path: String,
    /// Format version (1 or 2).
    pub version: u64,
}

/// Parse a single $I file.
///
/// Format (Windows Vista/7 - version 1):
///   - Offset 0: Version/Header (u64) = 1
///   - Offset 8: File size (u64)
///   - Offset 16: Deletion timestamp (FILETIME, i64 LE)
///   - Offset 24: Original file path (UTF-16LE, 520 bytes = 260 chars)
///
/// Format (Windows 10+ - version 2):
///   - Offset 0: Version/Header (u64) = 2
///   - Offset 8: File size (u64)
///   - Offset 16: Deletion timestamp (FILETIME, i64 LE)
///   - Offset 24: File name length (u32, in characters including null)
///   - Offset 28: Original file path (UTF-16LE, variable length)
pub fn parse_i_file(data: &[u8], i_file_path: &str) -> Result<RecycleBinEntry> {
    if data.len() < MIN_I_FILE_SIZE {
        anyhow::bail!("$I file too short: {} bytes", data.len());
    }

    let version = read_u64_le(data, 0).unwrap_or(0);
    if version != 1 && version != 2 {
        anyhow::bail!("Unknown $I file version: {}", version);
    }

    let file_size = read_u64_le(data, 8).unwrap_or(0);

    let deletion_filetime = read_u64_le(data, 16).unwrap_or(0);
    let deletion_time = filetime_to_datetime(deletion_filetime)
        .ok_or_else(|| anyhow::anyhow!("Invalid deletion timestamp in $I file"))?;

    let original_path = match version {
        1 => {
            // Version 1: fixed-size path at offset 24, 520 bytes (260 UTF-16 chars)
            if data.len() < 24 + 4 {
                anyhow::bail!("$I v1 file too short for path");
            }
            let path_end = std::cmp::min(24 + 520, data.len());
            decode_utf16le_null_terminated(&data[24..path_end])
        }
        2 => {
            // Version 2: variable-size path
            let name_len = read_u32_le(data, 24).unwrap_or(0) as usize;
            if name_len == 0 {
                anyhow::bail!("$I v2 file has zero path length");
            }
            let path_start = 28;
            let path_bytes = name_len * 2; // UTF-16LE = 2 bytes per char
            if path_start + path_bytes > data.len() {
                // Try to read what we can
                let available = data.len() - path_start;
                if available < 4 {
                    anyhow::bail!("$I v2 file too short for path data");
                }
                decode_utf16le_null_terminated(&data[path_start..])
            } else {
                decode_utf16le_null_terminated(&data[path_start..path_start + path_bytes])
            }
        }
        _ => unreachable!(),
    };

    if original_path.is_empty() {
        anyhow::bail!("Empty original path in $I file");
    }

    Ok(RecycleBinEntry {
        original_path,
        file_size,
        deletion_time,
        i_file_path: i_file_path.to_string(),
        version,
    })
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse all Recycle Bin $I files from the collection and populate the timeline store.
///
/// For each $I* file in the manifest's recycle_bin list, this extracts:
/// - Original file path
/// - Deletion timestamp
/// - File size
///
/// Creates TimelineEntry records with EventType::FileDelete and ArtifactSource::RecycleBin.
pub fn parse_recycle_bin(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    let rb_files = &manifest.recycle_bin;
    if rb_files.is_empty() {
        debug!("No Recycle Bin files found in manifest");
        return Ok(());
    }

    // Filter for $I files only
    let i_files: Vec<_> = rb_files
        .iter()
        .filter(|p| {
            let path = p.to_string();
            let basename = path
                .rsplit(|c| c == '\\' || c == '/')
                .next()
                .unwrap_or("");
            basename.starts_with("$I")
        })
        .collect();

    if i_files.is_empty() {
        debug!("No $I files found in Recycle Bin manifest entries");
        return Ok(());
    }

    debug!("Parsing {} Recycle Bin $I files", i_files.len());
    let mut parsed_count = 0u32;
    let mut error_count = 0u32;

    for i_path in &i_files {
        let data = match provider.open_file(i_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read $I file {}: {}", i_path, e);
                error_count += 1;
                continue;
            }
        };

        if data.len() > MAX_I_FILE_SIZE {
            warn!(
                "$I file {} is abnormally large ({} bytes), skipping",
                i_path,
                data.len()
            );
            error_count += 1;
            continue;
        }

        let rb_entry = match parse_i_file(&data, &i_path.to_string()) {
            Ok(entry) => entry,
            Err(e) => {
                debug!("Could not parse $I file {}: {}", i_path, e);
                error_count += 1;
                continue;
            }
        };

        let metadata = EntryMetadata {
            file_size: Some(rb_entry.file_size),
            ..EntryMetadata::default()
        };

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_recyclebin_id()),
            path: rb_entry.original_path.clone(),
            primary_timestamp: rb_entry.deletion_time,
            event_type: EventType::FileDelete,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::RecycleBin],
            anomalies: AnomalyFlags::empty(),
            metadata,
        };

        store.push(entry);
        parsed_count += 1;
    }

    debug!(
        "Recycle Bin parsing complete: {} files parsed, {} errors",
        parsed_count, error_count
    );
    Ok(())
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn datetime_to_filetime(dt: DateTime<Utc>) -> u64 {
        let secs = dt.timestamp() + 11_644_473_600;
        (secs as u64) * 10_000_000
    }

    #[test]
    fn test_filetime_to_datetime() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let ft = datetime_to_filetime(dt);
        let result = filetime_to_datetime(ft).unwrap();
        assert_eq!(result, dt);
    }

    #[test]
    fn test_filetime_zero() {
        assert!(filetime_to_datetime(0).is_none());
    }

    #[test]
    fn test_parse_i_file_v1() {
        use chrono::TimeZone;
        let deletion_time = Utc.with_ymd_and_hms(2025, 6, 15, 14, 30, 0).unwrap();
        let path_str = r"C:\Users\admin\Documents\secret.docx";

        let mut data = vec![0u8; 24 + 520]; // version 1 format

        // Version = 1
        data[0..8].copy_from_slice(&1u64.to_le_bytes());
        // File size = 12345
        data[8..16].copy_from_slice(&12345u64.to_le_bytes());
        // Deletion timestamp
        data[16..24].copy_from_slice(&datetime_to_filetime(deletion_time).to_le_bytes());
        // Original path (UTF-16LE)
        let path_bytes: Vec<u8> = path_str
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data[24..24 + path_bytes.len()].copy_from_slice(&path_bytes);

        let entry = parse_i_file(&data, r"$Recycle.Bin\$IABC123.docx").unwrap();

        assert_eq!(entry.original_path, path_str);
        assert_eq!(entry.file_size, 12345);
        assert_eq!(entry.deletion_time, deletion_time);
        assert_eq!(entry.version, 1);
    }

    #[test]
    fn test_parse_i_file_v2() {
        use chrono::TimeZone;
        let deletion_time = Utc.with_ymd_and_hms(2025, 8, 20, 9, 15, 0).unwrap();
        let path_str = r"C:\Users\admin\Desktop\malware.exe";

        let path_utf16: Vec<u8> = path_str
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let char_count = path_str.encode_utf16().count() + 1; // +1 for null terminator

        let mut data = vec![0u8; 28 + char_count * 2];

        // Version = 2
        data[0..8].copy_from_slice(&2u64.to_le_bytes());
        // File size = 999999
        data[8..16].copy_from_slice(&999999u64.to_le_bytes());
        // Deletion timestamp
        data[16..24].copy_from_slice(&datetime_to_filetime(deletion_time).to_le_bytes());
        // Path length (in characters)
        data[24..28].copy_from_slice(&(char_count as u32).to_le_bytes());
        // Original path (UTF-16LE)
        data[28..28 + path_utf16.len()].copy_from_slice(&path_utf16);

        let entry = parse_i_file(&data, r"$Recycle.Bin\$IXYZ789.exe").unwrap();

        assert_eq!(entry.original_path, path_str);
        assert_eq!(entry.file_size, 999999);
        assert_eq!(entry.deletion_time, deletion_time);
        assert_eq!(entry.version, 2);
    }

    #[test]
    fn test_parse_i_file_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_i_file(&data, "test").is_err());
    }

    #[test]
    fn test_parse_i_file_unknown_version() {
        let mut data = vec![0u8; 100];
        data[0..8].copy_from_slice(&99u64.to_le_bytes());
        assert!(parse_i_file(&data, "test").is_err());
    }

    #[test]
    fn test_parse_i_file_zero_timestamp() {
        let mut data = vec![0u8; 24 + 520];
        data[0..8].copy_from_slice(&1u64.to_le_bytes());
        data[8..16].copy_from_slice(&100u64.to_le_bytes());
        // Timestamp left at 0
        assert!(parse_i_file(&data, "test").is_err());
    }

    #[test]
    fn test_recyclebin_entry_creation() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 14, 30, 0).unwrap();

        let rb_entry = RecycleBinEntry {
            original_path: r"C:\Users\admin\Documents\evidence.pdf".to_string(),
            file_size: 54321,
            deletion_time: dt,
            i_file_path: r"$Recycle.Bin\$IABC.pdf".to_string(),
            version: 2,
        };

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_recyclebin_id()),
            path: rb_entry.original_path.clone(),
            primary_timestamp: rb_entry.deletion_time,
            event_type: EventType::FileDelete,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::RecycleBin],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata {
                file_size: Some(rb_entry.file_size),
                ..EntryMetadata::default()
            },
        };

        assert_eq!(entry.path, r"C:\Users\admin\Documents\evidence.pdf");
        assert_eq!(entry.event_type, EventType::FileDelete);
        assert_eq!(entry.primary_timestamp, dt);
        assert_eq!(entry.metadata.file_size, Some(54321));
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
        let result = parse_recycle_bin(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_decode_utf16le_null_terminated() {
        let s = r"C:\test\file.txt";
        let mut encoded: Vec<u8> = s
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        encoded.extend_from_slice(&[0, 0]); // null terminator
        encoded.extend_from_slice(&[0x41, 0x00]); // extra data after null

        let result = decode_utf16le_null_terminated(&encoded);
        assert_eq!(result, s);
    }

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_filetime_negative_secs() {
        // A FILETIME that results in secs < 0 after subtracting epoch
        // 1 second = 10_000_000 ticks. Use a value where secs < EPOCH_DIFF
        let filetime = 10_000_000u64; // 1 second since 1601 => way before 1970
        assert!(filetime_to_datetime(filetime).is_none());
    }

    #[test]
    fn test_filetime_with_subsecond_precision() {
        use chrono::TimeZone;
        // Create a FILETIME with non-zero nanoseconds component
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 0, 0, 0).unwrap();
        let base_ft = datetime_to_filetime(dt);
        // Add 5_000_000 ticks = 0.5 seconds
        let ft_with_nanos = base_ft + 5_000_000;
        let result = filetime_to_datetime(ft_with_nanos).unwrap();
        assert_eq!(result.timestamp(), dt.timestamp());
        assert!(result.timestamp_subsec_nanos() > 0);
    }

    #[test]
    fn test_read_u32_le_boundary() {
        // Exact boundary: offset + 4 == data.len()
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u32_le(&data, 0), Some(0x04030201));
        // Out of bounds
        assert!(read_u32_le(&data, 1).is_none());
    }

    #[test]
    fn test_read_u64_le_boundary() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u64_le(&data, 0), Some(0x0807060504030201));
        assert!(read_u64_le(&data, 1).is_none());
    }

    #[test]
    fn test_read_u32_le_empty() {
        let data: [u8; 0] = [];
        assert!(read_u32_le(&data, 0).is_none());
    }

    #[test]
    fn test_read_u64_le_empty() {
        let data: [u8; 0] = [];
        assert!(read_u64_le(&data, 0).is_none());
    }

    #[test]
    fn test_decode_utf16le_null_terminated_empty() {
        let data: Vec<u8> = vec![0, 0]; // Just a null terminator
        let result = decode_utf16le_null_terminated(&data);
        assert_eq!(result, "");
    }

    #[test]
    fn test_decode_utf16le_null_terminated_no_null() {
        // No null terminator - should decode entire string
        let s = "ABC";
        let encoded: Vec<u8> = s
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let result = decode_utf16le_null_terminated(&encoded);
        assert_eq!(result, "ABC");
    }

    #[test]
    fn test_decode_utf16le_null_terminated_odd_bytes() {
        // Odd number of bytes: last byte should be ignored by chunks_exact
        let data: Vec<u8> = vec![0x41, 0x00, 0xFF]; // 'A' + stray byte
        let result = decode_utf16le_null_terminated(&data);
        assert_eq!(result, "A");
    }

    #[test]
    fn test_parse_i_file_v1_too_short_for_path() {
        use chrono::TimeZone;
        let deletion_time = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        // Version 1 but only 27 bytes (need at least 24 + 4 = 28 for path)
        let mut data = vec![0u8; 27];
        data[0..8].copy_from_slice(&1u64.to_le_bytes());
        data[8..16].copy_from_slice(&100u64.to_le_bytes());
        data[16..24].copy_from_slice(&datetime_to_filetime(deletion_time).to_le_bytes());
        assert!(parse_i_file(&data, "test").is_err());
    }

    #[test]
    fn test_parse_i_file_v2_zero_path_length() {
        use chrono::TimeZone;
        let deletion_time = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let mut data = vec![0u8; 32];
        data[0..8].copy_from_slice(&2u64.to_le_bytes());
        data[8..16].copy_from_slice(&100u64.to_le_bytes());
        data[16..24].copy_from_slice(&datetime_to_filetime(deletion_time).to_le_bytes());
        // path length = 0 at offset 24
        data[24..28].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_i_file(&data, "test").is_err());
    }

    #[test]
    fn test_parse_i_file_v2_truncated_path() {
        use chrono::TimeZone;
        let deletion_time = Utc.with_ymd_and_hms(2025, 6, 15, 0, 0, 0).unwrap();
        let path_str = r"C:\test.txt";
        let path_utf16: Vec<u8> = path_str
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        // Declare a path length larger than available data
        let char_count = 100u32; // way more than we'll provide

        let mut data = vec![0u8; 28 + path_utf16.len()];
        data[0..8].copy_from_slice(&2u64.to_le_bytes());
        data[8..16].copy_from_slice(&100u64.to_le_bytes());
        data[16..24].copy_from_slice(&datetime_to_filetime(deletion_time).to_le_bytes());
        data[24..28].copy_from_slice(&char_count.to_le_bytes());
        // Copy partial path data
        data[28..28 + path_utf16.len()].copy_from_slice(&path_utf16);

        // Should still parse what's available (truncated path recovery)
        let entry = parse_i_file(&data, "test").unwrap();
        assert_eq!(entry.original_path, path_str);
    }

    #[test]
    fn test_parse_i_file_v2_too_short_for_path_data() {
        use chrono::TimeZone;
        let deletion_time = Utc.with_ymd_and_hms(2025, 6, 15, 0, 0, 0).unwrap();
        let mut data = vec![0u8; 30]; // Only 2 bytes of path data (< 4)
        data[0..8].copy_from_slice(&2u64.to_le_bytes());
        data[8..16].copy_from_slice(&100u64.to_le_bytes());
        data[16..24].copy_from_slice(&datetime_to_filetime(deletion_time).to_le_bytes());
        data[24..28].copy_from_slice(&100u32.to_le_bytes()); // large path length
        // Only 2 bytes available at offset 28 (< 4 required)
        assert!(parse_i_file(&data, "test").is_err());
    }

    #[test]
    fn test_parse_i_file_v1_empty_path() {
        use chrono::TimeZone;
        let deletion_time = Utc.with_ymd_and_hms(2025, 6, 15, 0, 0, 0).unwrap();
        // Version 1 with all zeroes in the path region (null terminator immediately)
        let mut data = vec![0u8; 24 + 520];
        data[0..8].copy_from_slice(&1u64.to_le_bytes());
        data[8..16].copy_from_slice(&100u64.to_le_bytes());
        data[16..24].copy_from_slice(&datetime_to_filetime(deletion_time).to_le_bytes());
        // Path area is all zeroes => empty path => error
        assert!(parse_i_file(&data, "test").is_err());
    }

    #[test]
    fn test_next_recyclebin_id_increments() {
        let id1 = next_recyclebin_id();
        let id2 = next_recyclebin_id();
        assert!(id2 > id1);
        assert_eq!(id1 >> 48, 0x5242);
    }

    #[test]
    fn test_parse_i_file_min_size_boundary() {
        // Exactly MIN_I_FILE_SIZE = 28 bytes
        let mut data = vec![0u8; 28];
        data[0..8].copy_from_slice(&99u64.to_le_bytes()); // invalid version
        assert!(parse_i_file(&data, "test").is_err());
    }

    #[test]
    fn test_parse_i_file_27_bytes() {
        // One byte below MIN_I_FILE_SIZE
        let data = vec![0u8; 27];
        let err = parse_i_file(&data, "test").unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn test_recycle_bin_entry_debug_clone() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let entry = RecycleBinEntry {
            original_path: "test".to_string(),
            file_size: 42,
            deletion_time: dt,
            i_file_path: "i_file".to_string(),
            version: 2,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.original_path, entry.original_path);
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("test"));
    }

    // ─── Coverage for parse_recycle_bin pipeline ─────────────────────────

    #[test]
    fn test_parse_recycle_bin_with_valid_i_file() {
        use chrono::TimeZone;
        use crate::collection::path::NormalizedPath;

        let deletion_time = Utc.with_ymd_and_hms(2025, 6, 15, 14, 30, 0).unwrap();
        let path_str = r"C:\Users\admin\Documents\secret.docx";
        let path_utf16: Vec<u8> = path_str
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let char_count = path_str.encode_utf16().count() + 1;

        let mut data = vec![0u8; 28 + char_count * 2];
        data[0..8].copy_from_slice(&2u64.to_le_bytes());
        data[8..16].copy_from_slice(&12345u64.to_le_bytes());
        data[16..24].copy_from_slice(&datetime_to_filetime(deletion_time).to_le_bytes());
        data[24..28].copy_from_slice(&(char_count as u32).to_le_bytes());
        data[28..28 + path_utf16.len()].copy_from_slice(&path_utf16);

        struct RbProvider {
            data: Vec<u8>,
        }
        impl CollectionProvider for RbProvider {
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

        let provider = RbProvider { data };
        let mut manifest = ArtifactManifest::default();
        manifest.recycle_bin.push(NormalizedPath::from_image_path("/$Recycle.Bin/$IABC123.docx", 'C'));
        let mut store = TimelineStore::new();

        let result = parse_recycle_bin(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 1);
        let entry = store.get(0).unwrap();
        assert_eq!(entry.event_type, EventType::FileDelete);
        assert!(entry.path.contains("secret.docx"));
        assert_eq!(entry.metadata.file_size, Some(12345));
        assert!(entry.sources.contains(&ArtifactSource::RecycleBin));
    }

    #[test]
    fn test_parse_recycle_bin_filters_non_i_files() {
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
                anyhow::bail!("should not be called for non-$I files")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let mut manifest = ArtifactManifest::default();
        // Add $R file (not $I) - should be filtered out
        manifest.recycle_bin.push(NormalizedPath::from_image_path("/$Recycle.Bin/$RABC123.docx", 'C'));
        let mut store = TimelineStore::new();

        let result = parse_recycle_bin(&NeverCalledProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_recycle_bin_provider_fails() {
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
        manifest.recycle_bin.push(NormalizedPath::from_image_path("/$Recycle.Bin/$IABC123.docx", 'C'));
        let mut store = TimelineStore::new();

        let result = parse_recycle_bin(&FailProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_recycle_bin_oversized_file() {
        use crate::collection::path::NormalizedPath;

        struct OversizedProvider;
        impl CollectionProvider for OversizedProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(vec![0u8; MAX_I_FILE_SIZE + 1])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let mut manifest = ArtifactManifest::default();
        manifest.recycle_bin.push(NormalizedPath::from_image_path("/$Recycle.Bin/$IABC123.docx", 'C'));
        let mut store = TimelineStore::new();

        let result = parse_recycle_bin(&OversizedProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_recycle_bin_invalid_data() {
        use crate::collection::path::NormalizedPath;

        struct InvalidProvider;
        impl CollectionProvider for InvalidProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                // Invalid version
                let mut data = vec![0u8; 100];
                data[0..8].copy_from_slice(&99u64.to_le_bytes());
                Ok(data)
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let mut manifest = ArtifactManifest::default();
        manifest.recycle_bin.push(NormalizedPath::from_image_path("/$Recycle.Bin/$IABC.txt", 'C'));
        let mut store = TimelineStore::new();

        let result = parse_recycle_bin(&InvalidProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_recycle_bin_with_forward_slash_path() {
        use crate::collection::path::NormalizedPath;

        // Test that $I files with forward slashes are also detected
        let mut manifest = ArtifactManifest::default();
        manifest.recycle_bin.push(NormalizedPath::from_image_path("/$Recycle.Bin/$IABC.txt", 'C'));

        struct StubProvider;
        impl CollectionProvider for StubProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                // Invalid data to trigger parse error
                Ok(vec![0u8; 10])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let mut store = TimelineStore::new();
        let result = parse_recycle_bin(&StubProvider, &manifest, &mut store);
        assert!(result.is_ok());
    }
}
