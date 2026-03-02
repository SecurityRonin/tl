use anyhow::Result;
use chrono::{DateTime, Utc};
use cfb::CompoundFile;
use log::{debug, warn};
use smallvec::smallvec;
use std::io::{Cursor, Read};

use crate::collection::manifest::ArtifactManifest;
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── Constants ───────────────────────────────────────────────────────────────

/// Maximum reasonable Jump List file size (50 MB).
const MAX_JUMPLIST_SIZE: usize = 50_000_000;

/// LNK file header size.
const LNK_HEADER_SIZE: usize = 0x4C;

/// The CLSID that identifies a shell link.
const LNK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x46,
];

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

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

/// Read a null-terminated ASCII string starting at offset.
fn read_ascii_string(data: &[u8], offset: usize, max_len: usize) -> String {
    let end = std::cmp::min(offset + max_len, data.len());
    let slice = &data[offset..end];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..nul]).to_string()
}

// ─── LNK header parsing (embedded in jump list) ──────────────────────────────

/// LinkFlags bits we care about.
const HAS_LINK_TARGET_ID_LIST: u32 = 0x0000_0001;
const HAS_LINK_INFO: u32 = 0x0000_0002;

/// Extract basic information from an embedded LNK entry.
///
/// Returns (target_path, created, modified, accessed) if parseable.
fn parse_embedded_lnk(data: &[u8]) -> Option<(Option<String>, Option<DateTime<Utc>>, Option<DateTime<Utc>>, Option<DateTime<Utc>>)> {
    if data.len() < LNK_HEADER_SIZE {
        return None;
    }

    // Validate header
    let header_size = read_u32_le(data, 0)?;
    if header_size != 0x4C {
        return None;
    }

    if data[4..20] != LNK_CLSID {
        return None;
    }

    let link_flags = read_u32_le(data, 20).unwrap_or(0);
    let creation_time = read_u64_le(data, 28).and_then(filetime_to_datetime);
    let access_time = read_u64_le(data, 36).and_then(filetime_to_datetime);
    let write_time = read_u64_le(data, 44).and_then(filetime_to_datetime);

    // Try to extract target path from LinkInfo
    let mut offset = LNK_HEADER_SIZE;
    let mut target_path: Option<String> = None;

    // Skip LinkTargetIDList if present
    if (link_flags & HAS_LINK_TARGET_ID_LIST) != 0 {
        if let Some(id_list_size) = read_u16_le(data, offset) {
            offset += 2 + id_list_size as usize;
        }
    }

    // Parse LinkInfo if present
    if (link_flags & HAS_LINK_INFO) != 0 && offset + 4 <= data.len() {
        let link_info_size = read_u32_le(data, offset).unwrap_or(0) as usize;
        if link_info_size >= 28 && offset + link_info_size <= data.len() {
            let info_start = offset;
            let link_info_flags = read_u32_le(data, info_start + 8).unwrap_or(0);

            if (link_info_flags & 0x01) != 0 {
                let local_base_path_offset =
                    read_u32_le(data, info_start + 16).unwrap_or(0) as usize;
                if local_base_path_offset > 0 {
                    let path_abs = info_start + local_base_path_offset;
                    if path_abs < data.len() {
                        let path = read_ascii_string(data, path_abs, data.len() - path_abs);
                        if !path.is_empty() {
                            target_path = Some(path);
                        }
                    }
                }
            }
        }
    }

    Some((target_path, creation_time, write_time, access_time))
}

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static JUMPLIST_ID_COUNTER: AtomicU64 = AtomicU64::new(0x4A4C_0000_0000_0000); // "JL" prefix

fn next_jumplist_id() -> u64 {
    JUMPLIST_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Jump List info extraction ───────────────────────────────────────────────

/// Extract the AppID from an AutomaticDestinations filename.
///
/// The filename format is: {AppID}.automaticDestinations-ms
/// The AppID is the first 16 hex characters.
pub fn extract_app_id(filename: &str) -> Option<String> {
    // Get just the filename part
    let basename = filename
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(filename);

    // Extract the hex portion before the dot
    if let Some(dot_pos) = basename.find('.') {
        let hex_part = &basename[..dot_pos];
        if hex_part.len() == 16 && hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(hex_part.to_lowercase());
        }
    }
    None
}

/// Parse a single AutomaticDestinations jump list file (OLE compound file).
///
/// Each stream inside (except "DestList") is an embedded LNK file.
fn parse_automatic_destinations(data: &[u8], jl_path: &str) -> Result<Vec<(String, Option<DateTime<Utc>>, Option<DateTime<Utc>>, Option<DateTime<Utc>>)>> {
    let mut results = Vec::new();

    let cursor = Cursor::new(data);
    let mut compound = CompoundFile::open(cursor)
        .map_err(|e| anyhow::anyhow!("Failed to open compound file {}: {}", jl_path, e))?;

    // List all stream entries in the root storage
    let stream_entries: Vec<String> = compound
        .read_root_storage()
        .filter(|entry| {
            entry.is_stream() && !entry.name().eq_ignore_ascii_case("DestList")
        })
        .map(|entry| entry.name().to_string())
        .collect();

    for entry_name in &stream_entries {
        let mut stream = match compound.open_stream(format!("/{}", entry_name)) {
            Ok(s) => s,
            Err(e) => {
                debug!("Could not open stream {} in {}: {}", entry_name, jl_path, e);
                continue;
            }
        };

        let mut lnk_data = Vec::new();
        if let Err(e) = stream.read_to_end(&mut lnk_data) {
            debug!("Could not read stream {} in {}: {}", entry_name, jl_path, e);
            continue;
        }

        if let Some((target_path, created, modified, accessed)) = parse_embedded_lnk(&lnk_data) {
            let path = target_path.unwrap_or_else(|| format!("{}:{}", jl_path, entry_name));
            results.push((path, created, modified, accessed));
        }
    }

    Ok(results)
}

/// Parse a CustomDestinations jump list file.
///
/// CustomDestinations files are a sequence of LNK entries separated by markers.
/// The file starts with a header and then contains embedded LNK files.
fn parse_custom_destinations(data: &[u8], jl_path: &str) -> Result<Vec<(String, Option<DateTime<Utc>>, Option<DateTime<Utc>>, Option<DateTime<Utc>>)>> {
    let mut results = Vec::new();

    // Scan for LNK signatures (0x4C followed by the CLSID)
    let mut offset = 0;
    while offset + LNK_HEADER_SIZE <= data.len() {
        // Look for LNK header signature: size=0x4C followed by the CLSID
        if read_u32_le(data, offset) == Some(0x4C) && offset + 20 <= data.len() && data[offset + 4..offset + 20] == LNK_CLSID {
            // Found a potential LNK entry
            let remaining = &data[offset..];
            if let Some((target_path, created, modified, accessed)) = parse_embedded_lnk(remaining) {
                let path = target_path.unwrap_or_else(|| format!("{}:offset_0x{:x}", jl_path, offset));
                results.push((path, created, modified, accessed));
            }
            // Move past this LNK header at minimum
            offset += LNK_HEADER_SIZE;
        } else {
            offset += 1;
        }
    }

    if results.is_empty() {
        debug!("No LNK entries found in custom jump list {}", jl_path);
    }

    Ok(results)
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse all Jump List files from the collection and populate the timeline store.
///
/// Supports both AutomaticDestinations (OLE compound files containing LNK streams)
/// and CustomDestinations (sequences of LNK entries).
pub fn parse_jump_lists(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    let auto_files = &manifest.jump_lists_auto;
    let custom_files = &manifest.jump_lists_custom;

    if auto_files.is_empty() && custom_files.is_empty() {
        debug!("No Jump List files found in manifest");
        return Ok(());
    }

    debug!(
        "Parsing {} auto + {} custom Jump List files",
        auto_files.len(),
        custom_files.len()
    );

    let mut parsed_count = 0u32;
    let mut error_count = 0u32;

    // Parse AutomaticDestinations files
    for jl_path in auto_files {
        let data = match provider.open_file(jl_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read Jump List file {}: {}", jl_path, e);
                error_count += 1;
                continue;
            }
        };

        if data.len() > MAX_JUMPLIST_SIZE {
            warn!(
                "Jump List file {} is abnormally large ({} bytes), skipping",
                jl_path,
                data.len()
            );
            error_count += 1;
            continue;
        }

        let entries = match parse_automatic_destinations(&data, &jl_path.to_string()) {
            Ok(e) => e,
            Err(e) => {
                debug!("Could not parse Jump List {}: {}", jl_path, e);
                error_count += 1;
                continue;
            }
        };

        for (path, created, modified, accessed) in &entries {
            let primary_timestamp = modified.or(*accessed).or(*created);
            let primary_timestamp = match primary_timestamp {
                Some(ts) => ts,
                None => continue,
            };

            let mut timestamps = TimestampSet::default();
            timestamps.jumplist_timestamp = Some(primary_timestamp);
            timestamps.lnk_target_created = *created;
            timestamps.lnk_target_modified = *modified;
            timestamps.lnk_target_accessed = *accessed;

            let entry = TimelineEntry {
                entity_id: EntityId::Generated(next_jumplist_id()),
                path: path.clone(),
                primary_timestamp,
                event_type: EventType::FileAccess,
                timestamps,
                sources: smallvec![ArtifactSource::JumpList],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
            };

            store.push(entry);
        }

        parsed_count += 1;
    }

    // Parse CustomDestinations files
    for jl_path in custom_files {
        let data = match provider.open_file(jl_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read custom Jump List file {}: {}", jl_path, e);
                error_count += 1;
                continue;
            }
        };

        if data.len() > MAX_JUMPLIST_SIZE {
            warn!(
                "Custom Jump List file {} is abnormally large ({} bytes), skipping",
                jl_path,
                data.len()
            );
            error_count += 1;
            continue;
        }

        let entries = match parse_custom_destinations(&data, &jl_path.to_string()) {
            Ok(e) => e,
            Err(e) => {
                debug!("Could not parse custom Jump List {}: {}", jl_path, e);
                error_count += 1;
                continue;
            }
        };

        for (path, created, modified, accessed) in &entries {
            let primary_timestamp = modified.or(*accessed).or(*created);
            let primary_timestamp = match primary_timestamp {
                Some(ts) => ts,
                None => continue,
            };

            let mut timestamps = TimestampSet::default();
            timestamps.jumplist_timestamp = Some(primary_timestamp);
            timestamps.lnk_target_created = *created;
            timestamps.lnk_target_modified = *modified;
            timestamps.lnk_target_accessed = *accessed;

            let entry = TimelineEntry {
                entity_id: EntityId::Generated(next_jumplist_id()),
                path: path.clone(),
                primary_timestamp,
                event_type: EventType::FileAccess,
                timestamps,
                sources: smallvec![ArtifactSource::JumpList],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
            };

            store.push(entry);
        }

        parsed_count += 1;
    }

    debug!(
        "Jump List parsing complete: {} files parsed, {} errors",
        parsed_count, error_count
    );
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
    fn test_extract_app_id_valid() {
        let filename = "5f7b5f1e01b83767.automaticDestinations-ms";
        let app_id = extract_app_id(filename);
        assert_eq!(app_id, Some("5f7b5f1e01b83767".to_string()));
    }

    #[test]
    fn test_extract_app_id_with_path() {
        let filename = r"C:\Users\test\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms";
        let app_id = extract_app_id(filename);
        assert_eq!(app_id, Some("5f7b5f1e01b83767".to_string()));
    }

    #[test]
    fn test_extract_app_id_invalid() {
        assert!(extract_app_id("notahexid.automaticDestinations-ms").is_none());
        assert!(extract_app_id("short.automaticDestinations-ms").is_none());
        assert!(extract_app_id("").is_none());
    }

    fn build_minimal_lnk(
        created_ft: u64,
        accessed_ft: u64,
        write_ft: u64,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; LNK_HEADER_SIZE];
        buf[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        buf[4..20].copy_from_slice(&LNK_CLSID);
        buf[20..24].copy_from_slice(&0u32.to_le_bytes()); // no optional structures
        buf[24..28].copy_from_slice(&0x20u32.to_le_bytes());
        buf[28..36].copy_from_slice(&created_ft.to_le_bytes());
        buf[36..44].copy_from_slice(&accessed_ft.to_le_bytes());
        buf[44..52].copy_from_slice(&write_ft.to_le_bytes());
        buf[52..56].copy_from_slice(&0u32.to_le_bytes());
        buf
    }

    fn datetime_to_filetime(dt: DateTime<Utc>) -> u64 {
        let secs = dt.timestamp() + 11_644_473_600;
        (secs as u64) * 10_000_000
    }

    #[test]
    fn test_parse_embedded_lnk_valid() {
        use chrono::TimeZone;
        let created = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();
        let accessed = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let written = Utc.with_ymd_and_hms(2025, 3, 1, 8, 30, 0).unwrap();

        let lnk = build_minimal_lnk(
            datetime_to_filetime(created),
            datetime_to_filetime(accessed),
            datetime_to_filetime(written),
        );

        let result = parse_embedded_lnk(&lnk);
        assert!(result.is_some());
        let (path, cr, wr, ac) = result.unwrap();
        assert!(path.is_none()); // no LinkInfo
        assert_eq!(cr, Some(created));
        assert_eq!(wr, Some(written));
        assert_eq!(ac, Some(accessed));
    }

    #[test]
    fn test_parse_embedded_lnk_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_embedded_lnk(&data).is_none());
    }

    #[test]
    fn test_parse_embedded_lnk_bad_header() {
        let mut data = vec![0u8; LNK_HEADER_SIZE];
        data[0..4].copy_from_slice(&0x50u32.to_le_bytes()); // wrong size
        assert!(parse_embedded_lnk(&data).is_none());
    }

    #[test]
    fn test_parse_custom_destinations_with_lnk() {
        use chrono::TimeZone;
        let written = Utc.with_ymd_and_hms(2025, 3, 1, 8, 30, 0).unwrap();
        let created = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();
        let accessed = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        // Create data with some garbage prefix + embedded LNK
        let mut data = vec![0xAA; 32]; // some header/garbage
        let lnk = build_minimal_lnk(
            datetime_to_filetime(created),
            datetime_to_filetime(accessed),
            datetime_to_filetime(written),
        );
        data.extend_from_slice(&lnk);

        let results = parse_custom_destinations(&data, "test.customDestinations-ms").unwrap();
        assert_eq!(results.len(), 1);
        // write_time is returned as the "modified" field (position 2)
        assert_eq!(results[0].2, Some(written));
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
        let result = parse_jump_lists(&provider, &manifest, &mut store);
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
    fn test_filetime_with_subsecond() {
        use chrono::TimeZone;
        let dt_base = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let secs = dt_base.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000 + 7_500_000; // +0.75s
        let result = filetime_to_datetime(filetime).unwrap();
        assert_eq!(result.timestamp_subsec_nanos(), 750_000_000);
    }

    #[test]
    fn test_read_u32_le_valid() {
        let data = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&data, 0), Some(0x12345678));
    }

    #[test]
    fn test_read_u32_le_out_of_bounds() {
        let data = [0x01, 0x02, 0x03];
        assert!(read_u32_le(&data, 0).is_none());
    }

    #[test]
    fn test_read_u32_le_offset() {
        let data = [0xFF, 0xFF, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&data, 2), Some(0x12345678));
    }

    #[test]
    fn test_read_u32_le_offset_out_of_bounds() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(read_u32_le(&data, 3).is_none()); // only 2 bytes left at offset 3
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
    fn test_read_u64_le_offset_out_of_bounds() {
        let data = [0u8; 10];
        assert!(read_u64_le(&data, 5).is_none()); // only 5 bytes left
    }

    #[test]
    fn test_read_u16_le_valid() {
        let data = [0x34, 0x12];
        assert_eq!(read_u16_le(&data, 0), Some(0x1234));
    }

    #[test]
    fn test_read_u16_le_out_of_bounds() {
        let data = [0x01];
        assert!(read_u16_le(&data, 0).is_none());
    }

    #[test]
    fn test_read_u16_le_offset() {
        let data = [0xFF, 0x34, 0x12];
        assert_eq!(read_u16_le(&data, 1), Some(0x1234));
    }

    #[test]
    fn test_read_ascii_string_basic() {
        let data = b"hello\x00world";
        let result = read_ascii_string(data, 0, 20);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_read_ascii_string_no_null() {
        let data = b"hello world";
        let result = read_ascii_string(data, 0, data.len());
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_read_ascii_string_with_offset() {
        let data = b"XXXhello\x00";
        let result = read_ascii_string(data, 3, 20);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_read_ascii_string_max_len_limits() {
        let data = b"hello world this is a long string\x00";
        let result = read_ascii_string(data, 0, 5);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_read_ascii_string_empty() {
        let data = b"\x00rest";
        let result = read_ascii_string(data, 0, 10);
        assert_eq!(result, "");
    }

    #[test]
    fn test_extract_app_id_uppercase_hex() {
        let filename = "5F7B5F1E01B83767.automaticDestinations-ms";
        let app_id = extract_app_id(filename);
        assert_eq!(app_id, Some("5f7b5f1e01b83767".to_string()));
    }

    #[test]
    fn test_extract_app_id_mixed_case() {
        let filename = "5F7b5f1E01B83767.automaticDestinations-ms";
        let app_id = extract_app_id(filename);
        assert_eq!(app_id, Some("5f7b5f1e01b83767".to_string()));
    }

    #[test]
    fn test_extract_app_id_too_short_hex() {
        let filename = "5f7b5f1e.automaticDestinations-ms";
        assert!(extract_app_id(filename).is_none());
    }

    #[test]
    fn test_extract_app_id_too_long_hex() {
        let filename = "5f7b5f1e01b837670.automaticDestinations-ms";
        assert!(extract_app_id(filename).is_none());
    }

    #[test]
    fn test_extract_app_id_non_hex() {
        let filename = "5f7b5f1e01b8376g.automaticDestinations-ms"; // 'g' not hex
        assert!(extract_app_id(filename).is_none());
    }

    #[test]
    fn test_extract_app_id_no_dot() {
        let filename = "5f7b5f1e01b83767automaticDestinations-ms";
        assert!(extract_app_id(filename).is_none());
    }

    #[test]
    fn test_extract_app_id_with_forward_slash_path() {
        let filename = "path/to/5f7b5f1e01b83767.automaticDestinations-ms";
        let app_id = extract_app_id(filename);
        assert_eq!(app_id, Some("5f7b5f1e01b83767".to_string()));
    }

    #[test]
    fn test_parse_embedded_lnk_bad_clsid() {
        let mut data = vec![0u8; LNK_HEADER_SIZE];
        data[0..4].copy_from_slice(&0x4Cu32.to_le_bytes()); // correct size
        data[4..20].copy_from_slice(&[0xFF; 16]); // wrong CLSID
        assert!(parse_embedded_lnk(&data).is_none());
    }

    #[test]
    fn test_parse_embedded_lnk_zero_timestamps() {
        let lnk = build_minimal_lnk(0, 0, 0);
        let result = parse_embedded_lnk(&lnk);
        assert!(result.is_some());
        let (path, cr, wr, ac) = result.unwrap();
        assert!(path.is_none());
        assert!(cr.is_none());
        assert!(wr.is_none());
        assert!(ac.is_none());
    }

    #[test]
    fn test_parse_embedded_lnk_with_link_target_id_list() {
        use chrono::TimeZone;
        let created = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let mut lnk = vec![0u8; LNK_HEADER_SIZE + 10];
        lnk[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        lnk[4..20].copy_from_slice(&LNK_CLSID);
        // Set HAS_LINK_TARGET_ID_LIST flag
        lnk[20..24].copy_from_slice(&HAS_LINK_TARGET_ID_LIST.to_le_bytes());
        lnk[28..36].copy_from_slice(&datetime_to_filetime(created).to_le_bytes());
        // IDListSize at offset 0x4C = 4 (small list)
        lnk[LNK_HEADER_SIZE..LNK_HEADER_SIZE + 2].copy_from_slice(&4u16.to_le_bytes());
        // 4 bytes of dummy IDList data
        lnk.extend_from_slice(&[0u8; 4]);

        let result = parse_embedded_lnk(&lnk);
        assert!(result.is_some());
        let (_, cr, _, _) = result.unwrap();
        assert_eq!(cr, Some(created));
    }

    #[test]
    fn test_parse_custom_destinations_empty_data() {
        let data = vec![0u8; 10];
        let results = parse_custom_destinations(&data, "test.customDestinations-ms").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_custom_destinations_no_lnk_signatures() {
        let data = vec![0xAA; 256];
        let results = parse_custom_destinations(&data, "test.customDestinations-ms").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_custom_destinations_multiple_lnks() {
        use chrono::TimeZone;
        let dt1 = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let dt2 = Utc.with_ymd_and_hms(2025, 6, 15, 0, 0, 0).unwrap();

        let lnk1 = build_minimal_lnk(datetime_to_filetime(dt1), 0, datetime_to_filetime(dt1));
        let lnk2 = build_minimal_lnk(datetime_to_filetime(dt2), 0, datetime_to_filetime(dt2));

        let mut data = Vec::new();
        data.extend_from_slice(&lnk1);
        data.extend_from_slice(&[0xFF; 8]); // gap
        data.extend_from_slice(&lnk2);

        let results = parse_custom_destinations(&data, "test.customDestinations-ms").unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_datetime_to_filetime_roundtrip() {
        use chrono::TimeZone;
        let original = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let ft = datetime_to_filetime(original);
        let roundtrip = filetime_to_datetime(ft).unwrap();
        assert_eq!(roundtrip, original);
    }

    #[test]
    fn test_next_jumplist_id_monotonic() {
        let id1 = next_jumplist_id();
        let id2 = next_jumplist_id();
        let id3 = next_jumplist_id();
        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[test]
    fn test_next_jumplist_id_has_jl_prefix() {
        let id = next_jumplist_id();
        // Top 2 bytes should be 0x4A4C ("JL")
        assert_eq!((id >> 48) & 0xFFFF, 0x4A4C);
    }

    #[test]
    fn test_lnk_constants() {
        assert_eq!(LNK_HEADER_SIZE, 0x4C);
        assert_eq!(LNK_CLSID.len(), 16);
        assert_eq!(MAX_JUMPLIST_SIZE, 50_000_000);
    }

    #[test]
    fn test_parse_embedded_lnk_exactly_header_size() {
        // Exactly LNK_HEADER_SIZE bytes but valid header
        let lnk = build_minimal_lnk(0, 0, 0);
        assert_eq!(lnk.len(), LNK_HEADER_SIZE);
        let result = parse_embedded_lnk(&lnk);
        assert!(result.is_some());
    }

    #[test]
    fn test_read_u32_le_zero() {
        let data = [0u8; 4];
        assert_eq!(read_u32_le(&data, 0), Some(0));
    }

    #[test]
    fn test_read_u64_le_max() {
        let data = [0xFF; 8];
        assert_eq!(read_u64_le(&data, 0), Some(u64::MAX));
    }

    #[test]
    fn test_read_u16_le_max() {
        let data = [0xFF, 0xFF];
        assert_eq!(read_u16_le(&data, 0), Some(u16::MAX));
    }

    #[test]
    fn test_parse_embedded_lnk_with_link_info() {
        // Build an LNK with HAS_LINK_INFO flag and a local base path
        let mut lnk = vec![0u8; 200];
        lnk[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        lnk[4..20].copy_from_slice(&LNK_CLSID);
        // Set HAS_LINK_INFO flag only (no IDList)
        lnk[20..24].copy_from_slice(&HAS_LINK_INFO.to_le_bytes());

        // LinkInfo starts at offset 0x4C (no IDList to skip)
        let info_start = LNK_HEADER_SIZE;
        // LinkInfoSize = 100 (plenty of room)
        lnk[info_start..info_start + 4].copy_from_slice(&100u32.to_le_bytes());
        // LinkInfoHeaderSize
        lnk[info_start + 4..info_start + 8].copy_from_slice(&28u32.to_le_bytes());
        // LinkInfoFlags: VolumeIDAndLocalBasePath = 0x01
        lnk[info_start + 8..info_start + 12].copy_from_slice(&1u32.to_le_bytes());
        // VolumeIDOffset
        lnk[info_start + 12..info_start + 16].copy_from_slice(&28u32.to_le_bytes());
        // LocalBasePathOffset - relative to info_start
        let path_offset = 60u32;
        lnk[info_start + 16..info_start + 20].copy_from_slice(&path_offset.to_le_bytes());

        // Write path at info_start + path_offset
        let path_str = b"C:\\Windows\\notepad.exe\x00";
        let abs_offset = info_start + path_offset as usize;
        lnk[abs_offset..abs_offset + path_str.len()].copy_from_slice(path_str);

        let result = parse_embedded_lnk(&lnk);
        assert!(result.is_some());
        let (target_path, _, _, _) = result.unwrap();
        assert!(target_path.is_some());
        assert_eq!(target_path.unwrap(), r"C:\Windows\notepad.exe");
    }

    #[test]
    fn test_parse_automatic_destinations_invalid_data() {
        let data = vec![0u8; 100];
        let result = parse_automatic_destinations(&data, "test.automaticDestinations-ms");
        assert!(result.is_err());
    }
}
