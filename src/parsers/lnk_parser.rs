use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, warn};
use smallvec::smallvec;

use crate::collection::manifest::ArtifactManifest;
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── Constants ───────────────────────────────────────────────────────────────

/// LNK file header size is always 0x4C (76 bytes).
const LNK_HEADER_SIZE: usize = 0x4C;

/// The CLSID that identifies a shell link: 00021401-0000-0000-C000-000000000046
const LNK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x46,
];

/// Maximum reasonable LNK file size (2 MB).
const MAX_LNK_SIZE: usize = 2_000_000;

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

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
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

/// Decode a UTF-16LE byte slice into a String.
fn decode_utf16le(data: &[u8]) -> String {
    let u16_iter = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
    char::decode_utf16(u16_iter)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>()
        .trim_end_matches('\0')
        .to_string()
}

/// Read a null-terminated ASCII string starting at offset.
fn read_ascii_string(data: &[u8], offset: usize, max_len: usize) -> String {
    let end = std::cmp::min(offset + max_len, data.len());
    let slice = &data[offset..end];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..nul]).to_string()
}

// ─── LNK header flags ────────────────────────────────────────────────────────

/// LinkFlags bits we care about.
const HAS_LINK_TARGET_ID_LIST: u32 = 0x0000_0001;
const HAS_LINK_INFO: u32 = 0x0000_0002;
const IS_UNICODE: u32 = 0x0000_0080;
const HAS_NAME: u32 = 0x0000_0004;
const HAS_RELATIVE_PATH: u32 = 0x0000_0008;
// Additional flag constants (kept for reference, used when parsing StringData fully)
#[allow(dead_code)]
const HAS_WORKING_DIR: u32 = 0x0000_0010;
#[allow(dead_code)]
const HAS_ARGUMENTS: u32 = 0x0000_0020;
#[allow(dead_code)]
const HAS_ICON_LOCATION: u32 = 0x0000_0040;

// ─── Parsed LNK info ─────────────────────────────────────────────────────────

/// Information extracted from a parsed LNK file.
#[derive(Debug, Clone)]
pub struct LnkInfo {
    /// Target file path (from LinkInfo or relative path).
    pub target_path: Option<String>,
    /// Target creation timestamp.
    pub target_created: Option<DateTime<Utc>>,
    /// Target modification (write) timestamp.
    pub target_modified: Option<DateTime<Utc>>,
    /// Target access timestamp.
    pub target_accessed: Option<DateTime<Utc>>,
    /// Volume serial number from LinkInfo.
    pub volume_serial: Option<u32>,
    /// Drive type from LinkInfo.
    pub drive_type: Option<u32>,
    /// File size of the target.
    pub target_file_size: u32,
    /// The source LNK file path.
    pub lnk_path: String,
}

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static LNK_ID_COUNTER: AtomicU64 = AtomicU64::new(0x4C4E_0000_0000_0000); // "LN" prefix

fn next_lnk_id() -> u64 {
    LNK_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── LNK parsing ─────────────────────────────────────────────────────────────

/// Parse a single LNK file from raw bytes.
///
/// The LNK format (MS-SHLLINK) has the following structure:
/// - ShellLinkHeader (76 bytes, offset 0)
///   - HeaderSize (4 bytes): must be 0x4C
///   - LinkCLSID (16 bytes): the GUID
///   - LinkFlags (4 bytes)
///   - FileAttributes (4 bytes)
///   - CreationTime (8 bytes, FILETIME)
///   - AccessTime (8 bytes, FILETIME)
///   - WriteTime (8 bytes, FILETIME)
///   - FileSize (4 bytes)
///   - ...
/// - LinkTargetIDList (variable, optional)
/// - LinkInfo (variable, optional)
/// - StringData (variable, optional)
pub fn parse_lnk_data(data: &[u8], lnk_path: &str) -> Result<LnkInfo> {
    if data.len() < LNK_HEADER_SIZE {
        anyhow::bail!("LNK data too short: {} bytes", data.len());
    }

    // Validate header size
    let header_size = read_u32_le(data, 0).unwrap_or(0);
    if header_size != 0x4C {
        anyhow::bail!("Invalid LNK header size: 0x{:08x}", header_size);
    }

    // Validate CLSID
    if data[4..20] != LNK_CLSID {
        anyhow::bail!("Invalid LNK CLSID");
    }

    // Parse LinkFlags
    let link_flags = read_u32_le(data, 20).unwrap_or(0);

    // Parse file attributes
    let _file_attributes = read_u32_le(data, 24).unwrap_or(0);

    // Parse timestamps from header (these are the target's timestamps)
    let creation_time = read_u64_le(data, 28).and_then(filetime_to_datetime);
    let access_time = read_u64_le(data, 36).and_then(filetime_to_datetime);
    let write_time = read_u64_le(data, 44).and_then(filetime_to_datetime);

    // File size of the target
    let file_size = read_u32_le(data, 52).unwrap_or(0);

    // Now parse optional structures after the header
    let mut offset = LNK_HEADER_SIZE;
    let mut target_path: Option<String> = None;
    let mut volume_serial: Option<u32> = None;
    let mut drive_type: Option<u32> = None;

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
            let _link_info_header_size = read_u32_le(data, info_start + 4).unwrap_or(0);
            let link_info_flags = read_u32_le(data, info_start + 8).unwrap_or(0);

            // VolumeIDAndLocalBasePath flag
            if (link_info_flags & 0x01) != 0 {
                let volume_id_offset =
                    read_u32_le(data, info_start + 12).unwrap_or(0) as usize;
                let local_base_path_offset =
                    read_u32_le(data, info_start + 16).unwrap_or(0) as usize;

                // Extract volume serial from VolumeID structure
                if volume_id_offset >= 4 {
                    let vol_abs = info_start + volume_id_offset;
                    if vol_abs + 12 <= data.len() {
                        drive_type = read_u32_le(data, vol_abs + 4);
                        volume_serial = read_u32_le(data, vol_abs + 8);
                    }
                }

                // Extract local base path
                if local_base_path_offset > 0 {
                    let path_abs = info_start + local_base_path_offset;
                    if path_abs < data.len() {
                        let path =
                            read_ascii_string(data, path_abs, data.len() - path_abs);
                        if !path.is_empty() {
                            target_path = Some(path);
                        }
                    }
                }
            }

            offset = info_start + link_info_size;
        }
    }

    // Parse StringData to try to get relative path if we don't have a target path yet
    if target_path.is_none() {
        let is_unicode = (link_flags & IS_UNICODE) != 0;
        let mut str_offset = offset;

        // Skip name string if present
        if (link_flags & HAS_NAME) != 0 {
            if let Some(count) = read_u16_le(data, str_offset) {
                let char_size = if is_unicode { 2 } else { 1 };
                str_offset += 2 + count as usize * char_size;
            }
        }

        // Read relative path if present
        if (link_flags & HAS_RELATIVE_PATH) != 0 && str_offset + 2 <= data.len() {
            if let Some(count) = read_u16_le(data, str_offset) {
                let char_size = if is_unicode { 2 } else { 1 };
                let str_start = str_offset + 2;
                let str_len = count as usize * char_size;
                if str_start + str_len <= data.len() && count > 0 {
                    let path = if is_unicode {
                        decode_utf16le(&data[str_start..str_start + str_len])
                    } else {
                        String::from_utf8_lossy(&data[str_start..str_start + str_len])
                            .to_string()
                    };
                    if !path.is_empty() {
                        target_path = Some(path);
                    }
                }
            }
        }
    }

    Ok(LnkInfo {
        target_path,
        target_created: creation_time,
        target_modified: write_time,
        target_accessed: access_time,
        volume_serial,
        drive_type,
        target_file_size: file_size,
        lnk_path: lnk_path.to_string(),
    })
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse all LNK files from the collection and populate the timeline store.
///
/// For each .lnk file in the manifest, this extracts:
/// - Target file path
/// - Target timestamps (created, modified, accessed)
/// - Volume serial and drive type
///
/// Creates TimelineEntry records with EventType::FileAccess and ArtifactSource::Lnk.
pub fn parse_lnk_files(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    let lnk_files = manifest.lnk_files();
    if lnk_files.is_empty() {
        debug!("No LNK files found in manifest");
        return Ok(());
    }

    debug!("Parsing {} LNK files", lnk_files.len());
    let mut parsed_count = 0u32;
    let mut error_count = 0u32;

    for lnk_path in lnk_files {
        let data = match provider.open_file(lnk_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read LNK file {}: {}", lnk_path, e);
                error_count += 1;
                continue;
            }
        };

        if data.len() > MAX_LNK_SIZE {
            warn!(
                "LNK file {} is abnormally large ({} bytes), skipping",
                lnk_path,
                data.len()
            );
            error_count += 1;
            continue;
        }

        let lnk_info = match parse_lnk_data(&data, &lnk_path.to_string()) {
            Ok(info) => info,
            Err(e) => {
                debug!("Could not parse LNK file {}: {}", lnk_path, e);
                error_count += 1;
                continue;
            }
        };

        // Determine the primary timestamp: prefer modified, then accessed, then created
        let primary_timestamp = lnk_info
            .target_modified
            .or(lnk_info.target_accessed)
            .or(lnk_info.target_created);

        let primary_timestamp = match primary_timestamp {
            Some(ts) => ts,
            None => {
                debug!(
                    "LNK file {} has no usable timestamps, skipping",
                    lnk_path
                );
                continue;
            }
        };

        let target_path = lnk_info
            .target_path
            .unwrap_or_else(|| lnk_path.to_string());

        let mut timestamps = TimestampSet::default();
        timestamps.lnk_target_created = lnk_info.target_created;
        timestamps.lnk_target_modified = lnk_info.target_modified;
        timestamps.lnk_target_accessed = lnk_info.target_accessed;

        let metadata = EntryMetadata {
            file_size: Some(lnk_info.target_file_size as u64),
            ..EntryMetadata::default()
        };

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_lnk_id()),
            path: target_path,
            primary_timestamp,
            event_type: EventType::FileAccess,
            timestamps,
            sources: smallvec![ArtifactSource::Lnk],
            anomalies: AnomalyFlags::empty(),
            metadata,
        };

        store.push(entry);
        parsed_count += 1;
    }

    debug!(
        "LNK parsing complete: {} files parsed, {} errors",
        parsed_count, error_count
    );
    Ok(())
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid LNK file header for testing.
    fn build_lnk_header(
        created_ft: u64,
        accessed_ft: u64,
        write_ft: u64,
        file_size: u32,
        link_flags: u32,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; LNK_HEADER_SIZE];

        // Header size = 0x4C
        buf[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());

        // CLSID
        buf[4..20].copy_from_slice(&LNK_CLSID);

        // LinkFlags
        buf[20..24].copy_from_slice(&link_flags.to_le_bytes());

        // File attributes (normal)
        buf[24..28].copy_from_slice(&0x20u32.to_le_bytes());

        // Timestamps
        buf[28..36].copy_from_slice(&created_ft.to_le_bytes());
        buf[36..44].copy_from_slice(&accessed_ft.to_le_bytes());
        buf[44..52].copy_from_slice(&write_ft.to_le_bytes());

        // File size
        buf[52..56].copy_from_slice(&file_size.to_le_bytes());

        buf
    }

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
    fn test_parse_lnk_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_lnk_data(&data, "test.lnk").is_err());
    }

    #[test]
    fn test_parse_lnk_bad_header_size() {
        let mut data = vec![0u8; LNK_HEADER_SIZE];
        data[0..4].copy_from_slice(&0x50u32.to_le_bytes()); // wrong header size
        data[4..20].copy_from_slice(&LNK_CLSID);
        assert!(parse_lnk_data(&data, "test.lnk").is_err());
    }

    #[test]
    fn test_parse_lnk_bad_clsid() {
        let mut data = vec![0u8; LNK_HEADER_SIZE];
        data[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        // Wrong CLSID
        data[4..20].copy_from_slice(&[0xFF; 16]);
        assert!(parse_lnk_data(&data, "test.lnk").is_err());
    }

    #[test]
    fn test_parse_lnk_header_only() {
        use chrono::TimeZone;
        let created = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();
        let accessed = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let written = Utc.with_ymd_and_hms(2025, 3, 1, 8, 30, 0).unwrap();

        let data = build_lnk_header(
            datetime_to_filetime(created),
            datetime_to_filetime(accessed),
            datetime_to_filetime(written),
            12345,
            0, // no optional structures
        );

        let info = parse_lnk_data(&data, r"C:\Users\test\Recent\doc.lnk").unwrap();

        assert_eq!(info.target_created, Some(created));
        assert_eq!(info.target_accessed, Some(accessed));
        assert_eq!(info.target_modified, Some(written));
        assert_eq!(info.target_file_size, 12345);
        assert!(info.target_path.is_none()); // no LinkInfo or StringData
    }

    #[test]
    fn test_parse_lnk_with_link_info() {
        use chrono::TimeZone;
        let created = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();
        let accessed = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let written = Utc.with_ymd_and_hms(2025, 3, 1, 8, 30, 0).unwrap();

        // Build header with HAS_LINK_INFO flag
        let mut data = build_lnk_header(
            datetime_to_filetime(created),
            datetime_to_filetime(accessed),
            datetime_to_filetime(written),
            5000,
            HAS_LINK_INFO,
        );

        // Build a minimal LinkInfo structure
        let target_path = b"C:\\Windows\\System32\\cmd.exe\0";
        let volume_id_size = 16u32; // minimal VolumeID
        let local_base_path_offset = 28u32 + volume_id_size; // after LinkInfo header + VolumeID

        let link_info_size =
            local_base_path_offset as usize + target_path.len();

        // LinkInfo header
        let link_info_start = data.len();
        data.extend_from_slice(&(link_info_size as u32).to_le_bytes()); // LinkInfoSize
        data.extend_from_slice(&28u32.to_le_bytes()); // LinkInfoHeaderSize
        data.extend_from_slice(&0x01u32.to_le_bytes()); // LinkInfoFlags: VolumeIDAndLocalBasePath
        data.extend_from_slice(&28u32.to_le_bytes()); // VolumeIDOffset (right after header)
        data.extend_from_slice(&local_base_path_offset.to_le_bytes()); // LocalBasePathOffset
        data.extend_from_slice(&0u32.to_le_bytes()); // CommonNetworkRelativeLinkOffset
        data.extend_from_slice(&0u32.to_le_bytes()); // CommonPathSuffixOffset

        // VolumeID structure (minimal)
        let vol_start = data.len();
        assert_eq!(vol_start - link_info_start, 28); // verify offset
        data.extend_from_slice(&volume_id_size.to_le_bytes()); // VolumeIDSize
        data.extend_from_slice(&3u32.to_le_bytes()); // DriveType = DRIVE_FIXED
        data.extend_from_slice(&0xABCD1234u32.to_le_bytes()); // DriveSerialNumber
        data.extend_from_slice(&0u32.to_le_bytes()); // VolumeLabelOffset

        // Local base path
        assert_eq!(data.len() - link_info_start, local_base_path_offset as usize);
        data.extend_from_slice(target_path);

        let info = parse_lnk_data(&data, r"C:\Users\test\Recent\cmd.lnk").unwrap();

        assert_eq!(
            info.target_path,
            Some(r"C:\Windows\System32\cmd.exe".to_string())
        );
        assert_eq!(info.volume_serial, Some(0xABCD1234));
        assert_eq!(info.drive_type, Some(3)); // DRIVE_FIXED
        assert_eq!(info.target_created, Some(created));
        assert_eq!(info.target_modified, Some(written));
        assert_eq!(info.target_accessed, Some(accessed));
    }

    #[test]
    fn test_parse_lnk_timeline_entry_creation() {
        use chrono::TimeZone;
        let written = Utc.with_ymd_and_hms(2025, 3, 1, 8, 30, 0).unwrap();

        let data = build_lnk_header(
            datetime_to_filetime(Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()),
            datetime_to_filetime(Utc.with_ymd_and_hms(2025, 6, 15, 0, 0, 0).unwrap()),
            datetime_to_filetime(written),
            1000,
            0,
        );

        let info = parse_lnk_data(&data, "test.lnk").unwrap();

        // Verify we can create a proper timeline entry
        let primary_timestamp = info
            .target_modified
            .or(info.target_accessed)
            .or(info.target_created)
            .unwrap();

        let mut timestamps = TimestampSet::default();
        timestamps.lnk_target_created = info.target_created;
        timestamps.lnk_target_modified = info.target_modified;
        timestamps.lnk_target_accessed = info.target_accessed;

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_lnk_id()),
            path: "test.lnk".to_string(),
            primary_timestamp,
            event_type: EventType::FileAccess,
            timestamps,
            sources: smallvec![ArtifactSource::Lnk],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        assert_eq!(entry.event_type, EventType::FileAccess);
        assert_eq!(entry.primary_timestamp, written);
        assert!(entry.timestamps.lnk_target_created.is_some());
        assert!(entry.timestamps.lnk_target_modified.is_some());
        assert!(entry.timestamps.lnk_target_accessed.is_some());
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
        let result = parse_lnk_files(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_decode_utf16le() {
        let s = r"C:\test\file.txt";
        let encoded: Vec<u8> = s
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(decode_utf16le(&encoded), s);
    }

    #[test]
    fn test_read_ascii_string() {
        let data = b"hello world\0extra";
        let result = read_ascii_string(data, 0, 20);
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_read_ascii_string_no_null() {
        let data = b"hello";
        let result = read_ascii_string(data, 0, 5);
        assert_eq!(result, "hello");
    }
}
