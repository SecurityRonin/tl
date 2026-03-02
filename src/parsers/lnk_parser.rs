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

// ─── TrackerDataBlock ────────────────────────────────────────────────────────

/// ExtraData block signature for TrackerDataBlock (MS-SHLLINK 2.5.10).
const TRACKER_DATA_SIGNATURE: u32 = 0xA000_0003;

/// TrackerDataBlock size is always 0x60 (96 bytes).
const TRACKER_DATA_BLOCK_SIZE: u32 = 0x60;

/// Distributed tracking data extracted from LNK ExtraData.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerData {
    /// NetBIOS name of the machine where the link target was last known to reside.
    pub machine_id: String,
    /// MAC address extracted from the birth Droid ObjectID (UUID v1 node field).
    pub mac_address: [u8; 6],
}

/// Parse a TrackerDataBlock from a 96-byte buffer.
///
/// Layout (MS-SHLLINK 2.5.10):
///   offset 0:  BlockSize     (4 bytes) = 0x00000060
///   offset 4:  BlockSignature(4 bytes) = 0xA0000003
///   offset 8:  Length        (4 bytes) = 0x00000058
///   offset 12: Version       (4 bytes) = 0x00000000
///   offset 16: MachineID     (16 bytes, null-terminated ASCII)
///   offset 32: Droid         (32 bytes: VolumeID GUID + ObjectID GUID)
///   offset 64: DroidBirth    (32 bytes: VolumeID GUID + ObjectID GUID)
///
/// MAC address is in the last 6 bytes of the DroidBirth ObjectID (UUID v1 node).
pub fn parse_tracker_data_block(data: &[u8]) -> Option<TrackerData> {
    if data.len() < 96 {
        return None;
    }
    let signature = read_u32_le(data, 4)?;
    if signature != TRACKER_DATA_SIGNATURE {
        return None;
    }

    let machine_id = read_ascii_string(data, 16, 16);

    // DroidBirth ObjectID starts at offset 80 (second GUID in DroidBirth).
    // UUID v1 node (MAC) is the last 6 bytes of the 16-byte UUID: offset 80+10=90.
    let mac = [
        data[90], data[91], data[92], data[93], data[94], data[95],
    ];

    Some(TrackerData { machine_id, mac_address: mac })
}

/// Format a 6-byte MAC address as a colon-separated hex string.
pub fn format_mac_address(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
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
    /// Distributed tracker data (MachineID, MAC address) from ExtraData.
    pub tracker_data: Option<TrackerData>,
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

    // Parse StringData: always traverse all fields to reach ExtraData position.
    let is_unicode = (link_flags & IS_UNICODE) != 0;
    let char_size: usize = if is_unicode { 2 } else { 1 };

    // Helper: skip one CountCharacters + String field, return new offset.
    let skip_string_field = |data: &[u8], off: usize, cs: usize| -> usize {
        if off + 2 > data.len() {
            return off;
        }
        let count = read_u16_le(data, off).unwrap_or(0) as usize;
        off + 2 + count * cs
    };

    // Skip NAME_STRING if present
    if (link_flags & HAS_NAME) != 0 {
        offset = skip_string_field(data, offset, char_size);
    }

    // Read RELATIVE_PATH if present (use it as target_path fallback)
    if (link_flags & HAS_RELATIVE_PATH) != 0 {
        if target_path.is_none() && offset + 2 <= data.len() {
            if let Some(count) = read_u16_le(data, offset) {
                let str_start = offset + 2;
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
        offset = skip_string_field(data, offset, char_size);
    }

    // Skip WORKING_DIR, ARGUMENTS, ICON_LOCATION
    if (link_flags & HAS_WORKING_DIR) != 0 {
        offset = skip_string_field(data, offset, char_size);
    }
    if (link_flags & HAS_ARGUMENTS) != 0 {
        offset = skip_string_field(data, offset, char_size);
    }
    if (link_flags & HAS_ICON_LOCATION) != 0 {
        offset = skip_string_field(data, offset, char_size);
    }

    // Scan ExtraData blocks for TrackerDataBlock
    let mut tracker_data: Option<TrackerData> = None;
    while offset + 8 <= data.len() {
        let block_size = read_u32_le(data, offset).unwrap_or(0) as usize;
        if block_size < 4 {
            break; // Terminal block
        }
        if offset + block_size > data.len() {
            break;
        }
        let signature = read_u32_le(data, offset + 4).unwrap_or(0);
        if signature == TRACKER_DATA_SIGNATURE && block_size as u32 == TRACKER_DATA_BLOCK_SIZE {
            tracker_data = parse_tracker_data_block(&data[offset..offset + block_size]);
        }
        offset += block_size;
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
        tracker_data,
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

        // Append tracker info (MachineID + MAC) if present
        let target_path = if let Some(ref tracker) = lnk_info.tracker_data {
            let mac = format_mac_address(&tracker.mac_address);
            format!("{} (via {}, MAC: {})", target_path, tracker.machine_id, mac)
        } else {
            target_path
        };

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

    // ─── TrackerDataBlock tests ───────────────────────────────────────────

    /// Build a 96-byte TrackerDataBlock for testing.
    fn build_tracker_block(machine_id: &str, mac: [u8; 6]) -> Vec<u8> {
        let mut block = vec![0u8; 96];
        block[0..4].copy_from_slice(&TRACKER_DATA_BLOCK_SIZE.to_le_bytes());
        block[4..8].copy_from_slice(&TRACKER_DATA_SIGNATURE.to_le_bytes());
        block[8..12].copy_from_slice(&0x58u32.to_le_bytes()); // Length
        // Version = 0 (already zero)
        let id_bytes = machine_id.as_bytes();
        let copy_len = std::cmp::min(id_bytes.len(), 15); // leave room for null
        block[16..16 + copy_len].copy_from_slice(&id_bytes[..copy_len]);
        // MAC in DroidBirth ObjectID: bytes 90..96
        block[90..96].copy_from_slice(&mac);
        block
    }

    #[test]
    fn test_parse_tracker_data_block_valid() {
        let mac = [0x08, 0x00, 0x27, 0x3A, 0xCE, 0x83];
        let block = build_tracker_block("DESKTOP-ABC", mac);
        let tracker = parse_tracker_data_block(&block).unwrap();
        assert_eq!(tracker.machine_id, "DESKTOP-ABC");
        assert_eq!(tracker.mac_address, mac);
    }

    #[test]
    fn test_parse_tracker_data_block_bad_signature() {
        let mut block = vec![0u8; 96];
        block[0..4].copy_from_slice(&0x60u32.to_le_bytes());
        block[4..8].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        assert!(parse_tracker_data_block(&block).is_none());
    }

    #[test]
    fn test_parse_tracker_data_block_too_short() {
        let block = vec![0u8; 50];
        assert!(parse_tracker_data_block(&block).is_none());
    }

    #[test]
    fn test_format_mac_address() {
        assert_eq!(
            format_mac_address(&[0x08, 0x00, 0x27, 0x3A, 0xCE, 0x83]),
            "08:00:27:3a:ce:83"
        );
        assert_eq!(
            format_mac_address(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            "ff:ff:ff:ff:ff:ff"
        );
    }

    #[test]
    fn test_parse_lnk_with_tracker_block() {
        use chrono::TimeZone;
        let created = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();
        let accessed = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let written = Utc.with_ymd_and_hms(2025, 3, 1, 8, 30, 0).unwrap();

        // Header with no optional sections (flags = 0)
        let mut data = build_lnk_header(
            datetime_to_filetime(created),
            datetime_to_filetime(accessed),
            datetime_to_filetime(written),
            5000,
            0,
        );

        // Append TrackerDataBlock as ExtraData
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        data.extend_from_slice(&build_tracker_block("WORKSTATION1", mac));

        // Terminal block
        data.extend_from_slice(&0u32.to_le_bytes());

        let info = parse_lnk_data(&data, "test.lnk").unwrap();
        let tracker = info.tracker_data.as_ref().unwrap();
        assert_eq!(tracker.machine_id, "WORKSTATION1");
        assert_eq!(tracker.mac_address, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_lnk_no_tracker_block() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();
        let data = build_lnk_header(
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            100,
            0,
        );
        let info = parse_lnk_data(&data, "test.lnk").unwrap();
        assert!(info.tracker_data.is_none());
    }

    #[test]
    fn test_tracker_data_in_timeline_path() {
        use chrono::TimeZone;
        let written = Utc.with_ymd_and_hms(2025, 3, 1, 8, 30, 0).unwrap();

        let mut data = build_lnk_header(
            datetime_to_filetime(written),
            datetime_to_filetime(written),
            datetime_to_filetime(written),
            1000,
            HAS_LINK_INFO,
        );

        // Minimal LinkInfo with local base path
        let target_path = b"C:\\Windows\\System32\\cmd.exe\0";
        let volume_id_size = 16u32;
        let local_base_path_offset = 28u32 + volume_id_size;
        let link_info_size = local_base_path_offset as usize + target_path.len();

        data.extend_from_slice(&(link_info_size as u32).to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes());
        data.extend_from_slice(&0x01u32.to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes());
        data.extend_from_slice(&local_base_path_offset.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        data.extend_from_slice(&volume_id_size.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&0xABCDu32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        data.extend_from_slice(target_path);

        // TrackerDataBlock
        let mac = [0x08, 0x00, 0x27, 0xAB, 0xCD, 0xEF];
        data.extend_from_slice(&build_tracker_block("SUSPECT-PC", mac));

        // Terminal block
        data.extend_from_slice(&0u32.to_le_bytes());

        let info = parse_lnk_data(&data, "test.lnk").unwrap();
        assert_eq!(info.target_path, Some(r"C:\Windows\System32\cmd.exe".to_string()));
        let tracker = info.tracker_data.as_ref().unwrap();
        assert_eq!(tracker.machine_id, "SUSPECT-PC");
        assert_eq!(format_mac_address(&tracker.mac_address), "08:00:27:ab:cd:ef");
    }

    // ─── Original tests ─────────────────────────────────────────────────────

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

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_filetime_negative_secs() {
        let filetime = 10_000_000u64;
        assert!(filetime_to_datetime(filetime).is_none());
    }

    #[test]
    fn test_read_u16_le_valid() {
        let data = [0x34, 0x12, 0x00, 0x00];
        assert_eq!(read_u16_le(&data, 0), Some(0x1234));
    }

    #[test]
    fn test_read_u16_le_boundary() {
        let data = [0x34, 0x12];
        assert_eq!(read_u16_le(&data, 0), Some(0x1234));
        assert!(read_u16_le(&data, 1).is_none());
    }

    #[test]
    fn test_read_u32_le_boundary() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u32_le(&data, 0), Some(0x04030201));
        assert!(read_u32_le(&data, 1).is_none());
    }

    #[test]
    fn test_read_u64_le_boundary() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u64_le(&data, 0), Some(0x0807060504030201));
        assert!(read_u64_le(&data, 1).is_none());
    }

    #[test]
    fn test_decode_utf16le_with_null_terminator() {
        let s = "test";
        let mut encoded: Vec<u8> = s
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        encoded.extend_from_slice(&[0, 0]); // null terminator
        // Should trim trailing nulls
        assert_eq!(decode_utf16le(&encoded), "test");
    }

    #[test]
    fn test_decode_utf16le_with_replacement_char() {
        // Invalid surrogate pair
        let data: Vec<u8> = vec![0x00, 0xD8, 0x41, 0x00]; // lone high surrogate + 'A'
        let result = decode_utf16le(&data);
        assert!(result.contains('\u{FFFD}')); // replacement character
        assert!(result.contains('A'));
    }

    #[test]
    fn test_decode_utf16le_empty() {
        let data: Vec<u8> = vec![];
        assert_eq!(decode_utf16le(&data), "");
    }

    #[test]
    fn test_read_ascii_string_with_offset() {
        let data = b"XXhello world\0more";
        let result = read_ascii_string(data, 2, 20);
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_read_ascii_string_max_len_limits() {
        let data = b"abcdefghij";
        let result = read_ascii_string(data, 0, 3);
        assert_eq!(result, "abc");
    }

    #[test]
    fn test_format_mac_all_zeros() {
        assert_eq!(
            format_mac_address(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "00:00:00:00:00:00"
        );
    }

    #[test]
    fn test_tracker_data_eq() {
        let t1 = TrackerData {
            machine_id: "PC1".to_string(),
            mac_address: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        };
        let t2 = TrackerData {
            machine_id: "PC1".to_string(),
            mac_address: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        };
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_tracker_data_ne() {
        let t1 = TrackerData {
            machine_id: "PC1".to_string(),
            mac_address: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        };
        let t2 = TrackerData {
            machine_id: "PC2".to_string(),
            mac_address: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        };
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_parse_lnk_with_id_list() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();

        // Header with HAS_LINK_TARGET_ID_LIST
        let mut data = build_lnk_header(
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            100,
            HAS_LINK_TARGET_ID_LIST,
        );

        // IDList: 2-byte size = 4, then 4 bytes of data
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 4]);

        let info = parse_lnk_data(&data, "test.lnk").unwrap();
        assert!(info.target_path.is_none());
        assert_eq!(info.target_created, Some(dt));
    }

    #[test]
    fn test_parse_lnk_with_string_data_unicode() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();

        // Header with HAS_RELATIVE_PATH and IS_UNICODE
        let flags = HAS_RELATIVE_PATH | IS_UNICODE;
        let mut data = build_lnk_header(
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            100,
            flags,
        );

        // Relative path string (Unicode): count=4, "test" in UTF-16LE
        let rel_path = "test";
        let count = rel_path.encode_utf16().count() as u16;
        data.extend_from_slice(&count.to_le_bytes());
        let utf16: Vec<u8> = rel_path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&utf16);

        let info = parse_lnk_data(&data, "test.lnk").unwrap();
        assert_eq!(info.target_path, Some("test".to_string()));
    }

    #[test]
    fn test_parse_lnk_with_string_data_ascii() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();

        // Header with HAS_RELATIVE_PATH (no IS_UNICODE)
        let flags = HAS_RELATIVE_PATH;
        let mut data = build_lnk_header(
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            100,
            flags,
        );

        // Relative path string (ASCII): count=4, "test"
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(b"test");

        let info = parse_lnk_data(&data, "test.lnk").unwrap();
        assert_eq!(info.target_path, Some("test".to_string()));
    }

    #[test]
    fn test_parse_lnk_skip_working_dir_args_icon() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();

        // Header with HAS_WORKING_DIR | HAS_ARGUMENTS | HAS_ICON_LOCATION
        let flags = HAS_WORKING_DIR | HAS_ARGUMENTS | HAS_ICON_LOCATION;
        let mut data = build_lnk_header(
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            100,
            flags,
        );

        // Working dir: count=3, "abc"
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(b"abc");
        // Arguments: count=2, "xy"
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(b"xy");
        // Icon: count=1, "z"
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(b"z");

        let info = parse_lnk_data(&data, "test.lnk").unwrap();
        assert!(info.target_path.is_none());
        assert!(info.tracker_data.is_none());
    }

    #[test]
    fn test_parse_lnk_with_name_string() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();

        // Header with HAS_NAME
        let flags = HAS_NAME;
        let mut data = build_lnk_header(
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            100,
            flags,
        );

        // Name string: count=5, "hello"
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(b"hello");

        let info = parse_lnk_data(&data, "test.lnk").unwrap();
        // NAME_STRING is skipped, not used
        assert!(info.target_path.is_none());
    }

    #[test]
    fn test_parse_lnk_extra_data_non_tracker() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();

        let mut data = build_lnk_header(
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            100,
            0,
        );

        // Add a non-tracker extra data block (random signature)
        let block_size = 20u32;
        data.extend_from_slice(&block_size.to_le_bytes());
        data.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
        data.extend_from_slice(&[0u8; 12]); // pad to 20 bytes

        // Terminal block
        data.extend_from_slice(&0u32.to_le_bytes());

        let info = parse_lnk_data(&data, "test.lnk").unwrap();
        assert!(info.tracker_data.is_none());
    }

    #[test]
    fn test_parse_lnk_no_timestamps() {
        // Header with all zero timestamps
        let data = build_lnk_header(0, 0, 0, 100, 0);
        let info = parse_lnk_data(&data, "test.lnk").unwrap();
        assert!(info.target_created.is_none());
        assert!(info.target_modified.is_none());
        assert!(info.target_accessed.is_none());
    }

    #[test]
    fn test_next_lnk_id_increments() {
        let id1 = next_lnk_id();
        let id2 = next_lnk_id();
        assert!(id2 > id1);
        assert_eq!(id1 >> 48, 0x4C4E);
    }

    #[test]
    fn test_lnk_info_debug_clone() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let info = LnkInfo {
            target_path: Some("test.txt".to_string()),
            target_created: Some(dt),
            target_modified: Some(dt),
            target_accessed: Some(dt),
            volume_serial: Some(0x1234),
            drive_type: Some(3),
            target_file_size: 42,
            lnk_path: "test.lnk".to_string(),
            tracker_data: None,
        };
        let cloned = info.clone();
        assert_eq!(cloned.target_path, info.target_path);
        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("test.txt"));
    }

    #[test]
    fn test_parse_lnk_link_info_no_volume_id() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();

        let mut data = build_lnk_header(
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            datetime_to_filetime(dt),
            100,
            HAS_LINK_INFO,
        );

        // LinkInfo with flags = 0 (no VolumeIDAndLocalBasePath)
        let link_info_size = 28u32;
        data.extend_from_slice(&link_info_size.to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes()); // header size
        data.extend_from_slice(&0x00u32.to_le_bytes()); // flags = 0
        data.extend_from_slice(&0u32.to_le_bytes());    // VolumeIDOffset
        data.extend_from_slice(&0u32.to_le_bytes());    // LocalBasePathOffset
        data.extend_from_slice(&0u32.to_le_bytes());    // CommonNetworkRelativeLinkOffset
        data.extend_from_slice(&0u32.to_le_bytes());    // CommonPathSuffixOffset

        let info = parse_lnk_data(&data, "test.lnk").unwrap();
        assert!(info.target_path.is_none());
        assert!(info.volume_serial.is_none());
    }
}
