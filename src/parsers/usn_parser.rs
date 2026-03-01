use anyhow::Result;
use bitflags::bitflags;
use chrono::{DateTime, Utc};
use log::{debug, warn};
use smallvec::smallvec;

use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

bitflags! {
    /// USN Journal reason flags indicating what operation triggered the journal entry.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct UsnReason: u32 {
        const DATA_OVERWRITE        = 0x0000_0001;
        const DATA_EXTEND           = 0x0000_0002;
        const DATA_TRUNCATION       = 0x0000_0004;
        const NAMED_DATA_OVERWRITE  = 0x0000_0010;
        const NAMED_DATA_EXTEND     = 0x0000_0020;
        const NAMED_DATA_TRUNCATION = 0x0000_0040;
        const FILE_CREATE           = 0x0000_0100;
        const FILE_DELETE           = 0x0000_0200;
        const EA_CHANGE             = 0x0000_0400;
        const SECURITY_CHANGE       = 0x0000_0800;
        const RENAME_OLD_NAME       = 0x0000_1000;
        const RENAME_NEW_NAME       = 0x0000_2000;
        const INDEXABLE_CHANGE      = 0x0000_4000;
        const BASIC_INFO_CHANGE     = 0x0000_8000;
        const HARD_LINK_CHANGE      = 0x0001_0000;
        const COMPRESSION_CHANGE    = 0x0002_0000;
        const ENCRYPTION_CHANGE     = 0x0004_0000;
        const OBJECT_ID_CHANGE      = 0x0008_0000;
        const REPARSE_POINT_CHANGE  = 0x0010_0000;
        const STREAM_CHANGE         = 0x0020_0000;
        const CLOSE                 = 0x8000_0000;
    }
}

/// A parsed USN_RECORD_V2 from the $UsnJrnl:$J.
#[derive(Debug, Clone)]
pub struct UsnRecord {
    pub mft_entry: u64,
    pub mft_sequence: u16,
    pub parent_mft_entry: u64,
    pub parent_mft_sequence: u16,
    pub usn: i64,
    pub timestamp: DateTime<Utc>,
    pub reason: UsnReason,
    pub filename: String,
    pub file_attributes: u32,
}

// ─── Helper functions ─────────────────────────────────────────────────────────

/// Convert a Windows FILETIME (100ns intervals since 1601-01-01) to DateTime<Utc>.
fn filetime_to_datetime(filetime: i64) -> Option<DateTime<Utc>> {
    if filetime <= 0 {
        return None;
    }
    // FILETIME epoch: 1601-01-01, Unix epoch: 1970-01-01
    // Difference: 11644473600 seconds
    const EPOCH_DIFF: i64 = 11_644_473_600;
    let secs = filetime / 10_000_000 - EPOCH_DIFF;
    let nanos = ((filetime % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}

/// Extract the MFT entry number (lower 48 bits) from a file reference number.
fn mft_entry_from_reference(reference: u64) -> u64 {
    reference & 0x0000_FFFF_FFFF_FFFF
}

/// Extract the MFT sequence number (upper 16 bits) from a file reference number.
fn mft_sequence_from_reference(reference: u64) -> u16 {
    (reference >> 48) as u16
}

/// Read a little-endian u16 from a byte slice at the given offset.
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a little-endian u32 from a byte slice at the given offset.
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Read a little-endian u64 from a byte slice at the given offset.
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Read a little-endian i64 from a byte slice at the given offset.
fn read_i64_le(data: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Decode a UTF-16LE byte slice into a Rust String.
fn decode_utf16le(data: &[u8]) -> String {
    let u16_iter = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
    char::decode_utf16(u16_iter)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

// ─── Minimum record header size (offset 0x3C is where filename starts) ───────
const USN_V2_MIN_SIZE: usize = 0x3C;
/// Maximum reasonable record length (V2 records should be well under 64KB).
const USN_V2_MAX_SIZE: usize = 65536;

// ─── Parser ──────────────────────────────────────────────────────────────────

/// Parse raw $UsnJrnl:$J data and return a vector of USN records.
///
/// The journal is often sparse with large zero-filled regions between records.
/// This parser scans forward, skipping zero-filled regions, and parses each
/// USN_RECORD_V2 it encounters.
///
/// Records with reason == CLOSE only (0x80000000) are skipped as they do not
/// carry independent forensic value. V3 records are also skipped.
pub fn parse_usn_journal(data: &[u8]) -> Result<Vec<UsnRecord>> {
    let mut records = Vec::new();
    let len = data.len();
    let mut offset = 0;

    while offset < len {
        // Need at least 4 bytes to read RecordLength
        if offset + 4 > len {
            break;
        }

        // Check for zero-filled region: if first 4 bytes are zero, skip forward
        let record_length_raw = read_u32_le(data, offset) as usize;
        if record_length_raw == 0 {
            // Skip forward in 8-byte increments looking for non-zero data
            // (USN records are 8-byte aligned)
            offset += 8;
            continue;
        }

        // Validate record length
        if record_length_raw < USN_V2_MIN_SIZE || record_length_raw > USN_V2_MAX_SIZE {
            debug!(
                "Invalid record length {} at offset 0x{:X}, skipping 8 bytes",
                record_length_raw, offset
            );
            offset += 8;
            continue;
        }

        // Must be 8-byte aligned
        if record_length_raw % 8 != 0 {
            debug!(
                "Record length {} not 8-byte aligned at offset 0x{:X}, skipping",
                record_length_raw, offset
            );
            offset += 8;
            continue;
        }

        // Ensure we have enough data for the full record
        if offset + record_length_raw > len {
            debug!(
                "Truncated record at offset 0x{:X}: need {} bytes, have {}",
                offset,
                record_length_raw,
                len - offset
            );
            break;
        }

        // Read MajorVersion
        let major_version = read_u16_le(data, offset + 0x04);

        if major_version != 2 {
            // Skip non-V2 records (e.g., V3)
            debug!(
                "Skipping USN record version {} at offset 0x{:X}",
                major_version, offset
            );
            offset += record_length_raw;
            continue;
        }

        // Parse the V2 record
        match parse_usn_record_v2(data, offset, record_length_raw) {
            Some(record) => {
                // Skip CLOSE-only records (reason == 0x80000000)
                if record.reason == UsnReason::CLOSE {
                    debug!(
                        "Skipping CLOSE-only record for '{}' at offset 0x{:X}",
                        record.filename, offset
                    );
                } else {
                    records.push(record);
                }
            }
            None => {
                warn!(
                    "Failed to parse USN record at offset 0x{:X}, skipping",
                    offset
                );
            }
        }

        offset += record_length_raw;
    }

    debug!("USN Journal parsing complete: {} records", records.len());
    Ok(records)
}

/// Parse a single USN_RECORD_V2 from the data buffer at the given offset.
fn parse_usn_record_v2(data: &[u8], offset: usize, record_length: usize) -> Option<UsnRecord> {
    // Ensure we have the minimum header
    if record_length < USN_V2_MIN_SIZE {
        return None;
    }

    let file_reference = read_u64_le(data, offset + 0x08);
    let parent_reference = read_u64_le(data, offset + 0x10);
    let usn = read_i64_le(data, offset + 0x18);
    let filetime = read_i64_le(data, offset + 0x20);
    let reason_bits = read_u32_le(data, offset + 0x28);
    let file_attributes = read_u32_le(data, offset + 0x34);
    let filename_length = read_u16_le(data, offset + 0x38) as usize;
    let filename_offset = read_u16_le(data, offset + 0x3A) as usize;

    // Validate filename bounds
    if filename_offset + filename_length > record_length {
        debug!(
            "Filename extends beyond record at offset 0x{:X}: fn_offset={}, fn_len={}, rec_len={}",
            offset, filename_offset, filename_length, record_length
        );
        return None;
    }

    // Decode filename (UTF-16LE)
    let fn_start = offset + filename_offset;
    let fn_end = fn_start + filename_length;
    let filename = decode_utf16le(&data[fn_start..fn_end]);

    // Convert FILETIME to DateTime<Utc>
    let timestamp = filetime_to_datetime(filetime)?;

    // Parse reason flags (allow unknown bits via from_bits_retain)
    let reason = UsnReason::from_bits_retain(reason_bits);

    Some(UsnRecord {
        mft_entry: mft_entry_from_reference(file_reference),
        mft_sequence: mft_sequence_from_reference(file_reference),
        parent_mft_entry: mft_entry_from_reference(parent_reference),
        parent_mft_sequence: mft_sequence_from_reference(parent_reference),
        usn,
        timestamp,
        reason,
        filename,
        file_attributes,
    })
}

// ─── Timeline merge ──────────────────────────────────────────────────────────

/// Map USN reason flags to the highest-priority EventType.
///
/// Priority order (highest first):
/// 1. FILE_CREATE
/// 2. FILE_DELETE
/// 3. RENAME_OLD_NAME / RENAME_NEW_NAME
/// 4. DATA_OVERWRITE / DATA_EXTEND / DATA_TRUNCATION (file content modification)
/// 5. SECURITY_CHANGE -> Other("SEC")
/// 6. BASIC_INFO_CHANGE -> Other("ATTR")
/// 7. Everything else -> FileModify (catch-all for remaining operations)
fn usn_reason_to_event_type(reason: UsnReason) -> EventType {
    if reason.contains(UsnReason::FILE_CREATE) {
        EventType::FileCreate
    } else if reason.contains(UsnReason::FILE_DELETE) {
        EventType::FileDelete
    } else if reason.intersects(UsnReason::RENAME_OLD_NAME | UsnReason::RENAME_NEW_NAME) {
        EventType::FileRename
    } else if reason.intersects(
        UsnReason::DATA_OVERWRITE | UsnReason::DATA_EXTEND | UsnReason::DATA_TRUNCATION,
    ) {
        EventType::FileModify
    } else if reason.contains(UsnReason::SECURITY_CHANGE) {
        EventType::Other("SEC".to_string())
    } else if reason.contains(UsnReason::BASIC_INFO_CHANGE) {
        EventType::Other("ATTR".to_string())
    } else {
        // Catch-all for named data changes, EA changes, compression, encryption, etc.
        EventType::FileModify
    }
}

/// Merge parsed USN records into the forensic timeline store.
///
/// For each UsnRecord, a TimelineEntry is created with:
/// - entity_id: EntityId::MftEntry(record.mft_entry)
/// - path: record.filename (USN only contains the filename, not the full path)
/// - primary_timestamp: record.timestamp
/// - event_type: mapped from reason flags using priority ordering
/// - timestamps.usn_timestamp: Some(record.timestamp)
/// - sources: [ArtifactSource::UsnJrnl]
/// - anomalies: empty (cross-artifact anomaly detection comes in a later phase)
pub fn merge_usn_to_timeline(records: &[UsnRecord], store: &mut TimelineStore) {
    for record in records {
        let event_type = usn_reason_to_event_type(record.reason);

        let mut timestamps = TimestampSet::default();
        timestamps.usn_timestamp = Some(record.timestamp);

        let metadata = EntryMetadata {
            mft_entry_number: Some(record.mft_entry),
            mft_sequence: Some(record.mft_sequence),
            ..EntryMetadata::default()
        };

        let entry = TimelineEntry {
            entity_id: EntityId::MftEntry(record.mft_entry),
            path: record.filename.clone(),
            primary_timestamp: record.timestamp,
            event_type,
            timestamps,
            sources: smallvec![ArtifactSource::UsnJrnl],
            anomalies: AnomalyFlags::empty(),
            metadata,
        };

        store.push(entry);
    }
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_filetime_to_datetime() {
        // Known value: 2025-01-01 00:00:00 UTC
        // = 133_800_288_000_000_000 in FILETIME (100ns units)
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let expected_secs = dt.timestamp() + 11_644_473_600;
        let filetime = expected_secs * 10_000_000;
        let result = filetime_to_datetime(filetime).unwrap();
        assert_eq!(result, dt);
    }

    #[test]
    fn test_filetime_zero_returns_none() {
        assert!(filetime_to_datetime(0).is_none());
    }

    #[test]
    fn test_filetime_negative_returns_none() {
        assert!(filetime_to_datetime(-1).is_none());
    }

    #[test]
    fn test_mft_entry_from_reference() {
        let reference: u64 = 0x0003_0000_0000_002A; // seq=3, entry=42
        assert_eq!(mft_entry_from_reference(reference), 42);
    }

    #[test]
    fn test_mft_sequence_from_reference() {
        let reference: u64 = 0x0003_0000_0000_002A; // seq=3, entry=42
        assert_eq!(mft_sequence_from_reference(reference), 3);
    }

    #[test]
    fn test_decode_utf16le_ascii() {
        // "ABC" in UTF-16LE
        let data: Vec<u8> = vec![0x41, 0x00, 0x42, 0x00, 0x43, 0x00];
        assert_eq!(decode_utf16le(&data), "ABC");
    }

    #[test]
    fn test_decode_utf16le_unicode() {
        // e-acute (U+00E9) in UTF-16LE = 0xE9, 0x00
        let data: Vec<u8> = vec![0xE9, 0x00];
        assert_eq!(decode_utf16le(&data), "\u{00E9}");
    }

    #[test]
    fn test_usn_reason_to_event_type_create() {
        let reason = UsnReason::FILE_CREATE | UsnReason::CLOSE;
        assert_eq!(usn_reason_to_event_type(reason), EventType::FileCreate);
    }

    #[test]
    fn test_usn_reason_to_event_type_delete() {
        let reason = UsnReason::FILE_DELETE | UsnReason::CLOSE;
        assert_eq!(usn_reason_to_event_type(reason), EventType::FileDelete);
    }

    #[test]
    fn test_usn_reason_to_event_type_rename() {
        assert_eq!(
            usn_reason_to_event_type(UsnReason::RENAME_NEW_NAME),
            EventType::FileRename
        );
        assert_eq!(
            usn_reason_to_event_type(UsnReason::RENAME_OLD_NAME),
            EventType::FileRename
        );
    }

    #[test]
    fn test_usn_reason_to_event_type_modify() {
        assert_eq!(
            usn_reason_to_event_type(UsnReason::DATA_OVERWRITE),
            EventType::FileModify
        );
        assert_eq!(
            usn_reason_to_event_type(UsnReason::DATA_EXTEND),
            EventType::FileModify
        );
        assert_eq!(
            usn_reason_to_event_type(UsnReason::DATA_TRUNCATION),
            EventType::FileModify
        );
    }

    #[test]
    fn test_usn_reason_to_event_type_security() {
        assert_eq!(
            usn_reason_to_event_type(UsnReason::SECURITY_CHANGE),
            EventType::Other("SEC".to_string())
        );
    }

    #[test]
    fn test_usn_reason_to_event_type_basic_info() {
        assert_eq!(
            usn_reason_to_event_type(UsnReason::BASIC_INFO_CHANGE),
            EventType::Other("ATTR".to_string())
        );
    }

    #[test]
    fn test_usn_reason_to_event_type_create_over_modify() {
        // FILE_CREATE should take priority over DATA_OVERWRITE
        let reason = UsnReason::FILE_CREATE | UsnReason::DATA_OVERWRITE;
        assert_eq!(usn_reason_to_event_type(reason), EventType::FileCreate);
    }
}
