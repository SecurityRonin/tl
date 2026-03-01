use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

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

impl std::fmt::Display for UsnReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.iter_names().map(|(name, _)| name).collect();
        if names.is_empty() {
            write!(f, "0x{:x}", self.bits())
        } else {
            write!(f, "{}", names.join("|"))
        }
    }
}

bitflags! {
    /// Windows file attributes from USN records.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FileAttributes: u32 {
        const READONLY            = 0x0000_0001;
        const HIDDEN              = 0x0000_0002;
        const SYSTEM              = 0x0000_0004;
        const DIRECTORY           = 0x0000_0010;
        const ARCHIVE             = 0x0000_0020;
        const DEVICE              = 0x0000_0040;
        const NORMAL              = 0x0000_0080;
        const TEMPORARY           = 0x0000_0100;
        const SPARSE_FILE         = 0x0000_0200;
        const REPARSE_POINT       = 0x0000_0400;
        const COMPRESSED          = 0x0000_0800;
        const OFFLINE             = 0x0000_1000;
        const NOT_CONTENT_INDEXED = 0x0000_2000;
        const ENCRYPTED           = 0x0000_4000;
        const INTEGRITY_STREAM    = 0x0000_8000;
        const VIRTUAL             = 0x0001_0000;
        const NO_SCRUB_DATA       = 0x0002_0000;
    }
}

impl std::fmt::Display for FileAttributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.iter_names().map(|(name, _)| name).collect();
        if names.is_empty() {
            write!(f, "0x{:x}", self.bits())
        } else {
            write!(f, "{}", names.join("|"))
        }
    }
}

/// A parsed USN record from the $UsnJrnl:$J (V2 or V3).
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
    pub file_attributes: FileAttributes,
    pub source_info: u32,
    pub security_id: u32,
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

/// Read a little-endian u128 from a byte slice at the given offset.
fn read_u128_le(data: &[u8], offset: usize) -> u128 {
    u128::from_le_bytes([
        data[offset],     data[offset + 1],  data[offset + 2],  data[offset + 3],
        data[offset + 4], data[offset + 5],  data[offset + 6],  data[offset + 7],
        data[offset + 8], data[offset + 9],  data[offset + 10], data[offset + 11],
        data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15],
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

// ─── Record size constants ───────────────────────────────────────────────────

/// Minimum V2 record header size (offset 0x3C is where filename starts).
const USN_V2_MIN_SIZE: usize = 0x3C;
/// Minimum V3 record header size (128-bit file references, filename at 0x4C).
const USN_V3_MIN_SIZE: usize = 0x4C;
/// Minimum V4 record size (header + at least no extents).
const USN_V4_MIN_SIZE: usize = 0x38;
/// Maximum reasonable record length (V2/V3 records should be well under 64KB).
const USN_MAX_RECORD_SIZE: usize = 65536;

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
        if record_length_raw < USN_V4_MIN_SIZE || record_length_raw > USN_MAX_RECORD_SIZE {
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

        let parsed = match major_version {
            2 => {
                if record_length_raw < USN_V2_MIN_SIZE {
                    debug!("V2 record too small at 0x{:X}", offset);
                    offset += record_length_raw;
                    continue;
                }
                parse_usn_record_v2(data, offset, record_length_raw)
            }
            3 => {
                if record_length_raw < USN_V3_MIN_SIZE {
                    debug!("V3 record too small at 0x{:X}", offset);
                    offset += record_length_raw;
                    continue;
                }
                parse_usn_record_v3(data, offset, record_length_raw)
            }
            4 => {
                // V4 records contain range tracking data (byte extents) but
                // no timestamp or filename -- skip for timeline purposes
                debug!(
                    "Skipping V4 range-tracking record at offset 0x{:X}",
                    offset
                );
                offset += record_length_raw;
                continue;
            }
            _ => {
                debug!(
                    "Skipping unknown USN record version {} at offset 0x{:X}",
                    major_version, offset
                );
                offset += record_length_raw;
                continue;
            }
        };

        match parsed {
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
    let source_info = read_u32_le(data, offset + 0x2C);
    let security_id = read_u32_le(data, offset + 0x30);
    let file_attributes_raw = read_u32_le(data, offset + 0x34);
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
        file_attributes: FileAttributes::from_bits_retain(file_attributes_raw),
        source_info,
        security_id,
    })
}

/// Parse a single USN_RECORD_V3 (128-bit file references, used on ReFS).
///
/// V3 layout:
///   0x00: RecordLength (u32), 0x04: MajorVersion (u16)=3, 0x06: MinorVersion (u16)
///   0x08: FileReferenceNumber (u128), 0x18: ParentFileReferenceNumber (u128)
///   0x28: Usn (i64), 0x30: TimeStamp (i64), 0x38: Reason (u32)
///   0x3C: SourceInfo (u32), 0x40: SecurityId (u32), 0x44: FileAttributes (u32)
///   0x48: FileNameLength (u16), 0x4A: FileNameOffset (u16), 0x4C: FileName
fn parse_usn_record_v3(data: &[u8], offset: usize, record_length: usize) -> Option<UsnRecord> {
    if record_length < USN_V3_MIN_SIZE {
        return None;
    }

    let file_ref_128 = read_u128_le(data, offset + 0x08);
    let parent_ref_128 = read_u128_le(data, offset + 0x18);
    let usn = read_i64_le(data, offset + 0x28);
    let filetime = read_i64_le(data, offset + 0x30);
    let reason_bits = read_u32_le(data, offset + 0x38);
    let source_info = read_u32_le(data, offset + 0x3C);
    let security_id = read_u32_le(data, offset + 0x40);
    let file_attributes_raw = read_u32_le(data, offset + 0x44);
    let filename_length = read_u16_le(data, offset + 0x48) as usize;
    let filename_offset = read_u16_le(data, offset + 0x4A) as usize;

    if filename_offset + filename_length > record_length {
        debug!(
            "V3 filename extends beyond record at offset 0x{:X}",
            offset
        );
        return None;
    }

    let fn_start = offset + filename_offset;
    let fn_end = fn_start + filename_length;
    let filename = decode_utf16le(&data[fn_start..fn_end]);
    let timestamp = filetime_to_datetime(filetime)?;
    let reason = UsnReason::from_bits_retain(reason_bits);

    // For V3/ReFS 128-bit references, use lower 64 bits as entry ID.
    // ReFS does not use the NTFS entry/sequence split, so sequence is 0.
    Some(UsnRecord {
        mft_entry: file_ref_128 as u64,
        mft_sequence: 0,
        parent_mft_entry: parent_ref_128 as u64,
        parent_mft_sequence: 0,
        usn,
        timestamp,
        reason,
        filename,
        file_attributes: FileAttributes::from_bits_retain(file_attributes_raw),
        source_info,
        security_id,
    })
}

// ─── Streaming Iterator ──────────────────────────────────────────────────────

/// Read buffer size for the streaming iterator (64 KB).
const STREAM_BUF_SIZE: usize = 65536;

/// A streaming iterator over USN Journal records from a `Read + Seek` source.
///
/// Unlike `parse_usn_journal(&[u8])` which loads everything into memory,
/// this reads records lazily, making it suitable for multi-GB journals.
pub struct UsnJournalReader<R: Read + Seek> {
    reader: R,
    buf: Vec<u8>,
    buf_len: usize,
    buf_offset: usize,
    stream_pos: u64,
    total_size: u64,
    done: bool,
}

impl<R: Read + Seek> UsnJournalReader<R> {
    /// Create a new streaming USN Journal reader.
    pub fn new(mut reader: R) -> Result<Self> {
        let total_size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self {
            reader,
            buf: vec![0u8; STREAM_BUF_SIZE],
            buf_len: 0,
            buf_offset: 0,
            stream_pos: 0,
            total_size,
            done: false,
        })
    }

    /// Fill the internal buffer from the current stream position.
    fn fill_buf(&mut self) -> std::io::Result<()> {
        self.reader.seek(SeekFrom::Start(self.stream_pos))?;
        self.buf_len = self.reader.read(&mut self.buf)?;
        self.buf_offset = 0;
        Ok(())
    }

    /// Read the next record, returning None when done.
    fn next_record(&mut self) -> Result<Option<UsnRecord>> {
        loop {
            if self.done || self.stream_pos >= self.total_size {
                self.done = true;
                return Ok(None);
            }

            // Refill buffer if needed
            if self.buf_offset >= self.buf_len {
                self.fill_buf()?;
                if self.buf_len == 0 {
                    self.done = true;
                    return Ok(None);
                }
            }

            let remaining = self.buf_len - self.buf_offset;
            if remaining < 4 {
                self.stream_pos += remaining as u64;
                self.buf_offset = self.buf_len;
                continue;
            }

            let record_length = read_u32_le(&self.buf, self.buf_offset) as usize;

            // Zero-filled sparse region
            if record_length == 0 {
                self.stream_pos += 8;
                self.buf_offset += 8;
                continue;
            }

            // Invalid record length
            if record_length < USN_V4_MIN_SIZE || record_length > USN_MAX_RECORD_SIZE {
                self.stream_pos += 8;
                self.buf_offset += 8;
                continue;
            }

            if record_length % 8 != 0 {
                self.stream_pos += 8;
                self.buf_offset += 8;
                continue;
            }

            // If record doesn't fit in current buffer, re-read from stream_pos
            if remaining < record_length {
                if record_length > self.buf.len() {
                    self.buf.resize(record_length, 0);
                }
                self.fill_buf()?;
                if self.buf_len < record_length {
                    self.done = true;
                    return Ok(None);
                }
            }

            let major_version = read_u16_le(&self.buf, self.buf_offset + 0x04);

            let parsed = match major_version {
                2 if record_length >= USN_V2_MIN_SIZE => {
                    parse_usn_record_v2(&self.buf, self.buf_offset, record_length)
                }
                3 if record_length >= USN_V3_MIN_SIZE => {
                    parse_usn_record_v3(&self.buf, self.buf_offset, record_length)
                }
                4 | _ => {
                    // V4 or unknown -- skip
                    self.stream_pos += record_length as u64;
                    self.buf_offset += record_length;
                    continue;
                }
            };

            self.stream_pos += record_length as u64;
            self.buf_offset += record_length;

            match parsed {
                Some(record) if record.reason == UsnReason::CLOSE => continue,
                Some(record) => return Ok(Some(record)),
                None => continue,
            }
        }
    }
}

impl<R: Read + Seek> Iterator for UsnJournalReader<R> {
    type Item = Result<UsnRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_record() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

// ─── MFT Path Resolution ────────────────────────────────────────────────────

/// Resolves USN record parent MFT entries to full directory paths.
///
/// Built from MFT-sourced entries in the TimelineStore, maps MFT entry
/// numbers to their full paths, enabling reconstruction of complete file
/// paths for USN records (which only contain the filename, not the path).
pub struct MftPathResolver {
    paths: HashMap<u64, String>,
}

impl MftPathResolver {
    /// Create an empty resolver.
    pub fn new() -> Self {
        Self {
            paths: HashMap::new(),
        }
    }

    /// Insert a path mapping directly.
    pub fn insert(&mut self, mft_entry: u64, path: String) {
        self.paths.entry(mft_entry).or_insert(path);
    }

    /// Build from MFT-sourced entries in the TimelineStore.
    ///
    /// Extracts all entries with `EntityId::MftEntry` and `ArtifactSource::Mft`
    /// to build the entry-number → path lookup table.
    pub fn from_store(store: &TimelineStore) -> Self {
        let mut paths = HashMap::new();
        for entry in store.entries() {
            if let EntityId::MftEntry(n) = entry.entity_id {
                if entry.sources.contains(&ArtifactSource::Mft) {
                    paths.entry(n).or_insert_with(|| entry.path.clone());
                }
            }
        }
        Self { paths }
    }

    /// Resolve a USN record's parent entry to a full file path.
    ///
    /// If the parent MFT entry is known, returns `parent_path\filename`.
    /// Otherwise falls back to just the filename.
    pub fn resolve(&self, parent_entry: u64, filename: &str) -> String {
        if let Some(parent_path) = self.paths.get(&parent_entry) {
            format!("{}\\{}", parent_path, filename)
        } else {
            filename.to_string()
        }
    }

    /// Number of resolved paths in the map.
    pub fn len(&self) -> usize {
        self.paths.len()
    }
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

/// Merge parsed USN records into the timeline with MFT path resolution.
///
/// Like `merge_usn_to_timeline`, but uses `MftPathResolver` to reconstruct
/// full file paths from parent MFT entry numbers.
pub fn merge_usn_to_timeline_with_paths(
    records: &[UsnRecord],
    store: &mut TimelineStore,
    resolver: &MftPathResolver,
) {
    for record in records {
        let event_type = usn_reason_to_event_type(record.reason);
        let full_path = resolver.resolve(record.parent_mft_entry, &record.filename);

        let mut timestamps = TimestampSet::default();
        timestamps.usn_timestamp = Some(record.timestamp);

        let metadata = EntryMetadata {
            mft_entry_number: Some(record.mft_entry),
            mft_sequence: Some(record.mft_sequence),
            ..EntryMetadata::default()
        };

        let entry = TimelineEntry {
            entity_id: EntityId::MftEntry(record.mft_entry),
            path: full_path,
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

    // ─── FileAttributes bitflags tests ───────────────────────────────────

    #[test]
    fn test_file_attributes_archive() {
        let attrs = FileAttributes::ARCHIVE;
        assert!(attrs.contains(FileAttributes::ARCHIVE));
        assert!(!attrs.contains(FileAttributes::HIDDEN));
    }

    #[test]
    fn test_file_attributes_directory() {
        let attrs = FileAttributes::DIRECTORY;
        assert!(attrs.contains(FileAttributes::DIRECTORY));
    }

    #[test]
    fn test_file_attributes_from_raw() {
        let attrs = FileAttributes::from_bits_retain(0x22); // HIDDEN | ARCHIVE
        assert!(attrs.contains(FileAttributes::HIDDEN));
        assert!(attrs.contains(FileAttributes::ARCHIVE));
    }

    #[test]
    fn test_file_attributes_display_single() {
        let attrs = FileAttributes::ARCHIVE;
        assert_eq!(format!("{}", attrs), "ARCHIVE");
    }

    #[test]
    fn test_file_attributes_display_multiple() {
        let attrs = FileAttributes::HIDDEN | FileAttributes::SYSTEM;
        let display = format!("{}", attrs);
        assert!(display.contains("HIDDEN"), "got: {}", display);
        assert!(display.contains("SYSTEM"), "got: {}", display);
    }

    #[test]
    fn test_file_attributes_display_empty() {
        let attrs = FileAttributes::empty();
        assert_eq!(format!("{}", attrs), "0x0");
    }

    // ─── UsnReason Display tests ─────────────────────────────────────────

    #[test]
    fn test_usn_reason_display_single() {
        let reason = UsnReason::FILE_CREATE;
        assert_eq!(format!("{}", reason), "FILE_CREATE");
    }

    #[test]
    fn test_usn_reason_display_multiple() {
        let reason = UsnReason::FILE_CREATE | UsnReason::CLOSE;
        let display = format!("{}", reason);
        assert!(display.contains("FILE_CREATE"), "got: {}", display);
        assert!(display.contains("CLOSE"), "got: {}", display);
    }

    #[test]
    fn test_usn_reason_display_empty() {
        let reason = UsnReason::empty();
        assert_eq!(format!("{}", reason), "0x0");
    }

    // ─── source_info / security_id tests ─────────────────────────────────

    #[test]
    fn test_usn_record_source_info_and_security_id() {
        let ts = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let record = UsnRecord {
            mft_entry: 42,
            mft_sequence: 3,
            parent_mft_entry: 5,
            parent_mft_sequence: 1,
            usn: 1024,
            timestamp: ts,
            reason: UsnReason::FILE_CREATE,
            filename: "test.txt".to_string(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 256,
        };
        assert_eq!(record.source_info, 0);
        assert_eq!(record.security_id, 256);
    }

    #[test]
    fn test_parse_v2_extracts_source_info_and_security_id() {
        let ts = Utc.with_ymd_and_hms(2025, 8, 10, 12, 0, 0).unwrap();
        let expected_secs = ts.timestamp() + 11_644_473_600;
        let filetime = expected_secs * 10_000_000;

        // Build a V2 record with specific source_info and security_id
        let utf16: Vec<u16> = "test.txt".encode_utf16().collect();
        let filename_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let raw_len = 0x3C + filename_bytes.len();
        let record_len = ((raw_len + 7) / 8) * 8;
        let mut buf = vec![0u8; record_len];

        buf[0x00..0x04].copy_from_slice(&(record_len as u32).to_le_bytes());
        buf[0x04..0x06].copy_from_slice(&2u16.to_le_bytes()); // V2
        let file_ref: u64 = 42 | (3u64 << 48);
        buf[0x08..0x10].copy_from_slice(&file_ref.to_le_bytes());
        let parent_ref: u64 = 5 | (1u64 << 48);
        buf[0x10..0x18].copy_from_slice(&parent_ref.to_le_bytes());
        buf[0x18..0x20].copy_from_slice(&1024i64.to_le_bytes()); // usn
        buf[0x20..0x28].copy_from_slice(&filetime.to_le_bytes()); // timestamp
        buf[0x28..0x2C].copy_from_slice(&0x100u32.to_le_bytes()); // FILE_CREATE
        buf[0x2C..0x30].copy_from_slice(&42u32.to_le_bytes()); // source_info = 42
        buf[0x30..0x34].copy_from_slice(&999u32.to_le_bytes()); // security_id = 999
        buf[0x34..0x38].copy_from_slice(&0x20u32.to_le_bytes()); // ARCHIVE
        buf[0x38..0x3A].copy_from_slice(&(filename_bytes.len() as u16).to_le_bytes());
        buf[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
        buf[0x3C..0x3C + filename_bytes.len()].copy_from_slice(&filename_bytes);

        let records = parse_usn_journal(&buf).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source_info, 42);
        assert_eq!(records[0].security_id, 999);
        assert!(records[0].file_attributes.contains(FileAttributes::ARCHIVE));
    }

    // ─── V3 record tests ─────────────────────────────────────────────────

    /// Build a synthetic USN_RECORD_V3 with 128-bit file references.
    fn build_v3_record(
        file_ref_lo: u64, file_ref_hi: u64,
        parent_ref_lo: u64, parent_ref_hi: u64,
        usn: i64, filetime: i64, reason: u32,
        filename: &str, file_attributes: u32,
    ) -> Vec<u8> {
        let utf16: Vec<u16> = filename.encode_utf16().collect();
        let filename_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let filename_offset: u16 = 0x4C;
        let raw_len = 0x4C + filename_bytes.len();
        let record_len = ((raw_len + 7) / 8) * 8;
        let mut buf = vec![0u8; record_len];

        buf[0x00..0x04].copy_from_slice(&(record_len as u32).to_le_bytes());
        buf[0x04..0x06].copy_from_slice(&3u16.to_le_bytes()); // V3
        buf[0x08..0x10].copy_from_slice(&file_ref_lo.to_le_bytes());
        buf[0x10..0x18].copy_from_slice(&file_ref_hi.to_le_bytes());
        buf[0x18..0x20].copy_from_slice(&parent_ref_lo.to_le_bytes());
        buf[0x20..0x28].copy_from_slice(&parent_ref_hi.to_le_bytes());
        buf[0x28..0x30].copy_from_slice(&usn.to_le_bytes());
        buf[0x30..0x38].copy_from_slice(&filetime.to_le_bytes());
        buf[0x38..0x3C].copy_from_slice(&reason.to_le_bytes());
        buf[0x3C..0x40].copy_from_slice(&0u32.to_le_bytes()); // source_info
        buf[0x40..0x44].copy_from_slice(&0u32.to_le_bytes()); // security_id
        buf[0x44..0x48].copy_from_slice(&file_attributes.to_le_bytes());
        buf[0x48..0x4A].copy_from_slice(&(filename_bytes.len() as u16).to_le_bytes());
        buf[0x4A..0x4C].copy_from_slice(&filename_offset.to_le_bytes());
        buf[0x4C..0x4C + filename_bytes.len()].copy_from_slice(&filename_bytes);
        buf
    }

    #[test]
    fn test_parse_v3_record() {
        let ts = Utc.with_ymd_and_hms(2025, 9, 1, 10, 0, 0).unwrap();
        let secs = ts.timestamp() + 11_644_473_600;
        let filetime = secs * 10_000_000;

        let data = build_v3_record(
            42, 0, // file_ref low/high
            5, 0,  // parent_ref low/high
            2048, filetime, 0x100, // usn, time, FILE_CREATE
            "refs_file.txt", 0x20,
        );

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].mft_entry, 42);
        assert_eq!(records[0].parent_mft_entry, 5);
        assert_eq!(records[0].filename, "refs_file.txt");
        assert!(records[0].reason.contains(UsnReason::FILE_CREATE));
    }

    #[test]
    fn test_parse_v3_with_high_bits() {
        let ts = Utc.with_ymd_and_hms(2025, 9, 1, 10, 0, 0).unwrap();
        let secs = ts.timestamp() + 11_644_473_600;
        let filetime = secs * 10_000_000;

        // ReFS uses full 128-bit references; lower 64 bits used as entry ID
        let data = build_v3_record(
            0xDEAD_BEEF, 0x1234, // file ref with high bits
            0xCAFE_BABE, 0x5678, // parent ref with high bits
            4096, filetime, 0x200, // FILE_DELETE
            "refs_deleted.dat", 0x20,
        );

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].mft_entry, 0xDEAD_BEEF);
        assert_eq!(records[0].parent_mft_entry, 0xCAFE_BABE);
    }

    #[test]
    fn test_parse_mixed_v2_v3_records() {
        let ts = Utc.with_ymd_and_hms(2025, 9, 1, 10, 0, 0).unwrap();
        let secs = ts.timestamp() + 11_644_473_600;
        let filetime = secs * 10_000_000;

        let mut data = build_v3_record(
            100, 0, 50, 0, 1000, filetime, 0x100, "v3file.txt", 0x20,
        );
        // Append a V2 record using the existing test helper bytes
        let utf16: Vec<u16> = "v2file.txt".encode_utf16().collect();
        let fn_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let raw_len = 0x3C + fn_bytes.len();
        let v2_len = ((raw_len + 7) / 8) * 8;
        let mut v2_buf = vec![0u8; v2_len];
        v2_buf[0x00..0x04].copy_from_slice(&(v2_len as u32).to_le_bytes());
        v2_buf[0x04..0x06].copy_from_slice(&2u16.to_le_bytes());
        let fref: u64 = 200 | (1u64 << 48);
        v2_buf[0x08..0x10].copy_from_slice(&fref.to_le_bytes());
        let pref: u64 = 60 | (1u64 << 48);
        v2_buf[0x10..0x18].copy_from_slice(&pref.to_le_bytes());
        v2_buf[0x18..0x20].copy_from_slice(&2000i64.to_le_bytes());
        v2_buf[0x20..0x28].copy_from_slice(&filetime.to_le_bytes());
        v2_buf[0x28..0x2C].copy_from_slice(&0x200u32.to_le_bytes()); // FILE_DELETE
        v2_buf[0x34..0x38].copy_from_slice(&0x20u32.to_le_bytes());
        v2_buf[0x38..0x3A].copy_from_slice(&(fn_bytes.len() as u16).to_le_bytes());
        v2_buf[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
        v2_buf[0x3C..0x3C + fn_bytes.len()].copy_from_slice(&fn_bytes);
        data.extend(v2_buf);

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].filename, "v3file.txt");
        assert_eq!(records[1].filename, "v2file.txt");
    }

    // ─── V4 record tests ─────────────────────────────────────────────────

    #[test]
    fn test_v4_record_skipped_no_panic() {
        // V4 records lack timestamps/filenames; parser should skip them gracefully
        let mut buf = vec![0u8; 56]; // minimal V4 record: header + 1 extent
        buf[0x00..0x04].copy_from_slice(&56u32.to_le_bytes()); // RecordLength
        buf[0x04..0x06].copy_from_slice(&4u16.to_le_bytes()); // V4
        // Rest is zeros (file refs, usn, extents)

        let records = parse_usn_journal(&buf).unwrap();
        // V4 records don't produce UsnRecord (no timestamp/filename)
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_v4_followed_by_v2() {
        let ts = Utc.with_ymd_and_hms(2025, 9, 1, 10, 0, 0).unwrap();
        let secs = ts.timestamp() + 11_644_473_600;
        let filetime = secs * 10_000_000;

        // V4 record (skipped)
        let mut data = vec![0u8; 56];
        data[0x00..0x04].copy_from_slice(&56u32.to_le_bytes());
        data[0x04..0x06].copy_from_slice(&4u16.to_le_bytes());

        // Followed by valid V2 record
        let utf16: Vec<u16> = "after_v4.txt".encode_utf16().collect();
        let fn_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let raw_len = 0x3C + fn_bytes.len();
        let v2_len = ((raw_len + 7) / 8) * 8;
        let mut v2_buf = vec![0u8; v2_len];
        v2_buf[0x00..0x04].copy_from_slice(&(v2_len as u32).to_le_bytes());
        v2_buf[0x04..0x06].copy_from_slice(&2u16.to_le_bytes());
        let fref: u64 = 10 | (1u64 << 48);
        v2_buf[0x08..0x10].copy_from_slice(&fref.to_le_bytes());
        let pref: u64 = 5 | (1u64 << 48);
        v2_buf[0x10..0x18].copy_from_slice(&pref.to_le_bytes());
        v2_buf[0x18..0x20].copy_from_slice(&500i64.to_le_bytes());
        v2_buf[0x20..0x28].copy_from_slice(&filetime.to_le_bytes());
        v2_buf[0x28..0x2C].copy_from_slice(&0x100u32.to_le_bytes());
        v2_buf[0x34..0x38].copy_from_slice(&0x20u32.to_le_bytes());
        v2_buf[0x38..0x3A].copy_from_slice(&(fn_bytes.len() as u16).to_le_bytes());
        v2_buf[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
        v2_buf[0x3C..0x3C + fn_bytes.len()].copy_from_slice(&fn_bytes);
        data.extend(v2_buf);

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "after_v4.txt");
    }

    // ─── Streaming iterator tests ────────────────────────────────────────

    #[test]
    fn test_streaming_reader_from_cursor() {
        let ts = Utc.with_ymd_and_hms(2025, 9, 1, 10, 0, 0).unwrap();
        let secs = ts.timestamp() + 11_644_473_600;
        let filetime = secs * 10_000_000;

        let utf16: Vec<u16> = "streamed.txt".encode_utf16().collect();
        let fn_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let raw_len = 0x3C + fn_bytes.len();
        let v2_len = ((raw_len + 7) / 8) * 8;
        let mut buf = vec![0u8; v2_len];
        buf[0x00..0x04].copy_from_slice(&(v2_len as u32).to_le_bytes());
        buf[0x04..0x06].copy_from_slice(&2u16.to_le_bytes());
        let fref: u64 = 42 | (3u64 << 48);
        buf[0x08..0x10].copy_from_slice(&fref.to_le_bytes());
        let pref: u64 = 5 | (1u64 << 48);
        buf[0x10..0x18].copy_from_slice(&pref.to_le_bytes());
        buf[0x18..0x20].copy_from_slice(&1024i64.to_le_bytes());
        buf[0x20..0x28].copy_from_slice(&filetime.to_le_bytes());
        buf[0x28..0x2C].copy_from_slice(&0x100u32.to_le_bytes());
        buf[0x34..0x38].copy_from_slice(&0x20u32.to_le_bytes());
        buf[0x38..0x3A].copy_from_slice(&(fn_bytes.len() as u16).to_le_bytes());
        buf[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
        buf[0x3C..0x3C + fn_bytes.len()].copy_from_slice(&fn_bytes);

        let cursor = std::io::Cursor::new(buf);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "streamed.txt");
        assert_eq!(records[0].mft_entry, 42);
    }

    #[test]
    fn test_streaming_reader_skips_sparse() {
        let ts = Utc.with_ymd_and_hms(2025, 9, 1, 10, 0, 0).unwrap();
        let secs = ts.timestamp() + 11_644_473_600;
        let filetime = secs * 10_000_000;

        // 512 bytes of zeros, then a record
        let mut data = vec![0u8; 512];
        let utf16: Vec<u16> = "found.txt".encode_utf16().collect();
        let fn_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let raw_len = 0x3C + fn_bytes.len();
        let v2_len = ((raw_len + 7) / 8) * 8;
        let mut v2 = vec![0u8; v2_len];
        v2[0x00..0x04].copy_from_slice(&(v2_len as u32).to_le_bytes());
        v2[0x04..0x06].copy_from_slice(&2u16.to_le_bytes());
        let fref: u64 = 99 | (2u64 << 48);
        v2[0x08..0x10].copy_from_slice(&fref.to_le_bytes());
        let pref: u64 = 10 | (1u64 << 48);
        v2[0x10..0x18].copy_from_slice(&pref.to_le_bytes());
        v2[0x18..0x20].copy_from_slice(&500i64.to_le_bytes());
        v2[0x20..0x28].copy_from_slice(&filetime.to_le_bytes());
        v2[0x28..0x2C].copy_from_slice(&0x100u32.to_le_bytes());
        v2[0x34..0x38].copy_from_slice(&0x20u32.to_le_bytes());
        v2[0x38..0x3A].copy_from_slice(&(fn_bytes.len() as u16).to_le_bytes());
        v2[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
        v2[0x3C..0x3C + fn_bytes.len()].copy_from_slice(&fn_bytes);
        data.extend(v2);

        let cursor = std::io::Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "found.txt");
    }

    #[test]
    fn test_streaming_reader_empty() {
        let cursor = std::io::Cursor::new(Vec::<u8>::new());
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.collect::<Result<Vec<_>, _>>().unwrap();
        assert!(records.is_empty());
    }

    // ─── MFT path resolution tests ───────────────────────────────────────

    #[test]
    fn test_mft_path_resolver_resolve_known_parent() {
        let mut resolver = MftPathResolver::new();
        resolver.insert(5, r"C:\Users\admin\Desktop".to_string());
        assert_eq!(
            resolver.resolve(5, "evil.exe"),
            r"C:\Users\admin\Desktop\evil.exe"
        );
    }

    #[test]
    fn test_mft_path_resolver_resolve_unknown_parent() {
        let resolver = MftPathResolver::new();
        assert_eq!(resolver.resolve(999, "orphan.txt"), "orphan.txt");
    }

    #[test]
    fn test_mft_path_resolver_from_store() {
        let mut store = TimelineStore::new();
        store.push(TimelineEntry {
            entity_id: EntityId::MftEntry(5),
            path: r"C:\Windows\System32".to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            event_type: EventType::FileModify,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        });

        let resolver = MftPathResolver::from_store(&store);
        assert_eq!(
            resolver.resolve(5, "cmd.exe"),
            r"C:\Windows\System32\cmd.exe"
        );
    }

    #[test]
    fn test_merge_usn_with_path_resolution() {
        let ts = Utc.with_ymd_and_hms(2025, 8, 10, 12, 0, 0).unwrap();

        let record = UsnRecord {
            mft_entry: 42,
            mft_sequence: 3,
            parent_mft_entry: 5,
            parent_mft_sequence: 1,
            usn: 1024,
            timestamp: ts,
            reason: UsnReason::FILE_CREATE,
            filename: "payload.exe".to_string(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
        };

        let mut resolver = MftPathResolver::new();
        resolver.insert(5, r"C:\Users\admin\Downloads".to_string());

        let mut store = TimelineStore::new();
        merge_usn_to_timeline_with_paths(&[record], &mut store, &resolver);

        assert_eq!(store.len(), 1);
        let entry = store.get(0).unwrap();
        assert_eq!(entry.path, r"C:\Users\admin\Downloads\payload.exe");
    }

    #[test]
    fn test_merge_usn_without_path_resolution_falls_back() {
        let ts = Utc.with_ymd_and_hms(2025, 8, 10, 12, 0, 0).unwrap();

        let record = UsnRecord {
            mft_entry: 42,
            mft_sequence: 3,
            parent_mft_entry: 999,
            parent_mft_sequence: 1,
            usn: 1024,
            timestamp: ts,
            reason: UsnReason::FILE_CREATE,
            filename: "orphan.txt".to_string(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
        };

        let resolver = MftPathResolver::new(); // empty
        let mut store = TimelineStore::new();
        merge_usn_to_timeline_with_paths(&[record], &mut store, &resolver);

        assert_eq!(store.len(), 1);
        assert_eq!(store.get(0).unwrap().path, "orphan.txt");
    }
}
