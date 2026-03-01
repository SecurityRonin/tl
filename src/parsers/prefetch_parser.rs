use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, warn};
use smallvec::smallvec;

use crate::collection::manifest::ArtifactManifest;
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── Constants ───────────────────────────────────────────────────────────────

/// Signature "MAM\0" for compressed prefetch (Win8+).
const MAM_SIGNATURE: &[u8] = b"MAM";

/// Signature "SCCA" indicating a valid prefetch header.
const SCCA_SIGNATURE: &[u8] = b"SCCA";

/// Maximum reasonable prefetch file size (1 MB).
const MAX_PREFETCH_SIZE: usize = 1_000_000;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a Windows FILETIME (100ns intervals since 1601-01-01) to DateTime<Utc>.
fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    const EPOCH_DIFF: i64 = 11_644_473_600;
    let secs = (filetime / 10_000_000) as i64 - EPOCH_DIFF;
    let nanos = ((filetime % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
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

/// Decode a UTF-16LE byte slice into a Rust String, stopping at the first null.
fn decode_utf16le_null_terminated(data: &[u8]) -> String {
    let u16_iter = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
    let chars: Vec<u16> = u16_iter.take_while(|&c| c != 0).collect();
    String::from_utf16_lossy(&chars)
}

// ─── Prefetch version-specific info extraction ──────────────────────────────

/// Parsed information from a prefetch file header.
#[derive(Debug, Clone)]
pub struct PrefetchInfo {
    pub executable_name: String,
    pub version: u32,
    pub last_run_times: Vec<DateTime<Utc>>,
    pub run_count: u32,
}

/// Extract prefetch file information from a decompressed/raw SCCA buffer.
fn parse_prefetch_data(data: &[u8]) -> Result<PrefetchInfo> {
    if data.len() < 84 {
        anyhow::bail!("Prefetch data too short: {} bytes", data.len());
    }

    let version = read_u32_le(data, 0);
    let signature = &data[4..8];
    if signature != SCCA_SIGNATURE {
        anyhow::bail!("Invalid prefetch signature: expected SCCA");
    }

    // Executable name is a UTF-16LE string at offset 16, length 60 bytes (30 chars max).
    let name_end = std::cmp::min(76, data.len());
    let executable_name = decode_utf16le_null_terminated(&data[16..name_end]);

    // File information starts at offset 84
    let info_offset = 84;
    if data.len() < info_offset + 8 {
        anyhow::bail!("Prefetch data too short for file information");
    }

    let (last_run_times, run_count) = match version {
        17 => {
            // WinXP/2003: single last run time at info+36, run count at info+60
            let ft = read_u64_le(data, info_offset + 36);
            let times: Vec<DateTime<Utc>> = filetime_to_datetime(ft).into_iter().collect();
            let count = read_u32_le(data, info_offset + 60);
            (times, count)
        }
        23 => {
            // WinVista/Win7: single last run time at info+44, run count at info+68
            let ft = read_u64_le(data, info_offset + 44);
            let times: Vec<DateTime<Utc>> = filetime_to_datetime(ft).into_iter().collect();
            let count = read_u32_le(data, info_offset + 68);
            (times, count)
        }
        26 => {
            // Win8/8.1: up to 8 last run times at info+44..info+108, run count at info+124
            let mut times = Vec::with_capacity(8);
            for i in (44..108).step_by(8) {
                let ft = read_u64_le(data, info_offset + i);
                if ft == 0 {
                    continue;
                }
                if let Some(dt) = filetime_to_datetime(ft) {
                    times.push(dt);
                }
            }
            let count = read_u32_le(data, info_offset + 124);
            (times, count)
        }
        30 | 31 => {
            // Win10+: up to 8 last run times at info+44..info+108
            let mut times = Vec::with_capacity(8);
            for i in (44..108).step_by(8) {
                let ft = read_u64_le(data, info_offset + i);
                if ft == 0 {
                    continue;
                }
                if let Some(dt) = filetime_to_datetime(ft) {
                    times.push(dt);
                }
            }
            // Run count location depends on metrics offset
            let metrics_offset = read_u32_le(data, info_offset);
            let count = if metrics_offset == 304 {
                read_u32_le(data, info_offset + 124)
            } else {
                read_u32_le(data, info_offset + 116)
            };
            (times, count)
        }
        _ => {
            anyhow::bail!("Unknown prefetch version: {}", version);
        }
    };

    Ok(PrefetchInfo {
        executable_name,
        version,
        last_run_times,
        run_count,
    })
}

/// Attempt to decompress a MAM-compressed prefetch file.
///
/// Windows 8+ prefetch files use XPRESS Huffman or LZNT1 compression with a
/// MAM header. Since implementing the full decompressor is complex, we attempt
/// a best-effort approach: if the file doesn't have MAM header, treat it as
/// uncompressed. If it does have MAM header, we skip it (log a warning) since
/// proper decompression requires an XPRESS Huffman implementation.
fn handle_prefetch_buffer(data: &[u8]) -> Result<PrefetchInfo> {
    if data.len() < 8 {
        anyhow::bail!("Prefetch file too small: {} bytes", data.len());
    }

    // Check for MAM compression header
    if data.len() >= 3 && &data[0..3] == MAM_SIGNATURE {
        // Compressed prefetch. The compression algorithm is encoded in the signature.
        // Without a full XPRESS Huffman/LZNT1 decompressor, we cannot parse these.
        // Return an error so the caller can log a warning and continue.
        anyhow::bail!(
            "Compressed prefetch (MAM) detected - decompression not yet supported"
        );
    }

    // Uncompressed prefetch (WinXP/Vista/7 or raw SCCA)
    parse_prefetch_data(data)
}

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static PREFETCH_ID_COUNTER: AtomicU64 = AtomicU64::new(0x5046_0000_0000_0000); // "PF" prefix

fn next_prefetch_id() -> u64 {
    PREFETCH_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse all prefetch files from the collection and populate the timeline store.
///
/// For each .pf file in the manifest, this extracts:
/// - Executable name
/// - Last run timestamps (up to 8 for Win8+)
/// - Run count
///
/// Creates TimelineEntry records with EventType::Execute and ArtifactSource::Prefetch.
pub fn parse_prefetch_files(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    let pf_files = manifest.prefetch_files();
    if pf_files.is_empty() {
        debug!("No prefetch files found in manifest");
        return Ok(());
    }

    debug!("Parsing {} prefetch files", pf_files.len());
    let mut parsed_count = 0u32;
    let mut error_count = 0u32;

    for pf_path in pf_files {
        let data = match provider.open_file(pf_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read prefetch file {}: {}", pf_path, e);
                error_count += 1;
                continue;
            }
        };

        if data.len() > MAX_PREFETCH_SIZE {
            warn!(
                "Prefetch file {} is abnormally large ({} bytes), skipping",
                pf_path,
                data.len()
            );
            error_count += 1;
            continue;
        }

        let info = match handle_prefetch_buffer(&data) {
            Ok(info) => info,
            Err(e) => {
                debug!("Could not parse prefetch file {}: {}", pf_path, e);
                error_count += 1;
                continue;
            }
        };

        // Create a timeline entry for each last-run timestamp
        if info.last_run_times.is_empty() {
            debug!(
                "Prefetch {} ({}) has no run times",
                pf_path, info.executable_name
            );
            continue;
        }

        // Collect all timestamps for the prefetch_last_run field
        let all_run_times = info.last_run_times.clone();

        for run_time in &info.last_run_times {
            let mut timestamps = TimestampSet::default();
            timestamps.prefetch_last_run = all_run_times.clone();

            let metadata = EntryMetadata {
                ..EntryMetadata::default()
            };

            let entry = TimelineEntry {
                entity_id: EntityId::Generated(next_prefetch_id()),
                path: info.executable_name.clone(),
                primary_timestamp: *run_time,
                event_type: EventType::Execute,
                timestamps,
                sources: smallvec![ArtifactSource::Prefetch],
                anomalies: AnomalyFlags::empty(),
                metadata,
            };

            store.push(entry);
        }

        parsed_count += 1;
    }

    debug!(
        "Prefetch parsing complete: {} files parsed, {} errors",
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
        // 2025-01-01 00:00:00 UTC
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let expected_secs = dt.timestamp() + 11_644_473_600;
        let filetime = (expected_secs as u64) * 10_000_000;
        let result = filetime_to_datetime(filetime).unwrap();
        assert_eq!(result, dt);
    }

    #[test]
    fn test_filetime_zero_returns_none() {
        assert!(filetime_to_datetime(0).is_none());
    }

    #[test]
    fn test_decode_utf16le_null_terminated() {
        // "CMD.EXE" in UTF-16LE followed by null
        let data: Vec<u8> = vec![
            0x43, 0x00, 0x4D, 0x00, 0x44, 0x00, 0x2E, 0x00, 0x45, 0x00, 0x58, 0x00, 0x45, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(decode_utf16le_null_terminated(&data), "CMD.EXE");
    }

    #[test]
    fn test_decode_utf16le_no_null() {
        // "AB" in UTF-16LE, no null terminator
        let data: Vec<u8> = vec![0x41, 0x00, 0x42, 0x00];
        assert_eq!(decode_utf16le_null_terminated(&data), "AB");
    }

    /// Build a minimal version 17 (WinXP) prefetch file buffer for testing.
    fn build_test_prefetch_v17(name: &str, filetime: u64, run_count: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 256];

        // Version 17
        buf[0..4].copy_from_slice(&17u32.to_le_bytes());
        // Signature "SCCA"
        buf[4..8].copy_from_slice(b"SCCA");

        // Executable name at offset 16 as UTF-16LE
        let name_bytes: Vec<u8> = name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let copy_len = std::cmp::min(name_bytes.len(), 60);
        buf[16..16 + copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // File information starts at offset 84
        // v17: last_run_time at info+36 = offset 120, run_count at info+60 = offset 144
        let ft_offset = 84 + 36;
        buf[ft_offset..ft_offset + 8].copy_from_slice(&filetime.to_le_bytes());
        let rc_offset = 84 + 60;
        buf[rc_offset..rc_offset + 4].copy_from_slice(&run_count.to_le_bytes());

        buf
    }

    /// Build a minimal version 26 (Win8) prefetch file buffer with multiple run times.
    fn build_test_prefetch_v26(name: &str, filetimes: &[u64], run_count: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 300];

        // Version 26
        buf[0..4].copy_from_slice(&26u32.to_le_bytes());
        // Signature "SCCA"
        buf[4..8].copy_from_slice(b"SCCA");

        // Executable name at offset 16 as UTF-16LE
        let name_bytes: Vec<u8> = name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let copy_len = std::cmp::min(name_bytes.len(), 60);
        buf[16..16 + copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // File information starts at offset 84
        // v26: last_run_times at info+44..info+108 (8 slots of 8 bytes)
        for (i, &ft) in filetimes.iter().enumerate().take(8) {
            let offset = 84 + 44 + i * 8;
            buf[offset..offset + 8].copy_from_slice(&ft.to_le_bytes());
        }
        // run_count at info+124 = offset 208
        let rc_offset = 84 + 124;
        buf[rc_offset..rc_offset + 4].copy_from_slice(&run_count.to_le_bytes());

        buf
    }

    #[test]
    fn test_parse_prefetch_v17() {
        // 2025-06-15 10:30:00 UTC as FILETIME
        use chrono::TimeZone;
        let expected_dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let secs = expected_dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;

        let data = build_test_prefetch_v17("CMD.EXE", filetime, 5);
        let info = parse_prefetch_data(&data).unwrap();

        assert_eq!(info.executable_name, "CMD.EXE");
        assert_eq!(info.version, 17);
        assert_eq!(info.run_count, 5);
        assert_eq!(info.last_run_times.len(), 1);
        assert_eq!(info.last_run_times[0], expected_dt);
    }

    #[test]
    fn test_parse_prefetch_v26_multiple_runtimes() {
        use chrono::TimeZone;
        let dt1 = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let dt2 = Utc.with_ymd_and_hms(2025, 6, 15, 11, 0, 0).unwrap();
        let dt3 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        let ft = |dt: DateTime<Utc>| -> u64 {
            let secs = dt.timestamp() + 11_644_473_600;
            (secs as u64) * 10_000_000
        };

        let data = build_test_prefetch_v26(
            "NOTEPAD.EXE",
            &[ft(dt1), ft(dt2), ft(dt3)],
            15,
        );
        let info = parse_prefetch_data(&data).unwrap();

        assert_eq!(info.executable_name, "NOTEPAD.EXE");
        assert_eq!(info.version, 26);
        assert_eq!(info.run_count, 15);
        assert_eq!(info.last_run_times.len(), 3);
        assert_eq!(info.last_run_times[0], dt1);
        assert_eq!(info.last_run_times[1], dt2);
        assert_eq!(info.last_run_times[2], dt3);
    }

    #[test]
    fn test_parse_prefetch_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_prefetch_data(&data).is_err());
    }

    #[test]
    fn test_parse_prefetch_bad_signature() {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&17u32.to_le_bytes());
        data[4..8].copy_from_slice(b"XXXX"); // Wrong signature
        assert!(parse_prefetch_data(&data).is_err());
    }

    #[test]
    fn test_handle_mam_compressed() {
        let mut data = vec![0u8; 100];
        data[0..3].copy_from_slice(MAM_SIGNATURE);
        assert!(handle_prefetch_buffer(&data).is_err());
    }

    #[test]
    fn test_parse_prefetch_unknown_version() {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&99u32.to_le_bytes()); // Unknown version
        data[4..8].copy_from_slice(b"SCCA");
        assert!(parse_prefetch_data(&data).is_err());
    }

    #[test]
    fn test_prefetch_entry_creation() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;

        let data = build_test_prefetch_v17("MALWARE.EXE", filetime, 1);
        let info = parse_prefetch_data(&data).unwrap();

        // Verify we can create a timeline entry from this
        assert_eq!(info.executable_name, "MALWARE.EXE");
        assert_eq!(info.last_run_times.len(), 1);

        let mut store = TimelineStore::new();
        let mut timestamps = TimestampSet::default();
        timestamps.prefetch_last_run = info.last_run_times.clone();

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_prefetch_id()),
            path: info.executable_name.clone(),
            primary_timestamp: info.last_run_times[0],
            event_type: EventType::Execute,
            timestamps,
            sources: smallvec![ArtifactSource::Prefetch],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        store.push(entry);
        assert_eq!(store.len(), 1);
        let e = store.get(0).unwrap();
        assert_eq!(e.path, "MALWARE.EXE");
        assert_eq!(e.event_type, EventType::Execute);
        assert_eq!(e.primary_timestamp, dt);
    }
}
