use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, warn};
use smallvec::smallvec;

use crate::collection::manifest::ArtifactManifest;
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static LOGFILE_ID_COUNTER: AtomicU64 = AtomicU64::new(0x4C46_0000_0000_0000); // "LF" prefix

fn next_logfile_id() -> u64 {
    LOGFILE_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Constants ───────────────────────────────────────────────────────────────

/// NTFS $LogFile restart area signature "RSTR".
const RSTR_SIGNATURE: &[u8; 4] = b"RSTR";

/// NTFS $LogFile record page signature "RCRD".
const RCRD_SIGNATURE: &[u8; 4] = b"RCRD";

/// Default NTFS $LogFile page size.
const LOG_PAGE_SIZE: usize = 0x1000; // 4096 bytes

// ─── Parsed structures ───────────────────────────────────────────────────────

/// Parsed NTFS $LogFile restart area.
#[derive(Debug, Clone)]
pub struct RestartArea {
    /// Offset within the $LogFile where this restart area was found.
    pub offset: usize,
    /// Current LSN (Log Sequence Number) at time of checkpoint.
    pub current_lsn: u64,
    /// Log client count.
    pub log_clients: u16,
    /// System page size recorded in the restart area.
    pub system_page_size: u32,
    /// Log page size recorded in the restart area.
    pub log_page_size: u32,
}

/// Summary of $LogFile analysis.
#[derive(Debug, Clone)]
pub struct LogFileSummary {
    /// Parsed restart areas (normally 2).
    pub restart_areas: Vec<RestartArea>,
    /// Total number of RCRD pages found.
    pub record_page_count: usize,
    /// Whether a gap was detected in record page sequence.
    pub has_gaps: bool,
    /// Highest LSN found across restart areas.
    pub highest_lsn: u64,
}

// ─── Parsing functions ───────────────────────────────────────────────────────

/// Parse a Windows FILETIME (100-nanosecond intervals since 1601-01-01) to DateTime<Utc>.
#[allow(dead_code)]
fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    // Windows FILETIME epoch is 1601-01-01, Unix epoch is 1970-01-01
    // Difference: 11644473600 seconds
    const EPOCH_DIFF: u64 = 11_644_473_600;
    let secs = filetime / 10_000_000;
    let nanos = (filetime % 10_000_000) * 100;
    if secs < EPOCH_DIFF {
        return None;
    }
    let unix_secs = secs - EPOCH_DIFF;
    DateTime::from_timestamp(unix_secs as i64, nanos as u32)
}

/// Read a little-endian u16 from a byte slice at the given offset.
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

/// Read a little-endian u32 from a byte slice at the given offset.
fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
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

/// Read a little-endian u64 from a byte slice at the given offset.
fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
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

/// Parse a restart area from the $LogFile at the given page offset.
///
/// The restart area layout (offsets relative to page start):
/// - 0x00: Signature "RSTR" (4 bytes)
/// - 0x08: ChkDskLsn (8 bytes)
/// - 0x10: SystemPageSize (4 bytes)
/// - 0x14: LogPageSize (4 bytes)
/// - 0x18: RestartOffset (2 bytes)
/// - 0x1A: MinorVersion (2 bytes) -- actually at -2 relative to some specs
/// - 0x1C: MajorVersion (2 bytes)
/// - 0x1E: UpdateSequenceArrayOffset (2 bytes)
/// - 0x20: UpdateSequenceArrayCount (2 bytes)
/// - Restart record (at RestartOffset from page start):
///   - 0x00: CurrentLsn (8 bytes)
///   - 0x08: LogClients (2 bytes)
pub fn parse_restart_area(data: &[u8], page_offset: usize) -> Option<RestartArea> {
    if page_offset + LOG_PAGE_SIZE > data.len() {
        return None;
    }

    let page = &data[page_offset..];

    // Check signature
    if &page[0..4] != RSTR_SIGNATURE {
        return None;
    }

    let system_page_size = read_u32(page, 0x10)?;
    let log_page_size = read_u32(page, 0x14)?;
    let restart_offset = read_u16(page, 0x18)? as usize;

    // The restart record is at restart_offset within the page
    if restart_offset + 10 > LOG_PAGE_SIZE {
        return None;
    }

    let current_lsn = read_u64(page, restart_offset)?;
    let log_clients = read_u16(page, restart_offset + 8)?;

    Some(RestartArea {
        offset: page_offset,
        current_lsn,
        log_clients,
        system_page_size,
        log_page_size,
    })
}

/// Count RCRD pages and detect gaps in the $LogFile.
///
/// After the two restart area pages (at offsets 0 and 0x1000),
/// the remaining pages should be RCRD pages. A page that is neither
/// RSTR nor RCRD, or that is zeroed out, indicates a potential gap.
fn analyze_record_pages(data: &[u8]) -> (usize, bool) {
    let mut count = 0;
    let mut has_gaps = false;
    let mut offset = 2 * LOG_PAGE_SIZE; // Skip the two restart pages

    while offset + 4 <= data.len() {
        if &data[offset..offset + 4] == RCRD_SIGNATURE {
            count += 1;
        } else if data[offset..offset + 4] != [0, 0, 0, 0] {
            // Non-zero, non-RCRD page = potential gap/corruption
            has_gaps = true;
        } else {
            // Zeroed page in the middle of the log = gap
            // Only flag if we've seen records before and there's more data
            if count > 0 && offset + LOG_PAGE_SIZE < data.len() {
                // Check if there are more RCRD pages after this
                let remaining = &data[offset + LOG_PAGE_SIZE..];
                if remaining.len() >= 4 && &remaining[0..4] == RCRD_SIGNATURE {
                    has_gaps = true;
                }
            }
        }
        offset += LOG_PAGE_SIZE;
    }

    (count, has_gaps)
}

/// Parse the NTFS $LogFile and produce a summary.
pub fn parse_logfile(data: &[u8]) -> Option<LogFileSummary> {
    if data.len() < 2 * LOG_PAGE_SIZE {
        return None;
    }

    let mut restart_areas = Vec::new();

    // Parse first restart area at offset 0
    if let Some(ra) = parse_restart_area(data, 0) {
        restart_areas.push(ra);
    }

    // Parse second restart area at offset 0x1000
    if let Some(ra) = parse_restart_area(data, LOG_PAGE_SIZE) {
        restart_areas.push(ra);
    }

    if restart_areas.is_empty() {
        return None;
    }

    let (record_page_count, has_gaps) = analyze_record_pages(data);
    let highest_lsn = restart_areas.iter().map(|ra| ra.current_lsn).max().unwrap_or(0);

    Some(LogFileSummary {
        restart_areas,
        record_page_count,
        has_gaps,
        highest_lsn,
    })
}

// ─── Pipeline integration ────────────────────────────────────────────────────

/// Parse $LogFile from the collection and add summary entries to the timeline.
pub fn parse_logfile_artifact(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    let logfile_path = match &manifest.logfile {
        Some(p) => p,
        None => {
            debug!("No $LogFile found in manifest");
            return Ok(());
        }
    };

    let data = match provider.open_file(logfile_path) {
        Ok(d) => d,
        Err(e) => {
            warn!("Failed to read $LogFile: {}", e);
            return Ok(());
        }
    };

    let summary = match parse_logfile(&data) {
        Some(s) => s,
        None => {
            warn!("Failed to parse $LogFile (invalid format or too small)");
            return Ok(());
        }
    };

    debug!(
        "$LogFile: {} restart areas, {} RCRD pages, highest LSN={}, gaps={}",
        summary.restart_areas.len(),
        summary.record_page_count,
        summary.highest_lsn,
        summary.has_gaps
    );

    // Create a timeline entry for each restart area checkpoint
    for ra in &summary.restart_areas {
        let mut anomalies = AnomalyFlags::empty();
        if summary.has_gaps {
            anomalies |= AnomalyFlags::LOG_GAP_DETECTED;
        }

        let description = format!(
            "$LogFile restart area at offset 0x{:X}: LSN={}, clients={}, pages={}",
            ra.offset, ra.current_lsn, ra.log_clients, summary.record_page_count
        );

        // $LogFile doesn't have a direct timestamp in the restart area,
        // so we use a sentinel timestamp. The primary value of this parser
        // is gap detection (anomaly flags) rather than timestamped events.
        // The anomaly flags will be surfaced in the TUI's anomaly view.
        store.push(TimelineEntry {
            entity_id: EntityId::Generated(next_logfile_id()),
            path: description,
            primary_timestamp: chrono::Utc::now(),
            event_type: EventType::Other("LogCheckpoint".to_string()),
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::LogFile],
            anomalies,
            metadata: EntryMetadata::default(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid $LogFile with two restart pages and some RCRD pages.
    fn build_test_logfile(
        lsn1: u64,
        lsn2: u64,
        clients: u16,
        rcrd_count: usize,
    ) -> Vec<u8> {
        let total_pages = 2 + rcrd_count;
        let mut data = vec![0u8; total_pages * LOG_PAGE_SIZE];

        // Build restart page at offset 0
        build_restart_page(&mut data, 0, lsn1, clients);

        // Build restart page at offset 0x1000
        build_restart_page(&mut data, LOG_PAGE_SIZE, lsn2, clients);

        // Build RCRD pages
        for i in 0..rcrd_count {
            let offset = (2 + i) * LOG_PAGE_SIZE;
            data[offset..offset + 4].copy_from_slice(RCRD_SIGNATURE);
        }

        data
    }

    fn build_restart_page(data: &mut [u8], offset: usize, lsn: u64, clients: u16) {
        // Signature "RSTR"
        data[offset..offset + 4].copy_from_slice(RSTR_SIGNATURE);
        // SystemPageSize at 0x10
        data[offset + 0x10..offset + 0x14].copy_from_slice(&4096u32.to_le_bytes());
        // LogPageSize at 0x14
        data[offset + 0x14..offset + 0x18].copy_from_slice(&4096u32.to_le_bytes());
        // RestartOffset at 0x18 (point to offset 0x30 within the page)
        data[offset + 0x18..offset + 0x1A].copy_from_slice(&0x30u16.to_le_bytes());
        // CurrentLsn at restart_offset (0x30)
        data[offset + 0x30..offset + 0x38].copy_from_slice(&lsn.to_le_bytes());
        // LogClients at restart_offset + 8
        data[offset + 0x38..offset + 0x3A].copy_from_slice(&clients.to_le_bytes());
    }

    #[test]
    fn test_filetime_to_datetime() {
        // 2025-01-15 12:00:00 UTC = 133813872000000000
        let ft = 133_813_872_000_000_000u64;
        let dt = filetime_to_datetime(ft).unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2025-01-15");
    }

    #[test]
    fn test_filetime_zero() {
        assert!(filetime_to_datetime(0).is_none());
    }

    #[test]
    fn test_read_helpers() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u16(&data, 0), Some(0x0201));
        assert_eq!(read_u32(&data, 0), Some(0x04030201));
        assert_eq!(read_u64(&data, 0), Some(0x0807060504030201));
        assert!(read_u16(&data, 7).is_none());
        assert!(read_u32(&data, 5).is_none());
        assert!(read_u64(&data, 1).is_none());
    }

    #[test]
    fn test_parse_restart_area_valid() {
        let data = build_test_logfile(12345, 12300, 1, 0);
        let ra = parse_restart_area(&data, 0).unwrap();
        assert_eq!(ra.current_lsn, 12345);
        assert_eq!(ra.log_clients, 1);
        assert_eq!(ra.system_page_size, 4096);
        assert_eq!(ra.log_page_size, 4096);
    }

    #[test]
    fn test_parse_restart_area_bad_signature() {
        let mut data = vec![0u8; LOG_PAGE_SIZE * 2];
        data[0..4].copy_from_slice(b"BAAD");
        assert!(parse_restart_area(&data, 0).is_none());
    }

    #[test]
    fn test_parse_restart_area_too_short() {
        let data = vec![0u8; 100]; // Less than one page
        assert!(parse_restart_area(&data, 0).is_none());
    }

    #[test]
    fn test_parse_logfile_two_restart_areas() {
        let data = build_test_logfile(5000, 4999, 1, 10);
        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.restart_areas.len(), 2);
        assert_eq!(summary.highest_lsn, 5000);
        assert_eq!(summary.record_page_count, 10);
        assert!(!summary.has_gaps);
    }

    #[test]
    fn test_parse_logfile_detects_gaps() {
        let mut data = build_test_logfile(1000, 999, 1, 5);
        // Zero out a RCRD page in the middle (page 3, offset 3*0x1000)
        // and keep a RCRD page after it (page 4)
        let gap_offset = 3 * LOG_PAGE_SIZE;
        for b in &mut data[gap_offset..gap_offset + LOG_PAGE_SIZE] {
            *b = 0;
        }
        let summary = parse_logfile(&data).unwrap();
        assert!(summary.has_gaps, "Should detect gap in RCRD sequence");
    }

    #[test]
    fn test_parse_logfile_too_small() {
        let data = vec![0u8; 100];
        assert!(parse_logfile(&data).is_none());
    }

    #[test]
    fn test_parse_logfile_no_valid_restart() {
        let data = vec![0u8; 3 * LOG_PAGE_SIZE];
        assert!(parse_logfile(&data).is_none());
    }

    #[test]
    fn test_empty_manifest_no_error() {
        let manifest = ArtifactManifest::default();
        let mut store = TimelineStore::new();

        struct NoOpProvider;
        impl CollectionProvider for NoOpProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(vec![])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata {
                    hostname: "test".into(),
                    collection_timestamp: "2025-01-01".into(),
                    source_tool: "test".into(),
                }
            }
        }

        let result = parse_logfile_artifact(&NoOpProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_logfile_summary_creation() {
        let data = build_test_logfile(9999, 9998, 2, 20);
        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.restart_areas.len(), 2);
        assert_eq!(summary.highest_lsn, 9999);
        assert_eq!(summary.record_page_count, 20);
        assert_eq!(summary.restart_areas[0].log_clients, 2);
        assert!(!summary.has_gaps);
    }

    #[test]
    fn test_second_restart_area_higher_lsn() {
        let data = build_test_logfile(100, 200, 1, 5);
        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.highest_lsn, 200);
    }

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_filetime_before_unix_epoch() {
        // secs < EPOCH_DIFF => None
        let filetime = 100u64; // very small
        assert!(filetime_to_datetime(filetime).is_none());
    }

    #[test]
    fn test_filetime_with_nanos() {
        // Ensure subsecond precision is preserved
        let ft = 133_813_872_000_000_000u64 + 5_000_000; // 0.5 sec extra
        let dt = filetime_to_datetime(ft).unwrap();
        assert!(dt.timestamp_subsec_nanos() > 0);
    }

    #[test]
    fn test_read_u16_empty() {
        let data: [u8; 0] = [];
        assert!(read_u16(&data, 0).is_none());
    }

    #[test]
    fn test_read_u16_exact() {
        let data = [0xAB, 0xCD];
        assert_eq!(read_u16(&data, 0), Some(0xCDAB));
    }

    #[test]
    fn test_read_u32_empty() {
        let data: [u8; 0] = [];
        assert!(read_u32(&data, 0).is_none());
    }

    #[test]
    fn test_read_u64_empty() {
        let data: [u8; 0] = [];
        assert!(read_u64(&data, 0).is_none());
    }

    #[test]
    fn test_parse_restart_area_bad_restart_offset() {
        // Restart offset pointing past the page
        let mut data = vec![0u8; LOG_PAGE_SIZE * 2];
        data[0..4].copy_from_slice(RSTR_SIGNATURE);
        data[0x10..0x14].copy_from_slice(&4096u32.to_le_bytes());
        data[0x14..0x18].copy_from_slice(&4096u32.to_le_bytes());
        // restart_offset = 0xFFF0 (way past page boundary)
        data[0x18..0x1A].copy_from_slice(&0xFFF0u16.to_le_bytes());
        assert!(parse_restart_area(&data, 0).is_none());
    }

    #[test]
    fn test_parse_restart_area_second_page() {
        let data = build_test_logfile(100, 200, 1, 0);
        let ra = parse_restart_area(&data, LOG_PAGE_SIZE).unwrap();
        assert_eq!(ra.current_lsn, 200);
        assert_eq!(ra.offset, LOG_PAGE_SIZE);
    }

    #[test]
    fn test_analyze_record_pages_no_pages() {
        // Data with only 2 restart pages, no RCRD pages
        let data = build_test_logfile(100, 200, 1, 0);
        let (count, gaps) = analyze_record_pages(&data);
        assert_eq!(count, 0);
        assert!(!gaps);
    }

    #[test]
    fn test_analyze_record_pages_non_zero_non_rcrd() {
        // A page that is non-zero and non-RCRD = corruption indicator
        let mut data = build_test_logfile(100, 200, 1, 3);
        let corrupt_offset = 3 * LOG_PAGE_SIZE;
        data[corrupt_offset..corrupt_offset + 4].copy_from_slice(b"BAAD");
        let (count, gaps) = analyze_record_pages(&data);
        // Only 2 RCRD pages remain valid (page 2 and page 4)
        assert_eq!(count, 2);
        assert!(gaps);
    }

    #[test]
    fn test_analyze_record_pages_zeroed_at_end() {
        // Zeroed page at the very end (no RCRD after it => no gap flagged)
        let mut data = build_test_logfile(100, 200, 1, 3);
        let last_offset = 4 * LOG_PAGE_SIZE;
        for b in &mut data[last_offset..last_offset + LOG_PAGE_SIZE] {
            *b = 0;
        }
        let (count, gaps) = analyze_record_pages(&data);
        assert_eq!(count, 2); // 2 RCRD pages remain
        assert!(!gaps); // No RCRD after the zeroed page
    }

    #[test]
    fn test_parse_logfile_one_restart_area() {
        // Only first restart area is valid
        let mut data = build_test_logfile(100, 200, 1, 5);
        // Corrupt the second restart area signature
        data[LOG_PAGE_SIZE..LOG_PAGE_SIZE + 4].copy_from_slice(b"BAAD");
        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.restart_areas.len(), 1);
        assert_eq!(summary.highest_lsn, 100);
    }

    #[test]
    fn test_parse_logfile_second_restart_only() {
        // Only second restart area is valid
        let mut data = build_test_logfile(100, 200, 1, 5);
        // Corrupt the first restart area signature
        data[0..4].copy_from_slice(b"BAAD");
        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.restart_areas.len(), 1);
        assert_eq!(summary.highest_lsn, 200);
    }

    #[test]
    fn test_restart_area_fields() {
        let data = build_test_logfile(42, 43, 3, 0);
        let ra = parse_restart_area(&data, 0).unwrap();
        assert_eq!(ra.current_lsn, 42);
        assert_eq!(ra.log_clients, 3);
        assert_eq!(ra.system_page_size, 4096);
        assert_eq!(ra.log_page_size, 4096);
        assert_eq!(ra.offset, 0);
    }

    #[test]
    fn test_logfile_summary_debug_clone() {
        let data = build_test_logfile(100, 200, 1, 5);
        let summary = parse_logfile(&data).unwrap();
        let cloned = summary.clone();
        assert_eq!(cloned.highest_lsn, summary.highest_lsn);
        let debug_str = format!("{:?}", summary);
        assert!(debug_str.contains("restart_areas"));
    }

    #[test]
    fn test_restart_area_debug_clone() {
        let ra = RestartArea {
            offset: 0,
            current_lsn: 42,
            log_clients: 1,
            system_page_size: 4096,
            log_page_size: 4096,
        };
        let cloned = ra.clone();
        assert_eq!(cloned.current_lsn, 42);
        let debug_str = format!("{:?}", ra);
        assert!(debug_str.contains("42"));
    }

    #[test]
    fn test_next_logfile_id_increments() {
        let id1 = next_logfile_id();
        let id2 = next_logfile_id();
        assert!(id2 > id1);
        assert_eq!(id1 >> 48, 0x4C46);
    }

    #[test]
    fn test_parse_logfile_exactly_two_pages() {
        // Minimum viable size: exactly 2 pages, both valid restart areas
        let data = build_test_logfile(10, 20, 1, 0);
        assert_eq!(data.len(), 2 * LOG_PAGE_SIZE);
        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.restart_areas.len(), 2);
        assert_eq!(summary.record_page_count, 0);
    }

    // ─── Coverage for parse_logfile_artifact with real data ──────────────

    #[test]
    fn test_parse_logfile_artifact_with_valid_data() {
        use crate::collection::path::NormalizedPath;

        let logfile_data = build_test_logfile(5000, 4999, 1, 10);

        struct ValidLogProvider {
            data: Vec<u8>,
        }
        impl CollectionProvider for ValidLogProvider {
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

        let provider = ValidLogProvider { data: logfile_data };
        let mut manifest = ArtifactManifest::default();
        manifest.logfile = Some(NormalizedPath::from_image_path("/$LogFile", 'C'));
        let mut store = TimelineStore::new();

        let result = parse_logfile_artifact(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        // Should have created entries for the 2 restart areas
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_parse_logfile_artifact_with_gaps_sets_anomaly() {
        use crate::collection::path::NormalizedPath;

        let mut logfile_data = build_test_logfile(1000, 999, 1, 5);
        // Zero out a RCRD page in the middle
        let gap_offset = 3 * LOG_PAGE_SIZE;
        for b in &mut logfile_data[gap_offset..gap_offset + LOG_PAGE_SIZE] {
            *b = 0;
        }

        struct GapLogProvider {
            data: Vec<u8>,
        }
        impl CollectionProvider for GapLogProvider {
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

        let provider = GapLogProvider { data: logfile_data };
        let mut manifest = ArtifactManifest::default();
        manifest.logfile = Some(NormalizedPath::from_image_path("/$LogFile", 'C'));
        let mut store = TimelineStore::new();

        let result = parse_logfile_artifact(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert!(store.len() > 0);
        // At least one entry should have LOG_GAP_DETECTED anomaly
        let has_gap_anomaly = store.entries().any(|e| {
            e.anomalies.contains(AnomalyFlags::LOG_GAP_DETECTED)
        });
        assert!(has_gap_anomaly, "Should detect gap anomaly in logfile entries");
    }

    #[test]
    fn test_parse_logfile_artifact_provider_fails() {
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
        manifest.logfile = Some(NormalizedPath::from_image_path("/$LogFile", 'C'));
        let mut store = TimelineStore::new();

        let result = parse_logfile_artifact(&FailProvider, &manifest, &mut store);
        assert!(result.is_ok()); // Should not error, just warn
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_logfile_artifact_invalid_data() {
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
                Ok(vec![0u8; 100]) // Too small for $LogFile
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let mut manifest = ArtifactManifest::default();
        manifest.logfile = Some(NormalizedPath::from_image_path("/$LogFile", 'C'));
        let mut store = TimelineStore::new();

        let result = parse_logfile_artifact(&InvalidProvider, &manifest, &mut store);
        assert!(result.is_ok()); // Should not error, just warn
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_logfile_entry_description_format() {
        use crate::collection::path::NormalizedPath;

        let logfile_data = build_test_logfile(12345, 12344, 2, 5);

        struct LogProvider {
            data: Vec<u8>,
        }
        impl CollectionProvider for LogProvider {
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

        let provider = LogProvider { data: logfile_data };
        let mut manifest = ArtifactManifest::default();
        manifest.logfile = Some(NormalizedPath::from_image_path("/$LogFile", 'C'));
        let mut store = TimelineStore::new();

        let _ = parse_logfile_artifact(&provider, &manifest, &mut store);
        assert_eq!(store.len(), 2);

        // Check entry description format
        let entry = store.get(0).unwrap();
        assert!(entry.path.contains("$LogFile restart area"));
        assert!(entry.path.contains("LSN="));
        assert!(entry.path.contains("clients="));
        assert!(matches!(entry.event_type, EventType::Other(ref s) if s == "LogCheckpoint"));
        assert!(entry.sources.contains(&ArtifactSource::LogFile));
    }

    #[test]
    fn test_analyze_record_pages_zeroed_before_any_rcrd() {
        // Zeroed page with count == 0 should NOT flag gap
        let mut data = vec![0u8; 4 * LOG_PAGE_SIZE];
        build_restart_page(&mut data, 0, 100, 1);
        build_restart_page(&mut data, LOG_PAGE_SIZE, 200, 1);
        // Pages 2 and 3 are zeroed (no RCRD at all)
        let (count, gaps) = analyze_record_pages(&data);
        assert_eq!(count, 0);
        assert!(!gaps);
    }
}
