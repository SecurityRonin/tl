use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, warn};
use smallvec::smallvec;
use std::io::{Cursor, Read, Seek};

use forensic_rs::{
    err::ForensicResult,
    traits::vfs::{VFileType, VMetadata, VirtualFile},
    utils::time::Filetime,
};
use frnsc_prefetch::prelude::*;

use crate::collection::manifest::ArtifactManifest;
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── In-memory VirtualFile adapter ──────────────────────────────────────────

/// Adapter that wraps a `Vec<u8>` as a `VirtualFile` for frnsc-prefetch.
struct InMemoryFile {
    cursor: Cursor<Vec<u8>>,
    size: u64,
}

impl InMemoryFile {
    fn new(data: Vec<u8>) -> Self {
        let size = data.len() as u64;
        Self {
            cursor: Cursor::new(data),
            size,
        }
    }
}

impl Read for InMemoryFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.cursor.read(buf)
    }
}

impl Seek for InMemoryFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.cursor.seek(pos)
    }
}

impl VirtualFile for InMemoryFile {
    fn metadata(&self) -> ForensicResult<VMetadata> {
        Ok(VMetadata {
            created: None,
            accessed: None,
            modified: None,
            file_type: VFileType::File,
            size: self.size,
        })
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a forensic-rs `Filetime` to `DateTime<Utc>`.
fn forensic_filetime_to_datetime(ft: &Filetime) -> Option<DateTime<Utc>> {
    let raw = ft.filetime();
    if raw == 0 {
        return None;
    }
    const EPOCH_DIFF: i64 = 11_644_473_600;
    let secs = (raw / 10_000_000) as i64 - EPOCH_DIFF;
    if secs < 0 {
        return None;
    }
    let nanos = ((raw % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}

/// Extract filename from a prefetch artifact path.
///
/// Input: "POWERSHELL.EXE-AE8EDC9B.pf" or full collection path.
/// Output: "POWERSHELL.EXE-AE8EDC9B.pf"
fn extract_pf_filename(path: &str) -> String {
    path.split(|c| c == '\\' || c == '/')
        .last()
        .unwrap_or(path)
        .to_string()
}

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static PREFETCH_ID_COUNTER: AtomicU64 = AtomicU64::new(0x5046_0000_0000_0000); // "PF" prefix

fn next_prefetch_id() -> u64 {
    PREFETCH_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Maximum reasonable prefetch file size (1 MB).
const MAX_PREFETCH_SIZE: usize = 1_000_000;

/// Parse all prefetch files from the collection and populate the timeline store.
///
/// Uses `frnsc-prefetch` which handles both compressed (MAM/XPRESS Huffman)
/// and uncompressed prefetch files across all Windows versions (XP through 11).
///
/// For each .pf file, this extracts:
/// - Executable name
/// - Last run timestamps (up to 8 for Win8+)
/// - Run count
/// - Loaded file count (DLLs/EXEs from metrics)
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

        let artifact_name = extract_pf_filename(&pf_path.to_string());
        let vfile: Box<dyn VirtualFile> = Box::new(InMemoryFile::new(data));

        let pf = match read_prefetch_file(&artifact_name, vfile) {
            Ok(pf) => pf,
            Err(e) => {
                debug!("Could not parse prefetch file {}: {}", pf_path, e);
                error_count += 1;
                continue;
            }
        };

        if pf.last_run_times.is_empty() {
            debug!(
                "Prefetch {} ({}) has no run times",
                pf_path, pf.name
            );
            continue;
        }

        // Convert all run times to DateTime<Utc>
        let run_times: Vec<DateTime<Utc>> = pf
            .last_run_times
            .iter()
            .filter_map(forensic_filetime_to_datetime)
            .collect();

        if run_times.is_empty() {
            continue;
        }

        let loaded_files_count = pf.metrics.len();

        // Create a timeline entry for each last-run timestamp
        for run_time in &run_times {
            let mut timestamps = TimestampSet::default();
            timestamps.prefetch_last_run = run_times.clone();

            let entry = TimelineEntry {
                entity_id: EntityId::Generated(next_prefetch_id()),
                path: format!(
                    "{} (run_count: {}, loaded: {} files)",
                    pf.name, pf.run_count, loaded_files_count
                ),
                primary_timestamp: *run_time,
                event_type: EventType::Execute,
                timestamps,
                sources: smallvec![ArtifactSource::Prefetch],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
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
    fn test_forensic_filetime_to_datetime() {
        // 2025-01-01 00:00:00 UTC
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let expected_secs = dt.timestamp() + 11_644_473_600;
        let filetime = (expected_secs as u64) * 10_000_000;
        let ft = Filetime::new(filetime);
        let result = forensic_filetime_to_datetime(&ft).unwrap();
        assert_eq!(result, dt);
    }

    #[test]
    fn test_forensic_filetime_zero_returns_none() {
        let ft = Filetime::new(0);
        assert!(forensic_filetime_to_datetime(&ft).is_none());
    }

    #[test]
    fn test_extract_pf_filename() {
        assert_eq!(
            extract_pf_filename(r"C:\Windows\Prefetch\CMD.EXE-087B4001.pf"),
            "CMD.EXE-087B4001.pf"
        );
        assert_eq!(
            extract_pf_filename("NOTEPAD.EXE-D8414F97.pf"),
            "NOTEPAD.EXE-D8414F97.pf"
        );
    }

    #[test]
    fn test_in_memory_file_read_seek() {
        let data = vec![1, 2, 3, 4, 5];
        let mut file = InMemoryFile::new(data);
        let mut buf = [0u8; 3];
        file.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3]);
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        file.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3]);
    }

    #[test]
    fn test_in_memory_file_metadata() {
        let file = InMemoryFile::new(vec![0u8; 1024]);
        let meta = file.metadata().unwrap();
        assert_eq!(meta.size, 1024);
        assert!(meta.file_type == VFileType::File);
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

        // Prefetch hash at offset 76 (required by frnsc-prefetch validation)
        // Just set to 0 - the crate logs a warning but doesn't fail
        buf[76..80].copy_from_slice(&0u32.to_le_bytes());

        // File information starts at offset 84
        // v17: metrics_offset at info+0, metrics_count at info+4
        // We need to set up minimal metrics info to avoid out-of-bounds
        let metrics_offset = 160u32; // Place metrics after file info
        buf[84..88].copy_from_slice(&metrics_offset.to_le_bytes()); // metrics_offsets
        buf[88..92].copy_from_slice(&0u32.to_le_bytes()); // metrics_count = 0

        // trace_chain_offset, trace_chain_count
        buf[92..96].copy_from_slice(&160u32.to_le_bytes());
        buf[96..100].copy_from_slice(&0u32.to_le_bytes());

        // filename_string_offset, filename_string_size
        buf[100..104].copy_from_slice(&160u32.to_le_bytes());
        buf[104..108].copy_from_slice(&0u32.to_le_bytes());

        // volume_information_offset, volume_count, volume_information_size
        buf[108..112].copy_from_slice(&160u32.to_le_bytes());
        buf[112..116].copy_from_slice(&0u32.to_le_bytes());
        buf[116..120].copy_from_slice(&0u32.to_le_bytes());

        // v17: last_run_time at info+36 = offset 120
        let ft_offset = 84 + 36;
        buf[ft_offset..ft_offset + 8].copy_from_slice(&filetime.to_le_bytes());

        // v17: run_count at info+60 = offset 144
        let rc_offset = 84 + 60;
        buf[rc_offset..rc_offset + 4].copy_from_slice(&run_count.to_le_bytes());

        buf
    }

    #[test]
    fn test_parse_v17_via_crate() {
        use chrono::TimeZone;
        let expected_dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let secs = expected_dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;

        let data = build_test_prefetch_v17("CMD.EXE", filetime, 5);
        let vfile: Box<dyn VirtualFile> = Box::new(InMemoryFile::new(data));

        let pf = read_prefetch_file("CMD.EXE-087B4001.pf", vfile).unwrap();

        assert_eq!(pf.name, "CMD.EXE");
        assert_eq!(pf.version, 17);
        assert_eq!(pf.run_count, 5);
        assert_eq!(pf.last_run_times.len(), 1);
        let run_dt = forensic_filetime_to_datetime(&pf.last_run_times[0]).unwrap();
        assert_eq!(run_dt, expected_dt);
    }

    #[test]
    fn test_parse_invalid_data() {
        let data = vec![0u8; 10];
        let vfile: Box<dyn VirtualFile> = Box::new(InMemoryFile::new(data));
        assert!(read_prefetch_file("test.pf", vfile).is_err());
    }

    #[test]
    fn test_parse_bad_signature() {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&17u32.to_le_bytes());
        data[4..8].copy_from_slice(b"XXXX"); // Wrong signature
        let vfile: Box<dyn VirtualFile> = Box::new(InMemoryFile::new(data));
        assert!(read_prefetch_file("test.pf", vfile).is_err());
    }

    #[test]
    fn test_prefetch_entry_creation() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;

        let data = build_test_prefetch_v17("MALWARE.EXE", filetime, 1);
        let vfile: Box<dyn VirtualFile> = Box::new(InMemoryFile::new(data));
        let pf = read_prefetch_file("MALWARE.EXE-12345678.pf", vfile).unwrap();

        assert_eq!(pf.name, "MALWARE.EXE");
        assert_eq!(pf.last_run_times.len(), 1);

        // Verify timeline entry construction
        let run_times: Vec<DateTime<Utc>> = pf
            .last_run_times
            .iter()
            .filter_map(forensic_filetime_to_datetime)
            .collect();

        let mut store = TimelineStore::new();
        let mut timestamps = TimestampSet::default();
        timestamps.prefetch_last_run = run_times.clone();

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_prefetch_id()),
            path: format!(
                "{} (run_count: {}, loaded: {} files)",
                pf.name, pf.run_count, pf.metrics.len()
            ),
            primary_timestamp: run_times[0],
            event_type: EventType::Execute,
            timestamps,
            sources: smallvec![ArtifactSource::Prefetch],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        store.push(entry);
        assert_eq!(store.len(), 1);
        let e = store.get(0).unwrap();
        assert!(e.path.contains("MALWARE.EXE"));
        assert_eq!(e.event_type, EventType::Execute);
        assert_eq!(e.primary_timestamp, dt);
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

        let result = parse_prefetch_files(&NoOpProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_forensic_filetime_negative_secs() {
        // Very small filetime that results in negative secs
        let ft = Filetime::new(1);
        assert!(forensic_filetime_to_datetime(&ft).is_none());
    }

    #[test]
    fn test_forensic_filetime_with_nanos() {
        use chrono::TimeZone;
        let dt_base = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let secs = dt_base.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000 + 1_000_000; // +100ms
        let ft = Filetime::new(filetime);
        let result = forensic_filetime_to_datetime(&ft).unwrap();
        assert_eq!(result.timestamp_subsec_nanos(), 100_000_000);
    }

    #[test]
    fn test_forensic_filetime_epoch_boundary() {
        use chrono::TimeZone;
        let epoch_diff: u64 = 11_644_473_600;
        let filetime = epoch_diff * 10_000_000;
        let ft = Filetime::new(filetime);
        let result = forensic_filetime_to_datetime(&ft).unwrap();
        assert_eq!(result, Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap());
    }

    #[test]
    fn test_extract_pf_filename_windows_path() {
        assert_eq!(
            extract_pf_filename(r"C:\Windows\Prefetch\SVCHOST.EXE-ABCD1234.pf"),
            "SVCHOST.EXE-ABCD1234.pf"
        );
    }

    #[test]
    fn test_extract_pf_filename_unix_path() {
        assert_eq!(
            extract_pf_filename("/collected/prefetch/CMD.EXE-12345678.pf"),
            "CMD.EXE-12345678.pf"
        );
    }

    #[test]
    fn test_extract_pf_filename_just_filename() {
        assert_eq!(
            extract_pf_filename("NOTEPAD.EXE-D8414F97.pf"),
            "NOTEPAD.EXE-D8414F97.pf"
        );
    }

    #[test]
    fn test_extract_pf_filename_empty() {
        assert_eq!(extract_pf_filename(""), "");
    }

    #[test]
    fn test_extract_pf_filename_trailing_separator() {
        // Edge case: trailing separator results in empty last element
        // But unwrap_or(path) should handle it
        let result = extract_pf_filename("path/to/");
        assert_eq!(result, "");
    }

    #[test]
    fn test_in_memory_file_empty() {
        let file = InMemoryFile::new(vec![]);
        let meta = file.metadata().unwrap();
        assert_eq!(meta.size, 0);
    }

    #[test]
    fn test_in_memory_file_large() {
        let data = vec![0xAA; 1_000_000];
        let file = InMemoryFile::new(data);
        let meta = file.metadata().unwrap();
        assert_eq!(meta.size, 1_000_000);
    }

    #[test]
    fn test_in_memory_file_seek_end() {
        let data = vec![1, 2, 3, 4, 5];
        let mut file = InMemoryFile::new(data);
        let pos = file.seek(std::io::SeekFrom::End(-2)).unwrap();
        assert_eq!(pos, 3);
        let mut buf = [0u8; 2];
        file.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [4, 5]);
    }

    #[test]
    fn test_in_memory_file_seek_current() {
        let data = vec![10, 20, 30, 40, 50];
        let mut file = InMemoryFile::new(data);
        let mut buf = [0u8; 2];
        file.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [10, 20]);
        // Seek 1 forward from current
        file.seek(std::io::SeekFrom::Current(1)).unwrap();
        file.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [40, 50]);
    }

    #[test]
    fn test_in_memory_file_metadata_fields() {
        let file = InMemoryFile::new(vec![0u8; 512]);
        let meta = file.metadata().unwrap();
        assert!(meta.created.is_none());
        assert!(meta.accessed.is_none());
        assert!(meta.modified.is_none());
        assert!(matches!(meta.file_type, VFileType::File));
    }

    #[test]
    fn test_next_prefetch_id_monotonic() {
        let id1 = next_prefetch_id();
        let id2 = next_prefetch_id();
        let id3 = next_prefetch_id();
        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[test]
    fn test_next_prefetch_id_has_pf_prefix() {
        let id = next_prefetch_id();
        assert_eq!((id >> 48) & 0xFFFF, 0x5046);
    }

    #[test]
    fn test_max_prefetch_size_constant() {
        assert_eq!(MAX_PREFETCH_SIZE, 1_000_000);
    }

    #[test]
    fn test_parse_v17_multiple_attributes() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 3, 15, 14, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;

        let data = build_test_prefetch_v17("POWERSHELL.EXE", filetime, 100);
        let vfile: Box<dyn VirtualFile> = Box::new(InMemoryFile::new(data));
        let pf = read_prefetch_file("POWERSHELL.EXE-AE8EDC9B.pf", vfile).unwrap();

        assert_eq!(pf.name, "POWERSHELL.EXE");
        assert_eq!(pf.run_count, 100);
        assert_eq!(pf.version, 17);
    }

    #[test]
    fn test_parse_v17_zero_run_count() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;

        let data = build_test_prefetch_v17("TEST.EXE", filetime, 0);
        let vfile: Box<dyn VirtualFile> = Box::new(InMemoryFile::new(data));
        let pf = read_prefetch_file("TEST.EXE-00000000.pf", vfile).unwrap();
        assert_eq!(pf.run_count, 0);
    }

    #[test]
    fn test_forensic_filetime_far_future() {
        use chrono::TimeZone;
        // Year 2100
        let dt = Utc.with_ymd_and_hms(2100, 12, 31, 23, 59, 59).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;
        let ft = Filetime::new(filetime);
        let result = forensic_filetime_to_datetime(&ft).unwrap();
        assert_eq!(result, dt);
    }

    #[test]
    fn test_extract_pf_filename_mixed_separators() {
        assert_eq!(
            extract_pf_filename(r"C:\collected/prefetch\CMD.EXE-087B4001.pf"),
            "CMD.EXE-087B4001.pf"
        );
    }

    // ─── Pipeline integration and deeper coverage ────────────────────────

    #[test]
    fn test_parse_prefetch_files_pipeline_with_valid_v17() {
        use crate::collection::path::NormalizedPath;
        use chrono::TimeZone;

        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;

        let pf_data = build_test_prefetch_v17("CMD.EXE", filetime, 5);

        let mut manifest = ArtifactManifest::default();
        manifest.prefetch.push(
            NormalizedPath::from_image_path("/Windows/Prefetch/CMD.EXE-087B4001.pf", 'C'),
        );

        struct PrefetchProvider {
            data: Vec<u8>,
        }
        impl CollectionProvider for PrefetchProvider {
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

        let mut store = TimelineStore::new();
        let provider = PrefetchProvider { data: pf_data };
        let result = parse_prefetch_files(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert!(store.len() >= 1);

        let e = store.get(0).unwrap();
        assert!(e.path.contains("CMD.EXE"));
        assert!(e.path.contains("run_count: 5"));
        assert_eq!(e.event_type, EventType::Execute);
        assert!(matches!(&e.sources[0], ArtifactSource::Prefetch));
        assert_eq!(e.primary_timestamp, dt);
    }

    #[test]
    fn test_parse_prefetch_files_pipeline_with_failing_provider() {
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.prefetch.push(
            NormalizedPath::from_image_path("/Windows/Prefetch/CMD.EXE-087B4001.pf", 'C'),
        );

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
                anyhow::bail!("File read error")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_prefetch_files(&FailProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_prefetch_files_pipeline_oversized_file() {
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.prefetch.push(
            NormalizedPath::from_image_path("/Windows/Prefetch/HUGE.EXE-00000000.pf", 'C'),
        );

        let mut store = TimelineStore::new();

        struct OversizedProvider;
        impl CollectionProvider for OversizedProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                // Return data larger than MAX_PREFETCH_SIZE (1MB)
                Ok(vec![0u8; 1_000_001])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_prefetch_files(&OversizedProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0); // Skipped due to size
    }

    #[test]
    fn test_parse_prefetch_files_pipeline_invalid_pf_data() {
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.prefetch.push(
            NormalizedPath::from_image_path("/Windows/Prefetch/BAD.EXE-00000000.pf", 'C'),
        );

        let mut store = TimelineStore::new();

        struct BadDataProvider;
        impl CollectionProvider for BadDataProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                // Valid size but garbage content
                Ok(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE].into_iter().cycle().take(512).collect())
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_prefetch_files(&BadDataProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_prefetch_files_pipeline_multiple_files() {
        use crate::collection::path::NormalizedPath;
        use chrono::TimeZone;

        let dt = Utc.with_ymd_and_hms(2025, 3, 15, 14, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;

        let mut manifest = ArtifactManifest::default();
        manifest.prefetch.push(
            NormalizedPath::from_image_path("/Windows/Prefetch/CMD.EXE-087B4001.pf", 'C'),
        );
        manifest.prefetch.push(
            NormalizedPath::from_image_path("/Windows/Prefetch/BAD.EXE-00000000.pf", 'C'),
        );

        struct MixedProvider {
            good_data: Vec<u8>,
        }
        impl CollectionProvider for MixedProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                if path.to_string().contains("CMD") {
                    Ok(self.good_data.clone())
                } else {
                    Ok(vec![0u8; 10]) // too small to parse
                }
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let mut store = TimelineStore::new();
        let provider = MixedProvider {
            good_data: build_test_prefetch_v17("CMD.EXE", filetime, 3),
        };
        let result = parse_prefetch_files(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        // Only the valid CMD.EXE file should produce entries
        assert!(store.len() >= 1);
        let e = store.get(0).unwrap();
        assert!(e.path.contains("CMD.EXE"));
    }

    #[test]
    fn test_parse_prefetch_files_pipeline_zero_filetime() {
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.prefetch.push(
            NormalizedPath::from_image_path("/Windows/Prefetch/ZERO.EXE-00000000.pf", 'C'),
        );

        // Build a prefetch with filetime=0 (no valid run times)
        let pf_data = build_test_prefetch_v17("ZERO.EXE", 0, 1);

        struct ZeroProvider {
            data: Vec<u8>,
        }
        impl CollectionProvider for ZeroProvider {
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

        let mut store = TimelineStore::new();
        let provider = ZeroProvider { data: pf_data };
        let result = parse_prefetch_files(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        // No entries because filetime=0 produces None from forensic_filetime_to_datetime
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_prefetch_files_pipeline_exactly_max_size() {
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.prefetch.push(
            NormalizedPath::from_image_path("/Windows/Prefetch/EXACT.EXE-00000000.pf", 'C'),
        );

        struct ExactSizeProvider;
        impl CollectionProvider for ExactSizeProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                // Exactly MAX_PREFETCH_SIZE - should NOT be skipped
                Ok(vec![0u8; 1_000_000])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let mut store = TimelineStore::new();
        let result = parse_prefetch_files(&ExactSizeProvider, &manifest, &mut store);
        assert!(result.is_ok());
        // Won't be skipped (exactly MAX_PREFETCH_SIZE), but will fail to parse
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_in_memory_file_read_partial() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut file = InMemoryFile::new(data);
        let mut buf = [0u8; 5];
        let n = file.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf, [1, 2, 3, 4, 5]);
        // Read remaining
        let n = file.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf, [6, 7, 8, 9, 10]);
        // Read past end
        let n = file.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_in_memory_file_metadata_vfile_type_is_file() {
        let file = InMemoryFile::new(vec![42; 100]);
        let meta = file.metadata().unwrap();
        assert!(matches!(meta.file_type, VFileType::File));
        assert!(meta.created.is_none());
        assert!(meta.accessed.is_none());
        assert!(meta.modified.is_none());
        assert_eq!(meta.size, 100);
    }

    #[test]
    fn test_build_test_prefetch_v17_name_truncation() {
        // Test with a very long name that exceeds the 60 byte copy limit
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;

        let long_name = "A".repeat(50); // 50 chars = 100 bytes UTF-16, but copy limit is 60
        let data = build_test_prefetch_v17(&long_name, filetime, 1);
        let vfile: Box<dyn VirtualFile> = Box::new(InMemoryFile::new(data));
        let pf = read_prefetch_file("LONG.EXE-00000000.pf", vfile).unwrap();
        // Name will be truncated to 30 chars (60 bytes / 2)
        assert_eq!(pf.name.len(), 30);
    }

    #[test]
    fn test_forensic_filetime_just_after_epoch() {
        use chrono::TimeZone;
        // Just 1 second after Unix epoch
        let epoch_diff: u64 = 11_644_473_600;
        let filetime = (epoch_diff + 1) * 10_000_000;
        let ft = Filetime::new(filetime);
        let result = forensic_filetime_to_datetime(&ft).unwrap();
        assert_eq!(result, Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 1).unwrap());
    }

    #[test]
    fn test_forensic_filetime_just_before_epoch() {
        // 1 tick before Unix epoch (negative secs)
        let epoch_diff: u64 = 11_644_473_600;
        let filetime = (epoch_diff - 1) * 10_000_000;
        let ft = Filetime::new(filetime);
        // This should produce secs = -1, which returns None
        assert!(forensic_filetime_to_datetime(&ft).is_none());
    }
}
