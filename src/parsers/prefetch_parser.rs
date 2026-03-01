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
}
