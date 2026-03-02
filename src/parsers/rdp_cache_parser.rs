use anyhow::Result;
use log::{debug, warn};
use smallvec::smallvec;

use crate::collection::manifest::ArtifactManifest;
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static RDPCACHE_ID_COUNTER: AtomicU64 = AtomicU64::new(0x5243_0000_0000_0000); // "RC" prefix

fn next_rdpcache_id() -> u64 {
    RDPCACHE_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── BMC file structures ─────────────────────────────────────────────────────

/// BMC (Bitmap Cache) file header signature.
const BMC_SIGNATURE: &[u8; 4] = b"RDP8";

/// BMC v2 file header.
const BMC_V2_SIGNATURE: &[u8; 4] = b"RDP6";

/// Summary of an RDP bitmap cache file.
#[derive(Debug, Clone)]
pub struct RdpCacheSummary {
    pub filename: String,
    pub file_size: u64,
    pub tile_count: usize,
    pub version: String,
    pub username: String,
}

// ─── Parsing functions ───────────────────────────────────────────────────────

/// Extract the username from an RDP cache file path.
/// Typical path: C:\Users\<username>\AppData\Local\Microsoft\Terminal Server Client\Cache\bcache24.bmc
pub fn extract_username_from_path(path: &str) -> String {
    let parts: Vec<&str> = path.split(|c| c == '\\' || c == '/').collect();
    for (i, part) in parts.iter().enumerate() {
        if part.eq_ignore_ascii_case("Users") && i + 1 < parts.len() {
            return parts[i + 1].to_string();
        }
    }
    "Unknown".to_string()
}

/// Extract the filename from a path.
pub fn extract_filename(path: &str) -> String {
    path.split(|c| c == '\\' || c == '/')
        .last()
        .unwrap_or("unknown")
        .to_string()
}

/// Analyze an RDP bitmap cache file and return a summary.
///
/// BMC files store bitmap tiles cached from RDP sessions. The exact format
/// varies between RDP versions. We detect the version from the header and
/// estimate tile count from file size.
pub fn analyze_bmc_file(data: &[u8], path: &str) -> Option<RdpCacheSummary> {
    if data.len() < 16 {
        return None;
    }

    let version = if data.len() >= 4 && &data[0..4] == BMC_SIGNATURE {
        "RDP8+".to_string()
    } else if data.len() >= 4 && &data[0..4] == BMC_V2_SIGNATURE {
        "RDP6".to_string()
    } else {
        // Many BMC files don't have a standard header - they're raw tile data
        // Files ending in .bmc in the cache directory are still valid
        "Unknown".to_string()
    };

    // Estimate tile count: typical tile is 64x64 pixels at 32bpp = 16384 bytes
    // This is a rough estimate for forensic context
    let estimated_tiles = if data.len() > 128 {
        data.len() / 16384
    } else {
        0
    };

    let username = extract_username_from_path(path);
    let filename = extract_filename(path);

    Some(RdpCacheSummary {
        filename,
        file_size: data.len() as u64,
        tile_count: estimated_tiles.max(1), // At least 1 if file exists
        version,
        username,
    })
}

// ─── Pipeline integration ────────────────────────────────────────────────────

/// Parse RDP bitmap cache files from the collection.
///
/// Each BMC file indicates outbound RDP activity by the user whose profile
/// contains the file. The file's existence proves the user connected to a
/// remote system via RDP.
pub fn parse_rdp_cache(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    if manifest.rdp_bitmap_cache.is_empty() {
        debug!("No RDP bitmap cache files found in manifest");
        return Ok(());
    }

    let mut total = 0u32;

    for cache_path in &manifest.rdp_bitmap_cache {
        let data = match provider.open_file(cache_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read RDP cache {}: {}", cache_path, e);
                continue;
            }
        };

        let summary = match analyze_bmc_file(&data, &cache_path.to_string()) {
            Some(s) => s,
            None => continue,
        };

        debug!(
            "RDP cache: {} ({} tiles, {}, user: {})",
            summary.filename, summary.tile_count, summary.version, summary.username
        );

        store.push(TimelineEntry {
            entity_id: EntityId::Generated(next_rdpcache_id()),
            path: format!(
                "[RDP:BitmapCache] {} (user: {}, tiles: ~{}, size: {} bytes, ver: {})",
                summary.filename,
                summary.username,
                summary.tile_count,
                summary.file_size,
                summary.version
            ),
            // No embedded timestamp in BMC files - use current time as placeholder
            primary_timestamp: chrono::Utc::now(),
            event_type: EventType::RdpSession,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Registry("RDPCache".to_string())],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        });
        total += 1;
    }

    if total > 0 {
        debug!("Processed {} RDP bitmap cache files", total);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_username() {
        let path = r"C:\Users\analyst\AppData\Local\Microsoft\Terminal Server Client\Cache\bcache24.bmc";
        assert_eq!(extract_username_from_path(path), "analyst");
    }

    #[test]
    fn test_extract_username_unknown() {
        assert_eq!(extract_username_from_path("/tmp/bcache.bmc"), "Unknown");
    }

    #[test]
    fn test_extract_filename() {
        assert_eq!(extract_filename(r"C:\path\to\bcache24.bmc"), "bcache24.bmc");
        assert_eq!(extract_filename("bcache.bmc"), "bcache.bmc");
    }

    #[test]
    fn test_analyze_bmc_rdp8() {
        let mut data = vec![0u8; 32768]; // ~2 tiles worth
        data[0..4].copy_from_slice(b"RDP8");

        let summary = analyze_bmc_file(&data, r"C:\Users\admin\Cache\bcache0.bmc").unwrap();
        assert_eq!(summary.version, "RDP8+");
        assert_eq!(summary.username, "admin");
        assert_eq!(summary.filename, "bcache0.bmc");
        assert!(summary.tile_count >= 1);
    }

    #[test]
    fn test_analyze_bmc_rdp6() {
        let mut data = vec![0u8; 16384];
        data[0..4].copy_from_slice(b"RDP6");

        let summary = analyze_bmc_file(&data, r"C:\Users\test\Cache\bcache1.bmc").unwrap();
        assert_eq!(summary.version, "RDP6");
    }

    #[test]
    fn test_analyze_bmc_unknown_header() {
        let data = vec![0xFFu8; 65536]; // Large file, no known header

        let summary = analyze_bmc_file(&data, "bcache.bmc").unwrap();
        assert_eq!(summary.version, "Unknown");
        assert!(summary.tile_count >= 1);
    }

    #[test]
    fn test_analyze_bmc_too_small() {
        let data = vec![0u8; 8];
        assert!(analyze_bmc_file(&data, "tiny.bmc").is_none());
    }

    #[test]
    fn test_rdp_cache_summary_creation() {
        let summary = RdpCacheSummary {
            filename: "bcache24.bmc".to_string(),
            file_size: 1048576,
            tile_count: 64,
            version: "RDP8+".to_string(),
            username: "attacker".to_string(),
        };
        assert_eq!(summary.tile_count, 64);
        assert_eq!(summary.file_size, 1048576);
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

        let result = parse_rdp_cache(&NoOpProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_extract_username_forward_slash_path() {
        let path = "C:/Users/forensic_analyst/AppData/Local/Microsoft/Terminal Server Client/Cache/bcache24.bmc";
        assert_eq!(extract_username_from_path(path), "forensic_analyst");
    }

    #[test]
    fn test_extract_username_case_insensitive() {
        let path = r"C:\users\Admin\AppData\Cache\bcache.bmc";
        assert_eq!(extract_username_from_path(path), "Admin");
    }

    #[test]
    fn test_extract_username_users_at_end() {
        // "Users" is the last component -- no username after it
        let path = r"C:\Users";
        assert_eq!(extract_username_from_path(path), "Unknown");
    }

    #[test]
    fn test_extract_filename_forward_slash() {
        assert_eq!(extract_filename("C:/path/to/bcache24.bmc"), "bcache24.bmc");
    }

    #[test]
    fn test_extract_filename_empty_string() {
        assert_eq!(extract_filename(""), "");
    }

    #[test]
    fn test_analyze_bmc_exactly_16_bytes() {
        // Exactly at the minimum: len >= 16 is true
        let data = vec![0u8; 16];
        let summary = analyze_bmc_file(&data, "test.bmc");
        assert!(summary.is_some());
        let s = summary.unwrap();
        // 16 bytes < 128, so estimated_tiles = 0, but max(1) = 1
        assert_eq!(s.tile_count, 1);
        assert_eq!(s.version, "Unknown");
    }

    #[test]
    fn test_analyze_bmc_just_above_128_bytes() {
        // data.len() = 129, which is > 128, so 129/16384 = 0, but max(1) = 1
        let data = vec![0u8; 129];
        let summary = analyze_bmc_file(&data, "test.bmc").unwrap();
        assert_eq!(summary.tile_count, 1);
    }

    #[test]
    fn test_analyze_bmc_large_file_tile_count() {
        // 10 * 16384 = 163840 bytes -> 10 tiles
        let data = vec![0u8; 163840];
        let summary = analyze_bmc_file(&data, "test.bmc").unwrap();
        assert_eq!(summary.tile_count, 10);
    }

    #[test]
    fn test_analyze_bmc_file_size_stored() {
        let data = vec![0xFFu8; 500];
        let summary = analyze_bmc_file(&data, "test.bmc").unwrap();
        assert_eq!(summary.file_size, 500);
    }

    #[test]
    fn test_analyze_bmc_15_bytes_returns_none() {
        let data = vec![0u8; 15];
        assert!(analyze_bmc_file(&data, "tiny.bmc").is_none());
    }

    #[test]
    fn test_next_rdpcache_id_increments() {
        let id1 = next_rdpcache_id();
        let id2 = next_rdpcache_id();
        assert!(id2 > id1);
        // Both should have the "RC" prefix
        assert_eq!(id1 >> 48, 0x5243);
        assert_eq!(id2 >> 48, 0x5243);
    }

    #[test]
    fn test_rdp_cache_summary_debug_impl() {
        let summary = RdpCacheSummary {
            filename: "bcache0.bmc".to_string(),
            file_size: 100,
            tile_count: 1,
            version: "RDP8+".to_string(),
            username: "test".to_string(),
        };
        let debug_str = format!("{:?}", summary);
        assert!(debug_str.contains("bcache0.bmc"));
        assert!(debug_str.contains("RDP8+"));
    }

    #[test]
    fn test_rdp_cache_summary_clone() {
        let summary = RdpCacheSummary {
            filename: "bcache0.bmc".to_string(),
            file_size: 100,
            tile_count: 1,
            version: "RDP8+".to_string(),
            username: "test".to_string(),
        };
        let cloned = summary.clone();
        assert_eq!(cloned.filename, summary.filename);
        assert_eq!(cloned.file_size, summary.file_size);
    }
}
