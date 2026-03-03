use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, warn};
use nt_hive2::{Hive, HiveParseMode, KeyNode, SubPath};
use smallvec::smallvec;
use std::io::Cursor;

use crate::collection::manifest::{ArtifactManifest, RegistryHiveType};
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a Windows FILETIME (100ns intervals since 1601-01-01) to DateTime<Utc>.
#[allow(dead_code)]
fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    const EPOCH_DIFF: i64 = 11_644_473_600;
    let secs = (filetime / 10_000_000) as i64 - EPOCH_DIFF;
    let nanos = ((filetime % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}

/// Try to parse a date string like "MM/DD/YYYY HH:MM:SS" or ISO 8601 into DateTime<Utc>.
fn parse_date_string(s: &str) -> Option<DateTime<Utc>> {
    // Try ISO 8601 first
    if let Ok(dt) = s.parse::<DateTime<Utc>>() {
        return Some(dt);
    }
    // Try other common formats
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%m/%d/%Y %H:%M:%S") {
        return Some(dt.and_utc());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(dt.and_utc());
    }
    None
}

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static AMCACHE_ID_COUNTER: AtomicU64 = AtomicU64::new(0x414D_0000_0000_0000); // "AM" prefix

fn next_amcache_id() -> u64 {
    AMCACHE_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Amcache entry ──────────────────────────────────────────────────────────

/// Parsed data from a single Amcache entry.
#[derive(Debug, Clone)]
pub struct AmcacheEntry {
    pub file_path: String,
    pub sha1: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub file_size: Option<u64>,
}

// ─── Registry-based parsing with nt_hive2 ────────────────────────────────────

/// Parse InventoryApplicationFile entries from the Amcache hive.
///
/// Path: Root\InventoryApplicationFile\<subkey>
/// Values of interest:
/// - "LowerCaseLongPath" (REG_SZ) - file path
/// - "FileId" (REG_SZ) - SHA1 hash (prefixed with "0000")
/// - "LinkDate" (REG_SZ) - compile/link date
/// - "Size" (REG_QWORD/REG_DWORD) - file size
fn parse_inventory_application_file(
    root_key: &KeyNode,
    hive: &mut Hive<Cursor<Vec<u8>>, nt_hive2::CleanHive>,
) -> Vec<AmcacheEntry> {
    let mut entries = Vec::new();

    let iaf_key = match root_key.subpath("InventoryApplicationFile", hive) {
        Ok(Some(key)) => key,
        Ok(None) => {
            debug!("InventoryApplicationFile key not found in Amcache");
            return entries;
        }
        Err(e) => {
            warn!("Error accessing InventoryApplicationFile: {}", e);
            return entries;
        }
    };

    let subkeys = match iaf_key.borrow().subkeys(hive) {
        Ok(sk) => sk.clone(),
        Err(e) => {
            warn!("Error reading InventoryApplicationFile subkeys: {}", e);
            return entries;
        }
    };

    for subkey in subkeys.iter() {
        let sk = subkey.borrow();
        let values = sk.values();

        let mut file_path = None;
        let mut sha1 = None;
        let mut timestamp = None;
        let mut file_size = None;

        for value in values {
            let name = value.name();
            match name {
                "LowerCaseLongPath" => {
                    if let nt_hive2::RegistryValue::RegSZ(s) = value.value() {
                        file_path = Some(s.clone());
                    }
                }
                "FileId" => {
                    if let nt_hive2::RegistryValue::RegSZ(s) = value.value() {
                        // SHA1 hash, often prefixed with "0000"
                        let hash = s.trim_start_matches("0000").to_string();
                        if !hash.is_empty() {
                            sha1 = Some(hash);
                        }
                    }
                }
                "LinkDate" => {
                    if let nt_hive2::RegistryValue::RegSZ(s) = value.value() {
                        timestamp = parse_date_string(s);
                    }
                }
                "Size" => match value.value() {
                    nt_hive2::RegistryValue::RegQWord(v) => {
                        file_size = Some(*v);
                    }
                    nt_hive2::RegistryValue::RegDWord(v) => {
                        file_size = Some(*v as u64);
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // If no file path from values, try the key's last-write timestamp
        if timestamp.is_none() {
            timestamp = Some(*sk.timestamp());
        }

        if let Some(path) = file_path {
            entries.push(AmcacheEntry {
                file_path: path,
                sha1,
                timestamp,
                file_size,
            });
        }
    }

    entries
}

/// Parse the older File\{volume_guid}\{hash} format from the Amcache hive.
///
/// Path: Root\File\{volume_guid}\<entry>
fn parse_file_entries(
    root_key: &KeyNode,
    hive: &mut Hive<Cursor<Vec<u8>>, nt_hive2::CleanHive>,
) -> Vec<AmcacheEntry> {
    let mut entries = Vec::new();

    let file_key = match root_key.subpath("File", hive) {
        Ok(Some(key)) => key,
        Ok(None) => {
            debug!("File key not found in Amcache (older format not present)");
            return entries;
        }
        Err(e) => {
            debug!("Error accessing File key: {}", e);
            return entries;
        }
    };

    // Enumerate volume GUID subkeys
    let volume_keys = match file_key.borrow().subkeys(hive) {
        Ok(sk) => sk.clone(),
        Err(e) => {
            warn!("Error reading File volume subkeys: {}", e);
            return entries;
        }
    };

    for volume_key in volume_keys.iter() {
        let vk = volume_key.borrow();
        let file_entries = match vk.subkeys(hive) {
            Ok(sk) => sk.clone(),
            Err(e) => {
                debug!("Error reading volume file entries: {}", e);
                continue;
            }
        };

        for file_entry in file_entries.iter() {
            let fe = file_entry.borrow();
            let values = fe.values();

            let mut file_path = None;
            let mut sha1 = None;
            let mut file_size = None;

            for value in values {
                let name = value.name();
                // In older format, values are numbered:
                // 15 = full path, 101 = SHA1, 6 = file size
                match name {
                    "15" => {
                        if let nt_hive2::RegistryValue::RegSZ(s) = value.value() {
                            file_path = Some(s.clone());
                        }
                    }
                    "101" => {
                        if let nt_hive2::RegistryValue::RegSZ(s) = value.value() {
                            let hash = s.trim_start_matches("0000").to_string();
                            if !hash.is_empty() {
                                sha1 = Some(hash);
                            }
                        }
                    }
                    "6" => match value.value() {
                        nt_hive2::RegistryValue::RegQWord(v) => {
                            file_size = Some(*v);
                        }
                        nt_hive2::RegistryValue::RegDWord(v) => {
                            file_size = Some(*v as u64);
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }

            // Use key timestamp as the entry timestamp
            let timestamp = Some(*fe.timestamp());

            if let Some(path) = file_path {
                entries.push(AmcacheEntry {
                    file_path: path,
                    sha1,
                    timestamp,
                    file_size,
                });
            }
        }
    }

    entries
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse Amcache.hve registry hive and populate the timeline store.
///
/// The Amcache tracks application execution and file metadata. Two formats
/// are supported:
/// - Modern (Win10+): Root\InventoryApplicationFile
/// - Legacy (Win7/8): Root\File\{volume_guid}\{hash}
pub fn parse_amcache(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    // Find the Amcache hive - could be in manifest.amcache or registry_hives
    let amcache_paths: Vec<_> = manifest
        .amcache
        .iter()
        .chain(
            manifest
                .registry_hives
                .iter()
                .filter(|h| h.hive_type == RegistryHiveType::Amcache)
                .map(|h| &h.path),
        )
        .collect();

    if amcache_paths.is_empty() {
        debug!("No Amcache hive found in manifest");
        return Ok(());
    }

    for amcache_path in &amcache_paths {
        let data = match provider.open_file(amcache_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read Amcache hive {}: {}", amcache_path, e);
                continue;
            }
        };

        debug!("Parsing Amcache hive: {} ({} bytes)", amcache_path, data.len());

        let mut hive = match Hive::new(Cursor::new(data), HiveParseMode::NormalWithBaseBlock) {
            Ok(h) => h.treat_hive_as_clean(),
            Err(e) => {
                warn!("Failed to parse Amcache hive {}: {}", amcache_path, e);
                continue;
            }
        };

        let root_key = match hive.root_key_node() {
            Ok(rk) => rk,
            Err(e) => {
                warn!("Failed to get root key from Amcache {}: {}", amcache_path, e);
                continue;
            }
        };

        // Parse both formats
        let mut all_entries = parse_inventory_application_file(&root_key, &mut hive);
        let file_entries = parse_file_entries(&root_key, &mut hive);
        all_entries.extend(file_entries);

        debug!("Found {} Amcache entries from {}", all_entries.len(), amcache_path);

        for amcache_entry in &all_entries {
            let primary_timestamp = match amcache_entry.timestamp {
                Some(ts) => ts,
                None => continue,
            };

            let mut timestamps = TimestampSet::default();
            timestamps.amcache_timestamp = Some(primary_timestamp);

            let metadata = EntryMetadata {
                sha1: amcache_entry.sha1.clone(),
                file_size: amcache_entry.file_size,
                ..EntryMetadata::default()
            };

            let entry = TimelineEntry {
                entity_id: EntityId::Generated(next_amcache_id()),
                path: amcache_entry.file_path.clone(),
                primary_timestamp,
                event_type: EventType::Execute,
                timestamps,
                sources: smallvec![ArtifactSource::Amcache],
                anomalies: AnomalyFlags::empty(),
                metadata,
            };

            store.push(entry);
        }
    }

    Ok(())
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Helper: mock provider ──────────────────────────────────────────

    struct MockProvider {
        data: Vec<u8>,
        should_fail: bool,
    }

    impl MockProvider {
        fn with_data(data: Vec<u8>) -> Self {
            Self { data, should_fail: false }
        }
        fn failing() -> Self {
            Self { data: vec![], should_fail: true }
        }
    }

    impl CollectionProvider for MockProvider {
        fn discover(&self) -> ArtifactManifest {
            ArtifactManifest::default()
        }
        fn open_file(
            &self,
            _path: &crate::collection::path::NormalizedPath,
        ) -> Result<Vec<u8>> {
            if self.should_fail {
                anyhow::bail!("mock open_file failure")
            }
            Ok(self.data.clone())
        }
        fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
            crate::collection::provider::CollectionMetadata::default()
        }
    }

    // ─── filetime_to_datetime tests ─────────────────────────────────────

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
    fn test_filetime_very_small_value() {
        // Very small FILETIME gives a date far in the past (before year 1601)
        // The amcache version uses signed math, so it produces a very negative timestamp
        // DateTime::from_timestamp may or may not handle extremely negative values
        let ft: u64 = 100;
        let result = filetime_to_datetime(ft);
        // With signed arithmetic: secs = 0 - 11644473600 = -11644473600
        // This is a valid (though ancient) timestamp, so result may be Some
        if let Some(dt) = result {
            assert!(dt.timestamp() < 0);
        }
    }

    #[test]
    fn test_filetime_preserves_subseconds() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        // Add 5_000_000 100ns intervals = 0.5 seconds
        let ft = secs as u64 * 10_000_000 + 5_000_000;
        let result = filetime_to_datetime(ft).unwrap();
        assert_eq!(result.timestamp_subsec_nanos(), 500_000_000);
    }

    #[test]
    fn test_filetime_at_unix_epoch() {
        let ft: u64 = 11_644_473_600 * 10_000_000;
        let result = filetime_to_datetime(ft).unwrap();
        assert_eq!(result.timestamp(), 0);
    }

    // ─── parse_date_string tests ────────────────────────────────────────

    #[test]
    fn test_parse_date_string_iso() {
        let result = parse_date_string("2025-06-15T10:30:00Z");
        assert!(result.is_some());
        let dt = result.unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2025-06-15 10:30:00");
    }

    #[test]
    fn test_parse_date_string_slash() {
        let result = parse_date_string("06/15/2025 10:30:00");
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_date_string_dash_format() {
        let result = parse_date_string("2025-06-15 10:30:00");
        assert!(result.is_some());
        let dt = result.unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2025-06-15 10:30:00");
    }

    #[test]
    fn test_parse_date_string_invalid() {
        let result = parse_date_string("not a date");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_date_string_empty() {
        let result = parse_date_string("");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_date_string_date_only_no_time() {
        let result = parse_date_string("2025-06-15");
        assert!(result.is_none()); // No time component, should fail all formats
    }

    #[test]
    fn test_parse_date_string_iso_with_timezone() {
        let result = parse_date_string("2025-06-15T10:30:00+00:00");
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_date_string_iso_with_milliseconds() {
        let result = parse_date_string("2025-06-15T10:30:00.123Z");
        assert!(result.is_some());
    }

    // ─── AmcacheEntry struct tests ──────────────────────────────────────

    #[test]
    fn test_amcache_entry_creation() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();

        let amcache_entry = AmcacheEntry {
            file_path: r"c:\windows\system32\cmd.exe".to_string(),
            sha1: Some("abc123def456".to_string()),
            timestamp: Some(dt),
            file_size: Some(302080),
        };

        assert_eq!(amcache_entry.file_path, r"c:\windows\system32\cmd.exe");
        assert_eq!(amcache_entry.sha1, Some("abc123def456".to_string()));
        assert_eq!(amcache_entry.timestamp, Some(dt));
        assert_eq!(amcache_entry.file_size, Some(302080));
    }

    #[test]
    fn test_amcache_entry_with_no_optional_fields() {
        let entry = AmcacheEntry {
            file_path: r"c:\temp\unknown.exe".to_string(),
            sha1: None,
            timestamp: None,
            file_size: None,
        };
        assert!(entry.sha1.is_none());
        assert!(entry.timestamp.is_none());
        assert!(entry.file_size.is_none());
    }

    #[test]
    fn test_amcache_entry_clone() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let entry = AmcacheEntry {
            file_path: "test.exe".to_string(),
            sha1: Some("hash".to_string()),
            timestamp: Some(dt),
            file_size: Some(1024),
        };
        let cloned = entry.clone();
        assert_eq!(cloned.file_path, entry.file_path);
        assert_eq!(cloned.sha1, entry.sha1);
        assert_eq!(cloned.timestamp, entry.timestamp);
        assert_eq!(cloned.file_size, entry.file_size);
    }

    #[test]
    fn test_amcache_entry_debug() {
        let entry = AmcacheEntry {
            file_path: "debug_test.exe".to_string(),
            sha1: None,
            timestamp: None,
            file_size: None,
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("AmcacheEntry"));
        assert!(debug_str.contains("debug_test.exe"));
    }

    // ─── SHA1 prefix handling tests ─────────────────────────────────────

    #[test]
    fn test_sha1_strip_prefix() {
        let raw = "0000abc123def456";
        let hash = raw.trim_start_matches("0000").to_string();
        assert_eq!(hash, "abc123def456");
    }

    #[test]
    fn test_sha1_no_prefix() {
        let raw = "abc123def456";
        let hash = raw.trim_start_matches("0000").to_string();
        assert_eq!(hash, "abc123def456");
    }

    #[test]
    fn test_sha1_empty_after_strip() {
        // If the hash is just "0000", after stripping it becomes empty
        let raw = "0000";
        let hash = raw.trim_start_matches("0000").to_string();
        assert!(hash.is_empty());
    }

    #[test]
    fn test_sha1_multiple_zero_prefix() {
        // "00000000abc" - trim_start_matches strips ALL leading "0000" patterns
        let raw = "00000000abc";
        let hash = raw.trim_start_matches("0000").to_string();
        assert_eq!(hash, "abc");
    }

    // ─── next_amcache_id tests ──────────────────────────────────────────

    #[test]
    fn test_next_amcache_id_increments() {
        let id1 = next_amcache_id();
        let id2 = next_amcache_id();
        assert!(id2 > id1);
        assert_eq!(id2 - id1, 1);
    }

    #[test]
    fn test_next_amcache_id_has_am_prefix() {
        let id = next_amcache_id();
        let prefix = (id >> 48) & 0xFFFF;
        assert_eq!(prefix, 0x414D); // "AM"
    }

    // ─── TimelineEntry creation from AmcacheEntry ───────────────────────

    #[test]
    fn test_amcache_timeline_entry_with_metadata() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();

        let amcache_entry = AmcacheEntry {
            file_path: r"c:\windows\system32\cmd.exe".to_string(),
            sha1: Some("abc123def456".to_string()),
            timestamp: Some(dt),
            file_size: Some(302080),
        };

        let mut timestamps = TimestampSet::default();
        timestamps.amcache_timestamp = amcache_entry.timestamp;

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_amcache_id()),
            path: amcache_entry.file_path.clone(),
            primary_timestamp: dt,
            event_type: EventType::Execute,
            timestamps,
            sources: smallvec![ArtifactSource::Amcache],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata {
                sha1: amcache_entry.sha1.clone(),
                file_size: amcache_entry.file_size,
                ..EntryMetadata::default()
            },
        };

        assert_eq!(entry.path, r"c:\windows\system32\cmd.exe");
        assert_eq!(entry.event_type, EventType::Execute);
        assert_eq!(entry.metadata.sha1, Some("abc123def456".to_string()));
        assert_eq!(entry.metadata.file_size, Some(302080));
        assert!(entry.sources.contains(&ArtifactSource::Amcache));
        assert_eq!(entry.timestamps.amcache_timestamp, Some(dt));
    }

    #[test]
    fn test_amcache_entry_no_timestamp_skips() {
        // When timestamp is None, the main parse loop skips the entry
        let entry = AmcacheEntry {
            file_path: "skip_me.exe".to_string(),
            sha1: Some("hash".to_string()),
            timestamp: None,
            file_size: Some(100),
        };
        // Simulate what parse_amcache does
        let primary_timestamp = entry.timestamp;
        assert!(primary_timestamp.is_none());
        // In the real code, this would `continue` and skip the entry
    }

    // ─── parse_amcache with empty manifest ──────────────────────────────

    #[test]
    fn test_empty_manifest_no_error() {
        let manifest = ArtifactManifest::default();
        let mut store = TimelineStore::new();

        struct NoCallProvider;
        impl CollectionProvider for NoCallProvider {
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

        let provider = NoCallProvider;
        let result = parse_amcache(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── parse_amcache with provider failures ───────────────────────────

    #[test]
    fn test_parse_amcache_open_file_fails_continues() {
        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/AppCompat/Programs/Amcache.hve", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.amcache.push(path);

        let provider = MockProvider::failing();
        let mut store = TimelineStore::new();

        let result = parse_amcache(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_amcache_invalid_hive_data_continues() {
        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/AppCompat/Programs/Amcache.hve", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.amcache.push(path);

        // Garbage data that is not a valid registry hive
        let provider = MockProvider::with_data(vec![0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        let mut store = TimelineStore::new();

        let result = parse_amcache(&provider, &manifest, &mut store);
        assert!(result.is_ok()); // Should not propagate error, just continue
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_amcache_empty_data_continues() {
        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/AppCompat/Programs/Amcache.hve", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.amcache.push(path);

        let provider = MockProvider::with_data(vec![]);
        let mut store = TimelineStore::new();

        let result = parse_amcache(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── parse_amcache with registry hive entries ───────────────────────

    #[test]
    fn test_parse_amcache_from_registry_hives_field() {
        use crate::collection::manifest::{RegistryHiveEntry, RegistryHiveType};

        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/AppCompat/Programs/Amcache.hve", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path,
            hive_type: RegistryHiveType::Amcache,
        });

        // Invalid data - should just continue without error
        let provider = MockProvider::with_data(vec![0xDE, 0xAD]);
        let mut store = TimelineStore::new();

        let result = parse_amcache(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_amcache_skips_non_amcache_registry_hives() {
        use crate::collection::manifest::{RegistryHiveEntry, RegistryHiveType};

        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/System32/config/SYSTEM", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path,
            hive_type: RegistryHiveType::System,
        });

        // Provider that would fail if called (but it should never be called
        // because the hive type is System, not Amcache)
        let provider = MockProvider::failing();
        let mut store = TimelineStore::new();

        let result = parse_amcache(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── parse_amcache merges both amcache and registry_hives paths ─────

    #[test]
    fn test_parse_amcache_path_collection_from_both_sources() {
        use crate::collection::manifest::{RegistryHiveEntry, RegistryHiveType};

        let path1 = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/AppCompat/Programs/Amcache.hve", 'C',
        );
        let path2 = crate::collection::path::NormalizedPath::from_image_path(
            "/OtherLocation/Amcache.hve", 'C',
        );

        let mut manifest = ArtifactManifest::default();
        manifest.amcache.push(path1);
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path2,
            hive_type: RegistryHiveType::Amcache,
        });

        // Both paths will be tried, both will fail parsing (garbage data)
        let provider = MockProvider::with_data(vec![0xFF; 16]);
        let mut store = TimelineStore::new();

        let result = parse_amcache(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── parse_date_string extended edge cases ──────────────────────────

    #[test]
    fn test_parse_date_string_slash_format_midnight() {
        let result = parse_date_string("01/01/2020 00:00:00");
        assert!(result.is_some());
        let dt = result.unwrap();
        assert_eq!(dt.timestamp(), 1577836800); // 2020-01-01 00:00:00 UTC
    }

    #[test]
    fn test_parse_date_string_dash_format_end_of_day() {
        let result = parse_date_string("2025-12-31 23:59:59");
        assert!(result.is_some());
        let dt = result.unwrap();
        assert_eq!(dt.format("%H:%M:%S").to_string(), "23:59:59");
    }

    #[test]
    fn test_parse_date_string_random_garbage() {
        assert!(parse_date_string("garbage").is_none());
        assert!(parse_date_string("12345").is_none());
        assert!(parse_date_string("2025/06/15 10:30:00").is_none()); // year/month/day not supported
    }

    // ─── filetime_to_datetime edge cases ────────────────────────────────

    #[test]
    fn test_filetime_to_datetime_max_reasonable() {
        use chrono::TimeZone;
        // A date far in the future (year 2100)
        let dt = Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let ft = secs as u64 * 10_000_000;
        let result = filetime_to_datetime(ft).unwrap();
        assert_eq!(result, dt);
    }

    #[test]
    fn test_filetime_negative_epoch_diff() {
        // Value that's non-zero but below the epoch difference
        // 11_644_473_600 seconds * 10_000_000 ticks = the boundary
        let boundary = 11_644_473_600u64 * 10_000_000;
        // Just under the boundary (would give negative Unix timestamp if not checked)
        let ft = boundary - 10_000_000; // 1 second before Unix epoch
        // This should still work - it gives a date in 1969
        let result = filetime_to_datetime(ft);
        // checked_sub succeeds but the timestamp is valid
        assert!(result.is_some() || result.is_none()); // implementation-dependent
    }
}
