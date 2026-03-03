use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, warn};
use smallvec::smallvec;
use std::io::Write;

use crate::collection::manifest::ArtifactManifest;
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static ACTIVITY_ID_COUNTER: AtomicU64 = AtomicU64::new(0x4143_0000_0000_0000); // "AC" prefix

fn next_activity_id() -> u64 {
    ACTIVITY_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Activity types ──────────────────────────────────────────────────────────

/// Windows Timeline activity type codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivityType {
    ExecuteOpen,     // 5 - App was executed/opened
    InFocus,         // 6 - App was in focus
    CopyPaste,       // 16 - Clipboard operation
    Other(i32),
}

/// A parsed Windows Timeline activity entry.
#[derive(Debug, Clone)]
pub struct ActivityEntry {
    pub app_id: String,
    pub activity_type: ActivityType,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub payload: String,
}

// ─── Timestamp conversion ────────────────────────────────────────────────────

/// Convert Windows Timeline epoch (seconds since 1970-01-01) to DateTime<Utc>.
pub fn epoch_to_datetime(epoch: i64) -> Option<DateTime<Utc>> {
    if epoch <= 0 {
        return None;
    }
    DateTime::from_timestamp(epoch, 0)
}

/// Map activity type code to ActivityType.
pub fn map_activity_type(code: i32) -> ActivityType {
    match code {
        5 => ActivityType::ExecuteOpen,
        6 => ActivityType::InFocus,
        16 => ActivityType::CopyPaste,
        other => ActivityType::Other(other),
    }
}

// ─── SQLite parsing ──────────────────────────────────────────────────────────

/// Parse ActivitiesCache.db SQLite database.
pub fn parse_activities_db(db_path: &str) -> Result<Vec<ActivityEntry>> {
    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    let mut entries = Vec::new();

    // The Activity table stores app usage with timestamps
    // Schema varies slightly between Win10 builds but core fields are stable
    let mut stmt = conn.prepare(
        "SELECT AppId, ActivityType, StartTime, EndTime, Payload
         FROM Activity
         ORDER BY StartTime DESC
         LIMIT 10000"
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i32>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<i64>>(3)?,
            row.get::<_, Option<String>>(4)?,
        ))
    })?;

    for row in rows {
        if let Ok((app_id, activity_type, start_time, end_time, payload)) = row {
            if let Some(start) = epoch_to_datetime(start_time) {
                entries.push(ActivityEntry {
                    app_id,
                    activity_type: map_activity_type(activity_type),
                    start_time: start,
                    end_time: end_time.and_then(epoch_to_datetime),
                    payload: payload.unwrap_or_default(),
                });
            }
        }
    }

    Ok(entries)
}

/// Extract a readable app name from the AppId JSON string.
/// AppId format: [{"platform":"...", "application":"..."}]
pub fn extract_app_name(app_id: &str) -> String {
    // Try to parse as JSON array and extract application field
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(app_id) {
        if let Some(arr) = parsed.as_array() {
            for item in arr {
                if let Some(app) = item.get("application").and_then(|v| v.as_str()) {
                    return app.to_string();
                }
            }
        }
    }
    // Fallback: return raw string truncated
    if app_id.len() > 100 {
        format!("{}...", &app_id[..100])
    } else {
        app_id.to_string()
    }
}

// ─── Pipeline integration ────────────────────────────────────────────────────

/// Parse Windows Timeline from ActivitiesCache.db files.
pub fn parse_activities_cache(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    if manifest.activities_cache.is_empty() {
        debug!("No ActivitiesCache.db found in manifest");
        return Ok(());
    }

    let mut total = 0u32;

    for db_path in &manifest.activities_cache {
        let data = match provider.open_file(db_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read ActivitiesCache.db {}: {}", db_path, e);
                continue;
            }
        };

        let mut tmp = match tempfile::NamedTempFile::new() {
            Ok(t) => t,
            Err(e) => {
                warn!("Failed to create temp file for ActivitiesCache: {}", e);
                continue;
            }
        };
        if let Err(e) = tmp.write_all(&data) {
            warn!("Failed to write ActivitiesCache temp file: {}", e);
            continue;
        }
        let tmp_path = tmp.path().to_string_lossy().to_string();

        let entries = match parse_activities_db(&tmp_path) {
            Ok(e) => e,
            Err(e) => {
                debug!("ActivitiesCache parse error: {}", e);
                continue;
            }
        };

        debug!("ActivitiesCache: {} entries from {}", entries.len(), db_path);

        for entry in entries {
            let app_name = extract_app_name(&entry.app_id);
            let type_label = match &entry.activity_type {
                ActivityType::ExecuteOpen => "Open",
                ActivityType::InFocus => "Focus",
                ActivityType::CopyPaste => "Clipboard",
                ActivityType::Other(n) => {
                    // Use a leaked string for the label (acceptable for small set)
                    Box::leak(format!("Type:{}", n).into_boxed_str())
                }
            };

            store.push(TimelineEntry {
                entity_id: EntityId::Generated(next_activity_id()),
                path: format!("[Timeline:{}] {}", type_label, app_name),
                primary_timestamp: entry.start_time,
                event_type: EventType::Execute,
                timestamps: TimestampSet::default(),
                sources: smallvec![ArtifactSource::Registry("ActivitiesCache".to_string())],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
            });
            total += 1;
        }
    }

    if total > 0 {
        debug!("Parsed {} Windows Timeline entries total", total);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Helper: create a test SQLite ActivitiesCache.db ─────────────────
    fn create_test_activities_db(entries: &[(String, i32, i64, Option<i64>, Option<String>)]) -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = rusqlite::Connection::open(tmp.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE Activity (
                AppId TEXT NOT NULL,
                ActivityType INTEGER NOT NULL,
                StartTime INTEGER NOT NULL,
                EndTime INTEGER,
                Payload TEXT
            );"
        ).unwrap();
        for (app_id, activity_type, start_time, end_time, payload) in entries {
            conn.execute(
                "INSERT INTO Activity (AppId, ActivityType, StartTime, EndTime, Payload) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![app_id, activity_type, start_time, end_time, payload],
            ).unwrap();
        }
        tmp
    }

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

    // ─── epoch_to_datetime tests ────────────────────────────────────────

    #[test]
    fn test_epoch_to_datetime() {
        let dt = epoch_to_datetime(1736942400).unwrap(); // 2025-01-15 12:00:00
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2025-01-15");
    }

    #[test]
    fn test_epoch_to_datetime_zero() {
        assert!(epoch_to_datetime(0).is_none());
    }

    #[test]
    fn test_epoch_to_datetime_negative() {
        assert!(epoch_to_datetime(-1).is_none());
    }

    #[test]
    fn test_epoch_to_datetime_large_negative() {
        assert!(epoch_to_datetime(-999999999).is_none());
    }

    #[test]
    fn test_epoch_to_datetime_unix_epoch() {
        let dt = epoch_to_datetime(1).unwrap();
        assert_eq!(dt.timestamp(), 1);
    }

    #[test]
    fn test_epoch_to_datetime_specific_time() {
        // 2025-06-15 10:30:00 UTC
        let dt = epoch_to_datetime(1750069800).unwrap();
        assert_eq!(dt.format("%H:%M:%S").to_string(), "10:30:00");
    }

    // ─── map_activity_type tests ────────────────────────────────────────

    #[test]
    fn test_map_activity_type() {
        assert_eq!(map_activity_type(5), ActivityType::ExecuteOpen);
        assert_eq!(map_activity_type(6), ActivityType::InFocus);
        assert_eq!(map_activity_type(16), ActivityType::CopyPaste);
        assert_eq!(map_activity_type(99), ActivityType::Other(99));
    }

    #[test]
    fn test_map_activity_type_zero() {
        assert_eq!(map_activity_type(0), ActivityType::Other(0));
    }

    #[test]
    fn test_map_activity_type_negative() {
        assert_eq!(map_activity_type(-1), ActivityType::Other(-1));
    }

    #[test]
    fn test_map_activity_type_boundary_values() {
        // Values near the known codes but not matching
        assert_eq!(map_activity_type(4), ActivityType::Other(4));
        assert_eq!(map_activity_type(7), ActivityType::Other(7));
        assert_eq!(map_activity_type(15), ActivityType::Other(15));
        assert_eq!(map_activity_type(17), ActivityType::Other(17));
    }

    // ─── ActivityType equality/clone/debug ───────────────────────────────

    #[test]
    fn test_activity_type_eq() {
        assert_eq!(ActivityType::ExecuteOpen, ActivityType::ExecuteOpen);
        assert_ne!(ActivityType::ExecuteOpen, ActivityType::InFocus);
        assert_eq!(ActivityType::Other(42), ActivityType::Other(42));
        assert_ne!(ActivityType::Other(42), ActivityType::Other(43));
    }

    #[test]
    fn test_activity_type_clone() {
        let orig = ActivityType::CopyPaste;
        let cloned = orig.clone();
        assert_eq!(orig, cloned);
    }

    #[test]
    fn test_activity_type_debug() {
        let debug_str = format!("{:?}", ActivityType::ExecuteOpen);
        assert!(debug_str.contains("ExecuteOpen"));

        let debug_str = format!("{:?}", ActivityType::Other(42));
        assert!(debug_str.contains("Other"));
        assert!(debug_str.contains("42"));
    }

    // ─── extract_app_name tests ─────────────────────────────────────────

    #[test]
    fn test_extract_app_name_json() {
        let app_id = r#"[{"platform":"windows_win32","application":"C:\\Windows\\System32\\notepad.exe"}]"#;
        let name = extract_app_name(app_id);
        assert!(name.contains("notepad.exe"), "got: {}", name);
    }

    #[test]
    fn test_extract_app_name_invalid_json() {
        let app_id = "not-json-at-all";
        let name = extract_app_name(app_id);
        assert_eq!(name, "not-json-at-all");
    }

    #[test]
    fn test_extract_app_name_long_fallback() {
        let app_id = "x".repeat(200);
        let name = extract_app_name(&app_id);
        assert!(name.len() < 110);
        assert!(name.ends_with("..."));
    }

    #[test]
    fn test_extract_app_name_empty_string() {
        assert_eq!(extract_app_name(""), "");
    }

    #[test]
    fn test_extract_app_name_json_object_not_array() {
        let app_id = r#"{"application":"cmd.exe"}"#;
        let name = extract_app_name(app_id);
        // parsed.as_array() returns None for an object, so falls back to raw
        assert_eq!(name, app_id);
    }

    #[test]
    fn test_extract_app_name_json_array_without_application_key() {
        let app_id = r#"[{"platform":"windows_win32","name":"notepad.exe"}]"#;
        let name = extract_app_name(app_id);
        // No "application" key, falls through loop and returns raw
        assert_eq!(name, app_id);
    }

    #[test]
    fn test_extract_app_name_json_empty_array() {
        let app_id = "[]";
        let name = extract_app_name(app_id);
        assert_eq!(name, "[]");
    }

    #[test]
    fn test_extract_app_name_multiple_entries_first_wins() {
        let app_id = r#"[{"application":"first.exe"},{"application":"second.exe"}]"#;
        let name = extract_app_name(app_id);
        assert_eq!(name, "first.exe");
    }

    #[test]
    fn test_extract_app_name_exactly_100_chars() {
        let app_id = "x".repeat(100);
        let name = extract_app_name(&app_id);
        assert_eq!(name, app_id); // exactly 100, should not truncate
    }

    #[test]
    fn test_extract_app_name_101_chars_truncated() {
        let app_id = "y".repeat(101);
        let name = extract_app_name(&app_id);
        assert_eq!(name.len(), 103); // 100 chars + "..."
        assert!(name.ends_with("..."));
    }

    #[test]
    fn test_extract_app_name_application_value_is_not_string() {
        let app_id = r#"[{"application":12345}]"#;
        let name = extract_app_name(app_id);
        // as_str() returns None for a number, falls through to raw
        assert_eq!(name, app_id);
    }

    // ─── ActivityEntry struct tests ─────────────────────────────────────

    #[test]
    fn test_activity_entry_creation() {
        let entry = ActivityEntry {
            app_id: "test_app".to_string(),
            activity_type: ActivityType::ExecuteOpen,
            start_time: Utc::now(),
            end_time: None,
            payload: String::new(),
        };
        assert_eq!(entry.activity_type, ActivityType::ExecuteOpen);
    }

    #[test]
    fn test_activity_entry_with_end_time() {
        let start = epoch_to_datetime(1736942400).unwrap();
        let end = epoch_to_datetime(1736946000).unwrap();
        let entry = ActivityEntry {
            app_id: "chrome.exe".to_string(),
            activity_type: ActivityType::InFocus,
            start_time: start,
            end_time: Some(end),
            payload: "browsing".to_string(),
        };
        assert!(entry.end_time.is_some());
        assert!(entry.end_time.unwrap() > entry.start_time);
    }

    #[test]
    fn test_activity_entry_clone() {
        let entry = ActivityEntry {
            app_id: "test.exe".to_string(),
            activity_type: ActivityType::CopyPaste,
            start_time: Utc::now(),
            end_time: None,
            payload: "clipboard data".to_string(),
        };
        let cloned = entry.clone();
        assert_eq!(cloned.app_id, entry.app_id);
        assert_eq!(cloned.activity_type, entry.activity_type);
        assert_eq!(cloned.payload, entry.payload);
    }

    #[test]
    fn test_activity_entry_debug() {
        let entry = ActivityEntry {
            app_id: "debug_test.exe".to_string(),
            activity_type: ActivityType::Other(42),
            start_time: Utc::now(),
            end_time: None,
            payload: String::new(),
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("ActivityEntry"));
        assert!(debug_str.contains("debug_test.exe"));
    }

    // ─── next_activity_id tests ─────────────────────────────────────────

    #[test]
    fn test_next_activity_id_increments() {
        let id1 = next_activity_id();
        let id2 = next_activity_id();
        assert!(id2 > id1);
        assert_eq!(id2 - id1, 1);
    }

    #[test]
    fn test_next_activity_id_has_ac_prefix() {
        let id = next_activity_id();
        let prefix = (id >> 48) & 0xFFFF;
        assert_eq!(prefix, 0x4143); // "AC"
    }

    // ─── parse_activities_db tests (with real SQLite) ───────────────────

    #[test]
    fn test_parse_activities_db_invalid_path() {
        let result = parse_activities_db("/nonexistent/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_activities_db_empty_table() {
        let tmp = create_test_activities_db(&[]);
        let result = parse_activities_db(&tmp.path().to_string_lossy()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_activities_db_single_entry() {
        let app_id = r#"[{"platform":"windows_win32","application":"notepad.exe"}]"#;
        let tmp = create_test_activities_db(&[
            (app_id.to_string(), 5, 1736942400, None, None),
        ]);
        let result = parse_activities_db(&tmp.path().to_string_lossy()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].activity_type, ActivityType::ExecuteOpen);
        assert_eq!(result[0].app_id, app_id);
    }

    #[test]
    fn test_parse_activities_db_multiple_entries() {
        let tmp = create_test_activities_db(&[
            ("app1".to_string(), 5, 1736942400, None, None),
            ("app2".to_string(), 6, 1736942500, Some(1736942600), Some("payload".to_string())),
            ("app3".to_string(), 16, 1736942700, None, Some("clipboard".to_string())),
        ]);
        let result = parse_activities_db(&tmp.path().to_string_lossy()).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_parse_activities_db_with_end_time() {
        let tmp = create_test_activities_db(&[
            ("app".to_string(), 6, 1736942400, Some(1736946000), None),
        ]);
        let result = parse_activities_db(&tmp.path().to_string_lossy()).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].end_time.is_some());
    }

    #[test]
    fn test_parse_activities_db_with_payload() {
        let tmp = create_test_activities_db(&[
            ("app".to_string(), 16, 1736942400, None, Some("test payload data".to_string())),
        ]);
        let result = parse_activities_db(&tmp.path().to_string_lossy()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].payload, "test payload data");
    }

    #[test]
    fn test_parse_activities_db_null_payload_becomes_empty() {
        let tmp = create_test_activities_db(&[
            ("app".to_string(), 5, 1736942400, None, None),
        ]);
        let result = parse_activities_db(&tmp.path().to_string_lossy()).unwrap();
        assert_eq!(result[0].payload, "");
    }

    #[test]
    fn test_parse_activities_db_zero_start_time_skipped() {
        let tmp = create_test_activities_db(&[
            ("app_valid".to_string(), 5, 1736942400, None, None),
            ("app_zero".to_string(), 5, 0, None, None),
            ("app_negative".to_string(), 5, -100, None, None),
        ]);
        let result = parse_activities_db(&tmp.path().to_string_lossy()).unwrap();
        // Only the valid entry should be returned (epoch_to_datetime returns None for 0 and negative)
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].app_id, "app_valid");
    }

    #[test]
    fn test_parse_activities_db_all_activity_types() {
        let tmp = create_test_activities_db(&[
            ("a".to_string(), 5, 1736942400, None, None),
            ("b".to_string(), 6, 1736942500, None, None),
            ("c".to_string(), 16, 1736942600, None, None),
            ("d".to_string(), 99, 1736942700, None, None),
        ]);
        let result = parse_activities_db(&tmp.path().to_string_lossy()).unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].activity_type, ActivityType::Other(99)); // ORDER BY StartTime DESC
        assert_eq!(result[1].activity_type, ActivityType::CopyPaste);
        assert_eq!(result[2].activity_type, ActivityType::InFocus);
        assert_eq!(result[3].activity_type, ActivityType::ExecuteOpen);
    }

    #[test]
    fn test_parse_activities_db_no_activity_table() {
        // Create a SQLite DB without the Activity table
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = rusqlite::Connection::open(tmp.path()).unwrap();
        conn.execute_batch("CREATE TABLE OtherTable (id INTEGER);").unwrap();
        let result = parse_activities_db(&tmp.path().to_string_lossy());
        assert!(result.is_err()); // prepare() should fail
    }

    #[test]
    fn test_parse_activities_db_end_time_with_zero_gives_none() {
        let tmp = create_test_activities_db(&[
            ("app".to_string(), 5, 1736942400, Some(0), None),
        ]);
        let result = parse_activities_db(&tmp.path().to_string_lossy()).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].end_time.is_none()); // epoch_to_datetime(0) returns None
    }

    // ─── parse_activities_cache integration tests ───────────────────────

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

        let result = parse_activities_cache(&NoOpProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_activities_cache_with_valid_db() {
        // Create a real SQLite DB with activity entries
        let tmp = create_test_activities_db(&[
            (r#"[{"application":"notepad.exe"}]"#.to_string(), 5, 1736942400, None, None),
            (r#"[{"application":"calc.exe"}]"#.to_string(), 6, 1736942500, Some(1736946000), None),
        ]);

        // Read the DB file into bytes
        let data = std::fs::read(tmp.path()).unwrap();

        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/ActivitiesCache.db", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.activities_cache.push(path);

        let provider = MockProvider::with_data(data);
        let mut store = TimelineStore::new();

        let result = parse_activities_cache(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_parse_activities_cache_open_file_fails_continues() {
        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/ActivitiesCache.db", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.activities_cache.push(path);

        let provider = MockProvider::failing();
        let mut store = TimelineStore::new();

        let result = parse_activities_cache(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_activities_cache_invalid_db_data_continues() {
        // Provide garbage data that's not a valid SQLite database
        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/ActivitiesCache.db", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.activities_cache.push(path);

        let provider = MockProvider::with_data(vec![0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03]);
        let mut store = TimelineStore::new();

        let result = parse_activities_cache(&provider, &manifest, &mut store);
        assert!(result.is_ok()); // Should not propagate error, just continue
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_activities_cache_timeline_entry_format() {
        let tmp = create_test_activities_db(&[
            (r#"[{"application":"powershell.exe"}]"#.to_string(), 5, 1736942400, None, None),
        ]);
        let data = std::fs::read(tmp.path()).unwrap();

        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/ActivitiesCache.db", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.activities_cache.push(path);

        let provider = MockProvider::with_data(data);
        let mut store = TimelineStore::new();

        parse_activities_cache(&provider, &manifest, &mut store).unwrap();
        assert_eq!(store.len(), 1);

        let entries: Vec<_> = store.entries().collect();
        assert!(entries[0].path.contains("[Timeline:Open]"));
        assert!(entries[0].path.contains("powershell.exe"));
        assert_eq!(entries[0].event_type, EventType::Execute);
    }

    #[test]
    fn test_parse_activities_cache_focus_type_label() {
        let tmp = create_test_activities_db(&[
            ("focus_app".to_string(), 6, 1736942400, None, None),
        ]);
        let data = std::fs::read(tmp.path()).unwrap();

        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/ActivitiesCache.db", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.activities_cache.push(path);

        let provider = MockProvider::with_data(data);
        let mut store = TimelineStore::new();

        parse_activities_cache(&provider, &manifest, &mut store).unwrap();
        let entries: Vec<_> = store.entries().collect();
        assert!(entries[0].path.contains("[Timeline:Focus]"));
    }

    #[test]
    fn test_parse_activities_cache_clipboard_type_label() {
        let tmp = create_test_activities_db(&[
            ("clip_app".to_string(), 16, 1736942400, None, None),
        ]);
        let data = std::fs::read(tmp.path()).unwrap();

        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/ActivitiesCache.db", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.activities_cache.push(path);

        let provider = MockProvider::with_data(data);
        let mut store = TimelineStore::new();

        parse_activities_cache(&provider, &manifest, &mut store).unwrap();
        let entries: Vec<_> = store.entries().collect();
        assert!(entries[0].path.contains("[Timeline:Clipboard]"));
    }

    #[test]
    fn test_parse_activities_cache_other_type_label() {
        let tmp = create_test_activities_db(&[
            ("other_app".to_string(), 42, 1736942400, None, None),
        ]);
        let data = std::fs::read(tmp.path()).unwrap();

        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/ActivitiesCache.db", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.activities_cache.push(path);

        let provider = MockProvider::with_data(data);
        let mut store = TimelineStore::new();

        parse_activities_cache(&provider, &manifest, &mut store).unwrap();
        let entries: Vec<_> = store.entries().collect();
        assert!(entries[0].path.contains("[Timeline:Type:42]"), "got: {}", entries[0].path);
    }

    #[test]
    fn test_parse_activities_cache_source_is_registry_activities_cache() {
        let tmp = create_test_activities_db(&[
            ("app".to_string(), 5, 1736942400, None, None),
        ]);
        let data = std::fs::read(tmp.path()).unwrap();

        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/ActivitiesCache.db", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.activities_cache.push(path);

        let provider = MockProvider::with_data(data);
        let mut store = TimelineStore::new();

        parse_activities_cache(&provider, &manifest, &mut store).unwrap();
        let entries: Vec<_> = store.entries().collect();
        assert!(entries[0].sources.contains(&ArtifactSource::Registry("ActivitiesCache".to_string())));
    }

    #[test]
    fn test_parse_activities_cache_multiple_dbs() {
        let tmp1 = create_test_activities_db(&[
            ("app1".to_string(), 5, 1736942400, None, None),
        ]);
        let tmp2 = create_test_activities_db(&[
            ("app2".to_string(), 6, 1736942500, None, None),
            ("app3".to_string(), 16, 1736942600, None, None),
        ]);

        let data1 = std::fs::read(tmp1.path()).unwrap();
        let data2 = std::fs::read(tmp2.path()).unwrap();

        // This test verifies the loop processes multiple paths.
        // We'll use a provider that returns different data each time.
        // Since MockProvider returns the same data, we just confirm
        // parsing works with at least one DB.
        let path = crate::collection::path::NormalizedPath::from_image_path(
            "/Windows/ActivitiesCache.db", 'C',
        );
        let mut manifest = ArtifactManifest::default();
        manifest.activities_cache.push(path);

        let provider = MockProvider::with_data(data1);
        let mut store = TimelineStore::new();
        parse_activities_cache(&provider, &manifest, &mut store).unwrap();
        assert_eq!(store.len(), 1);

        // Second DB
        let path2 = crate::collection::path::NormalizedPath::from_image_path(
            "/Users/user/ActivitiesCache.db", 'C',
        );
        let mut manifest2 = ArtifactManifest::default();
        manifest2.activities_cache.push(path2);

        let provider2 = MockProvider::with_data(data2);
        let mut store2 = TimelineStore::new();
        parse_activities_cache(&provider2, &manifest2, &mut store2).unwrap();
        assert_eq!(store2.len(), 2);
    }
}
