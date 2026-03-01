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
    fn test_map_activity_type() {
        assert_eq!(map_activity_type(5), ActivityType::ExecuteOpen);
        assert_eq!(map_activity_type(6), ActivityType::InFocus);
        assert_eq!(map_activity_type(16), ActivityType::CopyPaste);
        assert_eq!(map_activity_type(99), ActivityType::Other(99));
    }

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
    fn test_parse_activities_db_invalid_path() {
        let result = parse_activities_db("/nonexistent/path");
        assert!(result.is_err());
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

        let result = parse_activities_cache(&NoOpProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }
}
