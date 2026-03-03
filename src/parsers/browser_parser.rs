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

static BROWSER_ID_COUNTER: AtomicU64 = AtomicU64::new(0x4252_0000_0000_0000); // "BR" prefix

fn next_browser_id() -> u64 {
    BROWSER_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Browser types ───────────────────────────────────────────────────────────

/// Supported browser types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserType {
    Chrome,
    Edge,
    Firefox,
}

/// A parsed browser history entry.
#[derive(Debug, Clone)]
pub struct BrowserHistoryEntry {
    pub url: String,
    pub title: String,
    pub visit_time: DateTime<Utc>,
    pub visit_count: i64,
    pub browser: BrowserType,
}

// ─── Timestamp conversion ────────────────────────────────────────────────────

/// Convert Chrome/Edge timestamp (microseconds since 1601-01-01) to DateTime<Utc>.
pub fn chrome_time_to_datetime(chrome_time: i64) -> Option<DateTime<Utc>> {
    if chrome_time <= 0 {
        return None;
    }
    // Chrome epoch: 1601-01-01. Offset to Unix epoch: 11644473600 seconds.
    const EPOCH_DIFF_USEC: i64 = 11_644_473_600_000_000;
    let unix_usec = chrome_time - EPOCH_DIFF_USEC;
    if unix_usec < 0 {
        return None;
    }
    let secs = unix_usec / 1_000_000;
    let nanos = ((unix_usec % 1_000_000) * 1000) as u32;
    DateTime::from_timestamp(secs, nanos)
}

/// Convert Firefox timestamp (microseconds since Unix epoch) to DateTime<Utc>.
pub fn firefox_time_to_datetime(moz_time: i64) -> Option<DateTime<Utc>> {
    if moz_time <= 0 {
        return None;
    }
    let secs = moz_time / 1_000_000;
    let nanos = ((moz_time % 1_000_000) * 1000) as u32;
    DateTime::from_timestamp(secs, nanos)
}

/// Detect browser type from file path.
pub fn detect_browser(path: &str) -> BrowserType {
    let lower = path.to_lowercase();
    if lower.contains("firefox") || lower.contains("mozilla") {
        BrowserType::Firefox
    } else if lower.contains("edge") {
        BrowserType::Edge
    } else {
        BrowserType::Chrome // Default for Chromium-based
    }
}

// ─── SQLite parsing ──────────────────────────────────────────────────────────

/// Parse Chrome/Edge SQLite History database.
pub fn parse_chromium_history(db_path: &str) -> Result<Vec<BrowserHistoryEntry>> {
    let browser = detect_browser(db_path);
    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    let mut entries = Vec::new();

    // Chromium stores history in `urls` table with `visits` table for timestamps
    let mut stmt = conn.prepare(
        "SELECT u.url, u.title, v.visit_time, u.visit_count
         FROM urls u
         JOIN visits v ON u.id = v.url
         ORDER BY v.visit_time DESC
         LIMIT 10000"
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;

    for row in rows {
        if let Ok((url, title, visit_time, visit_count)) = row {
            if let Some(dt) = chrome_time_to_datetime(visit_time) {
                entries.push(BrowserHistoryEntry {
                    url,
                    title,
                    visit_time: dt,
                    visit_count,
                    browser: browser.clone(),
                });
            }
        }
    }

    Ok(entries)
}

/// Parse Firefox SQLite places.sqlite database.
pub fn parse_firefox_history(db_path: &str) -> Result<Vec<BrowserHistoryEntry>> {
    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    let mut entries = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT p.url, p.title, h.visit_date, p.visit_count
         FROM moz_places p
         JOIN moz_historyvisits h ON p.id = h.place_id
         ORDER BY h.visit_date DESC
         LIMIT 10000"
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;

    for row in rows {
        if let Ok((url, title, visit_date, visit_count)) = row {
            if let Some(dt) = firefox_time_to_datetime(visit_date) {
                entries.push(BrowserHistoryEntry {
                    url,
                    title: title.unwrap_or_default(),
                    visit_time: dt,
                    visit_count,
                    browser: BrowserType::Firefox,
                });
            }
        }
    }

    Ok(entries)
}

// ─── Pipeline integration ────────────────────────────────────────────────────

/// Parse browser history from all detected browser databases in the collection.
pub fn parse_browser_history(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    if manifest.browser_history.is_empty() {
        debug!("No browser history databases found in manifest");
        return Ok(());
    }

    let mut total = 0u32;

    for hist_path in &manifest.browser_history {
        let data = match provider.open_file(hist_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read browser history {}: {}", hist_path, e);
                continue;
            }
        };

        // Write to temp file since rusqlite needs a file path
        let mut tmp = match tempfile::NamedTempFile::new() {
            Ok(t) => t,
            Err(e) => {
                warn!("Failed to create temp file for browser history: {}", e);
                continue;
            }
        };
        if let Err(e) = tmp.write_all(&data) {
            warn!("Failed to write browser history temp file: {}", e);
            continue;
        }
        let tmp_path = tmp.path().to_string_lossy().to_string();

        let path_str = hist_path.to_string();
        let browser = detect_browser(&path_str);

        let entries = match browser {
            BrowserType::Firefox => match parse_firefox_history(&tmp_path) {
                Ok(e) => e,
                Err(e) => {
                    debug!("Firefox history parse error: {}", e);
                    continue;
                }
            },
            _ => match parse_chromium_history(&tmp_path) {
                Ok(e) => e,
                Err(e) => {
                    debug!("Chromium history parse error: {}", e);
                    continue;
                }
            },
        };

        debug!(
            "Browser history: {} entries from {} ({:?})",
            entries.len(),
            hist_path,
            browser
        );

        for entry in entries {
            let browser_name = match &entry.browser {
                BrowserType::Chrome => "Chrome",
                BrowserType::Edge => "Edge",
                BrowserType::Firefox => "Firefox",
            };
            let title_display = if entry.title.is_empty() {
                String::new()
            } else {
                format!(" \"{}\"", entry.title)
            };

            store.push(TimelineEntry {
                entity_id: EntityId::Generated(next_browser_id()),
                path: format!(
                    "[{}:History]{} {} (visits: {})",
                    browser_name, title_display, entry.url, entry.visit_count
                ),
                primary_timestamp: entry.visit_time,
                event_type: EventType::Other("BrowseURL".to_string()),
                timestamps: TimestampSet::default(),
                sources: smallvec![ArtifactSource::Registry(format!("{}:History", browser_name))],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
            });
            total += 1;
        }
    }

    if total > 0 {
        debug!("Parsed {} browser history entries total", total);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrome_time_to_datetime() {
        // 2025-01-15 12:00:00 UTC in Chrome time
        // Chrome epoch offset: 11644473600 seconds = 11644473600000000 microseconds
        let unix_usec: i64 = 1736942400 * 1_000_000; // 2025-01-15 12:00:00
        let chrome_time = unix_usec + 11_644_473_600_000_000;
        let dt = chrome_time_to_datetime(chrome_time).unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2025-01-15");
    }

    #[test]
    fn test_chrome_time_zero() {
        assert!(chrome_time_to_datetime(0).is_none());
    }

    #[test]
    fn test_chrome_time_negative() {
        assert!(chrome_time_to_datetime(-1).is_none());
    }

    #[test]
    fn test_firefox_time_to_datetime() {
        // 2025-01-15 12:00:00 UTC in Firefox time (microseconds since Unix epoch)
        let moz_time: i64 = 1736942400 * 1_000_000;
        let dt = firefox_time_to_datetime(moz_time).unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2025-01-15");
    }

    #[test]
    fn test_firefox_time_zero() {
        assert!(firefox_time_to_datetime(0).is_none());
    }

    #[test]
    fn test_detect_browser_chrome() {
        let path = r"C:\Users\admin\AppData\Local\Google\Chrome\User Data\Default\History";
        assert_eq!(detect_browser(path), BrowserType::Chrome);
    }

    #[test]
    fn test_detect_browser_edge() {
        let path = r"C:\Users\admin\AppData\Local\Microsoft\Edge\User Data\Default\History";
        assert_eq!(detect_browser(path), BrowserType::Edge);
    }

    #[test]
    fn test_detect_browser_firefox() {
        let path = r"C:\Users\admin\AppData\Roaming\Mozilla\Firefox\Profiles\abc123.default\places.sqlite";
        assert_eq!(detect_browser(path), BrowserType::Firefox);
    }

    #[test]
    fn test_browser_history_entry_creation() {
        let entry = BrowserHistoryEntry {
            url: "https://evil.com/payload".to_string(),
            title: "Totally Legit".to_string(),
            visit_time: Utc::now(),
            visit_count: 3,
            browser: BrowserType::Chrome,
        };
        assert_eq!(entry.url, "https://evil.com/payload");
        assert_eq!(entry.visit_count, 3);
    }

    #[test]
    fn test_parse_chromium_history_invalid_path() {
        let result = parse_chromium_history("/nonexistent/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_firefox_history_invalid_path() {
        let result = parse_firefox_history("/nonexistent/path");
        assert!(result.is_err());
    }

    // ─── next_browser_id tests ──────────────────────────────────────────

    #[test]
    fn test_next_browser_id_increments() {
        let id1 = next_browser_id();
        let id2 = next_browser_id();
        assert!(id2 > id1);
        assert_eq!(id2 - id1, 1);
    }

    #[test]
    fn test_next_browser_id_has_br_prefix() {
        let id = next_browser_id();
        let prefix = (id >> 48) & 0xFFFF;
        assert_eq!(prefix, 0x4252);
    }

    // ─── chrome_time_to_datetime edge cases ─────────────────────────────

    #[test]
    fn test_chrome_time_pre_unix_epoch() {
        // A Chrome time between 1601 and 1970 should return None
        // (because unix_usec would be negative)
        let chrome_time: i64 = 1_000_000; // Only 1 second after Chrome epoch
        assert!(chrome_time_to_datetime(chrome_time).is_none());
    }

    #[test]
    fn test_chrome_time_preserves_microseconds() {
        // Test that sub-second precision is preserved
        let unix_usec: i64 = 1736942400_500_000; // 2025-01-15 12:00:00.5
        let chrome_time = unix_usec + 11_644_473_600_000_000;
        let dt = chrome_time_to_datetime(chrome_time).unwrap();
        // 500,000 microseconds = 500,000,000 nanoseconds
        assert_eq!(dt.timestamp_subsec_micros(), 500_000);
    }

    #[test]
    fn test_chrome_time_at_unix_epoch() {
        // Chrome time at Unix epoch: 11644473600 * 1_000_000
        let chrome_time: i64 = 11_644_473_600_000_000;
        let dt = chrome_time_to_datetime(chrome_time).unwrap();
        assert_eq!(dt.timestamp(), 0);
    }

    #[test]
    fn test_chrome_time_large_value() {
        // A very large but valid Chrome time
        // 2030-01-01 00:00:00 UTC
        let unix_ts: i64 = 1893456000;
        let chrome_time = unix_ts * 1_000_000 + 11_644_473_600_000_000;
        let dt = chrome_time_to_datetime(chrome_time).unwrap();
        assert_eq!(dt.format("%Y").to_string(), "2030");
    }

    // ─── firefox_time_to_datetime edge cases ────────────────────────────

    #[test]
    fn test_firefox_time_negative() {
        assert!(firefox_time_to_datetime(-1).is_none());
    }

    #[test]
    fn test_firefox_time_preserves_microseconds() {
        let moz_time: i64 = 1736942400_250_000; // 0.25 seconds
        let dt = firefox_time_to_datetime(moz_time).unwrap();
        assert_eq!(dt.timestamp_subsec_micros(), 250_000);
    }

    #[test]
    fn test_firefox_time_at_epoch() {
        // 1 microsecond after epoch
        let dt = firefox_time_to_datetime(1).unwrap();
        assert_eq!(dt.timestamp(), 0);
        assert_eq!(dt.timestamp_subsec_micros(), 1);
    }

    #[test]
    fn test_firefox_time_year_2030() {
        let unix_ts: i64 = 1893456000;
        let moz_time = unix_ts * 1_000_000;
        let dt = firefox_time_to_datetime(moz_time).unwrap();
        assert_eq!(dt.format("%Y").to_string(), "2030");
    }

    // ─── detect_browser edge cases ──────────────────────────────────────

    #[test]
    fn test_detect_browser_case_insensitive() {
        assert_eq!(detect_browser("FIREFOX"), BrowserType::Firefox);
        assert_eq!(detect_browser("EDGE"), BrowserType::Edge);
        assert_eq!(detect_browser("MOZILLA"), BrowserType::Firefox);
    }

    #[test]
    fn test_detect_browser_unknown_defaults_chrome() {
        assert_eq!(detect_browser("somedb.sqlite"), BrowserType::Chrome);
        assert_eq!(detect_browser(""), BrowserType::Chrome);
    }

    #[test]
    fn test_detect_browser_mixed_case() {
        assert_eq!(
            detect_browser(r"C:\Users\Admin\AppData\Local\Mozilla\Firefox\profile\places.sqlite"),
            BrowserType::Firefox
        );
    }

    #[test]
    fn test_detect_browser_edge_in_path() {
        assert_eq!(
            detect_browser(r"C:\Users\test\AppData\Local\Microsoft\Edge\User Data\Default\History"),
            BrowserType::Edge
        );
    }

    #[test]
    fn test_detect_browser_mozilla_keyword() {
        assert_eq!(detect_browser("some/mozilla/path"), BrowserType::Firefox);
    }

    // ─── BrowserType tests ──────────────────────────────────────────────

    #[test]
    fn test_browser_type_equality() {
        assert_eq!(BrowserType::Chrome, BrowserType::Chrome);
        assert_ne!(BrowserType::Chrome, BrowserType::Firefox);
        assert_ne!(BrowserType::Firefox, BrowserType::Edge);
    }

    #[test]
    fn test_browser_type_clone() {
        let browser = BrowserType::Firefox;
        let cloned = browser.clone();
        assert_eq!(browser, cloned);
    }

    #[test]
    fn test_browser_type_debug() {
        let debug_str = format!("{:?}", BrowserType::Chrome);
        assert_eq!(debug_str, "Chrome");
        let debug_str = format!("{:?}", BrowserType::Edge);
        assert_eq!(debug_str, "Edge");
        let debug_str = format!("{:?}", BrowserType::Firefox);
        assert_eq!(debug_str, "Firefox");
    }

    // ─── BrowserHistoryEntry tests ──────────────────────────────────────

    #[test]
    fn test_browser_history_entry_clone() {
        let entry = BrowserHistoryEntry {
            url: "https://example.com".to_string(),
            title: "Example".to_string(),
            visit_time: Utc::now(),
            visit_count: 5,
            browser: BrowserType::Chrome,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.url, entry.url);
        assert_eq!(cloned.visit_count, entry.visit_count);
        assert_eq!(cloned.browser, entry.browser);
    }

    #[test]
    fn test_browser_history_entry_empty_title() {
        let entry = BrowserHistoryEntry {
            url: "https://example.com".to_string(),
            title: String::new(),
            visit_time: Utc::now(),
            visit_count: 1,
            browser: BrowserType::Firefox,
        };
        assert!(entry.title.is_empty());
    }

    #[test]
    fn test_browser_history_entry_high_visit_count() {
        let entry = BrowserHistoryEntry {
            url: "https://daily.com".to_string(),
            title: "Daily".to_string(),
            visit_time: Utc::now(),
            visit_count: 99999,
            browser: BrowserType::Edge,
        };
        assert_eq!(entry.visit_count, 99999);
    }

    // ─── Timeline entry description formatting ──────────────────────────

    #[test]
    fn test_browser_timeline_entry_with_title() {
        let entry = BrowserHistoryEntry {
            url: "https://evil.com".to_string(),
            title: "Phishing Page".to_string(),
            visit_time: Utc::now(),
            visit_count: 1,
            browser: BrowserType::Chrome,
        };
        let browser_name = "Chrome";
        let title_display = if entry.title.is_empty() {
            String::new()
        } else {
            format!(" \"{}\"", entry.title)
        };
        let path = format!(
            "[{}:History]{} {} (visits: {})",
            browser_name, title_display, entry.url, entry.visit_count
        );
        assert!(path.contains("\"Phishing Page\""));
        assert!(path.contains("https://evil.com"));
        assert!(path.contains("visits: 1"));
    }

    #[test]
    fn test_browser_timeline_entry_without_title() {
        let entry = BrowserHistoryEntry {
            url: "https://no-title.com".to_string(),
            title: String::new(),
            visit_time: Utc::now(),
            visit_count: 2,
            browser: BrowserType::Firefox,
        };
        let browser_name = "Firefox";
        let title_display = if entry.title.is_empty() {
            String::new()
        } else {
            format!(" \"{}\"", entry.title)
        };
        let path = format!(
            "[{}:History]{} {} (visits: {})",
            browser_name, title_display, entry.url, entry.visit_count
        );
        assert!(!path.contains("\"\""));
        assert!(path.contains("[Firefox:History] https://no-title.com"));
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

        let result = parse_browser_history(&NoOpProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── parse_browser_history pipeline tests ────────────────────────

    fn make_chrome_manifest() -> ArtifactManifest {
        use crate::collection::path::NormalizedPath;
        let mut manifest = ArtifactManifest::default();
        manifest.browser_history.push(
            NormalizedPath::from_image_path(
                "/Users/admin/AppData/Local/Google/Chrome/User Data/Default/History",
                'C',
            ),
        );
        manifest
    }

    fn make_firefox_manifest() -> ArtifactManifest {
        use crate::collection::path::NormalizedPath;
        let mut manifest = ArtifactManifest::default();
        manifest.browser_history.push(
            NormalizedPath::from_image_path(
                "/Users/admin/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default/places.sqlite",
                'C',
            ),
        );
        manifest
    }

    fn make_edge_manifest() -> ArtifactManifest {
        use crate::collection::path::NormalizedPath;
        let mut manifest = ArtifactManifest::default();
        manifest.browser_history.push(
            NormalizedPath::from_image_path(
                "/Users/admin/AppData/Local/Microsoft/Edge/User Data/Default/History",
                'C',
            ),
        );
        manifest
    }

    #[test]
    fn test_parse_browser_history_open_file_error() {
        // Tests warn path when provider.open_file fails (line 190-193)
        let manifest = make_chrome_manifest();
        let mut store = TimelineStore::new();

        struct FailOpenProvider;
        impl CollectionProvider for FailOpenProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                anyhow::bail!("Cannot read browser history file")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_browser_history(&FailOpenProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_browser_history_invalid_sqlite_data() {
        // Tests debug path when parse_chromium_history fails (line 223-225)
        let manifest = make_chrome_manifest();
        let mut store = TimelineStore::new();

        struct GarbageProvider;
        impl CollectionProvider for GarbageProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(vec![0xFFu8; 256]) // Not a valid SQLite database
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_browser_history(&GarbageProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_browser_history_firefox_invalid_sqlite() {
        // Tests debug path when parse_firefox_history fails (line 216-218)
        let manifest = make_firefox_manifest();
        let mut store = TimelineStore::new();

        struct GarbageProvider;
        impl CollectionProvider for GarbageProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(vec![0xABu8; 128])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_browser_history(&GarbageProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_browser_history_edge_invalid_sqlite() {
        // Edge uses Chromium path - tests line 221 match arm
        let manifest = make_edge_manifest();
        let mut store = TimelineStore::new();

        struct GarbageProvider;
        impl CollectionProvider for GarbageProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(vec![0u8; 64])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_browser_history(&GarbageProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_browser_history_with_valid_chromium_db() {
        // Create a real in-memory Chromium-format SQLite database
        // and test the full parsing path (lines 95-127, 237-263)
        use crate::collection::path::NormalizedPath;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let tmp_path = tmp.path().to_string_lossy().to_string();

        // Create Chromium-style history tables
        let conn = rusqlite::Connection::open(&tmp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
             INSERT INTO urls (id, url, title, visit_count) VALUES (1, 'https://example.com', 'Example', 5);
             INSERT INTO urls (id, url, title, visit_count) VALUES (2, 'https://test.com', '', 1);
             INSERT INTO visits (id, url, visit_time) VALUES (1, 1, 13370000000000000);
             INSERT INTO visits (id, url, visit_time) VALUES (2, 2, 13370000000000000);"
        ).unwrap();
        drop(conn);

        // Read the database file
        let db_data = std::fs::read(&tmp_path).unwrap();

        let mut manifest = ArtifactManifest::default();
        manifest.browser_history.push(
            NormalizedPath::from_image_path(
                "/Users/admin/AppData/Local/Google/Chrome/User Data/Default/History",
                'C',
            ),
        );

        let mut store = TimelineStore::new();

        struct DbProvider {
            data: Vec<u8>,
        }
        impl CollectionProvider for DbProvider {
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

        let provider = DbProvider { data: db_data };
        let result = parse_browser_history(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 2);

        // Verify entries contain expected data
        let entry0 = store.get(0).unwrap();
        assert!(entry0.path.contains("[Chrome:History]"));
        assert!(entry0.path.contains("https://example.com") || entry0.path.contains("https://test.com"));
    }

    #[test]
    fn test_parse_browser_history_with_valid_firefox_db() {
        // Create a real Firefox-format SQLite database (lines 138-170, 237-263)
        use crate::collection::path::NormalizedPath;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let tmp_path = tmp.path().to_string_lossy().to_string();

        let conn = rusqlite::Connection::open(&tmp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
             CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER);
             INSERT INTO moz_places (id, url, title, visit_count) VALUES (1, 'https://mozilla.org', 'Mozilla', 3);
             INSERT INTO moz_places (id, url, title, visit_count) VALUES (2, 'https://test.org', NULL, 1);
             INSERT INTO moz_historyvisits (id, place_id, visit_date) VALUES (1, 1, 1736942400000000);
             INSERT INTO moz_historyvisits (id, place_id, visit_date) VALUES (2, 2, 1736942400000000);"
        ).unwrap();
        drop(conn);

        let db_data = std::fs::read(&tmp_path).unwrap();

        let mut manifest = ArtifactManifest::default();
        manifest.browser_history.push(
            NormalizedPath::from_image_path(
                "/Users/admin/AppData/Roaming/Mozilla/Firefox/Profiles/abc/places.sqlite",
                'C',
            ),
        );

        let mut store = TimelineStore::new();

        struct DbProvider {
            data: Vec<u8>,
        }
        impl CollectionProvider for DbProvider {
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

        let provider = DbProvider { data: db_data };
        let result = parse_browser_history(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 2);

        // Verify Firefox entries
        let entry0 = store.get(0).unwrap();
        assert!(entry0.path.contains("[Firefox:History]"));
    }

    #[test]
    fn test_parse_browser_history_chromium_with_title_and_without() {
        // Tests the title_display branch: empty vs non-empty title (lines 243-247)
        use crate::collection::path::NormalizedPath;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let tmp_path = tmp.path().to_string_lossy().to_string();

        let conn = rusqlite::Connection::open(&tmp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
             INSERT INTO urls (id, url, title, visit_count) VALUES (1, 'https://titled.com', 'Has Title', 2);
             INSERT INTO urls (id, url, title, visit_count) VALUES (2, 'https://notitled.com', '', 1);
             INSERT INTO visits (id, url, visit_time) VALUES (1, 1, 13370000000000000);
             INSERT INTO visits (id, url, visit_time) VALUES (2, 2, 13370000000000000);"
        ).unwrap();
        drop(conn);

        let db_data = std::fs::read(&tmp_path).unwrap();

        let mut manifest = ArtifactManifest::default();
        manifest.browser_history.push(
            NormalizedPath::from_image_path(
                "/Users/admin/AppData/Local/Google/Chrome/User Data/Default/History",
                'C',
            ),
        );

        let mut store = TimelineStore::new();

        struct DbProvider {
            data: Vec<u8>,
        }
        impl CollectionProvider for DbProvider {
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

        let provider = DbProvider { data: db_data };
        let result = parse_browser_history(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 2);

        // Check that one entry has a quoted title and the other doesn't
        let paths: Vec<String> = store.entries().map(|e| e.path.clone()).collect();
        let has_title_entry = paths.iter().any(|p| p.contains("\"Has Title\""));
        let no_title_entry = paths.iter().any(|p| p.contains("https://notitled.com") && !p.contains("\"\""));
        assert!(has_title_entry, "Should have entry with quoted title");
        assert!(no_title_entry, "Should have entry without quoted empty title");
    }

    #[test]
    fn test_parse_browser_history_multiple_databases() {
        // Tests iterating multiple browser history paths (line 187 loop)
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.browser_history.push(
            NormalizedPath::from_image_path(
                "/Users/admin/AppData/Local/Google/Chrome/User Data/Default/History",
                'C',
            ),
        );
        manifest.browser_history.push(
            NormalizedPath::from_image_path(
                "/Users/admin/AppData/Local/Microsoft/Edge/User Data/Default/History",
                'C',
            ),
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
                anyhow::bail!("read error")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_browser_history(&FailProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── parse_chromium_history with real SQLite ─────────────────────

    #[test]
    fn test_parse_chromium_history_empty_db() {
        // Valid SQLite DB but no rows - tests empty query result (lines 112-124)
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let tmp_path = tmp.path().to_string_lossy().to_string();

        let conn = rusqlite::Connection::open(&tmp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);"
        ).unwrap();
        drop(conn);

        let result = parse_chromium_history(&tmp_path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_parse_chromium_history_with_zero_visit_time() {
        // visit_time=0 should be filtered out by chrome_time_to_datetime (line 114)
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let tmp_path = tmp.path().to_string_lossy().to_string();

        let conn = rusqlite::Connection::open(&tmp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
             INSERT INTO urls (id, url, title, visit_count) VALUES (1, 'https://zero.com', 'Zero', 1);
             INSERT INTO visits (id, url, visit_time) VALUES (1, 1, 0);"
        ).unwrap();
        drop(conn);

        let result = parse_chromium_history(&tmp_path).unwrap();
        assert_eq!(result.len(), 0); // zero visit_time should be filtered
    }

    #[test]
    fn test_parse_chromium_history_missing_tables() {
        // SQLite DB without required tables
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let tmp_path = tmp.path().to_string_lossy().to_string();

        let conn = rusqlite::Connection::open(&tmp_path).unwrap();
        conn.execute_batch("CREATE TABLE other (id INTEGER PRIMARY KEY);").unwrap();
        drop(conn);

        let result = parse_chromium_history(&tmp_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_firefox_history_empty_db() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let tmp_path = tmp.path().to_string_lossy().to_string();

        let conn = rusqlite::Connection::open(&tmp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
             CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER);"
        ).unwrap();
        drop(conn);

        let result = parse_firefox_history(&tmp_path).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_firefox_history_null_title() {
        // Tests title.unwrap_or_default() path (line 160)
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let tmp_path = tmp.path().to_string_lossy().to_string();

        let conn = rusqlite::Connection::open(&tmp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
             CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER);
             INSERT INTO moz_places (id, url, title, visit_count) VALUES (1, 'https://notitle.com', NULL, 1);
             INSERT INTO moz_historyvisits (id, place_id, visit_date) VALUES (1, 1, 1736942400000000);"
        ).unwrap();
        drop(conn);

        let result = parse_firefox_history(&tmp_path).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].title.is_empty()); // NULL becomes empty string
        assert_eq!(result[0].browser, BrowserType::Firefox);
    }

    #[test]
    fn test_parse_firefox_history_zero_visit_date() {
        // visit_date=0 should be filtered by firefox_time_to_datetime (line 157)
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let tmp_path = tmp.path().to_string_lossy().to_string();

        let conn = rusqlite::Connection::open(&tmp_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
             CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER);
             INSERT INTO moz_places (id, url, title, visit_count) VALUES (1, 'https://zero.com', 'Zero', 1);
             INSERT INTO moz_historyvisits (id, place_id, visit_date) VALUES (1, 1, 0);"
        ).unwrap();
        drop(conn);

        let result = parse_firefox_history(&tmp_path).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_firefox_history_missing_tables() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let tmp_path = tmp.path().to_string_lossy().to_string();

        let conn = rusqlite::Connection::open(&tmp_path).unwrap();
        conn.execute_batch("CREATE TABLE other (id INTEGER PRIMARY KEY);").unwrap();
        drop(conn);

        let result = parse_firefox_history(&tmp_path);
        assert!(result.is_err());
    }

    // ─── detect_browser additional tests ─────────────────────────────

    #[test]
    fn test_detect_browser_firefox_via_mozilla_in_path() {
        // Firefox detected via "mozilla" keyword (line 73)
        assert_eq!(
            detect_browser("/some/path/Mozilla/data"),
            BrowserType::Firefox,
        );
    }

    #[test]
    fn test_detect_browser_edge_priority_over_chrome() {
        // "edge" in path should detect Edge, not Chrome
        assert_eq!(
            detect_browser("C:\\Users\\test\\Edge\\History"),
            BrowserType::Edge,
        );
    }

    #[test]
    fn test_detect_browser_firefox_priority_over_edge() {
        // Firefox check comes before Edge check, so "firefox" wins
        assert_eq!(
            detect_browser("firefox_edge_path"),
            BrowserType::Firefox,
        );
    }

    #[test]
    fn test_detect_browser_generic_path_defaults_to_chrome() {
        assert_eq!(detect_browser("/data/History"), BrowserType::Chrome);
        assert_eq!(detect_browser(""), BrowserType::Chrome);
        assert_eq!(detect_browser("random.db"), BrowserType::Chrome);
    }

    // ─── chrome_time_to_datetime edge cases ──────────────────────────

    #[test]
    fn test_chrome_time_exactly_at_epoch_boundary() {
        // Test the exact boundary where unix_usec = 0
        let chrome_time: i64 = 11_644_473_600_000_000;
        let dt = chrome_time_to_datetime(chrome_time).unwrap();
        assert_eq!(dt.timestamp(), 0);
        assert_eq!(dt.timestamp_subsec_nanos(), 0);
    }

    #[test]
    fn test_chrome_time_one_below_epoch() {
        // unix_usec = -1 should return None
        let chrome_time: i64 = 11_644_473_600_000_000 - 1;
        assert!(chrome_time_to_datetime(chrome_time).is_none());
    }

    #[test]
    fn test_firefox_time_one_second() {
        let dt = firefox_time_to_datetime(1_000_000).unwrap();
        assert_eq!(dt.timestamp(), 1);
        assert_eq!(dt.timestamp_subsec_nanos(), 0);
    }

    // ─── next_browser_id uniqueness ──────────────────────────────────

    #[test]
    fn test_next_browser_id_uniqueness_batch() {
        let ids: Vec<u64> = (0..100).map(|_| next_browser_id()).collect();
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ids.len());
    }

    // ─── BrowserHistoryEntry debug format ────────────────────────────

    #[test]
    fn test_browser_history_entry_debug() {
        let entry = BrowserHistoryEntry {
            url: "https://debug.test".to_string(),
            title: "Debug".to_string(),
            visit_time: Utc::now(),
            visit_count: 1,
            browser: BrowserType::Chrome,
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("BrowserHistoryEntry"));
        assert!(debug_str.contains("debug.test"));
    }

    // ─── browser_name matching in pipeline ───────────────────────────

    #[test]
    fn test_browser_name_mapping() {
        // Directly test the match arms for browser name (lines 238-242)
        let names: Vec<(&str, BrowserType)> = vec![
            ("Chrome", BrowserType::Chrome),
            ("Edge", BrowserType::Edge),
            ("Firefox", BrowserType::Firefox),
        ];
        for (expected_name, browser_type) in names {
            let actual = match &browser_type {
                BrowserType::Chrome => "Chrome",
                BrowserType::Edge => "Edge",
                BrowserType::Firefox => "Firefox",
            };
            assert_eq!(actual, expected_name);
        }
    }

    #[test]
    fn test_parse_chromium_history_detects_browser_from_path() {
        // Tests that detect_browser is called with the db_path (line 86)
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let tmp_path_str = tmp.path().to_string_lossy().to_string();
        // Create a valid but empty chromium db
        let conn = rusqlite::Connection::open(&tmp_path_str).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
             INSERT INTO urls (id, url, title, visit_count) VALUES (1, 'https://test.com', 'Test', 1);
             INSERT INTO visits (id, url, visit_time) VALUES (1, 1, 13370000000000000);"
        ).unwrap();
        drop(conn);

        // parse_chromium_history detects browser from the path
        let entries = parse_chromium_history(&tmp_path_str).unwrap();
        assert_eq!(entries.len(), 1);
        // Since tmp_path doesn't contain "edge" or "firefox", it defaults to Chrome
        assert_eq!(entries[0].browser, BrowserType::Chrome);
    }
}
