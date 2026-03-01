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
}
