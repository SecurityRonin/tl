use anyhow::{Context, Result};
use log::{debug, warn};
use smallvec::smallvec;
use std::io::Write;

use crate::collection::manifest::ArtifactManifest;
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static SRUM_ID_COUNTER: AtomicU64 = AtomicU64::new(0x5352_0000_0000_0000); // "SR" prefix

fn next_srum_id() -> u64 {
    SRUM_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── SRUM table GUIDs ────────────────────────────────────────────────────────

/// Application Resource Usage table GUID.
pub const APP_RESOURCE_USAGE_TABLE: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}";

/// Network Data Usage table GUID.
pub const NETWORK_DATA_USAGE_TABLE: &str = "{DD6636C4-8929-4683-974E-22C046A43763}";

/// Network Connectivity table GUID.
pub const NETWORK_CONNECTIVITY_TABLE: &str = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";

// ─── Parsed SRUM entries ─────────────────────────────────────────────────────

/// A parsed SRUM application resource usage entry.
#[derive(Debug, Clone)]
pub struct SrumAppEntry {
    pub app_id: String,
    pub user_sid: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub foreground_cycle_time: u64,
    pub background_cycle_time: u64,
    pub face_time: u64,
}

/// A parsed SRUM network data usage entry.
#[derive(Debug, Clone)]
pub struct SrumNetworkEntry {
    pub app_id: String,
    pub user_sid: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub interface_luid: u64,
}

/// A parsed SRUM network connectivity entry.
#[derive(Debug, Clone)]
pub struct SrumConnectivityEntry {
    pub app_id: String,
    pub user_sid: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub connected_time: u32,
    pub interface_luid: u64,
}

// ─── Human-readable byte formatting ─────────────────────────────────

/// Format a byte count as a human-readable string (B, KB, MB, GB).
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;

    let b = bytes as f64;
    if bytes == 0 {
        "0 B".to_string()
    } else if b < KB {
        format!("{} B", bytes)
    } else if b < MB {
        format!("{:.1} KB", b / KB)
    } else if b < GB {
        format!("{:.1} MB", b / MB)
    } else {
        format!("{:.1} GB", b / GB)
    }
}

// ─── IdMap resolution ────────────────────────────────────────────────

/// Resolve a libesedb Value to a string using an IdMap lookup table.
///
/// If the value is a string (Text/LargeText), return it directly.
/// If it's a numeric type (I32/U32), look up in the map.
/// Falls back to "ID:<n>" for unmapped integers, "?" for null/other.
pub fn resolve_id(value: &libesedb::Value, map: &std::collections::HashMap<i32, String>) -> String {
    match value {
        libesedb::Value::Text(s) | libesedb::Value::LargeText(s) => s.clone(),
        libesedb::Value::I32(n) => {
            map.get(n).cloned().unwrap_or_else(|| format!("ID:{}", n))
        }
        libesedb::Value::U32(n) => {
            map.get(&(*n as i32)).cloned().unwrap_or_else(|| format!("ID:{}", n))
        }
        _ => "?".to_string(),
    }
}

// ─── FILETIME conversion ─────────────────────────────────────────────────────

/// Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to DateTime<Utc>.
pub fn filetime_to_datetime(ft: u64) -> Option<chrono::DateTime<chrono::Utc>> {
    if ft == 0 {
        return None;
    }
    let secs = (ft / 10_000_000).checked_sub(11_644_473_600)?;
    let nanos = ((ft % 10_000_000) * 100) as u32;
    chrono::DateTime::from_timestamp(secs as i64, nanos)
}

// ─── ESE Database Parsing ────────────────────────────────────────────────────

/// Build a column-name → index lookup for an ESE table.
fn build_col_index(table: &libesedb::Table) -> std::collections::HashMap<String, usize> {
    let columns: Vec<_> = match table.iter_columns() {
        Ok(iter) => iter.filter_map(|c| c.ok()).collect(),
        Err(_) => return std::collections::HashMap::new(),
    };
    let mut map = std::collections::HashMap::new();
    for (i, col) in columns.iter().enumerate() {
        if let Ok(name) = col.name() {
            map.insert(name.to_lowercase(), i);
        }
    }
    map
}

/// Get a column index by case-insensitive name from the column map.
fn col(map: &std::collections::HashMap<String, usize>, name: &str) -> Option<usize> {
    map.get(&name.to_lowercase()).copied()
}

/// Parse the SruDbIdMapTable to build numeric-ID → name lookup maps.
///
/// The IdMap table maps numeric IDs used in other SRUM tables to actual
/// application paths (as UTF-16LE in IdBlob) and user SIDs (as binary SID).
fn parse_id_map(db: &libesedb::EseDb) -> std::collections::HashMap<i32, String> {
    let mut map = std::collections::HashMap::new();

    let table = match db.table_by_name("SruDbIdMapTable") {
        Ok(t) => t,
        Err(_) => {
            debug!("SruDbIdMapTable not found, IDs will not be resolved");
            return map;
        }
    };

    let cols = build_col_index(&table);
    let idx_col = col(&cols, "IdIndex");
    let blob_col = col(&cols, "IdBlob");

    if idx_col.is_none() || blob_col.is_none() {
        debug!("SruDbIdMapTable missing expected columns");
        return map;
    }

    let records = match table.iter_records() {
        Ok(r) => r,
        Err(_) => return map,
    };

    for rec_result in records {
        let rec = match rec_result {
            Ok(r) => r,
            Err(_) => continue,
        };

        let values: Vec<_> = match rec.iter_values() {
            Ok(iter) => iter.map(|v| v.unwrap_or_default()).collect(),
            Err(_) => continue,
        };

        let id = idx_col
            .and_then(|i| values.get(i))
            .and_then(|v| v.to_i32());

        let id = match id {
            Some(n) => n,
            None => continue,
        };

        // IdBlob is typically Binary or LargeBinary containing UTF-16LE
        let name = blob_col.and_then(|i| values.get(i)).and_then(|v| {
            // Try text first (some versions store as text)
            if let Some(s) = v.as_str() {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
            // Try binary (UTF-16LE encoded app path or binary SID)
            if let Some(bytes) = v.as_bytes() {
                if bytes.len() >= 2 {
                    // Try UTF-16LE decode (application paths)
                    let u16s: Vec<u16> = bytes
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    let decoded = String::from_utf16_lossy(&u16s)
                        .trim_end_matches('\0')
                        .to_string();
                    if !decoded.is_empty()
                        && decoded.chars().all(|c| !c.is_control() || c == '\\')
                    {
                        return Some(decoded);
                    }
                }
            }
            None
        });

        if let Some(name) = name {
            map.insert(id, name);
        }
    }

    debug!("SruDbIdMapTable: {} entries resolved", map.len());
    map
}

/// Parse SRUM entries from an ESE database file on disk.
///
/// Opens the SRUDB.dat file using libesedb and extracts records from
/// the Application Resource Usage, Network Data Usage, and Network
/// Connectivity tables. Resolves numeric IDs via SruDbIdMapTable.
pub fn parse_srum_from_ese(
    path: &str,
) -> Result<(Vec<SrumAppEntry>, Vec<SrumNetworkEntry>, Vec<SrumConnectivityEntry>)> {
    let db = libesedb::EseDb::open(path)
        .map_err(|e| anyhow::anyhow!("Failed to open SRUM database: {}", e))?;

    // Build IdMap for resolving numeric AppId/UserId references
    let id_map = parse_id_map(&db);

    let mut app_entries = Vec::new();
    let mut net_entries = Vec::new();
    let mut conn_entries = Vec::new();

    // Parse Application Resource Usage table
    if let Ok(table) = db.table_by_name(APP_RESOURCE_USAGE_TABLE) {
        debug!("Parsing SRUM Application Resource Usage table");
        let cols = build_col_index(&table);

        if let Ok(records) = table.iter_records() {
            for rec_result in records {
                let rec = match rec_result {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let values: Vec<_> = match rec.iter_values() {
                    Ok(iter) => iter.map(|v| v.unwrap_or_default()).collect(),
                    Err(_) => continue,
                };

                let timestamp = col(&cols, "timestamp")
                    .and_then(|i| values.get(i))
                    .and_then(|v| v.to_u64())
                    .and_then(filetime_to_datetime);

                let timestamp = match timestamp {
                    Some(ts) => ts,
                    None => continue,
                };

                let app_id = col(&cols, "appid")
                    .and_then(|i| values.get(i))
                    .map(|v| resolve_id(v, &id_map))
                    .unwrap_or_else(|| "?".to_string());

                let user_sid = col(&cols, "userid")
                    .and_then(|i| values.get(i))
                    .map(|v| resolve_id(v, &id_map))
                    .unwrap_or_default();

                let fg = col(&cols, "foregroundcycletime")
                    .and_then(|i| values.get(i))
                    .and_then(|v| v.to_u64())
                    .unwrap_or(0);

                let bg = col(&cols, "backgroundcycletime")
                    .and_then(|i| values.get(i))
                    .and_then(|v| v.to_u64())
                    .unwrap_or(0);

                let face = col(&cols, "facetime")
                    .and_then(|i| values.get(i))
                    .and_then(|v| v.to_u64())
                    .unwrap_or(0);

                app_entries.push(SrumAppEntry {
                    app_id,
                    user_sid,
                    timestamp,
                    foreground_cycle_time: fg,
                    background_cycle_time: bg,
                    face_time: face,
                });
            }
        }
    } else {
        debug!("SRUM Application Resource Usage table not found");
    }

    // Parse Network Data Usage table
    if let Ok(table) = db.table_by_name(NETWORK_DATA_USAGE_TABLE) {
        debug!("Parsing SRUM Network Data Usage table");
        let cols = build_col_index(&table);

        if let Ok(records) = table.iter_records() {
            for rec_result in records {
                let rec = match rec_result {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let values: Vec<_> = match rec.iter_values() {
                    Ok(iter) => iter.map(|v| v.unwrap_or_default()).collect(),
                    Err(_) => continue,
                };

                let timestamp = col(&cols, "timestamp")
                    .and_then(|i| values.get(i))
                    .and_then(|v| v.to_u64())
                    .and_then(filetime_to_datetime);

                let timestamp = match timestamp {
                    Some(ts) => ts,
                    None => continue,
                };

                let app_id = col(&cols, "appid")
                    .and_then(|i| values.get(i))
                    .map(|v| resolve_id(v, &id_map))
                    .unwrap_or_else(|| "?".to_string());

                let user_sid = col(&cols, "userid")
                    .and_then(|i| values.get(i))
                    .map(|v| resolve_id(v, &id_map))
                    .unwrap_or_default();

                let sent = col(&cols, "bytessent")
                    .and_then(|i| values.get(i))
                    .and_then(|v| v.to_u64())
                    .unwrap_or(0);

                let recv = col(&cols, "bytesrecvd")
                    .and_then(|i| values.get(i))
                    .and_then(|v| v.to_u64())
                    .unwrap_or(0);

                let luid = col(&cols, "interfaceluid")
                    .and_then(|i| values.get(i))
                    .and_then(|v| v.to_u64())
                    .unwrap_or(0);

                net_entries.push(SrumNetworkEntry {
                    app_id,
                    user_sid,
                    timestamp,
                    bytes_sent: sent,
                    bytes_received: recv,
                    interface_luid: luid,
                });
            }
        }
    } else {
        debug!("SRUM Network Data Usage table not found");
    }

    // Parse Network Connectivity table
    if let Ok(table) = db.table_by_name(NETWORK_CONNECTIVITY_TABLE) {
        debug!("Parsing SRUM Network Connectivity table");
        let cols = build_col_index(&table);

        if let Ok(records) = table.iter_records() {
            for rec_result in records {
                let rec = match rec_result {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let values: Vec<_> = match rec.iter_values() {
                    Ok(iter) => iter.map(|v| v.unwrap_or_default()).collect(),
                    Err(_) => continue,
                };

                let timestamp = col(&cols, "timestamp")
                    .and_then(|i| values.get(i))
                    .and_then(|v| v.to_u64())
                    .and_then(filetime_to_datetime);

                let timestamp = match timestamp {
                    Some(ts) => ts,
                    None => continue,
                };

                let app_id = col(&cols, "appid")
                    .and_then(|i| values.get(i))
                    .map(|v| resolve_id(v, &id_map))
                    .unwrap_or_else(|| "?".to_string());

                let user_sid = col(&cols, "userid")
                    .and_then(|i| values.get(i))
                    .map(|v| resolve_id(v, &id_map))
                    .unwrap_or_default();

                let connected = col(&cols, "connectedtime")
                    .and_then(|i| values.get(i))
                    .and_then(|v| v.to_u32())
                    .unwrap_or(0);

                let luid = col(&cols, "interfaceluid")
                    .and_then(|i| values.get(i))
                    .and_then(|v| v.to_u64())
                    .unwrap_or(0);

                conn_entries.push(SrumConnectivityEntry {
                    app_id,
                    user_sid,
                    timestamp,
                    connected_time: connected,
                    interface_luid: luid,
                });
            }
        }
    } else {
        debug!("SRUM Network Connectivity table not found");
    }

    debug!(
        "SRUM: {} app, {} network, {} connectivity entries",
        app_entries.len(),
        net_entries.len(),
        conn_entries.len()
    );
    Ok((app_entries, net_entries, conn_entries))
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse SRUM database from the collection and populate the timeline.
pub fn parse_srum(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    if manifest.srum.is_empty() {
        debug!("No SRUM database found in manifest");
        return Ok(());
    }

    for srum_path in &manifest.srum {
        let data = match provider.open_file(srum_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read SRUM database {}: {}", srum_path, e);
                continue;
            }
        };

        // Write to temp file since libesedb requires a file path
        let mut tmp = tempfile::NamedTempFile::new()
            .context("Failed to create temp file for SRUM")?;
        tmp.write_all(&data)
            .context("Failed to write SRUM temp file")?;
        tmp.flush()?;

        let tmp_path = tmp.path().to_string_lossy().to_string();
        let (app_entries, net_entries, conn_entries) = match parse_srum_from_ese(&tmp_path) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to parse SRUM database: {}", e);
                continue;
            }
        };

        debug!(
            "SRUM from {}: {} app, {} network, {} connectivity entries",
            srum_path,
            app_entries.len(),
            net_entries.len(),
            conn_entries.len()
        );

        for app in &app_entries {
            let desc = format!(
                "[SRUM:App] {} user:{} fg:{} bg:{} face:{}",
                app.app_id, app.user_sid,
                app.foreground_cycle_time, app.background_cycle_time, app.face_time,
            );

            store.push(TimelineEntry {
                entity_id: EntityId::Generated(next_srum_id()),
                path: desc,
                primary_timestamp: app.timestamp,
                event_type: EventType::Execute,
                timestamps: TimestampSet::default(),
                sources: smallvec![ArtifactSource::Srum],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
            });
        }

        for net in &net_entries {
            let desc = format!(
                "[SRUM:Net] {} user:{} sent:{} recv:{}",
                net.app_id, net.user_sid,
                format_bytes(net.bytes_sent), format_bytes(net.bytes_received),
            );

            store.push(TimelineEntry {
                entity_id: EntityId::Generated(next_srum_id()),
                path: desc,
                primary_timestamp: net.timestamp,
                event_type: EventType::NetworkConnection,
                timestamps: TimestampSet::default(),
                sources: smallvec![ArtifactSource::Srum],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
            });
        }

        for conn in &conn_entries {
            let desc = format!(
                "[SRUM:Conn] {} user:{} connected:{}s",
                conn.app_id, conn.user_sid, conn.connected_time,
            );

            store.push(TimelineEntry {
                entity_id: EntityId::Generated(next_srum_id()),
                path: desc,
                primary_timestamp: conn.timestamp,
                event_type: EventType::NetworkConnection,
                timestamps: TimestampSet::default(),
                sources: smallvec![ArtifactSource::Srum],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
            });
        }
    }

    Ok(())
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn test_filetime_to_datetime() {
        // 2025-06-15T10:30:00Z in FILETIME
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let ft = secs as u64 * 10_000_000;
        let result = filetime_to_datetime(ft).unwrap();
        assert_eq!(result.date_naive(), dt.date_naive());
    }

    #[test]
    fn test_filetime_zero() {
        assert!(filetime_to_datetime(0).is_none());
    }

    #[test]
    fn test_srum_app_entry_creation() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = SrumAppEntry {
            app_id: "cmd.exe".to_string(),
            user_sid: "S-1-5-21-1234-5678-9012-1001".to_string(),
            timestamp: ts,
            foreground_cycle_time: 100000,
            background_cycle_time: 50000,
            face_time: 3600,
        };
        assert_eq!(entry.app_id, "cmd.exe");
        assert_eq!(entry.face_time, 3600);
    }

    #[test]
    fn test_srum_network_entry_creation() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let entry = SrumNetworkEntry {
            app_id: "chrome.exe".to_string(),
            user_sid: "S-1-5-21-1234-5678-9012-1001".to_string(),
            timestamp: ts,
            bytes_sent: 1024,
            bytes_received: 4096,
            interface_luid: 0,
        };
        assert_eq!(entry.bytes_received, 4096);
    }

    #[test]
    fn test_srum_app_timeline_entry() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let srum = SrumAppEntry {
            app_id: "powershell.exe".to_string(),
            user_sid: "S-1-5-21-1234".to_string(),
            timestamp: ts,
            foreground_cycle_time: 500000,
            background_cycle_time: 200000,
            face_time: 7200,
        };

        let desc = format!(
            "[SRUM:App] {} user:{} fg:{} bg:{} face:{}",
            srum.app_id, srum.user_sid,
            srum.foreground_cycle_time, srum.background_cycle_time, srum.face_time,
        );

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_srum_id()),
            path: desc.clone(),
            primary_timestamp: srum.timestamp,
            event_type: EventType::Execute,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Srum],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        assert_eq!(entry.event_type, EventType::Execute);
        assert!(entry.path.contains("powershell.exe"));
        assert!(entry.path.contains("SRUM:App"));
    }

    #[test]
    fn test_srum_network_timeline_entry() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let net = SrumNetworkEntry {
            app_id: "malware.exe".to_string(),
            user_sid: "S-1-5-21-1234".to_string(),
            timestamp: ts,
            bytes_sent: 1048576,
            bytes_received: 2097152,
            interface_luid: 0,
        };

        let desc = format!(
            "[SRUM:Net] {} user:{} sent:{} recv:{}",
            net.app_id, net.user_sid,
            format_bytes(net.bytes_sent), format_bytes(net.bytes_received),
        );

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_srum_id()),
            path: desc.clone(),
            primary_timestamp: net.timestamp,
            event_type: EventType::NetworkConnection,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Srum],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        assert_eq!(entry.event_type, EventType::NetworkConnection);
        assert!(entry.path.contains("malware.exe"));
        assert!(entry.path.contains("1.0 MB"), "got: {}", entry.path);
    }

    // ─── format_bytes tests ────────────────────────────────────────────────

    #[test]
    fn test_format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn test_format_bytes_small() {
        assert_eq!(format_bytes(512), "512 B");
    }

    #[test]
    fn test_format_bytes_kilobytes() {
        assert_eq!(format_bytes(1536), "1.5 KB");
    }

    #[test]
    fn test_format_bytes_megabytes() {
        assert_eq!(format_bytes(2_411_724), "2.3 MB");
    }

    #[test]
    fn test_format_bytes_gigabytes() {
        assert_eq!(format_bytes(1_073_741_824), "1.0 GB");
    }

    #[test]
    fn test_format_bytes_exact_kb() {
        assert_eq!(format_bytes(1024), "1.0 KB");
    }

    // ─── resolve_id tests ────────────────────────────────────────────────

    #[test]
    fn test_resolve_id_from_string_value() {
        let map = std::collections::HashMap::new();
        let val = libesedb::Value::Text("chrome.exe".to_string());
        assert_eq!(resolve_id(&val, &map), "chrome.exe");
    }

    #[test]
    fn test_resolve_id_from_int_with_map() {
        let mut map = std::collections::HashMap::new();
        map.insert(42, "powershell.exe".to_string());
        let val = libesedb::Value::I32(42);
        assert_eq!(resolve_id(&val, &map), "powershell.exe");
    }

    #[test]
    fn test_resolve_id_from_int_without_map() {
        let map = std::collections::HashMap::new();
        let val = libesedb::Value::I32(99);
        assert_eq!(resolve_id(&val, &map), "ID:99");
    }

    #[test]
    fn test_resolve_id_from_large_text() {
        let map = std::collections::HashMap::new();
        let val = libesedb::Value::LargeText("svchost.exe".to_string());
        assert_eq!(resolve_id(&val, &map), "svchost.exe");
    }

    #[test]
    fn test_resolve_id_null_value() {
        let map = std::collections::HashMap::new();
        let val = libesedb::Value::Null(());
        assert_eq!(resolve_id(&val, &map), "?");
    }

    // ─── SrumConnectivityEntry tests ─────────────────────────────────────

    #[test]
    fn test_srum_connectivity_entry_creation() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 8, 0, 0).unwrap();
        let entry = SrumConnectivityEntry {
            app_id: "svchost.exe".to_string(),
            user_sid: "S-1-5-18".to_string(),
            timestamp: ts,
            connected_time: 3600,
            interface_luid: 0x0600_0001_0000_0000,
        };
        assert_eq!(entry.connected_time, 3600);
        assert_eq!(entry.app_id, "svchost.exe");
    }

    #[test]
    fn test_srum_connectivity_timeline_entry() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 8, 0, 0).unwrap();
        let conn = SrumConnectivityEntry {
            app_id: "explorer.exe".to_string(),
            user_sid: "S-1-5-21-1234".to_string(),
            timestamp: ts,
            connected_time: 7200,
            interface_luid: 0,
        };

        let desc = format!(
            "[SRUM:Conn] {} user:{} connected:{}s",
            conn.app_id, conn.user_sid, conn.connected_time,
        );

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_srum_id()),
            path: desc.clone(),
            primary_timestamp: conn.timestamp,
            event_type: EventType::NetworkConnection,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Srum],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        assert_eq!(entry.event_type, EventType::NetworkConnection);
        assert!(entry.path.contains("SRUM:Conn"));
        assert!(entry.path.contains("7200s"));
    }

    // ─── Enhanced formatting tests ───────────────────────────────────────

    #[test]
    fn test_srum_net_entry_with_human_bytes() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let net = SrumNetworkEntry {
            app_id: "malware.exe".to_string(),
            user_sid: "S-1-5-21-1234".to_string(),
            timestamp: ts,
            bytes_sent: 1048576,
            bytes_received: 2097152,
            interface_luid: 0,
        };

        let desc = format!(
            "[SRUM:Net] {} user:{} sent:{} recv:{}",
            net.app_id, net.user_sid,
            format_bytes(net.bytes_sent), format_bytes(net.bytes_received),
        );

        assert!(desc.contains("sent:1.0 MB"), "got: {}", desc);
        assert!(desc.contains("recv:2.0 MB"), "got: {}", desc);
    }

    #[test]
    fn test_parse_srum_from_ese_invalid_path() {
        let result = parse_srum_from_ese("/nonexistent/srudb.dat");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_srum_from_ese_returns_three_tuple() {
        // Verify the return type is (app, net, conn) by destructuring
        // Using invalid path - we just need to confirm the type compiles
        let result = parse_srum_from_ese("/nonexistent/srudb.dat");
        assert!(result.is_err());
        // If this compiles, the return type is correct
        let _: Result<(Vec<SrumAppEntry>, Vec<SrumNetworkEntry>, Vec<SrumConnectivityEntry>)> =
            parse_srum_from_ese("/also/nonexistent");
    }

    // ─── next_srum_id tests ─────────────────────────────────────────────

    #[test]
    fn test_next_srum_id_increments() {
        let id1 = next_srum_id();
        let id2 = next_srum_id();
        assert!(id2 > id1);
        assert_eq!(id2 - id1, 1);
    }

    #[test]
    fn test_next_srum_id_has_sr_prefix() {
        let id = next_srum_id();
        // Top 2 bytes should be 0x5352 ("SR")
        let prefix = (id >> 48) & 0xFFFF;
        assert_eq!(prefix, 0x5352);
    }

    // ─── col() helper tests ─────────────────────────────────────────────

    #[test]
    fn test_col_case_insensitive() {
        let mut map = std::collections::HashMap::new();
        map.insert("appid".to_string(), 0);
        map.insert("timestamp".to_string(), 1);
        assert_eq!(col(&map, "AppId"), Some(0));
        assert_eq!(col(&map, "APPID"), Some(0));
        assert_eq!(col(&map, "Timestamp"), Some(1));
    }

    #[test]
    fn test_col_missing_key() {
        let map = std::collections::HashMap::new();
        assert_eq!(col(&map, "nonexistent"), None);
    }

    #[test]
    fn test_col_empty_map() {
        let map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        assert_eq!(col(&map, "anything"), None);
    }

    // ─── filetime_to_datetime edge cases ────────────────────────────────

    #[test]
    fn test_filetime_very_small_value() {
        // A FILETIME value smaller than the epoch diff should return None
        // (checked_sub would fail)
        let ft: u64 = 100; // tiny value, way before Unix epoch
        assert!(filetime_to_datetime(ft).is_none());
    }

    #[test]
    fn test_filetime_preserves_subseconds() {
        // Test that nanosecond portion is correctly computed
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        // Add 5_000_000 100ns intervals = 0.5 seconds
        let ft = secs as u64 * 10_000_000 + 5_000_000;
        let result = filetime_to_datetime(ft).unwrap();
        assert_eq!(result.timestamp_subsec_nanos(), 500_000_000);
    }

    #[test]
    fn test_filetime_at_unix_epoch() {
        // FILETIME for 1970-01-01 00:00:00 UTC
        let ft: u64 = 11_644_473_600 * 10_000_000;
        let result = filetime_to_datetime(ft).unwrap();
        assert_eq!(result.timestamp(), 0);
    }

    // ─── resolve_id edge cases ──────────────────────────────────────────

    #[test]
    fn test_resolve_id_from_u32_with_map() {
        let mut map = std::collections::HashMap::new();
        map.insert(7, "svchost.exe".to_string());
        let val = libesedb::Value::U32(7);
        assert_eq!(resolve_id(&val, &map), "svchost.exe");
    }

    #[test]
    fn test_resolve_id_from_u32_without_map() {
        let map = std::collections::HashMap::new();
        let val = libesedb::Value::U32(123);
        assert_eq!(resolve_id(&val, &map), "ID:123");
    }

    #[test]
    fn test_resolve_id_empty_text() {
        let map = std::collections::HashMap::new();
        let val = libesedb::Value::Text(String::new());
        assert_eq!(resolve_id(&val, &map), "");
    }

    // ─── format_bytes edge cases ────────────────────────────────────────

    #[test]
    fn test_format_bytes_one_byte() {
        assert_eq!(format_bytes(1), "1 B");
    }

    #[test]
    fn test_format_bytes_just_under_kb() {
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn test_format_bytes_just_under_mb() {
        // 1023 KB = 1047552 bytes
        let result = format_bytes(1047552);
        assert!(result.contains("KB"), "expected KB, got: {}", result);
    }

    #[test]
    fn test_format_bytes_exact_mb() {
        assert_eq!(format_bytes(1048576), "1.0 MB");
    }

    #[test]
    fn test_format_bytes_just_under_gb() {
        // 1023 MB = 1072693248 bytes
        let result = format_bytes(1072693248);
        assert!(result.contains("MB"), "expected MB, got: {}", result);
    }

    #[test]
    fn test_format_bytes_large_gb() {
        // 10 GB
        assert_eq!(format_bytes(10_737_418_240), "10.0 GB");
    }

    // ─── SRUM table GUID constant tests ─────────────────────────────────

    #[test]
    fn test_srum_table_guids_are_valid() {
        assert!(APP_RESOURCE_USAGE_TABLE.starts_with('{'));
        assert!(APP_RESOURCE_USAGE_TABLE.ends_with('}'));
        assert!(NETWORK_DATA_USAGE_TABLE.starts_with('{'));
        assert!(NETWORK_DATA_USAGE_TABLE.ends_with('}'));
        assert!(NETWORK_CONNECTIVITY_TABLE.starts_with('{'));
        assert!(NETWORK_CONNECTIVITY_TABLE.ends_with('}'));
    }

    #[test]
    fn test_srum_table_guids_are_distinct() {
        assert_ne!(APP_RESOURCE_USAGE_TABLE, NETWORK_DATA_USAGE_TABLE);
        assert_ne!(APP_RESOURCE_USAGE_TABLE, NETWORK_CONNECTIVITY_TABLE);
        assert_ne!(NETWORK_DATA_USAGE_TABLE, NETWORK_CONNECTIVITY_TABLE);
    }

    // ─── Struct Clone/Debug tests ───────────────────────────────────────

    #[test]
    fn test_srum_app_entry_clone() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = SrumAppEntry {
            app_id: "test.exe".to_string(),
            user_sid: "S-1-5-21-1234".to_string(),
            timestamp: ts,
            foreground_cycle_time: 100,
            background_cycle_time: 200,
            face_time: 300,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.app_id, entry.app_id);
        assert_eq!(cloned.foreground_cycle_time, entry.foreground_cycle_time);
    }

    #[test]
    fn test_srum_network_entry_clone() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let entry = SrumNetworkEntry {
            app_id: "app.exe".to_string(),
            user_sid: "S-1-5-21-5678".to_string(),
            timestamp: ts,
            bytes_sent: 999,
            bytes_received: 1111,
            interface_luid: 42,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.bytes_sent, 999);
        assert_eq!(cloned.interface_luid, 42);
    }

    #[test]
    fn test_srum_connectivity_entry_clone() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 8, 0, 0).unwrap();
        let entry = SrumConnectivityEntry {
            app_id: "svc.exe".to_string(),
            user_sid: "S-1-5-18".to_string(),
            timestamp: ts,
            connected_time: 999,
            interface_luid: 42,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.connected_time, 999);
    }

    #[test]
    fn test_srum_app_entry_debug() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = SrumAppEntry {
            app_id: "test.exe".to_string(),
            user_sid: "S-1-5-21-1234".to_string(),
            timestamp: ts,
            foreground_cycle_time: 100,
            background_cycle_time: 200,
            face_time: 300,
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("SrumAppEntry"));
        assert!(debug_str.contains("test.exe"));
    }

    // ─── Description formatting tests ───────────────────────────────────

    #[test]
    fn test_srum_app_desc_format_zero_values() {
        let ts = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let srum = SrumAppEntry {
            app_id: "idle.exe".to_string(),
            user_sid: "S-1-5-21-0".to_string(),
            timestamp: ts,
            foreground_cycle_time: 0,
            background_cycle_time: 0,
            face_time: 0,
        };
        let desc = format!(
            "[SRUM:App] {} user:{} fg:{} bg:{} face:{}",
            srum.app_id, srum.user_sid,
            srum.foreground_cycle_time, srum.background_cycle_time, srum.face_time,
        );
        assert!(desc.contains("fg:0"));
        assert!(desc.contains("bg:0"));
        assert!(desc.contains("face:0"));
    }

    #[test]
    fn test_srum_conn_desc_format() {
        let ts = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let conn = SrumConnectivityEntry {
            app_id: "net.exe".to_string(),
            user_sid: "S-1-5-21-999".to_string(),
            timestamp: ts,
            connected_time: 0,
            interface_luid: 0,
        };
        let desc = format!(
            "[SRUM:Conn] {} user:{} connected:{}s",
            conn.app_id, conn.user_sid, conn.connected_time,
        );
        assert!(desc.contains("connected:0s"));
    }

    #[test]
    fn test_srum_net_desc_with_zero_bytes() {
        let ts = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let net = SrumNetworkEntry {
            app_id: "quiet.exe".to_string(),
            user_sid: "S-1-5-18".to_string(),
            timestamp: ts,
            bytes_sent: 0,
            bytes_received: 0,
            interface_luid: 0,
        };
        let desc = format!(
            "[SRUM:Net] {} user:{} sent:{} recv:{}",
            net.app_id, net.user_sid,
            format_bytes(net.bytes_sent), format_bytes(net.bytes_received),
        );
        assert!(desc.contains("sent:0 B"));
        assert!(desc.contains("recv:0 B"));
    }

    #[test]
    fn test_empty_manifest_no_error() {
        use crate::collection::manifest::ArtifactManifest;
        let manifest = ArtifactManifest::default();
        let mut store = TimelineStore::new();

        struct MockProvider;
        impl CollectionProvider for MockProvider {
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

        let provider = MockProvider;
        let result = parse_srum(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }
}
