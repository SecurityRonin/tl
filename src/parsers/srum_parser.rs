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

/// Parse SRUM entries from an ESE database file on disk.
///
/// Opens the SRUDB.dat file using libesedb and extracts records from
/// the Application Resource Usage and Network Data Usage tables.
pub fn parse_srum_from_ese(
    path: &str,
) -> Result<(Vec<SrumAppEntry>, Vec<SrumNetworkEntry>)> {
    let db = libesedb::EseDb::open(path)
        .map_err(|e| anyhow::anyhow!("Failed to open SRUM database: {}", e))?;

    let mut app_entries = Vec::new();
    let mut net_entries = Vec::new();

    // Parse Application Resource Usage table
    if let Ok(table) = db.table_by_name(APP_RESOURCE_USAGE_TABLE) {
        debug!("Parsing SRUM Application Resource Usage table");
        let columns: Vec<_> = match table.iter_columns() {
            Ok(iter) => iter.filter_map(|c| c.ok()).collect(),
            Err(_) => Vec::new(),
        };

        // Build column index by name
        let col_idx = |name: &str| -> Option<i32> {
            columns.iter().position(|c| {
                c.name().map(|n| n.eq_ignore_ascii_case(name)).unwrap_or(false)
            }).map(|i| i as i32)
        };

        let ts_col = col_idx("TimeStamp");
        let app_col = col_idx("AppId");
        let user_col = col_idx("UserId");
        let fg_col = col_idx("ForegroundCycleTime");
        let bg_col = col_idx("BackgroundCycleTime");
        let face_col = col_idx("FaceTime");

        if let Ok(records) = table.iter_records() {
            for rec_result in records {
                let rec = match rec_result {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let values: Vec<_> = match rec.iter_values() {
                    Ok(iter) => iter
                        .map(|v| v.unwrap_or_default())
                        .collect(),
                    Err(_) => continue,
                };

                let timestamp = ts_col
                    .and_then(|i| values.get(i as usize))
                    .and_then(|v| v.to_u64())
                    .and_then(filetime_to_datetime);

                let timestamp = match timestamp {
                    Some(ts) => ts,
                    None => continue,
                };

                let app_id = app_col
                    .and_then(|i| values.get(i as usize))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string();

                let user_sid = user_col
                    .and_then(|i| values.get(i as usize))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let fg = fg_col
                    .and_then(|i| values.get(i as usize))
                    .and_then(|v| v.to_u64())
                    .unwrap_or(0);

                let bg = bg_col
                    .and_then(|i| values.get(i as usize))
                    .and_then(|v| v.to_u64())
                    .unwrap_or(0);

                let face = face_col
                    .and_then(|i| values.get(i as usize))
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
        let columns: Vec<_> = match table.iter_columns() {
            Ok(iter) => iter.filter_map(|c| c.ok()).collect(),
            Err(_) => Vec::new(),
        };

        let col_idx = |name: &str| -> Option<i32> {
            columns.iter().position(|c| {
                c.name().map(|n| n.eq_ignore_ascii_case(name)).unwrap_or(false)
            }).map(|i| i as i32)
        };

        let ts_col = col_idx("TimeStamp");
        let app_col = col_idx("AppId");
        let user_col = col_idx("UserId");
        let sent_col = col_idx("BytesSent");
        let recv_col = col_idx("BytesRecvd");
        let luid_col = col_idx("InterfaceLuid");

        if let Ok(records) = table.iter_records() {
            for rec_result in records {
                let rec = match rec_result {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let values: Vec<_> = match rec.iter_values() {
                    Ok(iter) => iter
                        .map(|v| v.unwrap_or_default())
                        .collect(),
                    Err(_) => continue,
                };

                let timestamp = ts_col
                    .and_then(|i| values.get(i as usize))
                    .and_then(|v| v.to_u64())
                    .and_then(filetime_to_datetime);

                let timestamp = match timestamp {
                    Some(ts) => ts,
                    None => continue,
                };

                let app_id = app_col
                    .and_then(|i| values.get(i as usize))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string();

                let user_sid = user_col
                    .and_then(|i| values.get(i as usize))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let sent = sent_col
                    .and_then(|i| values.get(i as usize))
                    .and_then(|v| v.to_u64())
                    .unwrap_or(0);

                let recv = recv_col
                    .and_then(|i| values.get(i as usize))
                    .and_then(|v| v.to_u64())
                    .unwrap_or(0);

                let luid = luid_col
                    .and_then(|i| values.get(i as usize))
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

    debug!(
        "SRUM: {} app entries, {} network entries",
        app_entries.len(),
        net_entries.len()
    );
    Ok((app_entries, net_entries))
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
        let (app_entries, net_entries) = match parse_srum_from_ese(&tmp_path) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to parse SRUM database: {}", e);
                continue;
            }
        };

        debug!(
            "SRUM from {}: {} app, {} network entries",
            srum_path,
            app_entries.len(),
            net_entries.len()
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
                net.app_id, net.user_sid, net.bytes_sent, net.bytes_received,
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
    }

    Ok(()
    )
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
            net.app_id, net.user_sid, net.bytes_sent, net.bytes_received,
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
        assert!(entry.path.contains("1048576"));
    }

    #[test]
    fn test_parse_srum_from_ese_invalid_path() {
        let result = parse_srum_from_ese("/nonexistent/srudb.dat");
        assert!(result.is_err());
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
