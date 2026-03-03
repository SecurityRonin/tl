use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;
use anyhow::Result;
use std::io::Write;

pub fn export_csv<W: Write>(store: &TimelineStore, writer: &mut W) -> Result<()> {
    let mut wtr = csv::Writer::from_writer(writer);

    wtr.write_record([
        "Timestamp",
        "Event",
        "Path",
        "Sources",
        "Anomalies",
        "SI_Created",
        "SI_Modified",
        "SI_Accessed",
        "SI_EntryMod",
        "FN_Created",
        "FN_Modified",
        "FN_Accessed",
        "FN_EntryMod",
        "MFT_Entry",
        "FileSize",
        "IsDir",
    ])?;

    for entry in store.entries() {
        let sources: String = entry
            .sources
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join("|");

        let anomalies = format_anomalies(entry.anomalies);

        wtr.write_record([
            entry
                .primary_timestamp
                .format("%Y-%m-%d %H:%M:%S%.3f")
                .to_string(),
            entry.event_type.to_string(),
            entry.path.clone(),
            sources,
            anomalies,
            fmt_ts_opt(entry.timestamps.si_created),
            fmt_ts_opt(entry.timestamps.si_modified),
            fmt_ts_opt(entry.timestamps.si_accessed),
            fmt_ts_opt(entry.timestamps.si_entry_modified),
            fmt_ts_opt(entry.timestamps.fn_created),
            fmt_ts_opt(entry.timestamps.fn_modified),
            fmt_ts_opt(entry.timestamps.fn_accessed),
            fmt_ts_opt(entry.timestamps.fn_entry_modified),
            entry
                .metadata
                .mft_entry_number
                .map(|n| n.to_string())
                .unwrap_or_default(),
            entry
                .metadata
                .file_size
                .map(|n| n.to_string())
                .unwrap_or_default(),
            entry.metadata.is_directory.to_string(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

fn fmt_ts_opt(ts: Option<chrono::DateTime<chrono::Utc>>) -> String {
    ts.map(|t| t.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
        .unwrap_or_default()
}

/// Format anomaly flags into a human-readable pipe-separated string for CSV export.
fn format_anomalies(flags: AnomalyFlags) -> String {
    if flags.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    if flags.contains(AnomalyFlags::TIMESTOMPED_SI_LT_FN) {
        parts.push("STOMP");
    }
    if flags.contains(AnomalyFlags::TIMESTOMPED_ZERO_NANOS) {
        parts.push("ZERO_NANOS");
    }
    if flags.contains(AnomalyFlags::METADATA_BACKDATED) {
        parts.push("BACKDATED");
    }
    if flags.contains(AnomalyFlags::NO_USN_CREATE) {
        parts.push("NO_USN");
    }
    if flags.contains(AnomalyFlags::LOG_GAP_DETECTED) {
        parts.push("LOG_GAP");
    }
    if flags.contains(AnomalyFlags::LOG_CLEARED) {
        parts.push("LOG_CLEARED");
    }
    if flags.contains(AnomalyFlags::EXECUTION_NO_PREFETCH) {
        parts.push("NO_PREFETCH");
    }
    if flags.contains(AnomalyFlags::HIDDEN_ADS) {
        parts.push("ADS");
    }
    parts.join("|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use smallvec::smallvec;

    fn make_entry(path: &str) -> TimelineEntry {
        TimelineEntry {
            entity_id: EntityId::Generated(1),
            path: path.to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 12, 30, 45).unwrap(),
            event_type: EventType::FileCreate,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        }
    }

    #[test]
    fn test_export_csv_header() {
        let store = TimelineStore::new();
        let mut buf = Vec::new();
        export_csv(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Timestamp"));
        assert!(output.contains("Event"));
        assert!(output.contains("Path"));
        assert!(output.contains("Sources"));
        assert!(output.contains("Anomalies"));
        assert!(output.contains("SI_Created"));
        assert!(output.contains("FN_Created"));
        assert!(output.contains("MFT_Entry"));
        assert!(output.contains("FileSize"));
        assert!(output.contains("IsDir"));
    }

    #[test]
    fn test_export_csv_single_entry() {
        let mut store = TimelineStore::new();
        store.push(make_entry("C:\\test.txt"));

        let mut buf = Vec::new();
        export_csv(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2); // header + 1 entry
        assert!(lines[1].contains("C:\\test.txt"));
        assert!(lines[1].contains("CREATE"));
    }

    #[test]
    fn test_export_csv_empty_store_only_header() {
        let store = TimelineStore::new();
        let mut buf = Vec::new();
        export_csv(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 1); // only header
    }

    #[test]
    fn test_export_csv_timestamp_format() {
        let mut store = TimelineStore::new();
        store.push(make_entry("test.txt"));

        let mut buf = Vec::new();
        export_csv(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("2025-06-15 12:30:45"));
    }

    #[test]
    fn test_export_csv_multiple_sources() {
        let mut store = TimelineStore::new();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(1),
            path: "test.txt".to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            event_type: EventType::FileModify,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft, ArtifactSource::UsnJrnl, ArtifactSource::Prefetch],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };
        store.push(entry);

        let mut buf = Vec::new();
        export_csv(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("MFT|USN|PF"), "Expected MFT|USN|PF in: {}", output);
    }

    #[test]
    fn test_export_csv_with_anomalies() {
        let mut store = TimelineStore::new();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(1),
            path: "evil.exe".to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            event_type: EventType::FileCreate,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::TIMESTOMPED_SI_LT_FN | AnomalyFlags::LOG_CLEARED,
            metadata: EntryMetadata::default(),
        };
        store.push(entry);

        let mut buf = Vec::new();
        export_csv(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("STOMP"), "Expected STOMP in: {}", output);
        assert!(output.contains("LOG_CLEARED"), "Expected LOG_CLEARED in: {}", output);
    }

    #[test]
    fn test_export_csv_with_si_timestamps() {
        let ts = Utc.with_ymd_and_hms(2025, 3, 10, 8, 0, 0).unwrap();
        let mut store = TimelineStore::new();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(1),
            path: "test.txt".to_string(),
            primary_timestamp: ts,
            event_type: EventType::FileCreate,
            timestamps: TimestampSet {
                si_created: Some(ts),
                si_modified: Some(ts),
                si_accessed: Some(ts),
                si_entry_modified: Some(ts),
                ..TimestampSet::default()
            },
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };
        store.push(entry);

        let mut buf = Vec::new();
        export_csv(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("2025-03-10 08:00:00"));
    }

    #[test]
    fn test_export_csv_metadata_fields() {
        let mut store = TimelineStore::new();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(1),
            path: "test.txt".to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            event_type: EventType::FileCreate,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata {
                mft_entry_number: Some(42),
                file_size: Some(1024),
                is_directory: true,
                ..EntryMetadata::default()
            },
        };
        store.push(entry);

        let mut buf = Vec::new();
        export_csv(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("42"), "Expected MFT entry 42 in: {}", output);
        assert!(output.contains("1024"), "Expected size 1024 in: {}", output);
        assert!(output.contains("true"), "Expected is_dir=true in: {}", output);
    }

    // ─── format_anomalies unit tests ────────────────────────────────────

    #[test]
    fn test_format_anomalies_empty() {
        assert_eq!(format_anomalies(AnomalyFlags::empty()), "");
    }

    #[test]
    fn test_format_anomalies_single_flag() {
        assert_eq!(format_anomalies(AnomalyFlags::TIMESTOMPED_SI_LT_FN), "STOMP");
        assert_eq!(format_anomalies(AnomalyFlags::TIMESTOMPED_ZERO_NANOS), "ZERO_NANOS");
        assert_eq!(format_anomalies(AnomalyFlags::METADATA_BACKDATED), "BACKDATED");
        assert_eq!(format_anomalies(AnomalyFlags::NO_USN_CREATE), "NO_USN");
        assert_eq!(format_anomalies(AnomalyFlags::LOG_GAP_DETECTED), "LOG_GAP");
        assert_eq!(format_anomalies(AnomalyFlags::LOG_CLEARED), "LOG_CLEARED");
        assert_eq!(format_anomalies(AnomalyFlags::EXECUTION_NO_PREFETCH), "NO_PREFETCH");
        assert_eq!(format_anomalies(AnomalyFlags::HIDDEN_ADS), "ADS");
    }

    #[test]
    fn test_format_anomalies_multiple_flags() {
        let flags = AnomalyFlags::TIMESTOMPED_SI_LT_FN | AnomalyFlags::HIDDEN_ADS;
        let result = format_anomalies(flags);
        assert!(result.contains("STOMP"));
        assert!(result.contains("ADS"));
        assert!(result.contains("|"));
    }

    #[test]
    fn test_format_anomalies_all_flags() {
        let all = AnomalyFlags::TIMESTOMPED_SI_LT_FN
            | AnomalyFlags::TIMESTOMPED_ZERO_NANOS
            | AnomalyFlags::METADATA_BACKDATED
            | AnomalyFlags::NO_USN_CREATE
            | AnomalyFlags::LOG_GAP_DETECTED
            | AnomalyFlags::LOG_CLEARED
            | AnomalyFlags::EXECUTION_NO_PREFETCH
            | AnomalyFlags::HIDDEN_ADS;
        let result = format_anomalies(all);
        assert!(result.contains("STOMP"));
        assert!(result.contains("ZERO_NANOS"));
        assert!(result.contains("BACKDATED"));
        assert!(result.contains("NO_USN"));
        assert!(result.contains("LOG_GAP"));
        assert!(result.contains("LOG_CLEARED"));
        assert!(result.contains("NO_PREFETCH"));
        assert!(result.contains("ADS"));
    }

    // ─── fmt_ts_opt unit tests ──────────────────────────────────────────

    #[test]
    fn test_fmt_ts_opt_some() {
        let ts = Some(Utc.with_ymd_and_hms(2025, 12, 25, 0, 0, 0).unwrap());
        let result = fmt_ts_opt(ts);
        assert_eq!(result, "2025-12-25 00:00:00.000");
    }

    #[test]
    fn test_fmt_ts_opt_none() {
        assert_eq!(fmt_ts_opt(None), "");
    }

    // ─── export_csv with FN timestamps ──────────────────────────────────

    #[test]
    fn test_export_csv_with_fn_timestamps() {
        let ts = Utc.with_ymd_and_hms(2025, 7, 20, 14, 30, 0).unwrap();
        let mut store = TimelineStore::new();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(1),
            path: "fn_test.txt".to_string(),
            primary_timestamp: ts,
            event_type: EventType::FileCreate,
            timestamps: TimestampSet {
                fn_created: Some(ts),
                fn_modified: Some(ts),
                fn_accessed: Some(ts),
                fn_entry_modified: Some(ts),
                ..TimestampSet::default()
            },
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };
        store.push(entry);

        let mut buf = Vec::new();
        export_csv(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("2025-07-20 14:30:00"));
    }
}
