use chrono::{TimeZone, Utc};
use smallvec::smallvec;
use tl::export::bodyfile_export::export_bodyfile;
use tl::timeline::entry::*;
use tl::timeline::store::TimelineStore;

#[test]
fn test_bodyfile_export_single_entry() {
    let mut store = TimelineStore::new();
    let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
    let mut timestamps = TimestampSet::default();
    timestamps.si_created = Some(ts);
    timestamps.si_modified = Some(ts);
    timestamps.si_accessed = Some(ts);
    timestamps.si_entry_modified = Some(ts);

    store.push(TimelineEntry {
        entity_id: EntityId::MftEntry(42),
        path: r"C:\test\file.exe".to_string(),
        primary_timestamp: ts,
        event_type: EventType::FileCreate,
        timestamps,
        sources: smallvec![ArtifactSource::Mft],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata {
            file_size: Some(4096),
            mft_entry_number: Some(42),
            mft_sequence: Some(1),
            is_directory: false,
            has_ads: false,
            parent_path: None,
            sha256: None,
            sha1: None,
        },
    });

    let mut buf = Vec::new();
    export_bodyfile(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // Should contain the path
    assert!(output.contains(r"C:\test\file.exe"));
    // Should be pipe-delimited
    assert!(output.contains("|"));
    // Should contain the file size
    assert!(output.contains("4096"));
    // Each line should have 11 pipe-separated fields
    for line in output.lines() {
        let fields: Vec<&str> = line.split('|').collect();
        assert_eq!(fields.len(), 11, "bodyfile line should have 11 fields: {}", line);
    }
}

#[test]
fn test_bodyfile_export_empty_store() {
    let store = TimelineStore::new();
    let mut buf = Vec::new();
    export_bodyfile(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.is_empty());
}

#[test]
fn test_bodyfile_export_timestamps_as_epoch() {
    let mut store = TimelineStore::new();
    let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
    let epoch = ts.timestamp(); // Unix epoch seconds

    let mut timestamps = TimestampSet::default();
    timestamps.si_accessed = Some(ts);
    timestamps.si_modified = Some(ts);
    timestamps.si_entry_modified = Some(ts);
    timestamps.si_created = Some(ts);

    store.push(TimelineEntry {
        entity_id: EntityId::MftEntry(10),
        path: "timestamps.txt".to_string(),
        primary_timestamp: ts,
        event_type: EventType::FileCreate,
        timestamps,
        sources: smallvec![ArtifactSource::Mft],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata::default(),
    });

    let mut buf = Vec::new();
    export_bodyfile(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // The epoch timestamp should appear in the output
    let epoch_str = epoch.to_string();
    assert!(output.contains(&epoch_str), "should contain epoch {}", epoch_str);
}

#[test]
fn test_bodyfile_export_missing_timestamps() {
    let mut store = TimelineStore::new();
    let ts = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

    // Entry with no SI timestamps (e.g., from EVTX or Prefetch)
    store.push(TimelineEntry {
        entity_id: EntityId::Generated(1),
        path: "[Logon] admin".to_string(),
        primary_timestamp: ts,
        event_type: EventType::UserLogon,
        timestamps: TimestampSet::default(),
        sources: smallvec![ArtifactSource::Evtx("Security".to_string())],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata::default(),
    });

    let mut buf = Vec::new();
    export_bodyfile(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // Should still produce a valid line with -1 for missing timestamps
    assert!(!output.is_empty());
    // Missing timestamps should be -1
    assert!(output.contains("-1"));
}

#[test]
fn test_bodyfile_export_mft_inode() {
    let mut store = TimelineStore::new();
    let ts = Utc.with_ymd_and_hms(2025, 8, 1, 0, 0, 0).unwrap();

    store.push(TimelineEntry {
        entity_id: EntityId::MftEntry(12345),
        path: r"C:\Windows\System32\cmd.exe".to_string(),
        primary_timestamp: ts,
        event_type: EventType::Execute,
        timestamps: TimestampSet::default(),
        sources: smallvec![ArtifactSource::Mft],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata {
            mft_entry_number: Some(12345),
            mft_sequence: Some(7),
            ..EntryMetadata::default()
        },
    });

    let mut buf = Vec::new();
    export_bodyfile(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // Should contain MFT entry as inode field (entry-seq format)
    assert!(output.contains("12345-7"));
}

#[test]
fn test_bodyfile_export_parseable_by_bodyfile_crate() {
    use std::convert::TryFrom;

    let mut store = TimelineStore::new();
    let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
    let mut timestamps = TimestampSet::default();
    timestamps.si_accessed = Some(ts);
    timestamps.si_modified = Some(ts);
    timestamps.si_entry_modified = Some(ts);
    timestamps.si_created = Some(ts);

    store.push(TimelineEntry {
        entity_id: EntityId::MftEntry(42),
        path: r"C:\test\file.exe".to_string(),
        primary_timestamp: ts,
        event_type: EventType::FileCreate,
        timestamps,
        sources: smallvec![ArtifactSource::Mft],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata {
            file_size: Some(4096),
            mft_entry_number: Some(42),
            mft_sequence: Some(1),
            ..EntryMetadata::default()
        },
    });

    let mut buf = Vec::new();
    export_bodyfile(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // Each line should be parseable by the bodyfile crate
    for line in output.lines() {
        let parsed = bodyfile::Bodyfile3Line::try_from(line);
        assert!(parsed.is_ok(), "bodyfile crate should parse: {}", line);
    }
}
