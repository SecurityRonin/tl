use chrono::{TimeZone, Utc};
use smallvec::smallvec;
use tl::export::json_export::export_json;
use tl::timeline::entry::*;
use tl::timeline::store::TimelineStore;

#[test]
fn test_json_export_single_entry() {
    let mut store = TimelineStore::new();
    let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
    store.push(TimelineEntry {
        entity_id: EntityId::MftEntry(42),
        path: r"C:\test\file.exe".to_string(),
        primary_timestamp: ts,
        event_type: EventType::FileCreate,
        timestamps: TimestampSet::default(),
        sources: smallvec![ArtifactSource::Mft],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata::default(),
    });

    let mut buf = Vec::new();
    export_json(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // Should be valid JSON array
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 1);

    let entry = &parsed[0];
    assert_eq!(entry["path"], r"C:\test\file.exe");
    assert_eq!(entry["event_type"], "FileCreate");
    assert!(entry["primary_timestamp"].as_str().unwrap().contains("2025-06-15"));
}

#[test]
fn test_json_export_empty_store() {
    let store = TimelineStore::new();
    let mut buf = Vec::new();
    export_json(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 0);
}

#[test]
fn test_json_export_preserves_metadata() {
    let mut store = TimelineStore::new();
    let ts = Utc.with_ymd_and_hms(2025, 8, 1, 0, 0, 0).unwrap();
    store.push(TimelineEntry {
        entity_id: EntityId::MftEntry(99),
        path: r"C:\evidence\bigfile.dat".to_string(),
        primary_timestamp: ts,
        event_type: EventType::FileModify,
        timestamps: TimestampSet::default(),
        sources: smallvec![ArtifactSource::Mft, ArtifactSource::UsnJrnl],
        anomalies: AnomalyFlags::TIMESTOMPED_SI_LT_FN,
        metadata: EntryMetadata {
            file_size: Some(1048576),
            mft_entry_number: Some(99),
            mft_sequence: Some(3),
            is_directory: false,
            has_ads: true,
            parent_path: None,
            sha256: None,
            sha1: None,
        },
    });

    let mut buf = Vec::new();
    export_json(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    let entry = &parsed[0];
    assert_eq!(entry["metadata"]["file_size"], 1048576);
    assert_eq!(entry["metadata"]["mft_entry_number"], 99);
    assert_eq!(entry["metadata"]["has_ads"], true);
}

#[test]
fn test_json_export_multiple_entries_ordered() {
    let mut store = TimelineStore::new();
    let ts1 = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
    let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

    store.push(TimelineEntry {
        entity_id: EntityId::Generated(1),
        path: "first.txt".to_string(),
        primary_timestamp: ts1,
        event_type: EventType::FileAccess,
        timestamps: TimestampSet::default(),
        sources: smallvec![ArtifactSource::Lnk],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata::default(),
    });
    store.push(TimelineEntry {
        entity_id: EntityId::Generated(2),
        path: "second.txt".to_string(),
        primary_timestamp: ts2,
        event_type: EventType::Execute,
        timestamps: TimestampSet::default(),
        sources: smallvec![ArtifactSource::Prefetch],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata::default(),
    });

    let mut buf = Vec::new();
    export_json(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["path"], "first.txt");
    assert_eq!(arr[1]["path"], "second.txt");
}
