use tl::timeline::entry::*;
use tl::timeline::store::TimelineStore;
use tl::export::csv_export::export_csv;
use chrono::Utc;
use smallvec::smallvec;

#[test]
fn test_csv_export() {
    let mut store = TimelineStore::new();
    let ts = Utc::now();
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
    export_csv(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    assert!(output.contains("file.exe"));
    assert!(output.contains("CREATE"));
    assert!(output.contains("MFT"));
}

#[test]
fn test_csv_export_header() {
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
fn test_csv_export_multiple_sources() {
    let mut store = TimelineStore::new();
    let ts = Utc::now();
    store.push(TimelineEntry {
        entity_id: EntityId::MftEntry(100),
        path: r"C:\Windows\System32\cmd.exe".to_string(),
        primary_timestamp: ts,
        event_type: EventType::Execute,
        timestamps: TimestampSet::default(),
        sources: smallvec![ArtifactSource::Mft, ArtifactSource::Prefetch],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata::default(),
    });

    let mut buf = Vec::new();
    export_csv(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    assert!(output.contains("MFT|PF"));
    assert!(output.contains("EXEC"));
}

#[test]
fn test_csv_export_with_anomalies() {
    let mut store = TimelineStore::new();
    let ts = Utc::now();
    store.push(TimelineEntry {
        entity_id: EntityId::MftEntry(55),
        path: r"C:\suspicious\malware.exe".to_string(),
        primary_timestamp: ts,
        event_type: EventType::FileCreate,
        timestamps: TimestampSet::default(),
        sources: smallvec![ArtifactSource::Mft],
        anomalies: AnomalyFlags::TIMESTOMPED_SI_LT_FN | AnomalyFlags::TIMESTOMPED_ZERO_NANOS,
        metadata: EntryMetadata::default(),
    });

    let mut buf = Vec::new();
    export_csv(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    assert!(output.contains("STOMP"));
    assert!(output.contains("ZERO_NANOS"));
}

#[test]
fn test_csv_export_with_metadata() {
    let mut store = TimelineStore::new();
    let ts = Utc::now();
    store.push(TimelineEntry {
        entity_id: EntityId::MftEntry(99),
        path: r"C:\test\bigfile.dat".to_string(),
        primary_timestamp: ts,
        event_type: EventType::FileCreate,
        timestamps: TimestampSet::default(),
        sources: smallvec![ArtifactSource::Mft],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata {
            file_size: Some(1048576),
            mft_entry_number: Some(99),
            mft_sequence: Some(3),
            is_directory: false,
            has_ads: false,
            parent_path: None,
            sha256: None,
            sha1: None,
        },
    });

    let mut buf = Vec::new();
    export_csv(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    assert!(output.contains("99"));
    assert!(output.contains("1048576"));
    assert!(output.contains("false"));
}

#[test]
fn test_csv_export_with_timestamps() {
    use chrono::TimeZone;

    let mut store = TimelineStore::new();
    let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
    let mut timestamps = TimestampSet::default();
    timestamps.si_created = Some(ts);
    timestamps.fn_created = Some(ts);

    store.push(TimelineEntry {
        entity_id: EntityId::MftEntry(10),
        path: r"C:\test\timestamps.txt".to_string(),
        primary_timestamp: ts,
        event_type: EventType::FileCreate,
        timestamps,
        sources: smallvec![ArtifactSource::Mft],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata::default(),
    });

    let mut buf = Vec::new();
    export_csv(&store, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    assert!(output.contains("2025-06-15 10:30:00"));
}
