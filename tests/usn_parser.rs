use std::path::Path;
use tl::collection::provider::CollectionProvider;
use tl::collection::velociraptor::VelociraptorProvider;
use tl::parsers::usn_parser::{
    parse_usn_journal, merge_usn_to_timeline, merge_usn_to_timeline_with_paths,
    UsnReason, FileAttributes, MftPathResolver,
};
use tl::timeline::entry::*;
use tl::timeline::store::TimelineStore;

/// Build a minimal valid USN_RECORD_V2 in a byte buffer.
fn build_usn_record_v2(
    mft_entry: u64,
    mft_seq: u16,
    parent_mft_entry: u64,
    parent_mft_seq: u16,
    usn: i64,
    filetime: i64,
    reason: u32,
    filename: &str,
    file_attributes: u32,
) -> Vec<u8> {
    // Encode filename as UTF-16LE
    let utf16: Vec<u16> = filename.encode_utf16().collect();
    let filename_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let filename_len = filename_bytes.len() as u16;
    let filename_offset: u16 = 0x3C; // standard offset for V2

    // RecordLength must be aligned to 8 bytes
    let raw_len = 0x3C + filename_bytes.len();
    let record_len = ((raw_len + 7) / 8) * 8;

    let mut buf = vec![0u8; record_len];

    // RecordLength (u32 at 0x00)
    buf[0x00..0x04].copy_from_slice(&(record_len as u32).to_le_bytes());
    // MajorVersion (u16 at 0x04) = 2
    buf[0x04..0x06].copy_from_slice(&2u16.to_le_bytes());
    // MinorVersion (u16 at 0x06) = 0
    buf[0x06..0x08].copy_from_slice(&0u16.to_le_bytes());
    // FileReferenceNumber (u64 at 0x08)
    let file_ref = mft_entry | ((mft_seq as u64) << 48);
    buf[0x08..0x10].copy_from_slice(&file_ref.to_le_bytes());
    // ParentFileReferenceNumber (u64 at 0x10)
    let parent_ref = parent_mft_entry | ((parent_mft_seq as u64) << 48);
    buf[0x10..0x18].copy_from_slice(&parent_ref.to_le_bytes());
    // Usn (i64 at 0x18)
    buf[0x18..0x20].copy_from_slice(&usn.to_le_bytes());
    // TimeStamp (i64 at 0x20) -- FILETIME
    buf[0x20..0x28].copy_from_slice(&filetime.to_le_bytes());
    // Reason (u32 at 0x28)
    buf[0x28..0x2C].copy_from_slice(&reason.to_le_bytes());
    // SourceInfo (u32 at 0x2C)
    buf[0x2C..0x30].copy_from_slice(&0u32.to_le_bytes());
    // SecurityId (u32 at 0x30)
    buf[0x30..0x34].copy_from_slice(&0u32.to_le_bytes());
    // FileAttributes (u32 at 0x34)
    buf[0x34..0x38].copy_from_slice(&file_attributes.to_le_bytes());
    // FileNameLength (u16 at 0x38)
    buf[0x38..0x3A].copy_from_slice(&filename_len.to_le_bytes());
    // FileNameOffset (u16 at 0x3A)
    buf[0x3A..0x3C].copy_from_slice(&filename_offset.to_le_bytes());
    // FileName (variable at 0x3C)
    buf[0x3C..0x3C + filename_bytes.len()].copy_from_slice(&filename_bytes);

    buf
}

/// Convert a DateTime<Utc> to a Windows FILETIME i64 for test construction.
fn datetime_to_filetime(dt: chrono::DateTime<chrono::Utc>) -> i64 {
    const EPOCH_DIFF: i64 = 11_644_473_600;
    let secs = dt.timestamp() + EPOCH_DIFF;
    let nanos = dt.timestamp_subsec_nanos() as i64;
    secs * 10_000_000 + nanos / 100
}

// ─── Unit Tests ───────────────────────────────────────────────────────────────

#[test]
fn test_parse_synthetic_usn_record_file_create() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 8, 10, 12, 30, 45).unwrap();
    let filetime = datetime_to_filetime(ts);

    let record_bytes = build_usn_record_v2(
        42,    // mft_entry
        3,     // mft_seq
        5,     // parent_mft_entry
        1,     // parent_mft_seq
        1024,  // usn
        filetime,
        0x00000100, // FILE_CREATE
        "test_file.txt",
        0x20, // FILE_ATTRIBUTE_ARCHIVE
    );

    let records = parse_usn_journal(&record_bytes).unwrap();
    assert_eq!(records.len(), 1);

    let r = &records[0];
    assert_eq!(r.mft_entry, 42);
    assert_eq!(r.mft_sequence, 3);
    assert_eq!(r.parent_mft_entry, 5);
    assert_eq!(r.parent_mft_sequence, 1);
    assert_eq!(r.usn, 1024);
    assert_eq!(r.filename, "test_file.txt");
    assert!(r.reason.contains(UsnReason::FILE_CREATE));
    assert!(r.file_attributes.contains(FileAttributes::ARCHIVE));
    // Timestamp should be within 1 second of what we set
    let diff = (r.timestamp - ts).num_seconds().abs();
    assert!(diff < 2, "Timestamp mismatch: expected ~{}, got {}", ts, r.timestamp);
}

#[test]
fn test_parse_synthetic_usn_record_rename() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 6, 15, 8, 0, 0).unwrap();
    let filetime = datetime_to_filetime(ts);

    let record_bytes = build_usn_record_v2(
        100, 7, 10, 2,
        2048,
        filetime,
        0x00002000, // RENAME_NEW_NAME
        "renamed_doc.docx",
        0x20,
    );

    let records = parse_usn_journal(&record_bytes).unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].reason.contains(UsnReason::RENAME_NEW_NAME));
    assert_eq!(records[0].filename, "renamed_doc.docx");
}

#[test]
fn test_parse_multiple_records() {
    use chrono::{TimeZone, Utc};

    let ts1 = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
    let ts2 = Utc.with_ymd_and_hms(2025, 2, 1, 0, 0, 0).unwrap();

    let mut data = build_usn_record_v2(
        1, 1, 5, 1, 100,
        datetime_to_filetime(ts1),
        0x00000100, // FILE_CREATE
        "file1.txt", 0x20,
    );
    data.extend(build_usn_record_v2(
        2, 1, 5, 1, 200,
        datetime_to_filetime(ts2),
        0x00000002, // DATA_EXTEND
        "file2.txt", 0x20,
    ));

    let records = parse_usn_journal(&data).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].filename, "file1.txt");
    assert_eq!(records[1].filename, "file2.txt");
}

#[test]
fn test_skip_close_only_records() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

    // CLOSE-only record should be skipped
    let mut data = build_usn_record_v2(
        1, 1, 5, 1, 100,
        datetime_to_filetime(ts),
        0x80000000, // CLOSE only
        "skipped.txt", 0x20,
    );
    // FILE_CREATE + CLOSE should NOT be skipped
    data.extend(build_usn_record_v2(
        2, 1, 5, 1, 200,
        datetime_to_filetime(ts),
        0x80000100, // FILE_CREATE | CLOSE
        "kept.txt", 0x20,
    ));

    let records = parse_usn_journal(&data).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].filename, "kept.txt");
}

#[test]
fn test_skip_zero_filled_regions() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 3, 15, 10, 0, 0).unwrap();

    // Start with a block of zeros (sparse region)
    let mut data = vec![0u8; 512];
    // Then a valid record
    data.extend(build_usn_record_v2(
        99, 2, 10, 1, 500,
        datetime_to_filetime(ts),
        0x00000100, // FILE_CREATE
        "after_zeros.txt", 0x20,
    ));

    let records = parse_usn_journal(&data).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].filename, "after_zeros.txt");
}

#[test]
fn test_skip_v3_records() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 5, 1, 0, 0, 0).unwrap();

    // Build a "V3" record (MajorVersion=3) -- should be skipped
    let mut v3_buf = build_usn_record_v2(
        10, 1, 5, 1, 100,
        datetime_to_filetime(ts),
        0x00000100, "v3file.txt", 0x20,
    );
    // Overwrite MajorVersion to 3
    v3_buf[0x04..0x06].copy_from_slice(&3u16.to_le_bytes());

    // Follow with a valid V2 record
    let v2_buf = build_usn_record_v2(
        20, 1, 5, 1, 200,
        datetime_to_filetime(ts),
        0x00000100, "v2file.txt", 0x20,
    );

    let mut data = v3_buf;
    data.extend(v2_buf);

    let records = parse_usn_journal(&data).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].filename, "v2file.txt");
}

#[test]
fn test_parse_empty_data() {
    let records = parse_usn_journal(&[]).unwrap();
    assert!(records.is_empty());
}

#[test]
fn test_parse_all_zeros() {
    let data = vec![0u8; 4096];
    let records = parse_usn_journal(&data).unwrap();
    assert!(records.is_empty());
}

#[test]
fn test_unicode_filename() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 7, 4, 12, 0, 0).unwrap();
    let record = build_usn_record_v2(
        50, 1, 5, 1, 300,
        datetime_to_filetime(ts),
        0x00000100,
        "\u{00E9}\u{00E8}\u{00EA}.txt", // accented characters
        0x20,
    );

    let records = parse_usn_journal(&record).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].filename, "\u{00E9}\u{00E8}\u{00EA}.txt");
}

// ─── USN Reason flag tests ───────────────────────────────────────────────────

#[test]
fn test_usn_reason_flags() {
    let reason = UsnReason::FILE_CREATE | UsnReason::CLOSE;
    assert!(reason.contains(UsnReason::FILE_CREATE));
    assert!(reason.contains(UsnReason::CLOSE));
    assert!(!reason.contains(UsnReason::FILE_DELETE));
}

#[test]
fn test_usn_reason_multiple_flags() {
    let reason = UsnReason::DATA_OVERWRITE | UsnReason::DATA_EXTEND | UsnReason::CLOSE;
    assert!(reason.contains(UsnReason::DATA_OVERWRITE));
    assert!(reason.contains(UsnReason::DATA_EXTEND));
    assert!(reason.contains(UsnReason::CLOSE));
}

// ─── Task 2.2: merge_usn_to_timeline tests ──────────────────────────────────

#[test]
fn test_merge_file_create_to_timeline() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 8, 10, 12, 30, 45).unwrap();
    let data = build_usn_record_v2(
        42, 3, 5, 1, 1024,
        datetime_to_filetime(ts),
        0x00000100, // FILE_CREATE
        "new_file.txt", 0x20,
    );

    let records = parse_usn_journal(&data).unwrap();
    let mut store = TimelineStore::new();
    merge_usn_to_timeline(&records, &mut store);

    assert_eq!(store.len(), 1);
    let entry = store.get(0).unwrap();
    assert_eq!(entry.event_type, EventType::FileCreate);
    assert_eq!(entry.path, "new_file.txt");
    assert!(entry.sources.contains(&ArtifactSource::UsnJrnl));
    assert!(entry.timestamps.usn_timestamp.is_some());
    assert_eq!(entry.entity_id, EntityId::MftEntry(42));
}

#[test]
fn test_merge_file_delete_to_timeline() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 4, 1, 0, 0, 0).unwrap();
    let data = build_usn_record_v2(
        10, 1, 5, 1, 500,
        datetime_to_filetime(ts),
        0x00000200, // FILE_DELETE
        "deleted.tmp", 0x20,
    );

    let records = parse_usn_journal(&data).unwrap();
    let mut store = TimelineStore::new();
    merge_usn_to_timeline(&records, &mut store);

    assert_eq!(store.len(), 1);
    assert_eq!(store.get(0).unwrap().event_type, EventType::FileDelete);
}

#[test]
fn test_merge_file_modify_to_timeline() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 5, 1, 0, 0, 0).unwrap();
    let data = build_usn_record_v2(
        15, 1, 5, 1, 600,
        datetime_to_filetime(ts),
        0x00000001, // DATA_OVERWRITE
        "modified.dat", 0x20,
    );

    let records = parse_usn_journal(&data).unwrap();
    let mut store = TimelineStore::new();
    merge_usn_to_timeline(&records, &mut store);

    assert_eq!(store.len(), 1);
    assert_eq!(store.get(0).unwrap().event_type, EventType::FileModify);
}

#[test]
fn test_merge_rename_to_timeline() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap();
    let data = build_usn_record_v2(
        20, 1, 5, 1, 700,
        datetime_to_filetime(ts),
        0x00002000, // RENAME_NEW_NAME
        "new_name.txt", 0x20,
    );

    let records = parse_usn_journal(&data).unwrap();
    let mut store = TimelineStore::new();
    merge_usn_to_timeline(&records, &mut store);

    assert_eq!(store.len(), 1);
    assert_eq!(store.get(0).unwrap().event_type, EventType::FileRename);
}

#[test]
fn test_merge_security_change_to_timeline() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 7, 1, 0, 0, 0).unwrap();
    let data = build_usn_record_v2(
        25, 1, 5, 1, 800,
        datetime_to_filetime(ts),
        0x00000800, // SECURITY_CHANGE
        "secured.exe", 0x20,
    );

    let records = parse_usn_journal(&data).unwrap();
    let mut store = TimelineStore::new();
    merge_usn_to_timeline(&records, &mut store);

    assert_eq!(store.len(), 1);
    assert_eq!(store.get(0).unwrap().event_type, EventType::Other("SEC".to_string()));
}

#[test]
fn test_merge_basic_info_change_to_timeline() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 7, 1, 0, 0, 0).unwrap();
    let data = build_usn_record_v2(
        30, 1, 5, 1, 900,
        datetime_to_filetime(ts),
        0x00008000, // BASIC_INFO_CHANGE
        "attrs_changed.dll", 0x20,
    );

    let records = parse_usn_journal(&data).unwrap();
    let mut store = TimelineStore::new();
    merge_usn_to_timeline(&records, &mut store);

    assert_eq!(store.len(), 1);
    assert_eq!(store.get(0).unwrap().event_type, EventType::Other("ATTR".to_string()));
}

#[test]
fn test_merge_priority_create_over_modify() {
    // When both FILE_CREATE and DATA_OVERWRITE are set, FILE_CREATE should win
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 8, 1, 0, 0, 0).unwrap();
    let data = build_usn_record_v2(
        35, 1, 5, 1, 1000,
        datetime_to_filetime(ts),
        0x00000101, // FILE_CREATE | DATA_OVERWRITE
        "created_and_written.txt", 0x20,
    );

    let records = parse_usn_journal(&data).unwrap();
    let mut store = TimelineStore::new();
    merge_usn_to_timeline(&records, &mut store);

    assert_eq!(store.len(), 1);
    // FILE_CREATE has higher priority than DATA_OVERWRITE
    assert_eq!(store.get(0).unwrap().event_type, EventType::FileCreate);
}

#[test]
fn test_merge_priority_delete_over_modify() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 8, 1, 0, 0, 0).unwrap();
    let data = build_usn_record_v2(
        36, 1, 5, 1, 1100,
        datetime_to_filetime(ts),
        0x00000201, // FILE_DELETE | DATA_OVERWRITE
        "delete_and_overwrite.txt", 0x20,
    );

    let records = parse_usn_journal(&data).unwrap();
    let mut store = TimelineStore::new();
    merge_usn_to_timeline(&records, &mut store);

    assert_eq!(store.len(), 1);
    assert_eq!(store.get(0).unwrap().event_type, EventType::FileDelete);
}

// ─── Integration test with real collection ───────────────────────────────────

#[test]
fn test_parse_real_usnjrnl() {
    let zip_path = Path::new("test/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
    if !zip_path.exists() {
        eprintln!("Skipping: test collection not found");
        return;
    }
    let provider = VelociraptorProvider::open(zip_path).unwrap();
    let manifest = provider.discover();

    let usn_path = manifest.usnjrnl_j.as_ref().expect("No $UsnJrnl:$J found");
    let usn_data = provider.open_file(usn_path).unwrap();
    eprintln!("$UsnJrnl:$J size: {} bytes", usn_data.len());

    let records = parse_usn_journal(&usn_data).unwrap();
    eprintln!("Parsed {} USN records", records.len());

    // A real journal should have many records
    assert!(records.len() > 100, "Expected >100 USN records, got {}", records.len());

    // Check variety of reason codes
    let has_create = records.iter().any(|r| r.reason.contains(UsnReason::FILE_CREATE));
    let has_delete = records.iter().any(|r| r.reason.contains(UsnReason::FILE_DELETE));
    let has_modify = records.iter().any(|r| {
        r.reason.contains(UsnReason::DATA_OVERWRITE)
            || r.reason.contains(UsnReason::DATA_EXTEND)
            || r.reason.contains(UsnReason::DATA_TRUNCATION)
    });
    let has_rename = records.iter().any(|r| {
        r.reason.contains(UsnReason::RENAME_OLD_NAME)
            || r.reason.contains(UsnReason::RENAME_NEW_NAME)
    });

    eprintln!("  FILE_CREATE present: {}", has_create);
    eprintln!("  FILE_DELETE present: {}", has_delete);
    eprintln!("  DATA_* (modify) present: {}", has_modify);
    eprintln!("  RENAME_* present: {}", has_rename);

    assert!(has_create, "Expected FILE_CREATE records in real journal");
}

#[test]
fn test_merge_real_usnjrnl_to_timeline() {
    let zip_path = Path::new("test/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
    if !zip_path.exists() {
        eprintln!("Skipping: test collection not found");
        return;
    }
    let provider = VelociraptorProvider::open(zip_path).unwrap();
    let manifest = provider.discover();

    // Parse MFT first
    let mut store = TimelineStore::new();
    if let Some(ref mft_path) = manifest.mft {
        let mft_data = provider.open_file(mft_path).unwrap();
        tl::parsers::mft_parser::parse_mft(&mft_data, &mut store).unwrap();
    }
    let mft_count = store.len();
    eprintln!("MFT entries: {}", mft_count);

    // Parse and merge USN with MFT path resolution
    let usn_path = manifest.usnjrnl_j.as_ref().expect("No $UsnJrnl:$J found");
    let usn_data = provider.open_file(usn_path).unwrap();
    let records = parse_usn_journal(&usn_data).unwrap();
    let usn_count = records.len();
    let resolver = MftPathResolver::from_store(&store);
    eprintln!("MFT path resolver: {} entries", resolver.len());
    merge_usn_to_timeline_with_paths(&records, &mut store, &resolver);

    eprintln!("USN records: {}", usn_count);
    eprintln!("Total timeline entries: {}", store.len());
    assert!(store.len() > mft_count, "Timeline should grow after USN merge");

    // Sort and verify ordering
    store.sort();
    let timestamps: Vec<_> = store.entries().map(|e| e.primary_timestamp).collect();
    assert!(timestamps.windows(2).all(|w| w[0] <= w[1]), "Timeline should be sorted");

    // Verify USN-sourced entries exist
    let usn_entries: Vec<_> = store.entries()
        .filter(|e| e.sources.contains(&ArtifactSource::UsnJrnl))
        .collect();
    assert!(!usn_entries.is_empty(), "Should have USN-sourced entries");
    eprintln!("USN-sourced timeline entries: {}", usn_entries.len());

    // Verify path resolution enriched at least some entries with full paths
    let resolved_count = usn_entries.iter()
        .filter(|e| e.path.contains('\\'))
        .count();
    eprintln!("USN entries with resolved paths: {}/{}", resolved_count, usn_entries.len());
    assert!(resolved_count > 0, "MFT path resolution should resolve at least some USN entries");
}

// ─── V3 record integration tests ────────────────────────────────────────────

#[test]
fn test_parse_v3_record_integration() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 9, 1, 10, 0, 0).unwrap();
    let filetime = datetime_to_filetime(ts);

    // Build V3 record with 128-bit file references
    let utf16: Vec<u16> = "refs_data.txt".encode_utf16().collect();
    let fn_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let filename_offset: u16 = 0x4C;
    let raw_len = 0x4C + fn_bytes.len();
    let record_len = ((raw_len + 7) / 8) * 8;
    let mut buf = vec![0u8; record_len];

    buf[0x00..0x04].copy_from_slice(&(record_len as u32).to_le_bytes());
    buf[0x04..0x06].copy_from_slice(&3u16.to_le_bytes()); // V3
    // FileReferenceNumber (u128) - lower 64 bits = 42
    buf[0x08..0x10].copy_from_slice(&42u64.to_le_bytes());
    buf[0x10..0x18].copy_from_slice(&0u64.to_le_bytes());
    // ParentFileReferenceNumber (u128) - lower 64 bits = 5
    buf[0x18..0x20].copy_from_slice(&5u64.to_le_bytes());
    buf[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());
    buf[0x28..0x30].copy_from_slice(&3000i64.to_le_bytes()); // usn
    buf[0x30..0x38].copy_from_slice(&filetime.to_le_bytes());
    buf[0x38..0x3C].copy_from_slice(&0x100u32.to_le_bytes()); // FILE_CREATE
    buf[0x44..0x48].copy_from_slice(&0x20u32.to_le_bytes()); // ARCHIVE
    buf[0x48..0x4A].copy_from_slice(&(fn_bytes.len() as u16).to_le_bytes());
    buf[0x4A..0x4C].copy_from_slice(&filename_offset.to_le_bytes());
    buf[0x4C..0x4C + fn_bytes.len()].copy_from_slice(&fn_bytes);

    let records = parse_usn_journal(&buf).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].filename, "refs_data.txt");
    assert_eq!(records[0].mft_entry, 42);
    assert_eq!(records[0].mft_sequence, 0); // V3 doesn't use NTFS sequence split

    // Merge with path resolver
    let mut resolver = MftPathResolver::new();
    resolver.insert(5, r"D:\ReFS\Share".to_string());

    let mut store = TimelineStore::new();
    merge_usn_to_timeline_with_paths(&records, &mut store, &resolver);

    assert_eq!(store.len(), 1);
    assert_eq!(store.get(0).unwrap().path, r"D:\ReFS\Share\refs_data.txt");
    assert_eq!(store.get(0).unwrap().event_type, EventType::FileCreate);
}

#[test]
fn test_file_attributes_display_in_context() {
    use chrono::{TimeZone, Utc};

    let ts = Utc.with_ymd_and_hms(2025, 8, 10, 12, 0, 0).unwrap();
    let data = build_usn_record_v2(
        42, 3, 5, 1, 1024,
        datetime_to_filetime(ts),
        0x00000100, // FILE_CREATE
        "hidden_system.dll",
        0x06, // HIDDEN | SYSTEM
    );

    let records = parse_usn_journal(&data).unwrap();
    assert_eq!(records.len(), 1);
    let display = format!("{}", records[0].file_attributes);
    assert!(display.contains("HIDDEN"), "got: {}", display);
    assert!(display.contains("SYSTEM"), "got: {}", display);

    let reason_display = format!("{}", records[0].reason);
    assert!(reason_display.contains("FILE_CREATE"), "got: {}", reason_display);
}
