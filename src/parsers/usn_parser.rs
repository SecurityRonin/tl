use std::collections::HashMap;

use smallvec::smallvec;

use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// Re-export core USN types from the usnjrnl crate.
pub use usnjrnl::usn::{
    parse_usn_journal, FileAttributes, UsnJournalReader, UsnReason, UsnRecord,
};

// ─── MFT Path Resolution ────────────────────────────────────────────────────

/// Resolves USN record parent MFT entries to full directory paths.
///
/// Built from MFT-sourced entries in the TimelineStore, maps MFT entry
/// numbers to their full paths, enabling reconstruction of complete file
/// paths for USN records (which only contain the filename, not the path).
pub struct MftPathResolver {
    paths: HashMap<u64, String>,
}

impl MftPathResolver {
    /// Create an empty resolver.
    pub fn new() -> Self {
        Self {
            paths: HashMap::new(),
        }
    }

    /// Insert a path mapping directly.
    pub fn insert(&mut self, mft_entry: u64, path: String) {
        self.paths.entry(mft_entry).or_insert(path);
    }

    /// Build from MFT-sourced entries in the TimelineStore.
    ///
    /// Extracts all entries with `EntityId::MftEntry` and `ArtifactSource::Mft`
    /// to build the entry-number → path lookup table.
    pub fn from_store(store: &TimelineStore) -> Self {
        let mut paths = HashMap::new();
        for entry in store.entries() {
            if let EntityId::MftEntry(n) = entry.entity_id {
                if entry.sources.contains(&ArtifactSource::Mft) {
                    paths.entry(n).or_insert_with(|| entry.path.clone());
                }
            }
        }
        Self { paths }
    }

    /// Resolve a USN record's parent entry to a full file path.
    ///
    /// If the parent MFT entry is known, returns `parent_path\filename`.
    /// Otherwise falls back to just the filename.
    pub fn resolve(&self, parent_entry: u64, filename: &str) -> String {
        if let Some(parent_path) = self.paths.get(&parent_entry) {
            format!("{}\\{}", parent_path, filename)
        } else {
            filename.to_string()
        }
    }

    /// Number of resolved paths in the map.
    pub fn len(&self) -> usize {
        self.paths.len()
    }
}

// ─── Timeline merge ──────────────────────────────────────────────────────────

/// Map USN reason flags to the highest-priority EventType.
///
/// Priority order (highest first):
/// 1. FILE_CREATE
/// 2. FILE_DELETE
/// 3. RENAME_OLD_NAME / RENAME_NEW_NAME
/// 4. DATA_OVERWRITE / DATA_EXTEND / DATA_TRUNCATION (file content modification)
/// 5. SECURITY_CHANGE -> Other("SEC")
/// 6. BASIC_INFO_CHANGE -> Other("ATTR")
/// 7. Everything else -> FileModify (catch-all for remaining operations)
fn usn_reason_to_event_type(reason: UsnReason) -> EventType {
    if reason.contains(UsnReason::FILE_CREATE) {
        EventType::FileCreate
    } else if reason.contains(UsnReason::FILE_DELETE) {
        EventType::FileDelete
    } else if reason.intersects(UsnReason::RENAME_OLD_NAME | UsnReason::RENAME_NEW_NAME) {
        EventType::FileRename
    } else if reason.intersects(
        UsnReason::DATA_OVERWRITE | UsnReason::DATA_EXTEND | UsnReason::DATA_TRUNCATION,
    ) {
        EventType::FileModify
    } else if reason.contains(UsnReason::SECURITY_CHANGE) {
        EventType::Other("SEC".to_string())
    } else if reason.contains(UsnReason::BASIC_INFO_CHANGE) {
        EventType::Other("ATTR".to_string())
    } else {
        // Catch-all for named data changes, EA changes, compression, encryption, etc.
        EventType::FileModify
    }
}

/// Merge parsed USN records into the forensic timeline store.
///
/// For each UsnRecord, a TimelineEntry is created with:
/// - entity_id: EntityId::MftEntry(record.mft_entry)
/// - path: record.filename (USN only contains the filename, not the full path)
/// - primary_timestamp: record.timestamp
/// - event_type: mapped from reason flags using priority ordering
/// - timestamps.usn_timestamp: Some(record.timestamp)
/// - sources: [ArtifactSource::UsnJrnl]
/// - anomalies: empty (cross-artifact anomaly detection comes in a later phase)
pub fn merge_usn_to_timeline(records: &[UsnRecord], store: &mut TimelineStore) {
    for record in records {
        let event_type = usn_reason_to_event_type(record.reason);

        let mut timestamps = TimestampSet::default();
        timestamps.usn_timestamp = Some(record.timestamp);

        let metadata = EntryMetadata {
            mft_entry_number: Some(record.mft_entry),
            mft_sequence: Some(record.mft_sequence),
            ..EntryMetadata::default()
        };

        let entry = TimelineEntry {
            entity_id: EntityId::MftEntry(record.mft_entry),
            path: record.filename.clone(),
            primary_timestamp: record.timestamp,
            event_type,
            timestamps,
            sources: smallvec![ArtifactSource::UsnJrnl],
            anomalies: AnomalyFlags::empty(),
            metadata,
        };

        store.push(entry);
    }
}

/// Merge parsed USN records into the timeline with MFT path resolution.
///
/// Like `merge_usn_to_timeline`, but uses `MftPathResolver` to reconstruct
/// full file paths from parent MFT entry numbers.
pub fn merge_usn_to_timeline_with_paths(
    records: &[UsnRecord],
    store: &mut TimelineStore,
    resolver: &MftPathResolver,
) {
    for record in records {
        let event_type = usn_reason_to_event_type(record.reason);
        let full_path = resolver.resolve(record.parent_mft_entry, &record.filename);

        let mut timestamps = TimestampSet::default();
        timestamps.usn_timestamp = Some(record.timestamp);

        let metadata = EntryMetadata {
            mft_entry_number: Some(record.mft_entry),
            mft_sequence: Some(record.mft_sequence),
            ..EntryMetadata::default()
        };

        let entry = TimelineEntry {
            entity_id: EntityId::MftEntry(record.mft_entry),
            path: full_path,
            primary_timestamp: record.timestamp,
            event_type,
            timestamps,
            sources: smallvec![ArtifactSource::UsnJrnl],
            anomalies: AnomalyFlags::empty(),
            metadata,
        };

        store.push(entry);
    }
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    // ─── Event type mapping tests ───────────────────────────────────────

    #[test]
    fn test_usn_reason_to_event_type_create() {
        let reason = UsnReason::FILE_CREATE | UsnReason::CLOSE;
        assert_eq!(usn_reason_to_event_type(reason), EventType::FileCreate);
    }

    #[test]
    fn test_usn_reason_to_event_type_delete() {
        let reason = UsnReason::FILE_DELETE | UsnReason::CLOSE;
        assert_eq!(usn_reason_to_event_type(reason), EventType::FileDelete);
    }

    #[test]
    fn test_usn_reason_to_event_type_rename() {
        assert_eq!(
            usn_reason_to_event_type(UsnReason::RENAME_NEW_NAME),
            EventType::FileRename
        );
        assert_eq!(
            usn_reason_to_event_type(UsnReason::RENAME_OLD_NAME),
            EventType::FileRename
        );
    }

    #[test]
    fn test_usn_reason_to_event_type_modify() {
        assert_eq!(
            usn_reason_to_event_type(UsnReason::DATA_OVERWRITE),
            EventType::FileModify
        );
        assert_eq!(
            usn_reason_to_event_type(UsnReason::DATA_EXTEND),
            EventType::FileModify
        );
        assert_eq!(
            usn_reason_to_event_type(UsnReason::DATA_TRUNCATION),
            EventType::FileModify
        );
    }

    #[test]
    fn test_usn_reason_to_event_type_security() {
        assert_eq!(
            usn_reason_to_event_type(UsnReason::SECURITY_CHANGE),
            EventType::Other("SEC".to_string())
        );
    }

    #[test]
    fn test_usn_reason_to_event_type_basic_info() {
        assert_eq!(
            usn_reason_to_event_type(UsnReason::BASIC_INFO_CHANGE),
            EventType::Other("ATTR".to_string())
        );
    }

    #[test]
    fn test_usn_reason_to_event_type_create_over_modify() {
        // FILE_CREATE should take priority over DATA_OVERWRITE
        let reason = UsnReason::FILE_CREATE | UsnReason::DATA_OVERWRITE;
        assert_eq!(usn_reason_to_event_type(reason), EventType::FileCreate);
    }

    // ─── MFT path resolution tests ─────────────────────────────────────

    #[test]
    fn test_mft_path_resolver_resolve_known_parent() {
        let mut resolver = MftPathResolver::new();
        resolver.insert(5, r"C:\Users\admin\Desktop".to_string());
        assert_eq!(
            resolver.resolve(5, "evil.exe"),
            r"C:\Users\admin\Desktop\evil.exe"
        );
    }

    #[test]
    fn test_mft_path_resolver_resolve_unknown_parent() {
        let resolver = MftPathResolver::new();
        assert_eq!(resolver.resolve(999, "orphan.txt"), "orphan.txt");
    }

    #[test]
    fn test_mft_path_resolver_from_store() {
        let mut store = TimelineStore::new();
        store.push(TimelineEntry {
            entity_id: EntityId::MftEntry(5),
            path: r"C:\Windows\System32".to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            event_type: EventType::FileModify,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        });

        let resolver = MftPathResolver::from_store(&store);
        assert_eq!(
            resolver.resolve(5, "cmd.exe"),
            r"C:\Windows\System32\cmd.exe"
        );
    }

    // ─── Timeline merge tests ───────────────────────────────────────────

    #[test]
    fn test_merge_usn_with_path_resolution() {
        let ts = Utc.with_ymd_and_hms(2025, 8, 10, 12, 0, 0).unwrap();

        let record = UsnRecord {
            mft_entry: 42,
            mft_sequence: 3,
            parent_mft_entry: 5,
            parent_mft_sequence: 1,
            usn: 1024,
            timestamp: ts,
            reason: UsnReason::FILE_CREATE,
            filename: "payload.exe".to_string(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        };

        let mut resolver = MftPathResolver::new();
        resolver.insert(5, r"C:\Users\admin\Downloads".to_string());

        let mut store = TimelineStore::new();
        merge_usn_to_timeline_with_paths(&[record], &mut store, &resolver);

        assert_eq!(store.len(), 1);
        let entry = store.get(0).unwrap();
        assert_eq!(entry.path, r"C:\Users\admin\Downloads\payload.exe");
    }

    #[test]
    fn test_merge_usn_without_path_resolution_falls_back() {
        let ts = Utc.with_ymd_and_hms(2025, 8, 10, 12, 0, 0).unwrap();

        let record = UsnRecord {
            mft_entry: 42,
            mft_sequence: 3,
            parent_mft_entry: 999,
            parent_mft_sequence: 1,
            usn: 1024,
            timestamp: ts,
            reason: UsnReason::FILE_CREATE,
            filename: "orphan.txt".to_string(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        };

        let resolver = MftPathResolver::new(); // empty
        let mut store = TimelineStore::new();
        merge_usn_to_timeline_with_paths(&[record], &mut store, &resolver);

        assert_eq!(store.len(), 1);
        assert_eq!(store.get(0).unwrap().path, "orphan.txt");
    }
}
