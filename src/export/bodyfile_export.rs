use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;
use anyhow::Result;
use bodyfile::Bodyfile3Line;
use std::io::Write;

/// Export the timeline in bodyfile (mactime) format.
///
/// The bodyfile format is: `md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime`
/// where timestamps are Unix epoch seconds (-1 = not available).
///
/// For MFT entries with SI timestamps, we map:
/// - atime  = si_accessed
/// - mtime  = si_modified
/// - ctime  = si_entry_modified (MFT entry change, closest to POSIX ctime)
/// - crtime = si_created
///
/// For non-MFT entries without SI timestamps, we use primary_timestamp as mtime
/// and -1 for the rest.
pub fn export_bodyfile<W: Write>(store: &TimelineStore, writer: &mut W) -> Result<()> {
    for entry in store.entries() {
        let name = format!(
            "{} ({})",
            entry.path,
            entry
                .sources
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join("|")
        );

        let inode = match (&entry.entity_id, entry.metadata.mft_entry_number) {
            (EntityId::MftEntry(n), _) => {
                let seq = entry.metadata.mft_sequence.unwrap_or(0);
                format!("{}-{}", n, seq)
            }
            (_, Some(n)) => {
                let seq = entry.metadata.mft_sequence.unwrap_or(0);
                format!("{}-{}", n, seq)
            }
            _ => "0".to_string(),
        };

        let size = entry.metadata.file_size.unwrap_or(0);

        let md5 = entry
            .metadata
            .sha256
            .as_deref()
            .unwrap_or("0")
            .to_string();

        let atime = ts_to_epoch(entry.timestamps.si_accessed);
        let mtime = ts_to_epoch(entry.timestamps.si_modified);
        let ctime = ts_to_epoch(entry.timestamps.si_entry_modified);
        let crtime = ts_to_epoch(entry.timestamps.si_created);

        // If no SI timestamps, use primary_timestamp as mtime
        let mtime = if mtime == -1 && atime == -1 && ctime == -1 && crtime == -1 {
            entry.primary_timestamp.timestamp()
        } else {
            mtime
        };

        let line = Bodyfile3Line::new()
            .with_owned_md5(md5)
            .with_owned_name(name)
            .with_owned_inode(inode)
            .with_size(size)
            .with_atime(atime)
            .with_mtime(mtime)
            .with_ctime(ctime)
            .with_crtime(crtime);

        writeln!(writer, "{}", line)?;
    }

    Ok(())
}

/// Convert an optional timestamp to Unix epoch seconds, or -1 if absent.
fn ts_to_epoch(ts: Option<chrono::DateTime<chrono::Utc>>) -> i64 {
    ts.map(|t| t.timestamp()).unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use smallvec::smallvec;

    fn make_entry_basic() -> TimelineEntry {
        TimelineEntry {
            entity_id: EntityId::MftEntry(100),
            path: "C:\\Windows\\System32\\evil.exe".to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 12, 30, 0).unwrap(),
            event_type: EventType::FileCreate,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata {
                file_size: Some(1024),
                mft_entry_number: Some(100),
                mft_sequence: Some(5),
                is_directory: false,
                has_ads: false,
                parent_path: None,
                sha256: Some("abc123def".to_string()),
                sha1: None,
            },
        }
    }

    #[test]
    fn test_export_bodyfile_basic_output() {
        let mut store = TimelineStore::new();
        store.push(make_entry_basic());

        let mut buf = Vec::new();
        export_bodyfile(&store, &mut buf).unwrap();

        let output = String::from_utf8(buf).unwrap();
        // Should contain the path with source
        assert!(output.contains("evil.exe"), "Output: {}", output);
        assert!(output.contains("MFT"), "Output: {}", output);
    }

    #[test]
    fn test_export_bodyfile_empty_store() {
        let store = TimelineStore::new();
        let mut buf = Vec::new();
        export_bodyfile(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn test_ts_to_epoch_with_timestamp() {
        let ts = Some(Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap());
        let epoch = ts_to_epoch(ts);
        assert!(epoch > 0);
        assert_eq!(epoch, 1735689600);
    }

    #[test]
    fn test_ts_to_epoch_none_returns_negative_one() {
        assert_eq!(ts_to_epoch(None), -1);
    }

    #[test]
    fn test_export_bodyfile_inode_with_mft_entry_id() {
        let mut store = TimelineStore::new();
        let entry = TimelineEntry {
            entity_id: EntityId::MftEntry(42),
            path: "test.txt".to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            event_type: EventType::FileCreate,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata {
                mft_sequence: Some(3),
                ..EntryMetadata::default()
            },
        };
        store.push(entry);

        let mut buf = Vec::new();
        export_bodyfile(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("42-3"), "Expected inode 42-3, got: {}", output);
    }

    #[test]
    fn test_export_bodyfile_inode_with_metadata_mft_number() {
        let mut store = TimelineStore::new();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(999),
            path: "test.txt".to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            event_type: EventType::FileCreate,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata {
                mft_entry_number: Some(77),
                mft_sequence: Some(2),
                ..EntryMetadata::default()
            },
        };
        store.push(entry);

        let mut buf = Vec::new();
        export_bodyfile(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("77-2"), "Expected inode 77-2, got: {}", output);
    }

    #[test]
    fn test_export_bodyfile_inode_fallback_zero() {
        let mut store = TimelineStore::new();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(1),
            path: "test.txt".to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            event_type: EventType::FileCreate,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(), // no mft_entry_number
        };
        store.push(entry);

        let mut buf = Vec::new();
        export_bodyfile(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // The inode field should be "0"
        assert!(output.contains("|0|"), "Expected |0| inode, got: {}", output);
    }

    #[test]
    fn test_export_bodyfile_no_sha256_uses_zero() {
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
                sha256: None,
                ..EntryMetadata::default()
            },
        };
        store.push(entry);

        let mut buf = Vec::new();
        export_bodyfile(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // md5 field (first field) should be "0" when sha256 is None
        assert!(output.starts_with("0|"), "Expected md5=0, got: {}", output);
    }

    #[test]
    fn test_export_bodyfile_si_timestamps_used() {
        let mut store = TimelineStore::new();
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
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
        export_bodyfile(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // SI timestamps present, so they should be used
        let epoch = ts.timestamp().to_string();
        assert!(output.contains(&epoch), "Expected epoch {} in: {}", epoch, output);
    }

    #[test]
    fn test_export_bodyfile_no_si_timestamps_uses_primary() {
        let mut store = TimelineStore::new();
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(1),
            path: "test.txt".to_string(),
            primary_timestamp: ts,
            event_type: EventType::FileCreate,
            timestamps: TimestampSet::default(), // all None
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };
        store.push(entry);

        let mut buf = Vec::new();
        export_bodyfile(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // When no SI timestamps, primary_timestamp should be used as mtime
        let epoch = ts.timestamp().to_string();
        assert!(output.contains(&epoch), "Expected primary ts epoch {} in: {}", epoch, output);
    }

    #[test]
    fn test_export_bodyfile_multiple_sources() {
        let mut store = TimelineStore::new();
        let entry = TimelineEntry {
            entity_id: EntityId::Generated(1),
            path: "test.txt".to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            event_type: EventType::FileCreate,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft, ArtifactSource::UsnJrnl],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };
        store.push(entry);

        let mut buf = Vec::new();
        export_bodyfile(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("MFT|USN"), "Expected MFT|USN in: {}", output);
    }

    #[test]
    fn test_export_bodyfile_mft_entry_without_sequence() {
        let mut store = TimelineStore::new();
        let entry = TimelineEntry {
            entity_id: EntityId::MftEntry(50),
            path: "test.txt".to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            event_type: EventType::FileCreate,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata {
                mft_sequence: None, // no sequence
                ..EntryMetadata::default()
            },
        };
        store.push(entry);

        let mut buf = Vec::new();
        export_bodyfile(&store, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Default sequence is 0
        assert!(output.contains("50-0"), "Expected 50-0 in: {}", output);
    }
}
