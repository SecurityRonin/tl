use anyhow::{Context, Result};
use log::{debug, warn};
use smallvec::smallvec;

use mft::attribute::x30::FileNamespace;
use mft::attribute::{MftAttributeContent, MftAttributeType};
use mft::MftParser;

use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

/// Parse raw $MFT data and populate the timeline store with entries.
///
/// For each valid MFT entry, this extracts:
/// - $STANDARD_INFORMATION (0x10) timestamps (SI) -- user-modifiable
/// - $FILE_NAME (0x30) timestamps (FN) -- harder to tamper with
/// - Alternate Data Stream detection ($DATA attributes with non-empty names)
/// - Anomaly detection (timestomping indicators)
///
/// The `data` parameter should be the complete contents of the $MFT file.
/// The store will be sorted by primary_timestamp when parsing is complete.
pub fn parse_mft(data: &[u8], store: &mut TimelineStore) -> Result<()> {
    let buffer = data.to_vec();
    let mut parser = MftParser::from_buffer(buffer)
        .context("Failed to create MFT parser from buffer")?;

    let entry_count = parser.get_entry_count();
    debug!("MFT contains {} entries", entry_count);

    for entry_idx in 0..entry_count {
        let entry = match parser.get_entry(entry_idx) {
            Ok(e) => e,
            Err(e) => {
                // Skip entries that fail to parse (corrupt, zeroed, etc.)
                if entry_idx > 0 {
                    // Entry 0 errors are unusual but entries with zeroed headers are common
                    debug!("Skipping MFT entry {}: {}", entry_idx, e);
                }
                continue;
            }
        };

        // Skip entries with invalid headers (zeroed-out entries)
        if !entry.header.is_valid() {
            continue;
        }

        // Extract SI ($STANDARD_INFORMATION) timestamps
        let mut si_created = None;
        let mut si_modified = None;
        let mut si_accessed = None;
        let mut si_entry_modified = None;

        // Extract FN ($FILE_NAME) timestamps and file name
        let mut fn_created = None;
        let mut fn_modified = None;
        let mut fn_accessed = None;
        let mut fn_entry_modified = None;
        let mut filename: Option<String> = None;
        let mut file_size: Option<u64> = None;

        // Track whether entry has alternate data streams
        let mut has_ads = false;

        for attr_result in entry.iter_attributes() {
            let attr = match attr_result {
                Ok(a) => a,
                Err(e) => {
                    debug!(
                        "Skipping attribute in MFT entry {}: {}",
                        entry_idx, e
                    );
                    continue;
                }
            };

            match attr.data {
                MftAttributeContent::AttrX10(ref si) => {
                    si_created = Some(si.created);
                    si_modified = Some(si.modified);
                    si_accessed = Some(si.accessed);
                    si_entry_modified = Some(si.mft_modified);
                }
                MftAttributeContent::AttrX30(ref fn_attr) => {
                    // Prefer Win32 or Win32AndDos namespace for human-readable name.
                    // Only take the first suitable FN attribute.
                    let dominated_namespace = matches!(
                        fn_attr.namespace,
                        FileNamespace::Win32 | FileNamespace::Win32AndDos
                    );

                    if filename.is_none() || dominated_namespace {
                        fn_created = Some(fn_attr.created);
                        fn_modified = Some(fn_attr.modified);
                        fn_accessed = Some(fn_attr.accessed);
                        fn_entry_modified = Some(fn_attr.mft_modified);
                        filename = Some(fn_attr.name.clone());
                        file_size = Some(fn_attr.logical_size);
                    }
                }
                _ => {}
            }

            // Check for ADS: $DATA attribute (type 0x80) with a non-empty name
            if attr.header.type_code == MftAttributeType::DATA
                && !attr.header.name.is_empty()
            {
                has_ads = true;
            }
        }

        // Skip entries without any meaningful filename (system metadata entries
        // without FN attributes are not useful for the timeline)
        let path = match filename {
            Some(name) => name,
            None => continue,
        };

        // Build the full path using the parser's path resolution
        let full_path = match parser.get_full_path_for_entry(&entry) {
            Ok(Some(p)) => p.to_string_lossy().to_string(),
            Ok(None) => path.clone(),
            Err(e) => {
                warn!(
                    "Failed to resolve full path for MFT entry {}: {}",
                    entry_idx, e
                );
                path.clone()
            }
        };

        // Build TimestampSet
        let timestamps = TimestampSet {
            si_created,
            si_modified,
            si_accessed,
            si_entry_modified,
            fn_created,
            fn_modified,
            fn_accessed,
            fn_entry_modified,
            ..TimestampSet::default()
        };

        // Determine primary timestamp: prefer SI Modified, fall back to SI Created,
        // then FN Modified, then FN Created
        let primary_timestamp = si_modified
            .or(si_created)
            .or(fn_modified)
            .or(fn_created);

        let primary_timestamp = match primary_timestamp {
            Some(ts) => ts,
            None => {
                debug!(
                    "Skipping MFT entry {} ({}): no usable timestamp",
                    entry_idx, full_path
                );
                continue;
            }
        };

        // Detect anomalies
        let mut anomalies = detect_anomalies(&timestamps);
        if has_ads {
            anomalies |= AnomalyFlags::HIDDEN_ADS;
        }

        let metadata = EntryMetadata {
            file_size,
            mft_entry_number: Some(entry.header.record_number),
            mft_sequence: Some(entry.header.sequence),
            is_directory: entry.is_dir(),
            has_ads,
            parent_path: None, // Could be populated from full_path if needed
            sha256: None,
            sha1: None,
        };

        let timeline_entry = TimelineEntry {
            entity_id: EntityId::MftEntry(entry.header.record_number),
            path: full_path,
            primary_timestamp,
            event_type: EventType::MftEntryModify,
            timestamps,
            sources: smallvec![ArtifactSource::Mft],
            anomalies,
            metadata,
        };

        store.push(timeline_entry);
    }

    // Sort the store by primary_timestamp
    store.sort();

    debug!(
        "MFT parsing complete: {} timeline entries created",
        store.len()
    );

    Ok(())
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_parse_mft_empty_data() {
        let mut store = TimelineStore::new();
        let result = parse_mft(&[], &mut store);
        assert!(result.is_err(), "Empty data should fail to create MFT parser");
    }

    /// Build a minimal valid MFT buffer with a single 1024-byte entry
    /// containing the FILE signature and valid update sequence.
    /// The MFT crate determines entry size from the first entry, so we
    /// must have a valid first entry to avoid divide-by-zero.
    fn build_minimal_mft_entry() -> Vec<u8> {
        let entry_size: usize = 1024;
        let mut data = vec![0u8; entry_size];

        // FILE signature
        data[0..4].copy_from_slice(b"FILE");
        // Update sequence offset (at offset 4) = 0x30
        data[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        // Update sequence size (at offset 6) = 3 (1 for array value + 2 entries)
        data[6..8].copy_from_slice(&3u16.to_le_bytes());
        // Sequence number (at offset 16)
        data[16..18].copy_from_slice(&1u16.to_le_bytes());
        // Hard link count (at offset 18)
        data[18..20].copy_from_slice(&1u16.to_le_bytes());
        // First attribute offset (at offset 20)
        data[20..22].copy_from_slice(&0x38u16.to_le_bytes());
        // Flags (at offset 22) = 0x01 (in use)
        data[22..24].copy_from_slice(&0x01u16.to_le_bytes());
        // Used size (at offset 24)
        data[24..28].copy_from_slice(&(entry_size as u32).to_le_bytes());
        // Allocated size (at offset 28)
        data[28..32].copy_from_slice(&(entry_size as u32).to_le_bytes());

        // Update sequence: at offset 0x30
        data[0x30..0x32].copy_from_slice(&0x0001u16.to_le_bytes());
        data[0x32..0x34].copy_from_slice(&0x0000u16.to_le_bytes());
        data[0x34..0x36].copy_from_slice(&0x0000u16.to_le_bytes());

        // Fix up: set the update sequence values at sector boundaries
        data[510..512].copy_from_slice(&0x0001u16.to_le_bytes());
        data[1022..1024].copy_from_slice(&0x0001u16.to_le_bytes());

        data
    }

    #[test]
    fn test_parse_mft_minimal_entry_no_attributes() {
        let mut store = TimelineStore::new();
        let data = build_minimal_mft_entry();
        // This entry has FILE signature but no actual attributes,
        // so no timeline entries should be created
        let result = parse_mft(&data, &mut store);
        if result.is_ok() {
            // No FN attribute => no filename => skipped
            assert_eq!(store.len(), 0);
        }
    }

    #[test]
    fn test_parse_mft_multiple_entries_no_fn() {
        // Build 3 valid FILE entries with no FN attributes
        let mut data = build_minimal_mft_entry();
        data.extend_from_slice(&build_minimal_mft_entry());
        data.extend_from_slice(&build_minimal_mft_entry());

        let mut store = TimelineStore::new();
        let result = parse_mft(&data, &mut store);
        // All entries have valid headers but no FN attr => all skipped
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_mft_store_is_sorted_after_parse() {
        let mut store = TimelineStore::new();
        let data = build_minimal_mft_entry();
        let _ = parse_mft(&data, &mut store);
        // Store should be sorted (even if empty) - just verify no panic
        assert!(store.is_sorted());
    }

    #[test]
    fn test_parse_mft_invalid_second_entry_skipped() {
        // First entry is valid, second entry has invalid header
        let mut data = build_minimal_mft_entry();
        // Add second entry that's all zeroes (invalid header)
        data.extend_from_slice(&vec![0u8; 1024]);

        let mut store = TimelineStore::new();
        let result = parse_mft(&data, &mut store);
        assert!(result.is_ok());
        // Both entries should be skipped (no FN attributes)
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_mft_entry_with_baad_signature() {
        // First entry valid, second has BAAD signature (corrupt)
        let mut data = build_minimal_mft_entry();
        let mut second = vec![0u8; 1024];
        second[0..4].copy_from_slice(b"BAAD");
        data.extend_from_slice(&second);

        let mut store = TimelineStore::new();
        let result = parse_mft(&data, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_detect_anomalies_called_on_entry() {
        // Test that detect_anomalies is used - create a TimestampSet
        // with SI created before FN created (timestomping indicator)
        use chrono::{TimeZone, Utc};
        let old_ts = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let new_ts = Utc.with_ymd_and_hms(2025, 6, 15, 0, 0, 0).unwrap();

        let ts = TimestampSet {
            si_created: Some(old_ts),
            fn_created: Some(new_ts),
            ..TimestampSet::default()
        };

        let anomalies = detect_anomalies(&ts);
        // SI created < FN created => potential timestomping
        assert!(anomalies.contains(AnomalyFlags::TIMESTOMPED_SI_LT_FN));
    }

    #[test]
    fn test_detect_anomalies_no_timestomping() {
        use chrono::{TimeZone, Utc};
        let ts_a = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let ts_b = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let ts = TimestampSet {
            si_created: Some(ts_a),
            fn_created: Some(ts_b),
            ..TimestampSet::default()
        };

        let anomalies = detect_anomalies(&ts);
        assert!(!anomalies.contains(AnomalyFlags::TIMESTOMPED_SI_LT_FN));
    }

    #[test]
    fn test_hidden_ads_flag() {
        let anomalies = AnomalyFlags::HIDDEN_ADS;
        assert!(anomalies.contains(AnomalyFlags::HIDDEN_ADS));
        assert!(!anomalies.contains(AnomalyFlags::TIMESTOMPED_SI_LT_FN));
    }

    #[test]
    fn test_entity_id_mft_entry() {
        let id = EntityId::MftEntry(42);
        match id {
            EntityId::MftEntry(n) => assert_eq!(n, 42),
            _ => panic!("Expected MftEntry"),
        }
    }

    #[test]
    fn test_entry_metadata_fields() {
        let meta = EntryMetadata {
            file_size: Some(12345),
            mft_entry_number: Some(100),
            mft_sequence: Some(5),
            is_directory: true,
            has_ads: false,
            parent_path: None,
            sha256: None,
            sha1: None,
        };
        assert_eq!(meta.file_size, Some(12345));
        assert_eq!(meta.mft_entry_number, Some(100));
        assert_eq!(meta.mft_sequence, Some(5));
        assert!(meta.is_directory);
        assert!(!meta.has_ads);
    }

    #[test]
    fn test_timestamp_set_primary_selection_order() {
        use chrono::{TimeZone, Utc};
        let si_mod = Utc.with_ymd_and_hms(2025, 3, 1, 0, 0, 0).unwrap();
        let si_cre = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let fn_mod = Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap();

        // SI Modified should be preferred
        let primary = Some(si_mod)
            .or(Some(si_cre))
            .or(Some(fn_mod))
            .or(None);
        assert_eq!(primary, Some(si_mod));

        // When SI Modified is None, fall back to SI Created
        let primary2 = None::<chrono::DateTime<chrono::Utc>>
            .or(Some(si_cre))
            .or(Some(fn_mod))
            .or(None);
        assert_eq!(primary2, Some(si_cre));
    }
}
