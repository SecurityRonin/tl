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
