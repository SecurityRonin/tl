use anyhow::Result;
use log::{debug, warn};
use smallvec::smallvec;

use crate::collection::manifest::ArtifactManifest;
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static WMI_ID_COUNTER: AtomicU64 = AtomicU64::new(0x574D_0000_0000_0000); // "WM" prefix

fn next_wmi_id() -> u64 {
    WMI_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Known benign WMI consumers ──────────────────────────────────────────────

/// Known benign WMI consumer names that ship with Windows.
const BENIGN_CONSUMERS: &[&str] = &[
    "BVTConsumer",
    "SCM Event Log Consumer",
];

// ─── Parsed WMI persistence entries ──────────────────────────────────────────

/// Type of WMI persistence object found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WmiPersistenceType {
    CommandLineConsumer,
    ActiveScriptConsumer,
    EventFilter,
    FilterToConsumerBinding,
    GenericConsumer(String),
}

/// A parsed WMI persistence entry extracted from OBJECTS.DATA.
#[derive(Debug, Clone)]
pub struct WmiPersistenceEntry {
    pub persistence_type: WmiPersistenceType,
    pub name: String,
    pub details: String,
    pub is_benign: bool,
}

// ─── Binary search helpers ───────────────────────────────────────────────────

/// Find all occurrences of a byte pattern in data, returning their offsets.
pub fn find_pattern(data: &[u8], pattern: &[u8]) -> Vec<usize> {
    let mut results = Vec::new();
    if pattern.is_empty() || data.len() < pattern.len() {
        return results;
    }
    let mut pos = 0;
    while pos <= data.len() - pattern.len() {
        if &data[pos..pos + pattern.len()] == pattern {
            results.push(pos);
            pos += pattern.len();
        } else {
            pos += 1;
        }
    }
    results
}

/// Extract a null-terminated ASCII string starting at offset, up to max_len bytes.
pub fn extract_ascii_string(data: &[u8], offset: usize, max_len: usize) -> String {
    let end = (offset + max_len).min(data.len());
    let slice = &data[offset..end];
    let nul_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    let valid = &slice[..nul_pos];
    String::from_utf8_lossy(valid)
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect()
}

/// Extract printable ASCII context around a match offset (before and after).
pub fn extract_context(data: &[u8], offset: usize, before: usize, after: usize) -> String {
    let start = offset.saturating_sub(before);
    let end = (offset + after).min(data.len());
    let slice = &data[start..end];
    slice
        .iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect()
}

// ─── WMI OBJECTS.DATA parser ─────────────────────────────────────────────────

/// Parse WMI OBJECTS.DATA binary for persistence artifacts.
///
/// Searches for CommandLineEventConsumer, ActiveScriptEventConsumer,
/// __EventFilter, and _FilterToConsumerBinding instances by pattern matching
/// on class name strings in the binary data.
pub fn parse_wmi_objects(data: &[u8]) -> Vec<WmiPersistenceEntry> {
    let mut entries = Vec::new();

    // Search for CommandLineEventConsumer instances
    let pattern = b"CommandLineEventConsumer";
    for offset in find_pattern(data, pattern) {
        let context = extract_context(data, offset, 256, 512);
        let name = extract_name_near(&context, "CommandLineEventConsumer");
        let details = extract_commandline_details(&context);
        let is_benign = BENIGN_CONSUMERS.iter().any(|b| name.contains(b));
        entries.push(WmiPersistenceEntry {
            persistence_type: WmiPersistenceType::CommandLineConsumer,
            name,
            details,
            is_benign,
        });
    }

    // Search for ActiveScriptEventConsumer instances
    let pattern = b"ActiveScriptEventConsumer";
    for offset in find_pattern(data, pattern) {
        let context = extract_context(data, offset, 256, 512);
        let name = extract_name_near(&context, "ActiveScriptEventConsumer");
        let details = extract_script_details(&context);
        let is_benign = BENIGN_CONSUMERS.iter().any(|b| name.contains(b));
        entries.push(WmiPersistenceEntry {
            persistence_type: WmiPersistenceType::ActiveScriptConsumer,
            name,
            details,
            is_benign,
        });
    }

    // Search for __EventFilter instances
    let pattern = b"__EventFilter";
    for offset in find_pattern(data, pattern) {
        // Skip if this is part of a FilterToConsumerBinding reference
        if offset >= 1 && data[offset - 1] == b'_' {
            continue;
        }
        let context = extract_context(data, offset, 256, 512);
        let name = extract_name_near(&context, "__EventFilter");
        let details = extract_filter_details(&context);
        let is_benign = BENIGN_CONSUMERS.iter().any(|b| name.contains(b));
        entries.push(WmiPersistenceEntry {
            persistence_type: WmiPersistenceType::EventFilter,
            name,
            details,
            is_benign,
        });
    }

    // Search for FilterToConsumerBinding instances
    let pattern = b"_FilterToConsumerBinding";
    for offset in find_pattern(data, pattern) {
        let context = extract_context(data, offset, 256, 512);
        let name = extract_name_near(&context, "_FilterToConsumerBinding");
        let details = extract_binding_details(&context);
        let is_benign = BENIGN_CONSUMERS.iter().any(|b| context.contains(b));
        entries.push(WmiPersistenceEntry {
            persistence_type: WmiPersistenceType::FilterToConsumerBinding,
            name,
            details,
            is_benign,
        });
    }

    // Deduplicate by (type, name) -- OBJECTS.DATA often has multiple references
    entries.sort_by(|a, b| {
        format!("{:?}{}", a.persistence_type, a.name)
            .cmp(&format!("{:?}{}", b.persistence_type, b.name))
    });
    entries.dedup_by(|a, b| {
        a.persistence_type == b.persistence_type && a.name == b.name
    });

    entries
}

/// Extract a name near a class reference in the printable context.
fn extract_name_near(context: &str, class_name: &str) -> String {
    // Look for "Name" followed by a value after the class name
    if let Some(idx) = context.find(class_name) {
        let after = &context[idx..];
        // Try to find a quoted or readable name string after the class reference
        // Common patterns: ClassName.Name="value" or Name followed by printable chars
        if let Some(name_idx) = after.find("Name") {
            let name_after = &after[name_idx + 4..];
            // Skip delimiters like = and "
            let trimmed = name_after.trim_start_matches(|c: char| c == '=' || c == '"' || c == ' ' || c == '.');
            let end = trimmed.find(|c: char| c == '"' || c == '.' || !(c.is_ascii_graphic() || c == ' '))
                .unwrap_or(trimmed.len().min(128));
            let name = trimmed[..end].trim().to_string();
            if !name.is_empty() {
                return name;
            }
        }
    }
    "Unknown".to_string()
}

/// Extract command-line details from context around a CommandLineEventConsumer.
fn extract_commandline_details(context: &str) -> String {
    // Look for CommandLineTemplate or ExecutablePath
    for keyword in &["CommandLineTemplate", "ExecutablePath"] {
        if let Some(idx) = context.find(keyword) {
            let after = &context[idx + keyword.len()..];
            let trimmed = after.trim_start_matches(|c: char| c == '=' || c == '"' || c == ' ' || c == '.');
            let end = trimmed.find(|c: char| c == '"' || c == '\0')
                .unwrap_or(trimmed.len().min(256));
            let val = trimmed[..end].trim().to_string();
            if !val.is_empty() {
                return format!("{}: {}", keyword, val);
            }
        }
    }
    String::new()
}

/// Extract script details from context around an ActiveScriptEventConsumer.
fn extract_script_details(context: &str) -> String {
    for keyword in &["ScriptText", "ScriptingEngine", "ScriptFileName"] {
        if let Some(idx) = context.find(keyword) {
            let after = &context[idx + keyword.len()..];
            let trimmed = after.trim_start_matches(|c: char| c == '=' || c == '"' || c == ' ' || c == '.');
            let end = trimmed.find(|c: char| c == '"' || c == '\0')
                .unwrap_or(trimmed.len().min(256));
            let val = trimmed[..end].trim().to_string();
            if !val.is_empty() {
                return format!("{}: {}", keyword, val);
            }
        }
    }
    String::new()
}

/// Extract filter query details from context around an __EventFilter.
fn extract_filter_details(context: &str) -> String {
    if let Some(idx) = context.find("SELECT") {
        let query_start = &context[idx..];
        let end = query_start.find(|c: char| c == '"' || c == '\0')
            .unwrap_or(query_start.len().min(256));
        return query_start[..end].trim().to_string();
    }
    String::new()
}

/// Extract binding details from context around a FilterToConsumerBinding.
fn extract_binding_details(context: &str) -> String {
    // Try to extract Consumer and Filter references
    let mut parts = Vec::new();
    for keyword in &["Consumer", "Filter"] {
        if let Some(idx) = context.find(keyword) {
            let after = &context[idx..];
            let end = after.find(|c: char| c == '"' || c == '\0' || c == '.')
                .unwrap_or(after.len().min(128));
            parts.push(after[..end].trim().to_string());
        }
    }
    parts.join(" -> ")
}

// ─── Pipeline integration ────────────────────────────────────────────────────

/// Parse WMI persistence from OBJECTS.DATA files in the collection.
pub fn parse_wmi_persistence(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    if manifest.wmi_repository.is_empty() {
        debug!("No WMI repository files found in manifest");
        return Ok(());
    }

    for wmi_path in &manifest.wmi_repository {
        let data = match provider.open_file(wmi_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read WMI file {}: {}", wmi_path, e);
                continue;
            }
        };

        let entries = parse_wmi_objects(&data);
        let suspicious_count = entries.iter().filter(|e| !e.is_benign).count();
        if !entries.is_empty() {
            debug!(
                "WMI persistence: {} entries ({} suspicious) from {}",
                entries.len(),
                suspicious_count,
                wmi_path
            );
        }

        for entry in entries {
            let description = match &entry.persistence_type {
                WmiPersistenceType::CommandLineConsumer => {
                    format!("[WMI:CmdConsumer] {} {}", entry.name, entry.details)
                }
                WmiPersistenceType::ActiveScriptConsumer => {
                    format!("[WMI:ScriptConsumer] {} {}", entry.name, entry.details)
                }
                WmiPersistenceType::EventFilter => {
                    format!("[WMI:Filter] {} {}", entry.name, entry.details)
                }
                WmiPersistenceType::FilterToConsumerBinding => {
                    format!("[WMI:Binding] {} {}", entry.name, entry.details)
                }
                WmiPersistenceType::GenericConsumer(class) => {
                    format!("[WMI:{}] {} {}", class, entry.name, entry.details)
                }
            };

            let event_type = match &entry.persistence_type {
                WmiPersistenceType::CommandLineConsumer
                | WmiPersistenceType::ActiveScriptConsumer => EventType::Execute,
                _ => EventType::RegistryModify,
            };

            let mut anomalies = AnomalyFlags::empty();
            if !entry.is_benign {
                // Non-benign WMI persistence is inherently suspicious
                anomalies |= AnomalyFlags::EXECUTION_NO_PREFETCH;
            }

            store.push(TimelineEntry {
                entity_id: EntityId::Generated(next_wmi_id()),
                path: description,
                primary_timestamp: chrono::Utc::now(), // No timestamp in OBJECTS.DATA
                event_type,
                timestamps: TimestampSet::default(),
                sources: smallvec![ArtifactSource::Wmi],
                anomalies,
                metadata: EntryMetadata::default(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_pattern_basic() {
        let data = b"hello world hello";
        let offsets = find_pattern(data, b"hello");
        assert_eq!(offsets, vec![0, 12]);
    }

    #[test]
    fn test_find_pattern_no_match() {
        let data = b"hello world";
        let offsets = find_pattern(data, b"xyz");
        assert!(offsets.is_empty());
    }

    #[test]
    fn test_find_pattern_empty() {
        let data = b"hello";
        let offsets = find_pattern(data, b"");
        assert!(offsets.is_empty());
    }

    #[test]
    fn test_extract_ascii_string() {
        let data = b"hello\x00world";
        let s = extract_ascii_string(data, 0, 20);
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_extract_ascii_string_max_len() {
        let data = b"hello world this is long";
        let s = extract_ascii_string(data, 0, 5);
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_extract_context_printable() {
        let data = b"ABC\x00\x01DEF";
        let ctx = extract_context(data, 3, 3, 5);
        assert_eq!(ctx, "ABC..DEF");
    }

    #[test]
    fn test_parse_wmi_objects_commandline_consumer() {
        // Simulate OBJECTS.DATA with a CommandLineEventConsumer
        let mut data = vec![0u8; 512];
        let consumer = b"CommandLineEventConsumer";
        let name_field = b"Name=\"EvilConsumer\"";
        let cmd = b"CommandLineTemplate=\"powershell -enc ZQBj...\"";

        // Place the class name and fields in the data
        let offset = 256;
        data[offset..offset + consumer.len()].copy_from_slice(consumer);
        let name_off = offset + consumer.len() + 5;
        data[name_off..name_off + name_field.len()].copy_from_slice(name_field);
        let cmd_off = name_off + name_field.len() + 5;
        if cmd_off + cmd.len() <= data.len() {
            data[cmd_off..cmd_off + cmd.len()].copy_from_slice(cmd);
        } else {
            data.resize(cmd_off + cmd.len() + 64, 0);
            data[cmd_off..cmd_off + cmd.len()].copy_from_slice(cmd);
        }

        let entries = parse_wmi_objects(&data);
        assert!(
            entries.iter().any(|e| e.persistence_type == WmiPersistenceType::CommandLineConsumer),
            "Should find CommandLineEventConsumer"
        );
        let cmd_entry = entries
            .iter()
            .find(|e| e.persistence_type == WmiPersistenceType::CommandLineConsumer)
            .unwrap();
        assert!(!cmd_entry.is_benign);
    }

    #[test]
    fn test_parse_wmi_objects_active_script_consumer() {
        let mut data = vec![0u8; 512];
        let consumer = b"ActiveScriptEventConsumer";
        let name_field = b"Name=\"ScriptRunner\"";
        let script = b"ScriptText=\"CreateObject(\"WScript.Shell\").Run\"";

        let offset = 256;
        data[offset..offset + consumer.len()].copy_from_slice(consumer);
        let name_off = offset + consumer.len() + 5;
        data[name_off..name_off + name_field.len()].copy_from_slice(name_field);
        let script_off = name_off + name_field.len() + 5;
        data.resize(script_off + script.len() + 64, 0);
        data[script_off..script_off + script.len()].copy_from_slice(script);

        let entries = parse_wmi_objects(&data);
        assert!(
            entries.iter().any(|e| e.persistence_type == WmiPersistenceType::ActiveScriptConsumer),
            "Should find ActiveScriptEventConsumer"
        );
    }

    #[test]
    fn test_parse_wmi_objects_event_filter() {
        let mut data = vec![0u8; 512];
        let filter = b"__EventFilter";
        let name_field = b"Name=\"EvilFilter\"";
        let query = b"SELECT * FROM __InstanceModificationEvent";

        let offset = 256;
        data[offset..offset + filter.len()].copy_from_slice(filter);
        let name_off = offset + filter.len() + 5;
        data[name_off..name_off + name_field.len()].copy_from_slice(name_field);
        let query_off = name_off + name_field.len() + 5;
        data.resize(query_off + query.len() + 64, 0);
        data[query_off..query_off + query.len()].copy_from_slice(query);

        let entries = parse_wmi_objects(&data);
        assert!(
            entries.iter().any(|e| e.persistence_type == WmiPersistenceType::EventFilter),
            "Should find __EventFilter"
        );
        let filter_entry = entries
            .iter()
            .find(|e| e.persistence_type == WmiPersistenceType::EventFilter)
            .unwrap();
        assert!(filter_entry.details.contains("SELECT"), "Should extract WMI query");
    }

    #[test]
    fn test_parse_wmi_objects_benign_consumer() {
        let mut data = vec![0u8; 512];
        let consumer = b"CommandLineEventConsumer";
        let name_field = b"Name=\"SCM Event Log Consumer\"";

        let offset = 256;
        data[offset..offset + consumer.len()].copy_from_slice(consumer);
        let name_off = offset + consumer.len() + 5;
        data[name_off..name_off + name_field.len()].copy_from_slice(name_field);

        let entries = parse_wmi_objects(&data);
        let cmd_entry = entries
            .iter()
            .find(|e| e.persistence_type == WmiPersistenceType::CommandLineConsumer);
        if let Some(entry) = cmd_entry {
            assert!(entry.is_benign, "SCM Event Log Consumer should be benign");
        }
    }

    #[test]
    fn test_parse_wmi_objects_empty_data() {
        let data = vec![0u8; 1024];
        let entries = parse_wmi_objects(&data);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_wmi_objects_binding() {
        let mut data = vec![0u8; 512];
        let binding = b"_FilterToConsumerBinding";
        let details = b"Consumer=\"CommandLineEventConsumer.Name=\\\"Evil\\\"\" Filter=\"__EventFilter.Name=\\\"EvilFilter\\\"\"";

        let offset = 256;
        data[offset..offset + binding.len()].copy_from_slice(binding);
        let det_off = offset + binding.len() + 5;
        data.resize(det_off + details.len() + 64, 0);
        data[det_off..det_off + details.len()].copy_from_slice(details);

        let entries = parse_wmi_objects(&data);
        assert!(
            entries
                .iter()
                .any(|e| e.persistence_type == WmiPersistenceType::FilterToConsumerBinding),
            "Should find FilterToConsumerBinding"
        );
    }

    #[test]
    fn test_empty_manifest_no_error() {
        let manifest = ArtifactManifest::default();
        let mut store = TimelineStore::new();

        struct NoOpProvider;
        impl CollectionProvider for NoOpProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(vec![])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata {
                    hostname: "test".into(),
                    collection_timestamp: "2025-01-01".into(),
                    source_tool: "test".into(),
                }
            }
        }

        let result = parse_wmi_persistence(&NoOpProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_wmi_timeline_entry_creation() {
        let entry = WmiPersistenceEntry {
            persistence_type: WmiPersistenceType::CommandLineConsumer,
            name: "EvilConsumer".to_string(),
            details: "CommandLineTemplate: powershell -enc ZQBj".to_string(),
            is_benign: false,
        };

        assert_eq!(entry.persistence_type, WmiPersistenceType::CommandLineConsumer);
        assert_eq!(entry.name, "EvilConsumer");
        assert!(!entry.is_benign);
    }

    #[test]
    fn test_deduplication() {
        // OBJECTS.DATA often has multiple references to the same consumer
        let mut data = vec![0u8; 1024];
        let consumer = b"CommandLineEventConsumer";
        let name = b"Name=\"DupeTest\"";

        // Place same consumer at two different offsets
        let off1 = 100;
        data[off1..off1 + consumer.len()].copy_from_slice(consumer);
        data[off1 + consumer.len() + 5..off1 + consumer.len() + 5 + name.len()]
            .copy_from_slice(name);

        let off2 = 600;
        data[off2..off2 + consumer.len()].copy_from_slice(consumer);
        data[off2 + consumer.len() + 5..off2 + consumer.len() + 5 + name.len()]
            .copy_from_slice(name);

        let entries = parse_wmi_objects(&data);
        let cmd_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.persistence_type == WmiPersistenceType::CommandLineConsumer)
            .collect();
        assert_eq!(cmd_entries.len(), 1, "Duplicate entries should be deduplicated");
    }

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_find_pattern_at_end() {
        let data = b"xxxhello";
        let offsets = find_pattern(data, b"hello");
        assert_eq!(offsets, vec![3]);
    }

    #[test]
    fn test_find_pattern_overlapping() {
        // Pattern "aa" in "aaaa" -- non-overlapping: [0, 2]
        let data = b"aaaa";
        let offsets = find_pattern(data, b"aa");
        assert_eq!(offsets, vec![0, 2]);
    }

    #[test]
    fn test_find_pattern_data_shorter_than_pattern() {
        let data = b"ab";
        let offsets = find_pattern(data, b"abc");
        assert!(offsets.is_empty());
    }

    #[test]
    fn test_find_pattern_exact_match() {
        let data = b"hello";
        let offsets = find_pattern(data, b"hello");
        assert_eq!(offsets, vec![0]);
    }

    #[test]
    fn test_extract_ascii_string_offset_at_end() {
        let data = b"hello";
        let s = extract_ascii_string(data, 5, 10);
        assert_eq!(s, "");
    }

    #[test]
    fn test_extract_ascii_string_filters_non_graphic() {
        // Non-graphic chars (except space) should be filtered out
        let data = [b'h', b'i', 0x01, 0x02, b'!', 0x00];
        let s = extract_ascii_string(&data, 0, 10);
        assert_eq!(s, "hi!");
    }

    #[test]
    fn test_extract_ascii_string_with_space() {
        let data = b"hello world\x00";
        let s = extract_ascii_string(data, 0, 20);
        assert_eq!(s, "hello world");
    }

    #[test]
    fn test_extract_context_at_start() {
        let data = b"ABCDEFGH";
        let ctx = extract_context(data, 0, 10, 4);
        assert_eq!(ctx, "ABCD");
    }

    #[test]
    fn test_extract_context_at_end() {
        let data = b"ABCDEFGH";
        let ctx = extract_context(data, 8, 4, 10);
        assert_eq!(ctx, "EFGH");
    }

    #[test]
    fn test_extract_context_all_nonprintable() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let ctx = extract_context(&data, 0, 0, 4);
        assert_eq!(ctx, "....");
    }

    #[test]
    fn test_extract_name_near_no_class_name() {
        let context = "some random text without the class";
        let name = extract_name_near(context, "CommandLineEventConsumer");
        assert_eq!(name, "Unknown");
    }

    #[test]
    fn test_extract_name_near_no_name_field() {
        let context = "CommandLineEventConsumer something else";
        let name = extract_name_near(context, "CommandLineEventConsumer");
        assert_eq!(name, "Unknown");
    }

    #[test]
    fn test_extract_name_near_with_name() {
        let context = "CommandLineEventConsumer.Name=\"EvilConsumer\" more data";
        let name = extract_name_near(context, "CommandLineEventConsumer");
        assert_eq!(name, "EvilConsumer");
    }

    #[test]
    fn test_extract_commandline_details_with_template() {
        let context = "CommandLineTemplate=\"powershell -enc ZQ\" more";
        let details = extract_commandline_details(context);
        assert!(details.contains("CommandLineTemplate"));
        assert!(details.contains("powershell"));
    }

    #[test]
    fn test_extract_commandline_details_with_executable_path() {
        let context = "ExecutablePath=\"C:\\evil.exe\" more";
        let details = extract_commandline_details(context);
        assert!(details.contains("ExecutablePath"));
        assert!(details.contains("evil.exe"));
    }

    #[test]
    fn test_extract_commandline_details_none() {
        let context = "no command line info here";
        let details = extract_commandline_details(context);
        assert!(details.is_empty());
    }

    #[test]
    fn test_extract_script_details_with_script_text() {
        let context = "ScriptText=\"CreateObject(...)\" more";
        let details = extract_script_details(context);
        assert!(details.contains("ScriptText"));
    }

    #[test]
    fn test_extract_script_details_with_engine() {
        let context = "ScriptingEngine=\"VBScript\" more";
        let details = extract_script_details(context);
        assert!(details.contains("ScriptingEngine"));
        assert!(details.contains("VBScript"));
    }

    #[test]
    fn test_extract_script_details_with_filename() {
        let context = "ScriptFileName=\"C:\\evil.vbs\" data";
        let details = extract_script_details(context);
        assert!(details.contains("ScriptFileName"));
    }

    #[test]
    fn test_extract_script_details_none() {
        let context = "nothing relevant here";
        let details = extract_script_details(context);
        assert!(details.is_empty());
    }

    #[test]
    fn test_extract_filter_details_with_select() {
        let context = "SELECT * FROM __InstanceModificationEvent WHERE something";
        let details = extract_filter_details(context);
        assert!(details.starts_with("SELECT"));
    }

    #[test]
    fn test_extract_filter_details_no_select() {
        let context = "no query here";
        let details = extract_filter_details(context);
        assert!(details.is_empty());
    }

    #[test]
    fn test_extract_binding_details_with_consumer_and_filter() {
        let context = "Consumer=\"CmdConsumer\" Filter=\"MyFilter\" end";
        let details = extract_binding_details(context);
        assert!(details.contains("Consumer"));
        assert!(details.contains("Filter"));
        assert!(details.contains("->"));
    }

    #[test]
    fn test_extract_binding_details_consumer_only() {
        let context = "Consumer=\"CmdConsumer\" end";
        let details = extract_binding_details(context);
        assert!(details.contains("Consumer"));
    }

    #[test]
    fn test_extract_binding_details_empty() {
        let context = "nothing here";
        let details = extract_binding_details(context);
        assert!(details.is_empty());
    }

    #[test]
    fn test_wmi_persistence_type_eq() {
        assert_eq!(WmiPersistenceType::CommandLineConsumer, WmiPersistenceType::CommandLineConsumer);
        assert_ne!(WmiPersistenceType::CommandLineConsumer, WmiPersistenceType::ActiveScriptConsumer);
        assert_eq!(
            WmiPersistenceType::GenericConsumer("test".to_string()),
            WmiPersistenceType::GenericConsumer("test".to_string())
        );
        assert_ne!(
            WmiPersistenceType::GenericConsumer("a".to_string()),
            WmiPersistenceType::GenericConsumer("b".to_string())
        );
    }

    #[test]
    fn test_wmi_persistence_type_debug() {
        let t = WmiPersistenceType::EventFilter;
        let debug_str = format!("{:?}", t);
        assert_eq!(debug_str, "EventFilter");
    }

    #[test]
    fn test_wmi_persistence_entry_debug_clone() {
        let entry = WmiPersistenceEntry {
            persistence_type: WmiPersistenceType::ActiveScriptConsumer,
            name: "test".to_string(),
            details: "details".to_string(),
            is_benign: false,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.name, "test");
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("ActiveScriptConsumer"));
    }

    #[test]
    fn test_parse_wmi_objects_event_filter_skip_binding() {
        // __EventFilter preceded by '_' (part of _FilterToConsumerBinding) should be skipped
        let mut data = vec![0u8; 512];
        // Place "_FilterToConsumerBinding__EventFilter" pattern
        let binding_filter = b"___EventFilter";
        let offset = 256;
        data[offset..offset + binding_filter.len()].copy_from_slice(binding_filter);

        let entries = parse_wmi_objects(&data);
        // The __EventFilter at offset 257 should be skipped because data[256] == '_'
        // Only the _FilterToConsumerBinding should be found
        let filter_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.persistence_type == WmiPersistenceType::EventFilter)
            .collect();
        assert_eq!(filter_entries.len(), 0, "Should skip __EventFilter preceded by _");
    }

    #[test]
    fn test_parse_wmi_objects_benign_bvt_consumer() {
        let mut data = vec![0u8; 512];
        let consumer = b"CommandLineEventConsumer";
        let name_field = b"Name=\"BVTConsumer\"";

        let offset = 256;
        data[offset..offset + consumer.len()].copy_from_slice(consumer);
        let name_off = offset + consumer.len() + 5;
        data[name_off..name_off + name_field.len()].copy_from_slice(name_field);

        let entries = parse_wmi_objects(&data);
        let cmd_entry = entries
            .iter()
            .find(|e| e.persistence_type == WmiPersistenceType::CommandLineConsumer);
        if let Some(entry) = cmd_entry {
            assert!(entry.is_benign, "BVTConsumer should be benign");
        }
    }

    #[test]
    fn test_next_wmi_id_increments() {
        let id1 = next_wmi_id();
        let id2 = next_wmi_id();
        assert!(id2 > id1);
        assert_eq!(id1 >> 48, 0x574D);
    }

    #[test]
    fn test_generic_consumer_type() {
        let entry = WmiPersistenceEntry {
            persistence_type: WmiPersistenceType::GenericConsumer("CustomClass".to_string()),
            name: "test".to_string(),
            details: "details".to_string(),
            is_benign: false,
        };
        match &entry.persistence_type {
            WmiPersistenceType::GenericConsumer(class) => assert_eq!(class, "CustomClass"),
            _ => panic!("Expected GenericConsumer"),
        }
    }
}
