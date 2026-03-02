use anyhow::{Context, Result};
use log::{debug, warn};
use nt_hive2::{Hive, HiveParseMode, SubPath};
use smallvec::smallvec;
use std::io::Cursor;

use crate::collection::manifest::{ArtifactManifest, RegistryHiveType};
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static USERREG_ID_COUNTER: AtomicU64 = AtomicU64::new(0x5552_0000_0000_0000); // "UR" prefix

fn next_userreg_id() -> u64 {
    USERREG_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Registry key paths ──────────────────────────────────────────────────────

/// TypedPaths: Explorer address bar history.
const TYPED_PATHS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths";

/// WordWheelQuery: Windows search bar queries.
const WORD_WHEEL_QUERY_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery";

/// OpenSavePidlMRU: File Open/Save dialog history.
const OPEN_SAVE_PIDL_MRU_KEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU";

/// LastVisitedPidlMRU: Last application + folder used in file dialogs.
const LAST_VISITED_PIDL_MRU_KEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU";

// ─── Parsed structures ───────────────────────────────────────────────────────

/// Type of user registry activity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserRegActivityType {
    TypedPath,
    SearchQuery,
    OpenSaveDialog,
    LastVisitedApp,
}

/// A parsed user registry activity entry.
#[derive(Debug, Clone)]
pub struct UserRegEntry {
    pub activity_type: UserRegActivityType,
    pub username: String,
    pub value_name: String,
    pub value_data: String,
    pub key_last_write: Option<chrono::DateTime<chrono::Utc>>,
}

// ─── Parsing functions ───────────────────────────────────────────────────────

/// Decode a UTF-16LE byte slice to a String, stopping at the first null.
fn decode_utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let nul_pos = u16s.iter().position(|&c| c == 0).unwrap_or(u16s.len());
    String::from_utf16_lossy(&u16s[..nul_pos])
}

/// Parse TypedPaths values from an NTUSER.DAT hive.
pub fn parse_typed_paths(data: &[u8], username: &str) -> Result<Vec<UserRegEntry>> {
    let mut entries = Vec::new();

    let mut hive = Hive::new(
        Cursor::new(data.to_vec()),
        HiveParseMode::NormalWithBaseBlock,
    )
    .context("Failed to parse NTUSER.DAT hive")?
    .treat_hive_as_clean();

    let root_key = hive
        .root_key_node()
        .context("Failed to get root key")?;

    if let Ok(Some(key)) = root_key.subpath(TYPED_PATHS_KEY, &mut hive) {
        let key_ref = key.borrow();
        let last_write = *key_ref.timestamp();
        for value in key_ref.values() {
            let vname = value.name();
            if !vname.starts_with("url") {
                continue;
            }
            let vdata = match value.value() {
                nt_hive2::RegistryValue::RegSZ(s) | nt_hive2::RegistryValue::RegExpandSZ(s) => {
                    s.clone()
                }
                _ => continue,
            };
            entries.push(UserRegEntry {
                activity_type: UserRegActivityType::TypedPath,
                username: username.to_string(),
                value_name: vname.to_string(),
                value_data: vdata,
                key_last_write: Some(last_write),
            });
        }
    }

    Ok(entries)
}

/// Parse WordWheelQuery values from an NTUSER.DAT hive.
pub fn parse_word_wheel_query(data: &[u8], username: &str) -> Result<Vec<UserRegEntry>> {
    let mut entries = Vec::new();

    let mut hive = Hive::new(
        Cursor::new(data.to_vec()),
        HiveParseMode::NormalWithBaseBlock,
    )
    .context("Failed to parse NTUSER.DAT hive")?
    .treat_hive_as_clean();

    let root_key = hive
        .root_key_node()
        .context("Failed to get root key")?;

    if let Ok(Some(key)) = root_key.subpath(WORD_WHEEL_QUERY_KEY, &mut hive) {
        let key_ref = key.borrow();
        let last_write = *key_ref.timestamp();
        for value in key_ref.values() {
            let vname = value.name();
            // Skip the MRUListEx ordering value
            if vname == "MRUListEx" {
                continue;
            }
            let vdata = match value.value() {
                nt_hive2::RegistryValue::RegBinary(bytes) => decode_utf16le(&bytes),
                nt_hive2::RegistryValue::RegSZ(s) => s.clone(),
                _ => continue,
            };
            if vdata.is_empty() {
                continue;
            }
            entries.push(UserRegEntry {
                activity_type: UserRegActivityType::SearchQuery,
                username: username.to_string(),
                value_name: vname.to_string(),
                value_data: vdata,
                key_last_write: Some(last_write),
            });
        }
    }

    Ok(entries)
}

/// Parse OpenSavePidlMRU and LastVisitedPidlMRU values from an NTUSER.DAT hive.
pub fn parse_open_save_mru(data: &[u8], username: &str) -> Result<Vec<UserRegEntry>> {
    let mut entries = Vec::new();

    let mut hive = Hive::new(
        Cursor::new(data.to_vec()),
        HiveParseMode::NormalWithBaseBlock,
    )
    .context("Failed to parse NTUSER.DAT hive")?
    .treat_hive_as_clean();

    let root_key = hive
        .root_key_node()
        .context("Failed to get root key")?;

    // OpenSavePidlMRU has subkeys per extension (*, .doc, .txt, etc.)
    if let Ok(Some(key)) = root_key.subpath(OPEN_SAVE_PIDL_MRU_KEY, &mut hive) {
        let subkeys = match key.borrow().subkeys(&mut hive) {
            Ok(sk) => sk.clone(),
            Err(_) => Vec::new(),
        };
        for subkey_rc in subkeys.iter() {
            let subkey = subkey_rc.borrow();
            let ext = subkey.name().to_string();
            let last_write = *subkey.timestamp();
            for value in subkey.values() {
                let vname = value.name();
                if vname == "MRUListEx" {
                    continue;
                }
                let vdata = match value.value() {
                    nt_hive2::RegistryValue::RegBinary(bytes) => {
                        // Binary data contains a PIDL - extract readable filename
                        extract_filename_from_binary(&bytes)
                    }
                    nt_hive2::RegistryValue::RegSZ(s) => s.clone(),
                    _ => continue,
                };
                if vdata.is_empty() {
                    continue;
                }
                entries.push(UserRegEntry {
                    activity_type: UserRegActivityType::OpenSaveDialog,
                    username: username.to_string(),
                    value_name: format!("{}/{}", ext, vname),
                    value_data: vdata,
                    key_last_write: Some(last_write),
                });
            }
        }
    }

    // LastVisitedPidlMRU
    if let Ok(Some(key)) = root_key.subpath(LAST_VISITED_PIDL_MRU_KEY, &mut hive) {
        let key_ref = key.borrow();
        let last_write = *key_ref.timestamp();
        for value in key_ref.values() {
            let vname = value.name();
            if vname == "MRUListEx" {
                continue;
            }
            let vdata = match value.value() {
                nt_hive2::RegistryValue::RegBinary(bytes) => {
                    extract_filename_from_binary(&bytes)
                }
                nt_hive2::RegistryValue::RegSZ(s) => s.clone(),
                _ => continue,
            };
            if vdata.is_empty() {
                continue;
            }
            entries.push(UserRegEntry {
                activity_type: UserRegActivityType::LastVisitedApp,
                username: username.to_string(),
                value_name: vname.to_string(),
                value_data: vdata,
                key_last_write: Some(last_write),
            });
        }
    }

    Ok(entries)
}

/// Extract a readable filename from a binary registry value (PIDL or UTF-16LE path).
/// These values often start with a UTF-16LE string followed by binary data.
pub fn extract_filename_from_binary(data: &[u8]) -> String {
    if data.len() < 4 {
        return String::new();
    }
    // Try to decode as UTF-16LE, which is the common format for these MRU values
    let decoded = decode_utf16le(data);
    if decoded.is_empty() {
        // Fall back to ASCII extraction
        let ascii: String = data
            .iter()
            .filter(|b| b.is_ascii_graphic() || **b == b' ')
            .map(|&b| b as char)
            .collect();
        ascii.trim().to_string()
    } else {
        decoded
    }
}

// ─── Pipeline integration ────────────────────────────────────────────────────

/// Parse user registry activity from all NTUSER.DAT hives in the collection.
pub fn parse_user_registry(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    let mut total = 0u32;

    for hive_entry in &manifest.registry_hives {
        let username = match &hive_entry.hive_type {
            RegistryHiveType::NtUser { username } => username.clone(),
            _ => continue,
        };

        let data = match provider.open_file(&hive_entry.path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read NTUSER.DAT for {}: {}", username, e);
                continue;
            }
        };

        // Parse TypedPaths
        match parse_typed_paths(&data, &username) {
            Ok(typed_entries) => {
                for entry in typed_entries {
                    add_entry_to_store(store, &entry);
                    total += 1;
                }
            }
            Err(e) => debug!("TypedPaths parse error for {}: {}", username, e),
        }

        // Parse WordWheelQuery
        match parse_word_wheel_query(&data, &username) {
            Ok(wwq_entries) => {
                for entry in wwq_entries {
                    add_entry_to_store(store, &entry);
                    total += 1;
                }
            }
            Err(e) => debug!("WordWheelQuery parse error for {}: {}", username, e),
        }

        // Parse OpenSave MRU
        match parse_open_save_mru(&data, &username) {
            Ok(os_entries) => {
                for entry in os_entries {
                    add_entry_to_store(store, &entry);
                    total += 1;
                }
            }
            Err(e) => debug!("OpenSaveMRU parse error for {}: {}", username, e),
        }
    }

    if total > 0 {
        debug!("Parsed {} user registry activity entries", total);
    }
    Ok(())
}

fn add_entry_to_store(store: &mut TimelineStore, entry: &UserRegEntry) {
    let primary_ts = entry
        .key_last_write
        .unwrap_or_else(chrono::Utc::now);

    let (description, event_type) = match entry.activity_type {
        UserRegActivityType::TypedPath => (
            format!(
                "[TypedPath] {} (user: {})",
                entry.value_data, entry.username
            ),
            EventType::FileAccess,
        ),
        UserRegActivityType::SearchQuery => (
            format!(
                "[SearchQuery] \"{}\" (user: {})",
                entry.value_data, entry.username
            ),
            EventType::Other("Search".to_string()),
        ),
        UserRegActivityType::OpenSaveDialog => (
            format!(
                "[OpenSave] {} (user: {}, key: {})",
                entry.value_data, entry.username, entry.value_name
            ),
            EventType::FileAccess,
        ),
        UserRegActivityType::LastVisitedApp => (
            format!(
                "[LastVisitedApp] {} (user: {})",
                entry.value_data, entry.username
            ),
            EventType::Execute,
        ),
    };

    store.push(TimelineEntry {
        entity_id: EntityId::Generated(next_userreg_id()),
        path: description,
        primary_timestamp: primary_ts,
        event_type,
        timestamps: TimestampSet::default(),
        sources: smallvec![ArtifactSource::Registry("NTUSER.DAT".to_string())],
        anomalies: AnomalyFlags::empty(),
        metadata: EntryMetadata::default(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_utf16le() {
        let data = b"h\x00e\x00l\x00l\x00o\x00\x00\x00";
        assert_eq!(decode_utf16le(data), "hello");
    }

    #[test]
    fn test_decode_utf16le_no_null() {
        let data = b"h\x00i\x00";
        assert_eq!(decode_utf16le(data), "hi");
    }

    #[test]
    fn test_extract_filename_from_binary_utf16() {
        let data = b"t\x00e\x00s\x00t\x00.\x00t\x00x\x00t\x00\x00\x00";
        assert_eq!(extract_filename_from_binary(data), "test.txt");
    }

    #[test]
    fn test_extract_filename_from_binary_empty() {
        assert_eq!(extract_filename_from_binary(&[0, 0]), "");
    }

    #[test]
    fn test_extract_filename_from_binary_too_short() {
        assert_eq!(extract_filename_from_binary(&[1, 2]), "");
    }

    #[test]
    fn test_user_reg_entry_creation() {
        let entry = UserRegEntry {
            activity_type: UserRegActivityType::TypedPath,
            username: "admin".to_string(),
            value_name: "url1".to_string(),
            value_data: r"C:\Users\admin\Documents".to_string(),
            key_last_write: None,
        };
        assert_eq!(entry.activity_type, UserRegActivityType::TypedPath);
        assert_eq!(entry.username, "admin");
    }

    #[test]
    fn test_user_reg_timeline_entry_typed_path() {
        let entry = UserRegEntry {
            activity_type: UserRegActivityType::TypedPath,
            username: "analyst".to_string(),
            value_name: "url1".to_string(),
            value_data: r"\\server\share".to_string(),
            key_last_write: Some(chrono::Utc::now()),
        };
        let mut store = TimelineStore::new();
        add_entry_to_store(&mut store, &entry);
        assert_eq!(store.len(), 1);
        let te = store.get(0).unwrap();
        assert!(te.path.contains("[TypedPath]"));
        assert!(te.path.contains(r"\\server\share"));
    }

    #[test]
    fn test_user_reg_timeline_entry_search() {
        let entry = UserRegEntry {
            activity_type: UserRegActivityType::SearchQuery,
            username: "user1".to_string(),
            value_name: "0".to_string(),
            value_data: "password reset tool".to_string(),
            key_last_write: Some(chrono::Utc::now()),
        };
        let mut store = TimelineStore::new();
        add_entry_to_store(&mut store, &entry);
        let te = store.get(0).unwrap();
        assert!(te.path.contains("[SearchQuery]"));
        assert!(te.path.contains("password reset tool"));
    }

    #[test]
    fn test_user_reg_timeline_entry_open_save() {
        let entry = UserRegEntry {
            activity_type: UserRegActivityType::OpenSaveDialog,
            username: "user1".to_string(),
            value_name: ".docx/0".to_string(),
            value_data: "secret_plan.docx".to_string(),
            key_last_write: Some(chrono::Utc::now()),
        };
        let mut store = TimelineStore::new();
        add_entry_to_store(&mut store, &entry);
        let te = store.get(0).unwrap();
        assert!(te.path.contains("[OpenSave]"));
        assert!(te.path.contains("secret_plan.docx"));
    }

    #[test]
    fn test_parse_typed_paths_invalid_hive() {
        let result = parse_typed_paths(&[0u8; 100], "testuser");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_word_wheel_query_invalid_hive() {
        let result = parse_word_wheel_query(&[0u8; 100], "testuser");
        assert!(result.is_err());
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

        let result = parse_user_registry(&NoOpProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_decode_utf16le_empty() {
        let data: &[u8] = &[];
        assert_eq!(decode_utf16le(data), "");
    }

    #[test]
    fn test_decode_utf16le_single_null() {
        let data = b"\x00\x00";
        assert_eq!(decode_utf16le(data), "");
    }

    #[test]
    fn test_decode_utf16le_odd_byte_count() {
        // Odd number of bytes - the last byte is ignored by chunks_exact
        let data = b"h\x00e\x00l\x00l\x00o\x00\x00\x00X";
        assert_eq!(decode_utf16le(data), "hello");
    }

    #[test]
    fn test_decode_utf16le_with_embedded_null() {
        // Should stop at the first null
        let data = b"A\x00B\x00\x00\x00C\x00D\x00";
        assert_eq!(decode_utf16le(data), "AB");
    }

    #[test]
    fn test_decode_utf16le_unicode_chars() {
        // Unicode snowman: U+2603 => 0x03, 0x26 in LE
        let data = [0x03, 0x26, 0x00, 0x00];
        let result = decode_utf16le(&data);
        assert_eq!(result, "\u{2603}");
    }

    #[test]
    fn test_extract_filename_from_binary_utf16_with_null() {
        let data = b"f\x00i\x00l\x00e\x00.\x00t\x00x\x00t\x00\x00\x00\xFF\xFF\xFF\xFF";
        assert_eq!(extract_filename_from_binary(data), "file.txt");
    }

    #[test]
    fn test_extract_filename_from_binary_falls_back_to_ascii() {
        // Data starts with null (empty UTF-16), so falls back to ASCII
        let data = b"\x00\x00\x00\x00hello.txt";
        let result = extract_filename_from_binary(data);
        assert!(result.contains("hello.txt"));
    }

    #[test]
    fn test_extract_filename_from_binary_3_bytes() {
        // Less than 4 bytes returns empty
        assert_eq!(extract_filename_from_binary(&[0x41, 0x00, 0x42]), "");
    }

    #[test]
    fn test_extract_filename_from_binary_all_nulls() {
        // All null bytes - UTF-16 decode returns empty, ASCII fallback also empty
        let data = vec![0u8; 16];
        assert_eq!(extract_filename_from_binary(&data), "");
    }

    #[test]
    fn test_extract_filename_from_binary_exactly_4_bytes() {
        let data = b"A\x00B\x00"; // "AB" in UTF-16LE
        assert_eq!(extract_filename_from_binary(data), "AB");
    }

    #[test]
    fn test_user_reg_activity_type_equality() {
        assert_eq!(UserRegActivityType::TypedPath, UserRegActivityType::TypedPath);
        assert_eq!(UserRegActivityType::SearchQuery, UserRegActivityType::SearchQuery);
        assert_eq!(UserRegActivityType::OpenSaveDialog, UserRegActivityType::OpenSaveDialog);
        assert_eq!(UserRegActivityType::LastVisitedApp, UserRegActivityType::LastVisitedApp);
        assert_ne!(UserRegActivityType::TypedPath, UserRegActivityType::SearchQuery);
        assert_ne!(UserRegActivityType::OpenSaveDialog, UserRegActivityType::LastVisitedApp);
    }

    #[test]
    fn test_user_reg_activity_type_debug() {
        let typed = UserRegActivityType::TypedPath;
        let debug_str = format!("{:?}", typed);
        assert!(debug_str.contains("TypedPath"));
    }

    #[test]
    fn test_user_reg_activity_type_clone() {
        let original = UserRegActivityType::SearchQuery;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_user_reg_entry_clone() {
        let entry = UserRegEntry {
            activity_type: UserRegActivityType::TypedPath,
            username: "admin".to_string(),
            value_name: "url1".to_string(),
            value_data: r"C:\temp".to_string(),
            key_last_write: None,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.activity_type, entry.activity_type);
        assert_eq!(cloned.username, entry.username);
        assert_eq!(cloned.value_name, entry.value_name);
        assert_eq!(cloned.value_data, entry.value_data);
        assert_eq!(cloned.key_last_write, entry.key_last_write);
    }

    #[test]
    fn test_user_reg_entry_debug() {
        let entry = UserRegEntry {
            activity_type: UserRegActivityType::SearchQuery,
            username: "user1".to_string(),
            value_name: "0".to_string(),
            value_data: "malware download".to_string(),
            key_last_write: Some(chrono::Utc::now()),
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("UserRegEntry"));
        assert!(debug_str.contains("SearchQuery"));
    }

    #[test]
    fn test_user_reg_entry_with_no_last_write() {
        let entry = UserRegEntry {
            activity_type: UserRegActivityType::TypedPath,
            username: "admin".to_string(),
            value_name: "url1".to_string(),
            value_data: r"\\server\share".to_string(),
            key_last_write: None,
        };
        assert!(entry.key_last_write.is_none());
    }

    #[test]
    fn test_add_entry_to_store_last_visited_app() {
        let entry = UserRegEntry {
            activity_type: UserRegActivityType::LastVisitedApp,
            username: "analyst".to_string(),
            value_name: "0".to_string(),
            value_data: "notepad.exe".to_string(),
            key_last_write: Some(chrono::Utc::now()),
        };
        let mut store = TimelineStore::new();
        add_entry_to_store(&mut store, &entry);
        assert_eq!(store.len(), 1);
        let te = store.get(0).unwrap();
        assert!(te.path.contains("[LastVisitedApp]"));
        assert!(te.path.contains("notepad.exe"));
        assert_eq!(te.event_type, EventType::Execute);
    }

    #[test]
    fn test_add_entry_to_store_uses_now_when_no_timestamp() {
        let entry = UserRegEntry {
            activity_type: UserRegActivityType::TypedPath,
            username: "user".to_string(),
            value_name: "url1".to_string(),
            value_data: "C:\\temp".to_string(),
            key_last_write: None,
        };
        let before = chrono::Utc::now();
        let mut store = TimelineStore::new();
        add_entry_to_store(&mut store, &entry);
        let after = chrono::Utc::now();
        let te = store.get(0).unwrap();
        // The timestamp should be between before and after
        assert!(te.primary_timestamp >= before);
        assert!(te.primary_timestamp <= after);
    }

    #[test]
    fn test_add_entry_to_store_open_save_contains_key_info() {
        let entry = UserRegEntry {
            activity_type: UserRegActivityType::OpenSaveDialog,
            username: "user1".to_string(),
            value_name: ".xlsx/3".to_string(),
            value_data: "budget.xlsx".to_string(),
            key_last_write: Some(chrono::Utc::now()),
        };
        let mut store = TimelineStore::new();
        add_entry_to_store(&mut store, &entry);
        let te = store.get(0).unwrap();
        assert!(te.path.contains(".xlsx/3"));
        assert!(te.path.contains("budget.xlsx"));
    }

    #[test]
    fn test_next_userreg_id_monotonic() {
        let id1 = next_userreg_id();
        let id2 = next_userreg_id();
        let id3 = next_userreg_id();
        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[test]
    fn test_add_entry_to_store_source_is_ntuser() {
        let entry = UserRegEntry {
            activity_type: UserRegActivityType::TypedPath,
            username: "admin".to_string(),
            value_name: "url1".to_string(),
            value_data: "C:\\temp".to_string(),
            key_last_write: Some(chrono::Utc::now()),
        };
        let mut store = TimelineStore::new();
        add_entry_to_store(&mut store, &entry);
        let te = store.get(0).unwrap();
        assert!(matches!(&te.sources[0], ArtifactSource::Registry(s) if s == "NTUSER.DAT"));
    }

    #[test]
    fn test_parse_open_save_mru_invalid_hive() {
        let result = parse_open_save_mru(&[0u8; 100], "testuser");
        assert!(result.is_err());
    }

    #[test]
    fn test_registry_key_path_constants() {
        assert!(TYPED_PATHS_KEY.contains("TypedPaths"));
        assert!(WORD_WHEEL_QUERY_KEY.contains("WordWheelQuery"));
        assert!(OPEN_SAVE_PIDL_MRU_KEY.contains("OpenSavePidlMRU"));
        assert!(LAST_VISITED_PIDL_MRU_KEY.contains("LastVisitedPidlMRU"));
    }

    #[test]
    fn test_search_query_event_type_is_other() {
        let entry = UserRegEntry {
            activity_type: UserRegActivityType::SearchQuery,
            username: "user1".to_string(),
            value_name: "0".to_string(),
            value_data: "suspicious query".to_string(),
            key_last_write: Some(chrono::Utc::now()),
        };
        let mut store = TimelineStore::new();
        add_entry_to_store(&mut store, &entry);
        let te = store.get(0).unwrap();
        assert!(matches!(&te.event_type, EventType::Other(s) if s == "Search"));
    }

    #[test]
    fn test_open_save_event_type_is_file_access() {
        let entry = UserRegEntry {
            activity_type: UserRegActivityType::OpenSaveDialog,
            username: "user1".to_string(),
            value_name: "*/0".to_string(),
            value_data: "file.txt".to_string(),
            key_last_write: Some(chrono::Utc::now()),
        };
        let mut store = TimelineStore::new();
        add_entry_to_store(&mut store, &entry);
        let te = store.get(0).unwrap();
        assert_eq!(te.event_type, EventType::FileAccess);
    }
}
