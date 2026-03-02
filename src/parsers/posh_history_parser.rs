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
}
