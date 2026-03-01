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
}
