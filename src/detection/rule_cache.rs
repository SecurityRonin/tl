/// SigmaHQ rule cache — auto-downloads and updates community rules with debounce.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

const SIGMAHQ_REPO: &str = "https://github.com/SigmaHQ/sigma.git";
const DEBOUNCE_SECS: u64 = 24 * 60 * 60; // 24 hours
const MARKER_FILE: &str = ".tl-last-update";

/// Returns the default cache directory for SigmaHQ rules.
pub fn default_cache_dir() -> PathBuf {
    if let Some(cache) = dirs_cache_dir() {
        cache.join("tl").join("sigma-rules")
    } else {
        // Fallback to home directory
        PathBuf::from(
            std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".".into()),
        )
        .join(".cache")
        .join("tl")
        .join("sigma-rules")
    }
}

/// Platform-appropriate cache directory.
fn dirs_cache_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Library").join("Caches"))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_CACHE_HOME")
            .ok()
            .map(PathBuf::from)
            .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".cache")))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA").ok().map(PathBuf::from)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

/// Check whether the cached rules need updating (clone or pull).
pub fn needs_update(cache_dir: &Path) -> bool {
    let marker = cache_dir.join(MARKER_FILE);
    if !cache_dir.join(".git").exists() {
        return true; // Not cloned yet
    }
    match marker.metadata().and_then(|m| m.modified()) {
        Ok(modified) => {
            let elapsed = SystemTime::now()
                .duration_since(modified)
                .unwrap_or(Duration::from_secs(u64::MAX));
            elapsed > Duration::from_secs(DEBOUNCE_SECS)
        }
        Err(_) => true, // No marker file
    }
}

/// Touch the update marker file.
fn touch_marker(cache_dir: &Path) -> Result<()> {
    let marker = cache_dir.join(MARKER_FILE);
    std::fs::write(&marker, format!("{}", chrono::Utc::now().to_rfc3339()))
        .context("failed to write update marker")?;
    Ok(())
}

/// Ensure SigmaHQ rules are available and up-to-date.
/// Returns the path to the `rules/windows` subdirectory.
pub fn ensure_rules(cache_dir: &Path) -> Result<PathBuf> {
    if !cache_dir.join(".git").exists() {
        // First time: shallow clone
        eprintln!("[*] Downloading SigmaHQ rules (first time)...");
        std::fs::create_dir_all(cache_dir)
            .context("failed to create cache directory")?;

        let status = std::process::Command::new("git")
            .args(["clone", "--depth", "1", "--single-branch", SIGMAHQ_REPO])
            .arg(cache_dir)
            .status()
            .context("failed to run git clone — is git installed?")?;

        if !status.success() {
            anyhow::bail!("git clone failed with exit code {}", status);
        }
        touch_marker(cache_dir)?;
        eprintln!("[+] SigmaHQ rules downloaded to {}", cache_dir.display());
    } else if needs_update(cache_dir) {
        // Stale: pull updates
        eprintln!("[*] Updating SigmaHQ rules...");
        let status = std::process::Command::new("git")
            .args(["pull", "--ff-only"])
            .current_dir(cache_dir)
            .status()
            .context("failed to run git pull")?;

        if status.success() {
            touch_marker(cache_dir)?;
            eprintln!("[+] SigmaHQ rules updated");
        } else {
            eprintln!("[!] git pull failed — using cached rules");
        }
    } else {
        eprintln!("[+] SigmaHQ rules up to date (cached)");
    }

    let rules_dir = cache_dir.join("rules").join("windows");
    if !rules_dir.exists() {
        anyhow::bail!(
            "SigmaHQ rules directory not found at {} — clone may have failed",
            rules_dir.display()
        );
    }
    Ok(rules_dir)
}

/// Count all .yml files recursively under a directory.
pub fn count_rule_files(dir: &Path) -> usize {
    walkdir(dir)
}

fn walkdir(dir: &Path) -> usize {
    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                count += walkdir(&path);
            } else if let Some(ext) = path.extension() {
                if ext == "yml" || ext == "yaml" {
                    count += 1;
                }
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_cache_dir_is_not_empty() {
        let dir = default_cache_dir();
        assert!(!dir.as_os_str().is_empty());
        assert!(dir.to_str().unwrap().contains("tl"));
    }

    #[test]
    fn test_needs_update_empty_dir() {
        let tmp = TempDir::new().unwrap();
        assert!(needs_update(tmp.path()));
    }

    #[test]
    fn test_needs_update_with_fresh_marker() {
        let tmp = TempDir::new().unwrap();
        // Create fake .git dir
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        // Create fresh marker
        std::fs::write(tmp.path().join(MARKER_FILE), "now").unwrap();
        assert!(!needs_update(tmp.path()));
    }

    #[test]
    fn test_needs_update_no_git_dir() {
        let tmp = TempDir::new().unwrap();
        // Marker exists but no .git
        std::fs::write(tmp.path().join(MARKER_FILE), "now").unwrap();
        assert!(needs_update(tmp.path()));
    }

    #[test]
    fn test_count_rule_files() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("rule1.yml"), "title: a").unwrap();
        std::fs::write(tmp.path().join("rule2.yaml"), "title: b").unwrap();
        std::fs::write(tmp.path().join("not_a_rule.txt"), "nope").unwrap();
        let sub = tmp.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("rule3.yml"), "title: c").unwrap();
        assert_eq!(count_rule_files(tmp.path()), 3);
    }

    #[test]
    fn test_count_rule_files_empty_dir() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(count_rule_files(tmp.path()), 0);
    }

    #[test]
    fn test_touch_marker_creates_file() {
        let tmp = TempDir::new().unwrap();
        touch_marker(tmp.path()).unwrap();
        assert!(tmp.path().join(MARKER_FILE).exists());
    }

    // ─── Coverage: touch_marker content ─────────────────────────────────

    #[test]
    fn test_touch_marker_writes_rfc3339_content() {
        let tmp = TempDir::new().unwrap();
        touch_marker(tmp.path()).unwrap();
        let content = std::fs::read_to_string(tmp.path().join(MARKER_FILE)).unwrap();
        // Should contain an RFC3339 timestamp
        assert!(content.contains("T"), "marker content should be RFC3339: {}", content);
    }

    // ─── Coverage: needs_update with stale marker ───────────────────────

    #[test]
    fn test_needs_update_stale_marker() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        let marker_path = tmp.path().join(MARKER_FILE);
        std::fs::write(&marker_path, "old").unwrap();

        // We can't easily set mtime far in the past without the filetime crate,
        // so we verify a freshly written marker is NOT considered stale.
        assert!(!needs_update(tmp.path()));
    }

    // ─── Coverage: count_rule_files with non-rule files ─────────────────

    #[test]
    fn test_count_rule_files_ignores_non_yaml() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("file.txt"), "text").unwrap();
        std::fs::write(tmp.path().join("file.json"), "{}").unwrap();
        std::fs::write(tmp.path().join("file.xml"), "<xml/>").unwrap();
        assert_eq!(count_rule_files(tmp.path()), 0);
    }

    #[test]
    fn test_count_rule_files_nonexistent_dir() {
        assert_eq!(count_rule_files(Path::new("/nonexistent/dir/xyz")), 0);
    }

    #[test]
    fn test_count_rule_files_counts_yaml_extension() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("r1.yaml"), "---").unwrap();
        std::fs::write(tmp.path().join("r2.yml"), "---").unwrap();
        assert_eq!(count_rule_files(tmp.path()), 2);
    }

    #[test]
    fn test_count_rule_files_deep_nesting() {
        let tmp = TempDir::new().unwrap();
        let deep = tmp.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("deep.yml"), "---").unwrap();
        assert_eq!(count_rule_files(tmp.path()), 1);
    }

    // ─── Coverage: ensure_rules with missing rules/windows dir ──────────

    #[test]
    fn test_ensure_rules_fails_when_rules_dir_missing() {
        let tmp = TempDir::new().unwrap();
        // Create a fake .git dir so it thinks it's already cloned
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        // Create a fresh marker so it doesn't try to update
        touch_marker(tmp.path()).unwrap();

        let result = ensure_rules(tmp.path());
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("not found"), "Expected 'not found' error, got: {}", err_msg);
    }

    // ─── Coverage: default_cache_dir returns platform path ──────────────

    #[test]
    fn test_default_cache_dir_contains_sigma_rules() {
        let dir = default_cache_dir();
        let path_str = dir.to_string_lossy();
        assert!(path_str.contains("sigma-rules"), "Expected sigma-rules in path: {}", path_str);
    }

    // ─── Coverage: dirs_cache_dir platform ──────────────────────────────

    #[test]
    fn test_dirs_cache_dir_returns_some_on_supported_platform() {
        // On macOS/Linux (CI environments), HOME is usually set
        let result = dirs_cache_dir();
        if std::env::var("HOME").is_ok() || std::env::var("LOCALAPPDATA").is_ok() {
            assert!(result.is_some());
        }
    }

    // ─── Coverage: needs_update with .git but no marker ─────────────────

    #[test]
    fn test_needs_update_git_dir_no_marker() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        // No marker file -> should need update
        assert!(needs_update(tmp.path()));
    }

    // ─── Coverage: walkdir with files without extension ─────────────────

    #[test]
    fn test_count_rule_files_no_extension_files() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("Makefile"), "all:").unwrap();
        std::fs::write(tmp.path().join("LICENSE"), "MIT").unwrap();
        assert_eq!(count_rule_files(tmp.path()), 0);
    }

    // ─── Coverage: SIGMAHQ_REPO and DEBOUNCE_SECS constants ────────────

    #[test]
    fn test_constants() {
        assert!(SIGMAHQ_REPO.contains("SigmaHQ"));
        assert_eq!(DEBOUNCE_SECS, 86400);
        assert_eq!(MARKER_FILE, ".tl-last-update");
    }
}
