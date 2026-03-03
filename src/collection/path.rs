use percent_encoding::percent_decode_str;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessorType {
    Ntfs,
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPath {
    windows_path: String,
    accessor: AccessorType,
    original_zip_path: String,
}

impl NormalizedPath {
    pub fn windows_path(&self) -> &str {
        &self.windows_path
    }

    pub fn accessor_type(&self) -> AccessorType {
        self.accessor.clone()
    }

    pub fn original_zip_path(&self) -> &str {
        &self.original_zip_path
    }

    /// Create a NormalizedPath from an NTFS filesystem path found in a disk image.
    ///
    /// Converts forward-slash NTFS paths like `/Windows/System32/config/SYSTEM`
    /// to Windows-style paths like `C:\Windows\System32\config\SYSTEM`.
    pub fn from_image_path(ntfs_path: &str, drive_letter: char) -> Self {
        // Normalize: strip leading slash, convert / to backslash
        let trimmed = ntfs_path.trim_start_matches('/');
        let win_path = format!("{}:\\{}", drive_letter, trimmed.replace('/', r"\"));
        NormalizedPath {
            windows_path: win_path,
            accessor: AccessorType::Ntfs,
            original_zip_path: ntfs_path.to_string(),
        }
    }
}

impl fmt::Display for NormalizedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.windows_path)
    }
}

/// Normalize a Velociraptor collection zip path to a Windows path.
///
/// Handles two accessor types:
/// - `uploads/ntfs/%5C%5C.%5CC%3A/...` -> `C:\...` (NTFS accessor)
/// - `uploads/auto/C%3A/...` -> `C:\...` (Auto accessor)
///
/// Returns None if the path doesn't match a known Velociraptor pattern.
pub fn normalize_velociraptor_path(zip_path: &str) -> Option<NormalizedPath> {
    if let Some(rest) = zip_path.strip_prefix("uploads/ntfs/") {
        // Decode the volume prefix: %5C%5C.%5CC%3A -> \\.\C:
        let decoded = percent_decode_str(rest).decode_utf8().ok()?;
        // Strip \\.\C: prefix and convert to C:\
        let without_prefix = decoded.strip_prefix(r"\\.\C:")?;
        let win_path = format!("C:{}", without_prefix.replace('/', r"\"));
        Some(NormalizedPath {
            windows_path: win_path,
            accessor: AccessorType::Ntfs,
            original_zip_path: zip_path.to_string(),
        })
    } else if let Some(rest) = zip_path.strip_prefix("uploads/auto/") {
        let decoded = percent_decode_str(rest).decode_utf8().ok()?;
        // decoded starts with C: or similar drive letter
        let win_path = decoded.replace('/', r"\");
        Some(NormalizedPath {
            windows_path: win_path,
            accessor: AccessorType::Auto,
            original_zip_path: zip_path.to_string(),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── NormalizedPath::from_image_path ─────────────────────────────────

    #[test]
    fn test_from_image_path_basic() {
        let np = NormalizedPath::from_image_path("/Windows/System32/config/SYSTEM", 'C');
        assert_eq!(np.windows_path(), r"C:\Windows\System32\config\SYSTEM");
        assert_eq!(np.accessor_type(), AccessorType::Ntfs);
        assert_eq!(np.original_zip_path(), "/Windows/System32/config/SYSTEM");
    }

    #[test]
    fn test_from_image_path_no_leading_slash() {
        let np = NormalizedPath::from_image_path("Users/test/Desktop/file.txt", 'D');
        assert_eq!(np.windows_path(), r"D:\Users\test\Desktop\file.txt");
    }

    #[test]
    fn test_from_image_path_root() {
        let np = NormalizedPath::from_image_path("/", 'C');
        assert_eq!(np.windows_path(), r"C:\");
    }

    #[test]
    fn test_from_image_path_display() {
        let np = NormalizedPath::from_image_path("/test.txt", 'C');
        assert_eq!(format!("{}", np), r"C:\test.txt");
    }

    // ─── normalize_velociraptor_path NTFS accessor ──────────────────────

    #[test]
    fn test_normalize_vr_ntfs_path() {
        let path = "uploads/ntfs/%5C%5C.%5CC%3A/Windows/System32/cmd.exe";
        let np = normalize_velociraptor_path(path).unwrap();
        assert_eq!(np.windows_path(), r"C:\Windows\System32\cmd.exe");
        assert_eq!(np.accessor_type(), AccessorType::Ntfs);
        assert_eq!(np.original_zip_path(), path);
    }

    #[test]
    fn test_normalize_vr_ntfs_nested_path() {
        let path = "uploads/ntfs/%5C%5C.%5CC%3A/Users/admin/Desktop/evil.exe";
        let np = normalize_velociraptor_path(path).unwrap();
        assert_eq!(np.windows_path(), r"C:\Users\admin\Desktop\evil.exe");
    }

    // ─── normalize_velociraptor_path Auto accessor ──────────────────────

    #[test]
    fn test_normalize_vr_auto_path() {
        let path = "uploads/auto/C%3A/Windows/System32/config/SAM";
        let np = normalize_velociraptor_path(path).unwrap();
        assert_eq!(np.windows_path(), r"C:\Windows\System32\config\SAM");
        assert_eq!(np.accessor_type(), AccessorType::Auto);
    }

    // ─── normalize_velociraptor_path unknown prefix ─────────────────────

    #[test]
    fn test_normalize_vr_unknown_prefix_returns_none() {
        assert!(normalize_velociraptor_path("unknown/prefix/file.txt").is_none());
    }

    #[test]
    fn test_normalize_vr_empty_string_returns_none() {
        assert!(normalize_velociraptor_path("").is_none());
    }

    #[test]
    fn test_normalize_vr_partial_prefix_returns_none() {
        assert!(normalize_velociraptor_path("uploads/other/file.txt").is_none());
    }

    // ─── normalize_velociraptor_path: ntfs without proper volume prefix ─

    #[test]
    fn test_normalize_vr_ntfs_without_volume_prefix_returns_none() {
        // ntfs path that doesn't have the \\.\C: prefix after decoding
        let path = "uploads/ntfs/SomeOtherPrefix/file.txt";
        assert!(normalize_velociraptor_path(path).is_none());
    }

    // ─── AccessorType equality ──────────────────────────────────────────

    #[test]
    fn test_accessor_type_equality() {
        assert_eq!(AccessorType::Ntfs, AccessorType::Ntfs);
        assert_eq!(AccessorType::Auto, AccessorType::Auto);
        assert_ne!(AccessorType::Ntfs, AccessorType::Auto);
    }

    // ─── NormalizedPath equality ────────────────────────────────────────

    #[test]
    fn test_normalized_path_equality() {
        let np1 = NormalizedPath::from_image_path("/test.txt", 'C');
        let np2 = NormalizedPath::from_image_path("/test.txt", 'C');
        assert_eq!(np1, np2);
    }

    #[test]
    fn test_normalized_path_inequality() {
        let np1 = NormalizedPath::from_image_path("/test.txt", 'C');
        let np2 = NormalizedPath::from_image_path("/other.txt", 'C');
        assert_ne!(np1, np2);
    }

    // ─── NormalizedPath Debug ───────────────────────────────────────────

    #[test]
    fn test_normalized_path_debug() {
        let np = NormalizedPath::from_image_path("/test.txt", 'C');
        let dbg = format!("{:?}", np);
        assert!(dbg.contains("NormalizedPath"));
        assert!(dbg.contains("test.txt"));
    }

    // ─── NormalizedPath Clone ───────────────────────────────────────────

    #[test]
    fn test_normalized_path_clone() {
        let np = NormalizedPath::from_image_path("/test.txt", 'C');
        let cloned = np.clone();
        assert_eq!(np, cloned);
    }

    // ─── AccessorType Clone ─────────────────────────────────────────────

    #[test]
    fn test_accessor_type_clone() {
        let at = AccessorType::Ntfs;
        let cloned = at.clone();
        assert_eq!(at, cloned);
    }
}
