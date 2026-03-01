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
