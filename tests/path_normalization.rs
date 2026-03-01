use tl::collection::path::{normalize_velociraptor_path, AccessorType};

#[test]
fn test_ntfs_accessor_path() {
    let raw = "uploads/ntfs/%5C%5C.%5CC%3A/$MFT";
    let norm = normalize_velociraptor_path(raw).unwrap();
    assert_eq!(norm.windows_path(), r"C:\$MFT");
    assert_eq!(norm.accessor_type(), AccessorType::Ntfs);
}

#[test]
fn test_auto_accessor_path() {
    let raw = "uploads/auto/C%3A/Windows/System32/config/SYSTEM";
    let norm = normalize_velociraptor_path(raw).unwrap();
    assert_eq!(norm.windows_path(), r"C:\Windows\System32\config\SYSTEM");
    assert_eq!(norm.accessor_type(), AccessorType::Auto);
}

#[test]
fn test_auto_accessor_user_profile() {
    let raw = "uploads/auto/C%3A/Users/4n6h4x0r/NTUSER.DAT";
    let norm = normalize_velociraptor_path(raw).unwrap();
    assert_eq!(norm.windows_path(), r"C:\Users\4n6h4x0r\NTUSER.DAT");
}

#[test]
fn test_ntfs_accessor_usnjrnl() {
    let raw = "uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J";
    let norm = normalize_velociraptor_path(raw).unwrap();
    assert_eq!(norm.windows_path(), r"C:\$Extend\$UsnJrnl:$J");
    assert_eq!(norm.accessor_type(), AccessorType::Ntfs);
}

#[test]
fn test_path_with_spaces() {
    let raw = "uploads/auto/C%3A/ProgramData/Microsoft/Windows/Start Menu/Programs/Word.lnk";
    let norm = normalize_velociraptor_path(raw).unwrap();
    assert_eq!(norm.windows_path(), r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Word.lnk");
}

#[test]
fn test_windows_old_path() {
    let raw = "uploads/auto/C%3A/Windows.old/WINDOWS/System32/config/SYSTEM";
    let norm = normalize_velociraptor_path(raw).unwrap();
    assert_eq!(norm.windows_path(), r"C:\Windows.old\WINDOWS\System32\config\SYSTEM");
}

#[test]
fn test_unknown_path_returns_none() {
    let raw = "some/random/path.txt";
    assert!(normalize_velociraptor_path(raw).is_none());
}
