use std::path::Path;
use tl::collection::provider::CollectionProvider;
use tl::collection::velociraptor::VelociraptorProvider;

#[test]
fn test_open_collection_zip() {
    let zip_path = Path::new("test/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
    if !zip_path.exists() {
        eprintln!(
            "Skipping: test collection not found at {}",
            zip_path.display()
        );
        return;
    }
    let provider = VelociraptorProvider::open(zip_path).unwrap();
    let manifest = provider.discover();

    // Should find the $MFT
    assert!(manifest.has_mft());
    // Should find the $UsnJrnl
    assert!(manifest.has_usnjrnl());
    // Should find registry hives
    assert!(!manifest.registry_hives().is_empty());
    // Should find event logs
    assert!(!manifest.event_logs().is_empty());
    // Should find prefetch files
    assert!(!manifest.prefetch_files().is_empty());
    // Should find LNK files
    assert!(!manifest.lnk_files().is_empty());
}

#[test]
fn test_collection_metadata() {
    let zip_path = Path::new("test/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
    if !zip_path.exists() {
        return;
    }
    let provider = VelociraptorProvider::open(zip_path).unwrap();
    let meta = provider.metadata();
    // Hostname extracted from zip filename
    assert!(meta.hostname.contains("A380"));
}
