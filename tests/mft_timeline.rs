use std::path::Path;
use tl::collection::velociraptor::VelociraptorProvider;
use tl::collection::provider::CollectionProvider;
use tl::parsers::mft_parser::parse_mft;
use tl::timeline::store::TimelineStore;

#[test]
fn test_parse_mft_from_collection() {
    let zip_path = Path::new("test/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
    if !zip_path.exists() {
        eprintln!("Skipping: test collection not found");
        return;
    }
    let provider = VelociraptorProvider::open(zip_path).unwrap();
    let manifest = provider.discover();

    let mft_path = manifest.mft.as_ref().expect("No $MFT found");
    let mft_data = provider.open_file(mft_path).unwrap();

    let mut store = TimelineStore::new();
    parse_mft(&mft_data, &mut store).unwrap();

    // A real $MFT should have thousands of entries
    eprintln!("Parsed {} timeline entries from $MFT ({} bytes)", store.len(), mft_data.len());
    assert!(store.len() > 1000, "Expected >1000 entries, got {}", store.len());

    // Check that entries have timestamps
    let first = store.entries().next().unwrap();
    assert!(first.timestamps.si_created.is_some() || first.timestamps.fn_created.is_some());
}

#[test]
fn test_timestomping_detection() {
    use tl::timeline::entry::*;
    use chrono::{Utc, TimeZone};

    // Create an entry where SI Created < FN Created (timestomped)
    let mut ts = TimestampSet::default();
    ts.si_created = Some(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap());
    ts.fn_created = Some(Utc.with_ymd_and_hms(2025, 8, 10, 11, 0, 0).unwrap());

    let anomalies = detect_anomalies(&ts);
    assert!(anomalies.contains(AnomalyFlags::TIMESTOMPED_SI_LT_FN));
}
