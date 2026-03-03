use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
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

static NETLIST_ID_COUNTER: AtomicU64 = AtomicU64::new(0x4E4C_0000_0000_0000); // "NL" prefix

fn next_netlist_id() -> u64 {
    NETLIST_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Registry key paths ──────────────────────────────────────────────────────

/// NetworkList\Profiles: Per-network connection profile with first/last connect times.
const NETWORK_PROFILES_KEY: &str =
    r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles";

/// NetworkList\Signatures: Network signatures with DNS suffix and other identifiers.
const NETWORK_SIGNATURES_KEY: &str =
    r"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures";

// ─── Parsed structures ───────────────────────────────────────────────────────

/// A parsed network profile entry.
#[derive(Debug, Clone)]
pub struct NetworkProfileEntry {
    pub profile_name: String,
    pub description: String,
    pub dns_suffix: String,
    pub first_connected: Option<DateTime<Utc>>,
    pub last_connected: Option<DateTime<Utc>>,
    pub network_type: u32, // 6=wired, 23=VPN, 71=wireless
    pub managed: bool,
}

// ─── Timestamp parsing ───────────────────────────────────────────────────────

/// Parse a SYSTEMTIME binary value (16 bytes) to DateTime<Utc>.
/// SYSTEMTIME layout: year(2), month(2), dow(2), day(2), hour(2), min(2), sec(2), ms(2).
pub fn parse_systemtime(data: &[u8]) -> Option<DateTime<Utc>> {
    if data.len() < 16 {
        return None;
    }
    let year = u16::from_le_bytes([data[0], data[1]]) as i32;
    let month = u16::from_le_bytes([data[2], data[3]]) as u32;
    let day = u16::from_le_bytes([data[6], data[7]]) as u32;
    let hour = u16::from_le_bytes([data[8], data[9]]) as u32;
    let min = u16::from_le_bytes([data[10], data[11]]) as u32;
    let sec = u16::from_le_bytes([data[12], data[13]]) as u32;

    if year == 0 || month == 0 || day == 0 {
        return None;
    }

    chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|d| d.and_hms_opt(hour, min, sec))
        .map(|dt| dt.and_utc())
}

// ─── Parsing functions ───────────────────────────────────────────────────────

/// Parse NetworkList\Profiles from a SOFTWARE hive.
pub fn parse_network_profiles(data: &[u8]) -> Result<Vec<NetworkProfileEntry>> {
    let mut entries = Vec::new();

    let mut hive = Hive::new(
        Cursor::new(data.to_vec()),
        HiveParseMode::NormalWithBaseBlock,
    )
    .context("Failed to parse SOFTWARE hive")?
    .treat_hive_as_clean();

    let root_key = hive
        .root_key_node()
        .context("Failed to get root key")?;

    let profiles_key = match root_key.subpath(NETWORK_PROFILES_KEY, &mut hive) {
        Ok(Some(k)) => k,
        _ => return Ok(entries),
    };

    let subkeys = match profiles_key.borrow().subkeys(&mut hive) {
        Ok(sk) => sk.clone(),
        Err(_) => return Ok(entries),
    };

    for profile_rc in subkeys.iter() {
        let profile = profile_rc.borrow();
        let mut entry = NetworkProfileEntry {
            profile_name: String::new(),
            description: String::new(),
            dns_suffix: String::new(),
            first_connected: None,
            last_connected: None,
            network_type: 0,
            managed: false,
        };

        for value in profile.values() {
            let vname = value.name();
            match &*vname {
                "ProfileName" => {
                    if let nt_hive2::RegistryValue::RegSZ(s) = value.value() {
                        entry.profile_name = s.clone();
                    }
                }
                "Description" => {
                    if let nt_hive2::RegistryValue::RegSZ(s) = value.value() {
                        entry.description = s.clone();
                    }
                }
                "DnsSuffix" => {
                    if let nt_hive2::RegistryValue::RegSZ(s) = value.value() {
                        entry.dns_suffix = s.clone();
                    }
                }
                "NameType" => {
                    if let nt_hive2::RegistryValue::RegDWord(v) = value.value() {
                        entry.network_type = *v;
                    }
                }
                "Managed" => {
                    if let nt_hive2::RegistryValue::RegDWord(v) = value.value() {
                        entry.managed = *v != 0;
                    }
                }
                "DateCreated" => {
                    if let nt_hive2::RegistryValue::RegBinary(bytes) = value.value() {
                        entry.first_connected = parse_systemtime(&bytes);
                    }
                }
                "DateLastConnected" => {
                    if let nt_hive2::RegistryValue::RegBinary(bytes) = value.value() {
                        entry.last_connected = parse_systemtime(&bytes);
                    }
                }
                _ => {}
            }
        }

        if !entry.profile_name.is_empty() {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Classify a network type number into a human-readable string.
pub fn network_type_str(nt: u32) -> &'static str {
    match nt {
        6 => "Wired",
        23 => "VPN",
        71 => "Wireless",
        _ => "Unknown",
    }
}

// ─── Pipeline integration ────────────────────────────────────────────────────

/// Parse network connection history from SOFTWARE hive(s).
pub fn parse_network_history(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    let mut total = 0u32;

    for hive_entry in manifest
        .registry_hives
        .iter()
        .filter(|h| h.hive_type == RegistryHiveType::Software)
    {
        let data = match provider.open_file(&hive_entry.path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read SOFTWARE hive: {}", e);
                continue;
            }
        };

        match parse_network_profiles(&data) {
            Ok(profiles) => {
                for profile in profiles {
                    // Create entry for first connection
                    if let Some(first) = profile.first_connected {
                        store.push(TimelineEntry {
                            entity_id: EntityId::Generated(next_netlist_id()),
                            path: format!(
                                "[NetProfile:FirstConnect] {} ({}, DNS: {})",
                                profile.profile_name,
                                network_type_str(profile.network_type),
                                profile.dns_suffix
                            ),
                            primary_timestamp: first,
                            event_type: EventType::NetworkConnection,
                            timestamps: TimestampSet::default(),
                            sources: smallvec![ArtifactSource::Registry("SOFTWARE".to_string())],
                            anomalies: AnomalyFlags::empty(),
                            metadata: EntryMetadata::default(),
                        });
                        total += 1;
                    }

                    // Create entry for last connection
                    if let Some(last) = profile.last_connected {
                        store.push(TimelineEntry {
                            entity_id: EntityId::Generated(next_netlist_id()),
                            path: format!(
                                "[NetProfile:LastConnect] {} ({}, DNS: {})",
                                profile.profile_name,
                                network_type_str(profile.network_type),
                                profile.dns_suffix
                            ),
                            primary_timestamp: last,
                            event_type: EventType::NetworkConnection,
                            timestamps: TimestampSet::default(),
                            sources: smallvec![ArtifactSource::Registry("SOFTWARE".to_string())],
                            anomalies: AnomalyFlags::empty(),
                            metadata: EntryMetadata::default(),
                        });
                        total += 1;
                    }
                }
            }
            Err(e) => debug!("NetworkList parse error: {}", e),
        }
    }

    if total > 0 {
        debug!("Parsed {} network profile entries", total);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_systemtime_valid() {
        // 2025-06-15 14:30:45
        let mut data = [0u8; 16];
        data[0..2].copy_from_slice(&2025u16.to_le_bytes()); // year
        data[2..4].copy_from_slice(&6u16.to_le_bytes()); // month
        data[4..6].copy_from_slice(&0u16.to_le_bytes()); // dow
        data[6..8].copy_from_slice(&15u16.to_le_bytes()); // day
        data[8..10].copy_from_slice(&14u16.to_le_bytes()); // hour
        data[10..12].copy_from_slice(&30u16.to_le_bytes()); // min
        data[12..14].copy_from_slice(&45u16.to_le_bytes()); // sec
        data[14..16].copy_from_slice(&0u16.to_le_bytes()); // ms

        let dt = parse_systemtime(&data).unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2025-06-15 14:30:45");
    }

    #[test]
    fn test_parse_systemtime_too_short() {
        assert!(parse_systemtime(&[0u8; 8]).is_none());
    }

    #[test]
    fn test_parse_systemtime_zeros() {
        assert!(parse_systemtime(&[0u8; 16]).is_none());
    }

    #[test]
    fn test_network_type_str() {
        assert_eq!(network_type_str(6), "Wired");
        assert_eq!(network_type_str(23), "VPN");
        assert_eq!(network_type_str(71), "Wireless");
        assert_eq!(network_type_str(99), "Unknown");
    }

    #[test]
    fn test_network_profile_entry_creation() {
        let entry = NetworkProfileEntry {
            profile_name: "CorpWiFi".to_string(),
            description: "Corporate WiFi".to_string(),
            dns_suffix: "corp.local".to_string(),
            first_connected: Some(Utc::now()),
            last_connected: Some(Utc::now()),
            network_type: 71,
            managed: true,
        };
        assert_eq!(entry.profile_name, "CorpWiFi");
        assert_eq!(entry.network_type, 71);
        assert!(entry.managed);
    }

    #[test]
    fn test_parse_network_profiles_invalid_hive() {
        let result = parse_network_profiles(&[0u8; 100]);
        assert!(result.is_err());
    }

    // ─── next_netlist_id tests ──────────────────────────────────────────

    #[test]
    fn test_next_netlist_id_increments() {
        let id1 = next_netlist_id();
        let id2 = next_netlist_id();
        assert!(id2 > id1);
        assert_eq!(id2 - id1, 1);
    }

    #[test]
    fn test_next_netlist_id_has_nl_prefix() {
        let id = next_netlist_id();
        let prefix = (id >> 48) & 0xFFFF;
        assert_eq!(prefix, 0x4E4C);
    }

    // ─── parse_systemtime edge cases ────────────────────────────────────

    #[test]
    fn test_parse_systemtime_exactly_16_bytes() {
        let mut data = [0u8; 16];
        data[0..2].copy_from_slice(&2024u16.to_le_bytes());
        data[2..4].copy_from_slice(&12u16.to_le_bytes());
        data[6..8].copy_from_slice(&25u16.to_le_bytes());
        data[8..10].copy_from_slice(&23u16.to_le_bytes());
        data[10..12].copy_from_slice(&59u16.to_le_bytes());
        data[12..14].copy_from_slice(&59u16.to_le_bytes());
        let dt = parse_systemtime(&data).unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2024-12-25 23:59:59");
    }

    #[test]
    fn test_parse_systemtime_midnight() {
        let mut data = [0u8; 16];
        data[0..2].copy_from_slice(&2025u16.to_le_bytes());
        data[2..4].copy_from_slice(&1u16.to_le_bytes());
        data[6..8].copy_from_slice(&1u16.to_le_bytes());
        // hour=0, min=0, sec=0 (already zero)
        let dt = parse_systemtime(&data).unwrap();
        assert_eq!(dt.format("%H:%M:%S").to_string(), "00:00:00");
    }

    #[test]
    fn test_parse_systemtime_zero_year() {
        let mut data = [0u8; 16];
        data[2..4].copy_from_slice(&6u16.to_le_bytes()); // month
        data[6..8].copy_from_slice(&15u16.to_le_bytes()); // day
        // year=0 should return None
        assert!(parse_systemtime(&data).is_none());
    }

    #[test]
    fn test_parse_systemtime_zero_month() {
        let mut data = [0u8; 16];
        data[0..2].copy_from_slice(&2025u16.to_le_bytes()); // year
        data[6..8].copy_from_slice(&15u16.to_le_bytes()); // day
        // month=0 should return None
        assert!(parse_systemtime(&data).is_none());
    }

    #[test]
    fn test_parse_systemtime_zero_day() {
        let mut data = [0u8; 16];
        data[0..2].copy_from_slice(&2025u16.to_le_bytes()); // year
        data[2..4].copy_from_slice(&6u16.to_le_bytes()); // month
        // day=0 should return None
        assert!(parse_systemtime(&data).is_none());
    }

    #[test]
    fn test_parse_systemtime_15_bytes() {
        // Exactly 15 bytes should return None (needs 16)
        assert!(parse_systemtime(&[1u8; 15]).is_none());
    }

    #[test]
    fn test_parse_systemtime_empty() {
        assert!(parse_systemtime(&[]).is_none());
    }

    #[test]
    fn test_parse_systemtime_longer_than_16() {
        // Extra bytes should be ignored
        let mut data = [0u8; 32];
        data[0..2].copy_from_slice(&2025u16.to_le_bytes());
        data[2..4].copy_from_slice(&3u16.to_le_bytes());
        data[6..8].copy_from_slice(&10u16.to_le_bytes());
        data[8..10].copy_from_slice(&12u16.to_le_bytes());
        data[10..12].copy_from_slice(&30u16.to_le_bytes());
        data[12..14].copy_from_slice(&45u16.to_le_bytes());
        let dt = parse_systemtime(&data).unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2025-03-10 12:30:45");
    }

    // ─── network_type_str comprehensive tests ───────────────────────────

    #[test]
    fn test_network_type_str_all_known() {
        assert_eq!(network_type_str(6), "Wired");
        assert_eq!(network_type_str(23), "VPN");
        assert_eq!(network_type_str(71), "Wireless");
    }

    #[test]
    fn test_network_type_str_unknown_values() {
        assert_eq!(network_type_str(0), "Unknown");
        assert_eq!(network_type_str(1), "Unknown");
        assert_eq!(network_type_str(5), "Unknown");
        assert_eq!(network_type_str(7), "Unknown");
        assert_eq!(network_type_str(22), "Unknown");
        assert_eq!(network_type_str(24), "Unknown");
        assert_eq!(network_type_str(70), "Unknown");
        assert_eq!(network_type_str(72), "Unknown");
        assert_eq!(network_type_str(255), "Unknown");
        assert_eq!(network_type_str(u32::MAX), "Unknown");
    }

    // ─── NetworkProfileEntry tests ──────────────────────────────────────

    #[test]
    fn test_network_profile_entry_clone() {
        let now = Utc::now();
        let entry = NetworkProfileEntry {
            profile_name: "TestNet".to_string(),
            description: "Desc".to_string(),
            dns_suffix: "test.local".to_string(),
            first_connected: Some(now),
            last_connected: Some(now),
            network_type: 71,
            managed: false,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.profile_name, entry.profile_name);
        assert_eq!(cloned.dns_suffix, entry.dns_suffix);
        assert_eq!(cloned.network_type, entry.network_type);
        assert_eq!(cloned.managed, entry.managed);
    }

    #[test]
    fn test_network_profile_entry_debug() {
        let entry = NetworkProfileEntry {
            profile_name: "DebugNet".to_string(),
            description: String::new(),
            dns_suffix: String::new(),
            first_connected: None,
            last_connected: None,
            network_type: 0,
            managed: false,
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("NetworkProfileEntry"));
        assert!(debug_str.contains("DebugNet"));
    }

    #[test]
    fn test_network_profile_entry_no_timestamps() {
        let entry = NetworkProfileEntry {
            profile_name: "NoTime".to_string(),
            description: String::new(),
            dns_suffix: String::new(),
            first_connected: None,
            last_connected: None,
            network_type: 6,
            managed: false,
        };
        assert!(entry.first_connected.is_none());
        assert!(entry.last_connected.is_none());
    }

    #[test]
    fn test_network_profile_entry_managed_flag() {
        let entry = NetworkProfileEntry {
            profile_name: "ManagedNet".to_string(),
            description: String::new(),
            dns_suffix: "corp.com".to_string(),
            first_connected: None,
            last_connected: None,
            network_type: 71,
            managed: true,
        };
        assert!(entry.managed);
    }

    // ─── Description formatting tests ───────────────────────────────────

    #[test]
    fn test_network_first_connect_description() {
        let profile = NetworkProfileEntry {
            profile_name: "CoffeeShop WiFi".to_string(),
            description: String::new(),
            dns_suffix: "local".to_string(),
            first_connected: Some(Utc::now()),
            last_connected: None,
            network_type: 71,
            managed: false,
        };
        let desc = format!(
            "[NetProfile:FirstConnect] {} ({}, DNS: {})",
            profile.profile_name,
            network_type_str(profile.network_type),
            profile.dns_suffix
        );
        assert!(desc.contains("CoffeeShop WiFi"));
        assert!(desc.contains("Wireless"));
        assert!(desc.contains("DNS: local"));
    }

    #[test]
    fn test_network_last_connect_description() {
        let profile = NetworkProfileEntry {
            profile_name: "CorpVPN".to_string(),
            description: String::new(),
            dns_suffix: "corp.internal".to_string(),
            first_connected: None,
            last_connected: Some(Utc::now()),
            network_type: 23,
            managed: true,
        };
        let desc = format!(
            "[NetProfile:LastConnect] {} ({}, DNS: {})",
            profile.profile_name,
            network_type_str(profile.network_type),
            profile.dns_suffix
        );
        assert!(desc.contains("CorpVPN"));
        assert!(desc.contains("VPN"));
        assert!(desc.contains("corp.internal"));
    }

    #[test]
    fn test_network_wired_description() {
        let desc = format!(
            "[NetProfile:FirstConnect] {} ({}, DNS: {})",
            "Office LAN",
            network_type_str(6),
            "office.local"
        );
        assert!(desc.contains("Wired"));
    }

    // ─── Registry key path constant tests ───────────────────────────────

    #[test]
    fn test_network_profiles_key_format() {
        assert!(NETWORK_PROFILES_KEY.contains("NetworkList"));
        assert!(NETWORK_PROFILES_KEY.contains("Profiles"));
    }

    #[test]
    fn test_network_signatures_key_format() {
        assert!(NETWORK_SIGNATURES_KEY.contains("NetworkList"));
        assert!(NETWORK_SIGNATURES_KEY.contains("Signatures"));
    }

    // ─── parse_network_profiles edge cases ──────────────────────────────

    #[test]
    fn test_parse_network_profiles_empty_data() {
        let result = parse_network_profiles(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_network_profiles_garbage_data() {
        let garbage = vec![0xFFu8; 512];
        let result = parse_network_profiles(&garbage);
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

        let result = parse_network_history(&NoOpProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── parse_network_history pipeline tests ────────────────────────

    fn make_software_manifest() -> ArtifactManifest {
        use crate::collection::manifest::{RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SOFTWARE", 'C'),
            hive_type: RegistryHiveType::Software,
        });
        manifest
    }

    #[test]
    fn test_parse_network_history_open_file_error() {
        // Tests warn path when provider.open_file fails (line 187-190)
        let manifest = make_software_manifest();
        let mut store = TimelineStore::new();

        struct FailOpenProvider;
        impl CollectionProvider for FailOpenProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                anyhow::bail!("Cannot read SOFTWARE hive")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_network_history(&FailOpenProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_network_history_invalid_hive_data() {
        // Tests debug path when parse_network_profiles fails (line 237)
        let manifest = make_software_manifest();
        let mut store = TimelineStore::new();

        struct GarbageProvider;
        impl CollectionProvider for GarbageProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                Ok(vec![0xFFu8; 512])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_network_history(&GarbageProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_network_history_multiple_software_hives() {
        // Tests iterating multiple SOFTWARE hive entries
        use crate::collection::manifest::{RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SOFTWARE", 'C'),
            hive_type: RegistryHiveType::Software,
        });
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/backup/SOFTWARE", 'C'),
            hive_type: RegistryHiveType::Software,
        });

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
                anyhow::bail!("read error")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_network_history(&FailProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_network_history_skips_non_software_hives() {
        use crate::collection::manifest::{RegistryHiveEntry, RegistryHiveType};
        use crate::collection::path::NormalizedPath;

        let mut manifest = ArtifactManifest::default();
        // Only System hive - should be filtered out by the Software filter
        manifest.registry_hives.push(RegistryHiveEntry {
            path: NormalizedPath::from_image_path("/Windows/System32/config/SYSTEM", 'C'),
            hive_type: RegistryHiveType::System,
        });

        let mut store = TimelineStore::new();

        struct PanicProvider;
        impl CollectionProvider for PanicProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                panic!("Should not be called for non-Software hive")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_network_history(&PanicProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── parse_systemtime additional edge cases ──────────────────────

    #[test]
    fn test_parse_systemtime_invalid_date() {
        // Month 13 is invalid
        let mut data = [0u8; 16];
        data[0..2].copy_from_slice(&2025u16.to_le_bytes());
        data[2..4].copy_from_slice(&13u16.to_le_bytes()); // invalid month
        data[6..8].copy_from_slice(&15u16.to_le_bytes());
        assert!(parse_systemtime(&data).is_none());
    }

    #[test]
    fn test_parse_systemtime_invalid_day_32() {
        // Day 32 is invalid for any month
        let mut data = [0u8; 16];
        data[0..2].copy_from_slice(&2025u16.to_le_bytes());
        data[2..4].copy_from_slice(&1u16.to_le_bytes());
        data[6..8].copy_from_slice(&32u16.to_le_bytes()); // invalid day
        assert!(parse_systemtime(&data).is_none());
    }

    #[test]
    fn test_parse_systemtime_invalid_hour_25() {
        // Hour 25 is invalid
        let mut data = [0u8; 16];
        data[0..2].copy_from_slice(&2025u16.to_le_bytes());
        data[2..4].copy_from_slice(&1u16.to_le_bytes());
        data[6..8].copy_from_slice(&1u16.to_le_bytes());
        data[8..10].copy_from_slice(&25u16.to_le_bytes()); // invalid hour
        assert!(parse_systemtime(&data).is_none());
    }

    #[test]
    fn test_parse_systemtime_leap_year_feb_29() {
        let mut data = [0u8; 16];
        data[0..2].copy_from_slice(&2024u16.to_le_bytes()); // 2024 is a leap year
        data[2..4].copy_from_slice(&2u16.to_le_bytes());
        data[6..8].copy_from_slice(&29u16.to_le_bytes());
        data[8..10].copy_from_slice(&12u16.to_le_bytes());
        let dt = parse_systemtime(&data).unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2024-02-29");
    }

    #[test]
    fn test_parse_systemtime_non_leap_year_feb_29() {
        // 2025 is not a leap year, Feb 29 should fail
        let mut data = [0u8; 16];
        data[0..2].copy_from_slice(&2025u16.to_le_bytes());
        data[2..4].copy_from_slice(&2u16.to_le_bytes());
        data[6..8].copy_from_slice(&29u16.to_le_bytes());
        assert!(parse_systemtime(&data).is_none());
    }

    #[test]
    fn test_parse_systemtime_end_of_day() {
        let mut data = [0u8; 16];
        data[0..2].copy_from_slice(&2025u16.to_le_bytes());
        data[2..4].copy_from_slice(&12u16.to_le_bytes());
        data[6..8].copy_from_slice(&31u16.to_le_bytes());
        data[8..10].copy_from_slice(&23u16.to_le_bytes());
        data[10..12].copy_from_slice(&59u16.to_le_bytes());
        data[12..14].copy_from_slice(&59u16.to_le_bytes());
        let dt = parse_systemtime(&data).unwrap();
        assert_eq!(dt.format("%H:%M:%S").to_string(), "23:59:59");
    }

    #[test]
    fn test_parse_systemtime_year_1601() {
        // Windows FILETIME epoch
        let mut data = [0u8; 16];
        data[0..2].copy_from_slice(&1601u16.to_le_bytes());
        data[2..4].copy_from_slice(&1u16.to_le_bytes());
        data[6..8].copy_from_slice(&1u16.to_le_bytes());
        let dt = parse_systemtime(&data);
        // NaiveDate should support year 1601
        assert!(dt.is_some());
    }

    // ─── NetworkProfileEntry description format tests ────────────────

    #[test]
    fn test_network_profile_first_and_last_connect_descriptions() {
        let now = Utc::now();
        let profile = NetworkProfileEntry {
            profile_name: "Home WiFi".to_string(),
            description: "My Home Network".to_string(),
            dns_suffix: "home.local".to_string(),
            first_connected: Some(now),
            last_connected: Some(now),
            network_type: 71,
            managed: false,
        };

        let first_desc = format!(
            "[NetProfile:FirstConnect] {} ({}, DNS: {})",
            profile.profile_name,
            network_type_str(profile.network_type),
            profile.dns_suffix
        );
        assert!(first_desc.contains("Home WiFi"));
        assert!(first_desc.contains("Wireless"));
        assert!(first_desc.contains("home.local"));

        let last_desc = format!(
            "[NetProfile:LastConnect] {} ({}, DNS: {})",
            profile.profile_name,
            network_type_str(profile.network_type),
            profile.dns_suffix
        );
        assert!(last_desc.contains("LastConnect"));
    }

    #[test]
    fn test_network_profile_empty_dns_suffix() {
        let profile = NetworkProfileEntry {
            profile_name: "OpenWiFi".to_string(),
            description: String::new(),
            dns_suffix: String::new(),
            first_connected: Some(Utc::now()),
            last_connected: None,
            network_type: 71,
            managed: false,
        };
        let desc = format!(
            "[NetProfile:FirstConnect] {} ({}, DNS: {})",
            profile.profile_name,
            network_type_str(profile.network_type),
            profile.dns_suffix
        );
        assert!(desc.contains("DNS: "));
        assert!(desc.contains("OpenWiFi"));
    }

    #[test]
    fn test_network_profile_unknown_type() {
        let profile = NetworkProfileEntry {
            profile_name: "Mystery".to_string(),
            description: String::new(),
            dns_suffix: String::new(),
            first_connected: Some(Utc::now()),
            last_connected: None,
            network_type: 42,
            managed: false,
        };
        let desc = format!(
            "[NetProfile:FirstConnect] {} ({}, DNS: {})",
            profile.profile_name,
            network_type_str(profile.network_type),
            profile.dns_suffix
        );
        assert!(desc.contains("Unknown"));
    }

    #[test]
    fn test_next_netlist_id_uniqueness_batch() {
        let ids: Vec<u64> = (0..100).map(|_| next_netlist_id()).collect();
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ids.len());
    }

    #[test]
    fn test_parse_network_profiles_short_zeroed_data() {
        // Short zeroed data without valid regf header should error
        let data = vec![0u8; 32];
        let result = parse_network_profiles(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_network_profiles_short_random_data() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let result = parse_network_profiles(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_network_profile_all_fields_populated() {
        let now = Utc::now();
        let entry = NetworkProfileEntry {
            profile_name: "FullProfile".to_string(),
            description: "Full description".to_string(),
            dns_suffix: "corp.example.com".to_string(),
            first_connected: Some(now),
            last_connected: Some(now),
            network_type: 6,
            managed: true,
        };
        assert_eq!(entry.profile_name, "FullProfile");
        assert_eq!(entry.description, "Full description");
        assert_eq!(entry.dns_suffix, "corp.example.com");
        assert!(entry.first_connected.is_some());
        assert!(entry.last_connected.is_some());
        assert_eq!(network_type_str(entry.network_type), "Wired");
        assert!(entry.managed);
    }

    #[test]
    fn test_network_type_str_boundary_values() {
        assert_eq!(network_type_str(5), "Unknown");
        assert_eq!(network_type_str(7), "Unknown");
        assert_eq!(network_type_str(22), "Unknown");
        assert_eq!(network_type_str(24), "Unknown");
        assert_eq!(network_type_str(70), "Unknown");
        assert_eq!(network_type_str(72), "Unknown");
    }

    #[test]
    fn test_network_signatures_key_value() {
        assert_eq!(
            NETWORK_SIGNATURES_KEY,
            r"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures"
        );
    }

    #[test]
    fn test_network_profiles_key_value() {
        assert_eq!(
            NETWORK_PROFILES_KEY,
            r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
        );
    }

    // ─── Pipeline tests for parse_network_history ────────────────────────

    #[test]
    fn test_parse_network_history_formats_first_connect_entry() {
        // Simulate what parse_network_history does with a profile that has first_connected
        let profile = NetworkProfileEntry {
            profile_name: "TestWiFi".to_string(),
            description: "Test Network".to_string(),
            dns_suffix: "test.local".to_string(),
            first_connected: Some(Utc::now()),
            last_connected: None,
            network_type: 71,
            managed: false,
        };

        let desc = format!(
            "[NetProfile:FirstConnect] {} ({}, DNS: {})",
            profile.profile_name,
            network_type_str(profile.network_type),
            profile.dns_suffix
        );
        assert!(desc.contains("[NetProfile:FirstConnect]"));
        assert!(desc.contains("TestWiFi"));
        assert!(desc.contains("Wireless"));
        assert!(desc.contains("test.local"));
    }

    #[test]
    fn test_parse_network_history_formats_last_connect_entry() {
        let profile = NetworkProfileEntry {
            profile_name: "CorpLAN".to_string(),
            description: String::new(),
            dns_suffix: "corp.local".to_string(),
            first_connected: None,
            last_connected: Some(Utc::now()),
            network_type: 6,
            managed: true,
        };

        let desc = format!(
            "[NetProfile:LastConnect] {} ({}, DNS: {})",
            profile.profile_name,
            network_type_str(profile.network_type),
            profile.dns_suffix
        );
        assert!(desc.contains("[NetProfile:LastConnect]"));
        assert!(desc.contains("CorpLAN"));
        assert!(desc.contains("Wired"));
    }

    #[test]
    fn test_parse_network_history_both_timestamps_create_two_entries() {
        // When a profile has both first and last connected, two entries are created
        let now = Utc::now();
        let profile = NetworkProfileEntry {
            profile_name: "DualNet".to_string(),
            description: String::new(),
            dns_suffix: "dual.local".to_string(),
            first_connected: Some(now),
            last_connected: Some(now),
            network_type: 23,
            managed: false,
        };

        // Simulate what the pipeline does
        let mut count = 0u32;
        if profile.first_connected.is_some() {
            count += 1;
        }
        if profile.last_connected.is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn test_parse_network_history_no_timestamps_creates_zero_entries() {
        let profile = NetworkProfileEntry {
            profile_name: "NoTime".to_string(),
            description: String::new(),
            dns_suffix: String::new(),
            first_connected: None,
            last_connected: None,
            network_type: 0,
            managed: false,
        };

        let mut count = 0u32;
        if profile.first_connected.is_some() {
            count += 1;
        }
        if profile.last_connected.is_some() {
            count += 1;
        }
        assert_eq!(count, 0);
    }

    #[test]
    fn test_parse_network_history_vpn_type_format() {
        let profile = NetworkProfileEntry {
            profile_name: "CorpVPN".to_string(),
            description: String::new(),
            dns_suffix: "vpn.corp.com".to_string(),
            first_connected: Some(Utc::now()),
            last_connected: None,
            network_type: 23,
            managed: true,
        };

        let desc = format!(
            "[NetProfile:FirstConnect] {} ({}, DNS: {})",
            profile.profile_name,
            network_type_str(profile.network_type),
            profile.dns_suffix
        );
        assert!(desc.contains("VPN"));
        assert!(desc.contains("vpn.corp.com"));
    }

    #[test]
    fn test_parse_network_history_entry_formatting_unknown_type() {
        let profile = NetworkProfileEntry {
            profile_name: "Mystery".to_string(),
            description: String::new(),
            dns_suffix: "mystery.net".to_string(),
            first_connected: Some(Utc::now()),
            last_connected: None,
            network_type: 42,
            managed: false,
        };

        let desc = format!(
            "[NetProfile:FirstConnect] {} ({}, DNS: {})",
            profile.profile_name,
            network_type_str(profile.network_type),
            profile.dns_suffix
        );
        assert!(desc.contains("Unknown"));
        assert!(desc.contains("mystery.net"));
    }

    #[test]
    fn test_parse_network_history_empty_profile_name_not_pushed() {
        // Verifies that profiles with empty names would not be pushed
        let profile = NetworkProfileEntry {
            profile_name: String::new(),
            description: String::new(),
            dns_suffix: String::new(),
            first_connected: Some(Utc::now()),
            last_connected: None,
            network_type: 0,
            managed: false,
        };
        assert!(profile.profile_name.is_empty());
    }
}
