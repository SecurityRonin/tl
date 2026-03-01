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
}
