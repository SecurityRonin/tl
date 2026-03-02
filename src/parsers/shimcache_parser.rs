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

// ─── Constants ───────────────────────────────────────────────────────────────

/// Windows 10 AppCompatCache header signature: "10ts" (0x30747331)
const WIN10_HEADER_MAGIC: u32 = 0x30747331;
/// Windows 10 Creator Update header signature: "10ts" variant (0x34747331)
const WIN10_CREATOR_MAGIC: u32 = 0x34747331;
/// Windows 8.x header signature (0x00000080)
const WIN8_HEADER_MAGIC: u32 = 0x00000080;
/// Windows 7/Vista header signature (0xbadc0fee)
const WIN7_HEADER_MAGIC: u32 = 0xbadc0fee;
/// Windows XP header signature (0xdeadbeef)
const WINXP_HEADER_MAGIC: u32 = 0xdeadbeef;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a Windows FILETIME (100ns intervals since 1601-01-01) to DateTime<Utc>.
fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    const EPOCH_DIFF: i64 = 11_644_473_600;
    let secs = (filetime / 10_000_000) as i64 - EPOCH_DIFF;
    if secs < 0 {
        return None; // Invalid timestamp
    }
    let nanos = ((filetime % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    if offset + 8 > data.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}

/// Decode a UTF-16LE byte slice into a String.
fn decode_utf16le(data: &[u8]) -> String {
    let u16_iter = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
    char::decode_utf16(u16_iter)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>()
        .trim_end_matches('\0')
        .to_string()
}

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static SHIMCACHE_ID_COUNTER: AtomicU64 = AtomicU64::new(0x5348_0000_0000_0000); // "SH" prefix

fn next_shimcache_id() -> u64 {
    SHIMCACHE_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Parsed entry ────────────────────────────────────────────────────────────

/// A parsed Shimcache entry.
#[derive(Debug, Clone)]
pub struct ShimcacheEntry {
    pub path: String,
    pub last_modified: Option<DateTime<Utc>>,
}

// ─── AppCompatCache binary parsing ──────────────────────────────────────────

/// Parse the AppCompatCache binary blob.
///
/// The format varies by Windows version, detected by the first 4 bytes (magic).
pub fn parse_appcompat_cache(data: &[u8]) -> Result<Vec<ShimcacheEntry>> {
    if data.len() < 4 {
        anyhow::bail!("AppCompatCache data too short: {} bytes", data.len());
    }

    let magic = read_u32_le(data, 0).unwrap();

    match magic {
        WIN10_HEADER_MAGIC | WIN10_CREATOR_MAGIC => parse_win10(data),
        WIN8_HEADER_MAGIC => parse_win8(data),
        WIN7_HEADER_MAGIC => parse_win7(data),
        WINXP_HEADER_MAGIC => parse_winxp(data),
        _ => {
            debug!("Unknown AppCompatCache magic: 0x{:08x}", magic);
            // Try Win10 format as fallback (some variants don't have standard magic)
            parse_win10_fallback(data)
        }
    }
}

/// Parse Windows 10/11 AppCompatCache format.
///
/// Header: 0x30 bytes (or 0x34 bytes for Creator Update+)
/// Each entry:
///   - Signature "10ts" (4 bytes)
///   - Unknown (4 bytes)
///   - Cache entry size (4 bytes) -- total size of this entry
///   - Path length in bytes (u16) -- includes null terminator
///   - Path (UTF-16LE)
///   - Last modified timestamp (FILETIME, 8 bytes)
///   - Data size (u32)
///   - Data (variable)
fn parse_win10(data: &[u8]) -> Result<Vec<ShimcacheEntry>> {
    let mut entries = Vec::new();

    // Skip past the header (0x30 or 0x34 bytes)
    let header_size = if data.len() >= 0x34 {
        let magic = read_u32_le(data, 0).unwrap();
        if magic == WIN10_CREATOR_MAGIC {
            0x34
        } else {
            0x30
        }
    } else {
        0x30
    };

    let mut offset = header_size;

    while offset + 12 <= data.len() {
        // Check for "10ts" entry signature
        let entry_sig = read_u32_le(data, offset);
        if entry_sig != Some(WIN10_HEADER_MAGIC) && entry_sig != Some(WIN10_CREATOR_MAGIC) {
            // No more entries or corrupted data
            break;
        }

        // Unknown field (4 bytes)
        // Cache entry size (4 bytes)
        let _cache_entry_size = match read_u32_le(data, offset + 8) {
            Some(s) => s as usize,
            None => break,
        };

        // Path length in bytes (u16) at offset + 12
        let path_len = match read_u16_le(data, offset + 0x0C) {
            Some(l) => l as usize,
            None => break,
        };

        let path_start = offset + 0x0E;
        if path_start + path_len > data.len() {
            debug!(
                "Shimcache Win10: path extends beyond data at offset 0x{:x}",
                offset
            );
            break;
        }

        let path = decode_utf16le(&data[path_start..path_start + path_len]);

        // Timestamp follows the path (FILETIME, 8 bytes)
        let ts_offset = path_start + path_len;
        let last_modified = read_u64_le(data, ts_offset).and_then(filetime_to_datetime);

        // Data size follows timestamp
        let data_size_offset = ts_offset + 8;
        let data_size = read_u32_le(data, data_size_offset).unwrap_or(0) as usize;

        if !path.is_empty() {
            entries.push(ShimcacheEntry {
                path,
                last_modified,
            });
        }

        // Move to next entry: past data_size field + data
        offset = data_size_offset + 4 + data_size;
    }

    debug!("Parsed {} Win10 shimcache entries", entries.len());
    Ok(entries)
}

/// Fallback parser for unknown Win10 variants.
fn parse_win10_fallback(data: &[u8]) -> Result<Vec<ShimcacheEntry>> {
    // Scan for "10ts" signatures in the data
    let mut entries = Vec::new();
    let sig_bytes = WIN10_HEADER_MAGIC.to_le_bytes();

    let mut offset = 0x30; // Start after potential header
    while offset + 16 <= data.len() {
        // Look for entry signature
        if &data[offset..offset + 4] == &sig_bytes {
            let path_len = match read_u16_le(data, offset + 0x0C) {
                Some(l) => l as usize,
                None => {
                    offset += 4;
                    continue;
                }
            };

            let path_start = offset + 0x0E;
            if path_start + path_len <= data.len() && path_len > 0 && path_len < 2048 {
                let path = decode_utf16le(&data[path_start..path_start + path_len]);
                let ts_offset = path_start + path_len;
                let last_modified = read_u64_le(data, ts_offset).and_then(filetime_to_datetime);

                let data_size_offset = ts_offset + 8;
                let data_size = read_u32_le(data, data_size_offset).unwrap_or(0) as usize;

                if !path.is_empty() {
                    entries.push(ShimcacheEntry {
                        path,
                        last_modified,
                    });
                }

                offset = data_size_offset + 4 + data_size;
                continue;
            }
        }
        offset += 4;
    }

    if entries.is_empty() {
        anyhow::bail!("No shimcache entries found with fallback parser");
    }

    debug!(
        "Parsed {} shimcache entries with fallback parser",
        entries.len()
    );
    Ok(entries)
}

/// Parse Windows 8.x AppCompatCache format.
///
/// Header: 0x80 bytes
/// Each entry:
///   - Path length (u32)
///   - Path (UTF-16LE)
///   - Insertion flags (u32)
///   - Shim flags (u32)
///   - Last modified timestamp (FILETIME)
///   - Data size (u32)
///   - Data (variable)
fn parse_win8(data: &[u8]) -> Result<Vec<ShimcacheEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0x80; // Skip header

    while offset + 12 <= data.len() {
        let path_len = match read_u32_le(data, offset) {
            Some(l) if l > 0 && l < 2048 => l as usize,
            _ => break,
        };

        let path_start = offset + 4;
        if path_start + path_len > data.len() {
            break;
        }

        let path = decode_utf16le(&data[path_start..path_start + path_len]);

        // Skip insertion flags (4 bytes) and shim flags (4 bytes)
        let ts_offset = path_start + path_len + 8;
        let last_modified = read_u64_le(data, ts_offset).and_then(filetime_to_datetime);

        let data_size_offset = ts_offset + 8;
        let data_size = read_u32_le(data, data_size_offset).unwrap_or(0) as usize;

        if !path.is_empty() {
            entries.push(ShimcacheEntry {
                path,
                last_modified,
            });
        }

        offset = data_size_offset + 4 + data_size;
    }

    debug!("Parsed {} Win8 shimcache entries", entries.len());
    Ok(entries)
}

/// Parse Windows 7 AppCompatCache format.
///
/// Header: 0x80 bytes
///   - Signature (4 bytes): 0xbadc0fee
///   - Number of entries (4 bytes) at offset 4
/// Each entry (fixed 0x30 bytes + data):
///   - Path length (u16)
///   - Max path length (u16)
///   - Path offset (u32) - offset from start of data
///   - Last modified timestamp (FILETIME)
///   - Insertion flags (u32)
///   - Shim flags (u32)
///   - Data size (u32)
///   - Data offset (u32)
fn parse_win7(data: &[u8]) -> Result<Vec<ShimcacheEntry>> {
    let mut entries = Vec::new();

    let num_entries = read_u32_le(data, 4).unwrap_or(0) as usize;
    if num_entries == 0 || num_entries > 2048 {
        return Ok(entries);
    }

    let header_size = 0x80usize;
    let entry_size = 0x30usize; // Fixed entry size for Win7 64-bit
    let entry_size_32 = 0x20usize; // Fixed entry size for Win7 32-bit

    // Determine 32 vs 64 bit by checking if entries fit
    let is_64bit = header_size + num_entries * entry_size <= data.len();
    let actual_entry_size = if is_64bit { entry_size } else { entry_size_32 };

    for i in 0..num_entries {
        let entry_offset = header_size + i * actual_entry_size;
        if entry_offset + actual_entry_size > data.len() {
            break;
        }

        let path_len = match read_u16_le(data, entry_offset) {
            Some(l) => l as usize,
            None => break,
        };
        let _max_path_len = read_u16_le(data, entry_offset + 2);

        let (path_ptr, ts_offset) = if is_64bit {
            // 64-bit: 4 bytes padding after max_path_len, then 8-byte path offset
            let ptr = match read_u64_le(data, entry_offset + 8) {
                Some(p) => p as usize,
                None => break,
            };
            (ptr, entry_offset + 16)
        } else {
            // 32-bit: 4-byte path offset
            let ptr = match read_u32_le(data, entry_offset + 4) {
                Some(p) => p as usize,
                None => break,
            };
            (ptr, entry_offset + 8)
        };

        let last_modified = read_u64_le(data, ts_offset).and_then(filetime_to_datetime);

        // Path offset is from the start of the file
        if path_ptr + path_len <= data.len() && path_len > 0 {
            let path = decode_utf16le(&data[path_ptr..path_ptr + path_len]);
            if !path.is_empty() {
                entries.push(ShimcacheEntry {
                    path,
                    last_modified,
                });
            }
        }
    }

    debug!("Parsed {} Win7 shimcache entries", entries.len());
    Ok(entries)
}

/// Parse Windows XP AppCompatCache format (basic).
fn parse_winxp(data: &[u8]) -> Result<Vec<ShimcacheEntry>> {
    let mut entries = Vec::new();

    let num_entries = read_u32_le(data, 4).unwrap_or(0) as usize;
    if num_entries == 0 || num_entries > 2048 {
        return Ok(entries);
    }

    // XP format: header at 0x190, each entry 0x228 bytes
    // Entry: path (MAX_PATH * 2 = 520 bytes UTF-16LE), then timestamps
    let header_size = 0x190usize;
    let entry_size = 0x228usize;

    for i in 0..num_entries {
        let entry_offset = header_size + i * entry_size;
        if entry_offset + entry_size > data.len() {
            break;
        }

        let path = decode_utf16le(&data[entry_offset..entry_offset + 520]);
        let last_modified =
            read_u64_le(data, entry_offset + 528).and_then(filetime_to_datetime);

        if !path.is_empty() {
            entries.push(ShimcacheEntry {
                path,
                last_modified,
            });
        }
    }

    debug!("Parsed {} WinXP shimcache entries", entries.len());
    Ok(entries)
}

// ─── Registry navigation helper ──────────────────────────────────────────────

/// Try to find the AppCompatCache value in the SYSTEM hive.
///
/// Navigates to: ControlSet001\Control\Session Manager\AppCompatCache
/// and reads the "AppCompatCache" binary value.
fn extract_appcompat_cache_value(data: &[u8]) -> Result<Vec<u8>> {
    let mut hive = Hive::new(
        Cursor::new(data.to_vec()),
        HiveParseMode::NormalWithBaseBlock,
    )
    .context("Failed to parse SYSTEM registry hive")?
    .treat_hive_as_clean();

    let root_key = hive
        .root_key_node()
        .context("Failed to get root key from SYSTEM hive")?;

    // Try ControlSet001 first, then ControlSet002
    for control_set in &["ControlSet001", "ControlSet002"] {
        let path = format!(
            r"{}\Control\Session Manager\AppCompatCache",
            control_set
        );

        let cache_key = match root_key.subpath(path.as_str(), &mut hive) {
            Ok(Some(key)) => key,
            _ => continue,
        };

        let cache_key_ref = cache_key.borrow();
        let values = cache_key_ref.values();
        for value in values.iter() {
            if value.name().eq_ignore_ascii_case("AppCompatCache") {
                if let nt_hive2::RegistryValue::RegBinary(binary) = value.value() {
                    debug!(
                        "Found AppCompatCache value ({} bytes) in {}",
                        binary.len(),
                        path
                    );
                    return Ok(binary.clone());
                }
            }
        }
    }

    anyhow::bail!("AppCompatCache value not found in SYSTEM hive")
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse Shimcache entries from the SYSTEM registry hive.
///
/// The Shimcache (AppCompatCache) tracks file execution evidence. It is stored
/// as a binary blob in the SYSTEM hive at:
///   ControlSet001\Control\Session Manager\AppCompatCache\AppCompatCache
///
/// The binary format varies by Windows version and is auto-detected by this parser.
pub fn parse_shimcache(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    // Find the SYSTEM hive
    let system_hives: Vec<_> = manifest
        .registry_hives
        .iter()
        .filter(|h| h.hive_type == RegistryHiveType::System)
        .collect();

    if system_hives.is_empty() {
        debug!("No SYSTEM hive found in manifest");
        return Ok(());
    }

    for hive_entry in &system_hives {
        let data = match provider.open_file(&hive_entry.path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read SYSTEM hive {}: {}", hive_entry.path, e);
                continue;
            }
        };

        debug!(
            "Parsing Shimcache from SYSTEM hive: {} ({} bytes)",
            hive_entry.path,
            data.len()
        );

        // Extract the AppCompatCache binary value
        let cache_data = match extract_appcompat_cache_value(&data) {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    "Could not extract AppCompatCache from {}: {}",
                    hive_entry.path, e
                );
                continue;
            }
        };

        // Parse the binary blob
        let shimcache_entries = match parse_appcompat_cache(&cache_data) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to parse AppCompatCache blob: {}", e);
                continue;
            }
        };

        debug!(
            "Found {} Shimcache entries from {}",
            shimcache_entries.len(),
            hive_entry.path
        );

        for sc_entry in &shimcache_entries {
            let primary_timestamp = match sc_entry.last_modified {
                Some(ts) => ts,
                None => continue, // Skip entries without timestamps
            };

            let mut timestamps = TimestampSet::default();
            timestamps.shimcache_timestamp = Some(primary_timestamp);

            let entry = TimelineEntry {
                entity_id: EntityId::Generated(next_shimcache_id()),
                path: sc_entry.path.clone(),
                primary_timestamp,
                event_type: EventType::Execute,
                timestamps,
                sources: smallvec![ArtifactSource::Shimcache],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
            };

            store.push(entry);
        }
    }

    Ok(())
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_to_datetime() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;
        let result = filetime_to_datetime(filetime).unwrap();
        assert_eq!(result, dt);
    }

    #[test]
    fn test_filetime_zero() {
        assert!(filetime_to_datetime(0).is_none());
    }

    #[test]
    fn test_decode_utf16le() {
        // "C:\Windows\cmd.exe" in UTF-16LE
        let s = r"C:\Windows\cmd.exe";
        let encoded: Vec<u8> = s
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(decode_utf16le(&encoded), s);
    }

    #[test]
    fn test_decode_utf16le_with_null() {
        let s = "test\0";
        let encoded: Vec<u8> = s
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(decode_utf16le(&encoded), "test");
    }

    /// Build a minimal Win10 AppCompatCache blob for testing.
    fn build_test_win10_cache(entries: &[(&str, u64)]) -> Vec<u8> {
        let mut buf = Vec::new();

        // Header: 0x30 bytes
        // Magic (first 4 bytes)
        buf.extend_from_slice(&WIN10_HEADER_MAGIC.to_le_bytes());
        // Pad rest of header
        buf.extend(vec![0u8; 0x30 - 4]);

        for (path, filetime) in entries {
            // Entry signature "10ts"
            buf.extend_from_slice(&WIN10_HEADER_MAGIC.to_le_bytes());
            // Unknown (4 bytes)
            buf.extend_from_slice(&0u32.to_le_bytes());

            // Encode path as UTF-16LE
            let path_bytes: Vec<u8> = path
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect();

            // Cache entry size = 12 (sig+unk+size) + 2 (path_len) + path_bytes + 8 (ts) + 4 (data_size)
            let entry_size = 12 + 2 + path_bytes.len() + 8 + 4;
            buf.extend_from_slice(&(entry_size as u32).to_le_bytes());

            // Path length (u16)
            buf.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());

            // Path
            buf.extend_from_slice(&path_bytes);

            // Timestamp (FILETIME)
            buf.extend_from_slice(&filetime.to_le_bytes());

            // Data size (0)
            buf.extend_from_slice(&0u32.to_le_bytes());
        }

        buf
    }

    #[test]
    fn test_parse_win10_single_entry() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let filetime = (secs as u64) * 10_000_000;

        let data = build_test_win10_cache(&[(r"C:\Windows\System32\cmd.exe", filetime)]);
        let entries = parse_appcompat_cache(&data).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, r"C:\Windows\System32\cmd.exe");
        assert_eq!(entries[0].last_modified, Some(dt));
    }

    #[test]
    fn test_parse_win10_multiple_entries() {
        use chrono::TimeZone;
        let dt1 = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let dt2 = Utc.with_ymd_and_hms(2025, 6, 15, 11, 0, 0).unwrap();

        let ft = |dt: DateTime<Utc>| -> u64 {
            let secs = dt.timestamp() + 11_644_473_600;
            (secs as u64) * 10_000_000
        };

        let data = build_test_win10_cache(&[
            (r"C:\Windows\System32\cmd.exe", ft(dt1)),
            (r"C:\Windows\notepad.exe", ft(dt2)),
        ]);
        let entries = parse_appcompat_cache(&data).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, r"C:\Windows\System32\cmd.exe");
        assert_eq!(entries[0].last_modified, Some(dt1));
        assert_eq!(entries[1].path, r"C:\Windows\notepad.exe");
        assert_eq!(entries[1].last_modified, Some(dt2));
    }

    #[test]
    fn test_parse_appcompat_too_short() {
        let data = vec![0u8; 2];
        assert!(parse_appcompat_cache(&data).is_err());
    }

    #[test]
    fn test_shimcache_entry_creation() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();

        let sc_entry = ShimcacheEntry {
            path: r"C:\Windows\System32\cmd.exe".to_string(),
            last_modified: Some(dt),
        };

        let mut timestamps = TimestampSet::default();
        timestamps.shimcache_timestamp = sc_entry.last_modified;

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_shimcache_id()),
            path: sc_entry.path.clone(),
            primary_timestamp: dt,
            event_type: EventType::Execute,
            timestamps,
            sources: smallvec![ArtifactSource::Shimcache],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        assert_eq!(entry.path, r"C:\Windows\System32\cmd.exe");
        assert_eq!(entry.event_type, EventType::Execute);
    }

    // ─── next_shimcache_id tests ────────────────────────────────────────

    #[test]
    fn test_next_shimcache_id_increments() {
        let id1 = next_shimcache_id();
        let id2 = next_shimcache_id();
        assert!(id2 > id1);
        assert_eq!(id2 - id1, 1);
    }

    #[test]
    fn test_next_shimcache_id_has_sh_prefix() {
        let id = next_shimcache_id();
        let prefix = (id >> 48) & 0xFFFF;
        assert_eq!(prefix, 0x5348);
    }

    // ─── filetime_to_datetime edge cases ────────────────────────────────

    #[test]
    fn test_filetime_pre_unix_epoch() {
        // A filetime that would be before Unix epoch should return None
        let ft: u64 = 100; // very small, way before 1970
        assert!(filetime_to_datetime(ft).is_none());
    }

    #[test]
    fn test_filetime_at_unix_epoch() {
        let ft: u64 = 11_644_473_600 * 10_000_000;
        let result = filetime_to_datetime(ft).unwrap();
        assert_eq!(result.timestamp(), 0);
    }

    #[test]
    fn test_filetime_preserves_subseconds() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let ft = secs as u64 * 10_000_000 + 5_000_000; // +0.5s
        let result = filetime_to_datetime(ft).unwrap();
        assert_eq!(result.timestamp_subsec_nanos(), 500_000_000);
    }

    // ─── read_u16_le tests ──────────────────────────────────────────────

    #[test]
    fn test_read_u16_le_valid() {
        let data = [0x34, 0x12];
        assert_eq!(read_u16_le(&data, 0), Some(0x1234));
    }

    #[test]
    fn test_read_u16_le_offset() {
        let data = [0x00, 0x00, 0xAB, 0xCD];
        assert_eq!(read_u16_le(&data, 2), Some(0xCDAB));
    }

    #[test]
    fn test_read_u16_le_out_of_bounds() {
        let data = [0x34];
        assert_eq!(read_u16_le(&data, 0), None);
    }

    #[test]
    fn test_read_u16_le_at_boundary() {
        let data = [0x01, 0x00];
        assert_eq!(read_u16_le(&data, 0), Some(1));
        assert_eq!(read_u16_le(&data, 1), None);
    }

    #[test]
    fn test_read_u16_le_empty() {
        let data: [u8; 0] = [];
        assert_eq!(read_u16_le(&data, 0), None);
    }

    // ─── read_u32_le tests ──────────────────────────────────────────────

    #[test]
    fn test_read_u32_le_valid() {
        let data = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&data, 0), Some(0x12345678));
    }

    #[test]
    fn test_read_u32_le_offset() {
        let data = [0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE];
        assert_eq!(read_u32_le(&data, 2), Some(0xDEADBEEF));
    }

    #[test]
    fn test_read_u32_le_out_of_bounds() {
        let data = [0x01, 0x02, 0x03];
        assert_eq!(read_u32_le(&data, 0), None);
    }

    #[test]
    fn test_read_u32_le_at_boundary() {
        let data = [0x01, 0x00, 0x00, 0x00];
        assert_eq!(read_u32_le(&data, 0), Some(1));
        assert_eq!(read_u32_le(&data, 1), None);
    }

    #[test]
    fn test_read_u32_le_empty() {
        let data: [u8; 0] = [];
        assert_eq!(read_u32_le(&data, 0), None);
    }

    #[test]
    fn test_read_u32_le_known_magic() {
        let data = WIN10_HEADER_MAGIC.to_le_bytes();
        assert_eq!(read_u32_le(&data, 0), Some(WIN10_HEADER_MAGIC));
    }

    // ─── read_u64_le tests ──────────────────────────────────────────────

    #[test]
    fn test_read_u64_le_valid() {
        let data = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_u64_le(&data, 0), Some(1));
    }

    #[test]
    fn test_read_u64_le_max() {
        let data = [0xFF; 8];
        assert_eq!(read_u64_le(&data, 0), Some(u64::MAX));
    }

    #[test]
    fn test_read_u64_le_out_of_bounds() {
        let data = [0x01; 7];
        assert_eq!(read_u64_le(&data, 0), None);
    }

    #[test]
    fn test_read_u64_le_offset() {
        let data = [0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_u64_le(&data, 2), Some(1));
    }

    #[test]
    fn test_read_u64_le_empty() {
        let data: [u8; 0] = [];
        assert_eq!(read_u64_le(&data, 0), None);
    }

    // ─── decode_utf16le tests ───────────────────────────────────────────

    #[test]
    fn test_decode_utf16le_empty() {
        assert_eq!(decode_utf16le(&[]), "");
    }

    #[test]
    fn test_decode_utf16le_ascii_path() {
        let s = r"C:\Program Files\test.exe";
        let encoded: Vec<u8> = s
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(decode_utf16le(&encoded), s);
    }

    #[test]
    fn test_decode_utf16le_multiple_nulls() {
        let s = "abc\0\0\0";
        let encoded: Vec<u8> = s
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(decode_utf16le(&encoded), "abc");
    }

    #[test]
    fn test_decode_utf16le_odd_byte_count() {
        // Odd byte count: chunks_exact(2) skips the last byte
        let data = [0x41, 0x00, 0x42]; // "A" + incomplete
        assert_eq!(decode_utf16le(&data), "A");
    }

    #[test]
    fn test_decode_utf16le_single_char() {
        // 'Z' = 0x005A in UTF-16LE
        let data = [0x5A, 0x00];
        assert_eq!(decode_utf16le(&data), "Z");
    }

    // ─── Header magic constant tests ────────────────────────────────────

    #[test]
    fn test_win10_magic_value() {
        assert_eq!(WIN10_HEADER_MAGIC, 0x30747331);
    }

    #[test]
    fn test_win10_creator_magic_value() {
        assert_eq!(WIN10_CREATOR_MAGIC, 0x34747331);
    }

    #[test]
    fn test_win8_magic_value() {
        assert_eq!(WIN8_HEADER_MAGIC, 0x00000080);
    }

    #[test]
    fn test_win7_magic_value() {
        assert_eq!(WIN7_HEADER_MAGIC, 0xbadc0fee);
    }

    #[test]
    fn test_winxp_magic_value() {
        assert_eq!(WINXP_HEADER_MAGIC, 0xdeadbeef);
    }

    #[test]
    fn test_all_magics_are_distinct() {
        let magics = [
            WIN10_HEADER_MAGIC,
            WIN10_CREATOR_MAGIC,
            WIN8_HEADER_MAGIC,
            WIN7_HEADER_MAGIC,
            WINXP_HEADER_MAGIC,
        ];
        for i in 0..magics.len() {
            for j in (i + 1)..magics.len() {
                assert_ne!(magics[i], magics[j], "Magics at {} and {} are equal", i, j);
            }
        }
    }

    // ─── parse_appcompat_cache dispatch tests ───────────────────────────

    #[test]
    fn test_parse_appcompat_cache_empty() {
        assert!(parse_appcompat_cache(&[]).is_err());
    }

    #[test]
    fn test_parse_appcompat_cache_three_bytes() {
        assert!(parse_appcompat_cache(&[0x01, 0x02, 0x03]).is_err());
    }

    #[test]
    fn test_parse_appcompat_cache_unknown_magic_short() {
        // Unknown magic with too little data should fail via fallback parser
        let mut data = vec![0u8; 0x40];
        data[0..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let result = parse_appcompat_cache(&data);
        assert!(result.is_err()); // fallback parser won't find entries
    }

    // ─── parse_win10 builder tests ──────────────────────────────────────

    #[test]
    fn test_parse_win10_no_entries() {
        // Just a header with Win10 magic, no entry data following
        let mut data = vec![0u8; 0x30];
        data[0..4].copy_from_slice(&WIN10_HEADER_MAGIC.to_le_bytes());
        let entries = parse_appcompat_cache(&data).unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_parse_win10_empty_path_skipped() {
        // Build entry with 0-length path
        let mut buf = vec![0u8; 0x30];
        buf[0..4].copy_from_slice(&WIN10_HEADER_MAGIC.to_le_bytes());

        // Entry sig
        buf.extend_from_slice(&WIN10_HEADER_MAGIC.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // unknown
        buf.extend_from_slice(&26u32.to_le_bytes()); // cache entry size
        buf.extend_from_slice(&0u16.to_le_bytes()); // path_len = 0
        buf.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        buf.extend_from_slice(&0u32.to_le_bytes()); // data_size

        let entries = parse_appcompat_cache(&buf).unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_build_test_win10_cache_helper() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let ft = (secs as u64) * 10_000_000;

        let data = build_test_win10_cache(&[
            (r"C:\test1.exe", ft),
            (r"C:\test2.exe", ft),
            (r"C:\test3.exe", ft),
        ]);
        let entries = parse_appcompat_cache(&data).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, r"C:\test1.exe");
        assert_eq!(entries[2].path, r"C:\test3.exe");
    }

    #[test]
    fn test_parse_win10_zero_timestamp() {
        let data = build_test_win10_cache(&[(r"C:\zero_ts.exe", 0)]);
        let entries = parse_appcompat_cache(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].last_modified.is_none());
    }

    // ─── parse_win8 tests ───────────────────────────────────────────────

    #[test]
    fn test_parse_win8_no_entries() {
        let mut data = vec![0u8; 0x80];
        data[0..4].copy_from_slice(&WIN8_HEADER_MAGIC.to_le_bytes());
        let entries = parse_appcompat_cache(&data).unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_parse_win8_single_entry() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let ft = (secs as u64) * 10_000_000;

        let path = r"C:\Windows\win8app.exe";
        let path_bytes: Vec<u8> = path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut data = vec![0u8; 0x80];
        data[0..4].copy_from_slice(&WIN8_HEADER_MAGIC.to_le_bytes());

        // Entry: path_len(4) + path + insertion_flags(4) + shim_flags(4) + timestamp(8) + data_size(4)
        data.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&path_bytes);
        data.extend_from_slice(&0u32.to_le_bytes()); // insertion flags
        data.extend_from_slice(&0u32.to_le_bytes()); // shim flags
        data.extend_from_slice(&ft.to_le_bytes()); // timestamp
        data.extend_from_slice(&0u32.to_le_bytes()); // data size

        let entries = parse_appcompat_cache(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, path);
        assert_eq!(entries[0].last_modified, Some(dt));
    }

    // ─── parse_win7 tests ───────────────────────────────────────────────

    #[test]
    fn test_parse_win7_zero_entries() {
        let mut data = vec![0u8; 0x80];
        data[0..4].copy_from_slice(&WIN7_HEADER_MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // num_entries = 0
        let entries = parse_appcompat_cache(&data).unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_parse_win7_too_many_entries() {
        let mut data = vec![0u8; 0x80];
        data[0..4].copy_from_slice(&WIN7_HEADER_MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&3000u32.to_le_bytes()); // > 2048 limit
        let entries = parse_appcompat_cache(&data).unwrap();
        assert_eq!(entries.len(), 0);
    }

    // ─── parse_winxp tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_winxp_zero_entries() {
        let mut data = vec![0u8; 0x190];
        data[0..4].copy_from_slice(&WINXP_HEADER_MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // num_entries = 0
        let entries = parse_appcompat_cache(&data).unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_parse_winxp_too_many_entries() {
        let mut data = vec![0u8; 0x190];
        data[0..4].copy_from_slice(&WINXP_HEADER_MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&5000u32.to_le_bytes()); // > 2048 limit
        let entries = parse_appcompat_cache(&data).unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_parse_winxp_single_entry() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2005, 3, 1, 8, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let ft = (secs as u64) * 10_000_000;

        let path = r"C:\WINDOWS\system32\notepad.exe";

        // XP format: header at 0x190, entry is 0x228 bytes
        // Entry: path (520 bytes UTF-16LE) then 8 bytes padding, then timestamp
        let mut data = vec![0u8; 0x190 + 0x228];
        data[0..4].copy_from_slice(&WINXP_HEADER_MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // 1 entry

        // Write path at entry offset (0x190)
        let path_bytes: Vec<u8> = path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let entry_offset = 0x190;
        data[entry_offset..entry_offset + path_bytes.len()].copy_from_slice(&path_bytes);

        // Timestamp at offset 528 within entry
        let ts_offset = entry_offset + 528;
        data[ts_offset..ts_offset + 8].copy_from_slice(&ft.to_le_bytes());

        let entries = parse_appcompat_cache(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, path);
        assert_eq!(entries[0].last_modified, Some(dt));
    }

    // ─── ShimcacheEntry struct tests ────────────────────────────────────

    #[test]
    fn test_shimcache_entry_clone() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let entry = ShimcacheEntry {
            path: r"C:\test.exe".to_string(),
            last_modified: Some(dt),
        };
        let cloned = entry.clone();
        assert_eq!(cloned.path, entry.path);
        assert_eq!(cloned.last_modified, entry.last_modified);
    }

    #[test]
    fn test_shimcache_entry_no_timestamp() {
        let entry = ShimcacheEntry {
            path: r"C:\unknown.exe".to_string(),
            last_modified: None,
        };
        assert!(entry.last_modified.is_none());
    }

    #[test]
    fn test_shimcache_entry_debug() {
        let entry = ShimcacheEntry {
            path: "debug_test".to_string(),
            last_modified: None,
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("ShimcacheEntry"));
        assert!(debug_str.contains("debug_test"));
    }

    // ─── Win10 Creator Update magic ─────────────────────────────────────

    #[test]
    fn test_parse_win10_creator_update_magic() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        let secs = dt.timestamp() + 11_644_473_600;
        let ft = (secs as u64) * 10_000_000;

        let path = r"C:\Windows\creator.exe";
        let path_bytes: Vec<u8> = path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        // Creator Update header is 0x34 bytes
        let mut buf = vec![0u8; 0x34];
        buf[0..4].copy_from_slice(&WIN10_CREATOR_MAGIC.to_le_bytes());

        // Entry with creator magic signature
        buf.extend_from_slice(&WIN10_CREATOR_MAGIC.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // unknown
        let entry_size = 12 + 2 + path_bytes.len() + 8 + 4;
        buf.extend_from_slice(&(entry_size as u32).to_le_bytes());
        buf.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&path_bytes);
        buf.extend_from_slice(&ft.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // data_size

        let entries = parse_appcompat_cache(&buf).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, path);
    }

    // ─── extract_appcompat_cache_value tests ────────────────────────────

    #[test]
    fn test_extract_appcompat_cache_value_invalid_hive() {
        let result = extract_appcompat_cache_value(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_appcompat_cache_value_garbage() {
        let result = extract_appcompat_cache_value(&[0xFFu8; 256]);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_manifest_no_error() {
        use crate::collection::manifest::ArtifactManifest;
        let manifest = ArtifactManifest::default();
        let mut store = TimelineStore::new();

        struct MockProvider;
        impl CollectionProvider for MockProvider {
            fn discover(&self) -> ArtifactManifest {
                ArtifactManifest::default()
            }
            fn open_file(
                &self,
                _path: &crate::collection::path::NormalizedPath,
            ) -> Result<Vec<u8>> {
                anyhow::bail!("should not be called")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let provider = MockProvider;
        let result = parse_shimcache(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }
}
