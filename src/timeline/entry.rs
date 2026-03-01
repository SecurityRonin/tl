use bitflags::bitflags;
use chrono::{DateTime, Utc};
use serde::Serialize;
use smallvec::SmallVec;
use std::fmt;

/// Convenience alias for Windows-style NTFS timestamps (always UTC).
pub type WinTimestamp = DateTime<Utc>;

/// Unique identifier for a timeline entity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum EntityId {
    /// An MFT entry number from the $MFT.
    MftEntry(u64),
    /// A generated ID for entries not tied to an MFT record.
    Generated(u64),
}

/// The type of event represented by a timeline entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum EventType {
    FileCreate,
    FileModify,
    FileAccess,
    FileDelete,
    FileRename,
    MftEntryModify,
    Execute,
    RegistryModify,
    ServiceInstall,
    ScheduledTaskCreate,
    UserLogon,
    UserLogoff,
    ProcessCreate,
    NetworkConnection,
    BitsTransfer,
    RdpSession,
    Other(String),
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventType::FileCreate => write!(f, "CREATE"),
            EventType::FileModify => write!(f, "MOD"),
            EventType::FileAccess => write!(f, "ACC"),
            EventType::FileDelete => write!(f, "DEL"),
            EventType::FileRename => write!(f, "REN"),
            EventType::MftEntryModify => write!(f, "MFT"),
            EventType::Execute => write!(f, "EXEC"),
            EventType::RegistryModify => write!(f, "REG"),
            EventType::ServiceInstall => write!(f, "SVC"),
            EventType::ScheduledTaskCreate => write!(f, "TASK"),
            EventType::UserLogon => write!(f, "LOGON"),
            EventType::UserLogoff => write!(f, "LOGOFF"),
            EventType::ProcessCreate => write!(f, "PROC"),
            EventType::NetworkConnection => write!(f, "NET"),
            EventType::BitsTransfer => write!(f, "BITS"),
            EventType::RdpSession => write!(f, "RDP"),
            EventType::Other(s) => write!(f, "{}", s),
        }
    }
}

/// The source artifact from which a timeline entry was derived.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum ArtifactSource {
    Mft,
    UsnJrnl,
    LogFile,
    Prefetch,
    Amcache,
    Shimcache,
    BamDam,
    UserAssist,
    Evtx(String),
    Lnk,
    JumpList,
    Shellbags,
    Registry(String),
    RecycleBin,
    ScheduledTask,
    Srum,
    Wmi,
}

impl fmt::Display for ArtifactSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArtifactSource::Mft => write!(f, "MFT"),
            ArtifactSource::UsnJrnl => write!(f, "USN"),
            ArtifactSource::LogFile => write!(f, "LOG"),
            ArtifactSource::Prefetch => write!(f, "PF"),
            ArtifactSource::Amcache => write!(f, "AM"),
            ArtifactSource::Shimcache => write!(f, "SHIM"),
            ArtifactSource::BamDam => write!(f, "BAM"),
            ArtifactSource::UserAssist => write!(f, "UA"),
            ArtifactSource::Evtx(name) => write!(f, "EVT:{}", name),
            ArtifactSource::Lnk => write!(f, "LNK"),
            ArtifactSource::JumpList => write!(f, "JL"),
            ArtifactSource::Shellbags => write!(f, "SB"),
            ArtifactSource::Registry(name) => write!(f, "REG:{}", name),
            ArtifactSource::RecycleBin => write!(f, "RB"),
            ArtifactSource::ScheduledTask => write!(f, "TSK"),
            ArtifactSource::Srum => write!(f, "SRUM"),
            ArtifactSource::Wmi => write!(f, "WMI"),
        }
    }
}

bitflags! {
    /// Anomaly flags indicating potential evidence tampering or suspicious artifacts.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AnomalyFlags: u32 {
        /// SI Created timestamp is earlier than FN Created -- strong indicator of timestomping.
        const TIMESTOMPED_SI_LT_FN    = 0b0000_0001;
        /// SI timestamps have zero nanoseconds while FN timestamps do not.
        const TIMESTOMPED_ZERO_NANOS  = 0b0000_0010;
        /// Metadata timestamps appear to have been backdated.
        const METADATA_BACKDATED      = 0b0000_0100;
        /// No USN Journal create record found for the file.
        const NO_USN_CREATE           = 0b0000_1000;
        /// A gap was detected in the $LogFile sequence.
        const LOG_GAP_DETECTED        = 0b0001_0000;
        /// Event log was cleared.
        const LOG_CLEARED             = 0b0010_0000;
        /// Execution evidence without corresponding prefetch file.
        const EXECUTION_NO_PREFETCH   = 0b0100_0000;
        /// File has a hidden Alternate Data Stream.
        const HIDDEN_ADS              = 0b1000_0000;
    }
}

impl Serialize for AnomalyFlags {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.bits())
    }
}

/// Full set of timestamps collected from various forensic artifacts for a single entity.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TimestampSet {
    // $STANDARD_INFORMATION timestamps (user-modifiable)
    pub si_created: Option<WinTimestamp>,
    pub si_modified: Option<WinTimestamp>,
    pub si_accessed: Option<WinTimestamp>,
    pub si_entry_modified: Option<WinTimestamp>,

    // $FILE_NAME timestamps (harder to modify -- more trustworthy)
    pub fn_created: Option<WinTimestamp>,
    pub fn_modified: Option<WinTimestamp>,
    pub fn_accessed: Option<WinTimestamp>,
    pub fn_entry_modified: Option<WinTimestamp>,

    // USN Journal
    pub usn_timestamp: Option<WinTimestamp>,

    // LNK file target timestamps
    pub lnk_target_created: Option<WinTimestamp>,
    pub lnk_target_modified: Option<WinTimestamp>,
    pub lnk_target_accessed: Option<WinTimestamp>,

    // Jump List
    pub jumplist_timestamp: Option<WinTimestamp>,

    // Prefetch (can have multiple last-run times)
    pub prefetch_last_run: Vec<WinTimestamp>,

    // Amcache
    pub amcache_timestamp: Option<WinTimestamp>,

    // Shimcache
    pub shimcache_timestamp: Option<WinTimestamp>,

    // Event log
    pub evtx_timestamp: Option<WinTimestamp>,
}

/// Metadata associated with a timeline entry (primarily from MFT).
#[derive(Debug, Clone, Default, Serialize)]
pub struct EntryMetadata {
    pub file_size: Option<u64>,
    pub mft_entry_number: Option<u64>,
    pub mft_sequence: Option<u16>,
    pub is_directory: bool,
    pub has_ads: bool,
    pub parent_path: Option<String>,
    pub sha256: Option<String>,
    pub sha1: Option<String>,
}

/// A single entry in the forensic timeline.
#[derive(Debug, Clone, Serialize)]
pub struct TimelineEntry {
    /// Unique identifier for the entity this entry describes.
    pub entity_id: EntityId,
    /// Full file path (or registry path, etc.).
    pub path: String,
    /// The primary timestamp used for sorting in the timeline view.
    pub primary_timestamp: WinTimestamp,
    /// The type of event.
    pub event_type: EventType,
    /// All collected timestamps from various artifacts.
    pub timestamps: TimestampSet,
    /// Which artifacts contributed to this entry.
    pub sources: SmallVec<[ArtifactSource; 4]>,
    /// Detected anomalies / indicators of tampering.
    pub anomalies: AnomalyFlags,
    /// Additional metadata about the entry.
    pub metadata: EntryMetadata,
}

/// Analyze a `TimestampSet` and return any detected anomaly flags.
///
/// Current checks:
/// - `TIMESTOMPED_SI_LT_FN`: SI Created is earlier than FN Created. This is a strong
///   indicator that the SI timestamps were manipulated (timestomped) to appear older
///   than the actual file creation time recorded in the FN attribute.
/// - `TIMESTOMPED_ZERO_NANOS`: SI timestamps have zero nanosecond components while
///   the corresponding FN timestamps have non-zero nanoseconds, suggesting the SI
///   timestamps were set with a tool that doesn't preserve sub-second precision.
pub fn detect_anomalies(ts: &TimestampSet) -> AnomalyFlags {
    let mut flags = AnomalyFlags::empty();

    // Check for timestomping: SI Created < FN Created
    if let (Some(si_created), Some(fn_created)) = (ts.si_created, ts.fn_created) {
        if si_created < fn_created {
            flags |= AnomalyFlags::TIMESTOMPED_SI_LT_FN;
        }
    }

    // Check for zero nanoseconds in SI but non-zero in FN
    // This is a common artifact of timestamp manipulation tools
    if let (Some(si_created), Some(fn_created)) = (ts.si_created, ts.fn_created) {
        let si_nanos = si_created.timestamp_subsec_nanos();
        let fn_nanos = fn_created.timestamp_subsec_nanos();
        if si_nanos == 0 && fn_nanos != 0 {
            flags |= AnomalyFlags::TIMESTOMPED_ZERO_NANOS;
        }
    }

    // Also check modified timestamps for zero-nanos anomaly
    if let (Some(si_modified), Some(fn_modified)) = (ts.si_modified, ts.fn_modified) {
        let si_nanos = si_modified.timestamp_subsec_nanos();
        let fn_nanos = fn_modified.timestamp_subsec_nanos();
        if si_nanos == 0 && fn_nanos != 0 {
            flags |= AnomalyFlags::TIMESTOMPED_ZERO_NANOS;
        }
    }

    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_detect_timestomping_si_lt_fn() {
        let mut ts = TimestampSet::default();
        ts.si_created = Some(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap());
        ts.fn_created = Some(Utc.with_ymd_and_hms(2025, 8, 10, 11, 0, 0).unwrap());

        let anomalies = detect_anomalies(&ts);
        assert!(anomalies.contains(AnomalyFlags::TIMESTOMPED_SI_LT_FN));
        // SI has zero nanos, FN also has zero nanos (from with_ymd_and_hms), so
        // TIMESTOMPED_ZERO_NANOS should NOT be set here
        assert!(!anomalies.contains(AnomalyFlags::TIMESTOMPED_ZERO_NANOS));
    }

    #[test]
    fn test_no_anomalies_when_si_after_fn() {
        let mut ts = TimestampSet::default();
        ts.si_created = Some(Utc.with_ymd_and_hms(2025, 8, 10, 12, 0, 0).unwrap());
        ts.fn_created = Some(Utc.with_ymd_and_hms(2025, 8, 10, 11, 0, 0).unwrap());

        let anomalies = detect_anomalies(&ts);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_no_anomalies_when_timestamps_missing() {
        let ts = TimestampSet::default();
        let anomalies = detect_anomalies(&ts);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(format!("{}", EventType::FileCreate), "CREATE");
        assert_eq!(format!("{}", EventType::FileModify), "MOD");
        assert_eq!(format!("{}", EventType::MftEntryModify), "MFT");
        assert_eq!(format!("{}", EventType::Other("CUSTOM".to_string())), "CUSTOM");
    }

    #[test]
    fn test_artifact_source_display() {
        assert_eq!(format!("{}", ArtifactSource::Mft), "MFT");
        assert_eq!(format!("{}", ArtifactSource::Evtx("Security".to_string())), "EVT:Security");
        assert_eq!(format!("{}", ArtifactSource::Registry("SYSTEM".to_string())), "REG:SYSTEM");
    }
}
