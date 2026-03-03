use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, warn};
use quick_xml::events::Event;
use quick_xml::Reader;
use smallvec::smallvec;
use std::collections::HashMap;

use crate::collection::manifest::ArtifactManifest;
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static EVTX_ID_COUNTER: AtomicU64 = AtomicU64::new(0x4558_0000_0000_0000); // "EX" prefix

fn next_evtx_id() -> u64 {
    EVTX_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Parsed EVTX record ─────────────────────────────────────────────────────

/// A parsed EVTX record with fields extracted from XML.
#[derive(Debug, Clone)]
pub struct EvtxEntry {
    pub event_id: u32,
    pub timestamp: DateTime<Utc>,
    pub channel: String,
    pub computer: String,
    pub provider: String,
    pub event_data: HashMap<String, String>,
}

// ─── XML Parsing ─────────────────────────────────────────────────────────────

/// Parse a single EVTX XML record string into an EvtxEntry.
///
/// Extracts EventID, TimeCreated, Channel, Computer, Provider, and
/// all EventData/UserData Name=Value pairs from the Windows Event Log
/// XML schema.
pub fn parse_evtx_record_xml(xml: &str) -> Option<EvtxEntry> {
    if xml.is_empty() {
        return None;
    }

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut event_id: Option<u32> = None;
    let mut timestamp: Option<DateTime<Utc>> = None;
    let mut channel = String::new();
    let mut computer = String::new();
    let mut provider = String::new();
    let mut event_data: HashMap<String, String> = HashMap::new();

    let mut in_event_id = false;
    let mut in_channel = false;
    let mut in_computer = false;
    let mut in_data = false;
    let mut current_data_name = String::new();
    let mut depth_system = false;
    let mut depth_event_data = false;

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(ref e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name(&name_bytes);
                match local {
                    "System" => depth_system = true,
                    "EventData" | "UserData" => depth_event_data = true,
                    "EventID" if depth_system => in_event_id = true,
                    "Channel" if depth_system => in_channel = true,
                    "Computer" if depth_system => in_computer = true,
                    "Data" if depth_event_data => {
                        current_data_name.clear();
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"Name" {
                                current_data_name =
                                    String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                        in_data = true;
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(ref e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name(&name_bytes);
                match local {
                    "Provider" if depth_system => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"Name" {
                                provider = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                    "TimeCreated" if depth_system => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"SystemTime" {
                                let ts_str = String::from_utf8_lossy(&attr.value);
                                timestamp = parse_evtx_timestamp(&ts_str);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(ref t)) => {
                let text = t.unescape().ok().map(|s| s.to_string()).unwrap_or_default();
                if in_event_id {
                    event_id = text.trim().parse().ok();
                    in_event_id = false;
                } else if in_channel {
                    channel = text.trim().to_string();
                    in_channel = false;
                } else if in_computer {
                    computer = text.trim().to_string();
                    in_computer = false;
                } else if in_data && !current_data_name.is_empty() {
                    event_data.insert(current_data_name.clone(), text.trim().to_string());
                    in_data = false;
                }
            }
            Ok(Event::End(ref e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name(&name_bytes);
                match local {
                    "System" => depth_system = false,
                    "EventData" | "UserData" => depth_event_data = false,
                    "EventID" => in_event_id = false,
                    "Channel" => in_channel = false,
                    "Computer" => in_computer = false,
                    "Data" => in_data = false,
                    _ => {}
                }
            }
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }

    let event_id = event_id?;
    let timestamp = timestamp?;

    Some(EvtxEntry {
        event_id,
        timestamp,
        channel,
        computer,
        provider,
        event_data,
    })
}

/// Strip namespace prefix from XML element name.
fn local_name(name: &[u8]) -> &str {
    let s = std::str::from_utf8(name).unwrap_or("");
    s.rsplit(':').next().unwrap_or(s)
}

/// Parse an EVTX SystemTime timestamp string.
///
/// Format: "2025-06-15T10:30:00.1234567Z"
/// EVTX uses 7-digit fractional seconds; chrono supports up to 9 (nanoseconds)
/// but RFC3339 parsing expects at most 6. Truncate to 6 for compat.
fn parse_evtx_timestamp(s: &str) -> Option<DateTime<Utc>> {
    // Try RFC3339 first (handles most formats)
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }

    // EVTX uses 7-digit fractional seconds which chrono can't parse directly
    // Truncate to 6 digits (microseconds) for parsing
    if let Some(dot_pos) = s.find('.') {
        if let Some(z_pos) = s.find('Z') {
            let frac = &s[dot_pos + 1..z_pos];
            if frac.len() > 6 {
                let truncated = format!("{}.{}Z", &s[..dot_pos], &frac[..6]);
                if let Ok(dt) = DateTime::parse_from_rfc3339(&truncated) {
                    return Some(dt.with_timezone(&Utc));
                }
            }
        }
    }

    None
}

// ─── Event type mapping ──────────────────────────────────────────────────────

const SECURITY_LOGON: &[u32] = &[4624, 4625]; // success + failed
const SECURITY_LOGOFF: &[u32] = &[4634, 4647];
const SECURITY_PROCESS_CREATE: u32 = 4688;
const SECURITY_SCHEDULED_TASK: &[u32] = &[4698, 4702];
const SECURITY_LOG_CLEARED: u32 = 1102;
const SYSTEM_LOG_CLEARED: u32 = 104;
const SYSTEM_SERVICE_INSTALL: u32 = 7045;
const RDP_SESSION_IDS: &[u32] = &[21, 22, 23, 24, 25];
const POWERSHELL_SCRIPTBLOCK: u32 = 4104;
const BITS_TRANSFER_IDS: &[u32] = &[59, 60, 61];
const FIREWALL_CONNECTION: &[u32] = &[5156, 5157];
const ACCOUNT_CREATED: u32 = 4720;
const GROUP_MEMBER_ADD: u32 = 4732;

// Task Scheduler Operational
const TASK_REGISTERED: u32 = 106;
const TASK_COMPLETED: u32 = 201;
const TASK_ACTION_STARTED: u32 = 200;

// WMI-Activity Operational
const WMI_ACTIVITY_IDS: &[u32] = &[5857, 5858, 5859, 5860, 5861];

// TerminalServices-RDPClient
const RDP_CLIENT_IDS: &[u32] = &[1024, 1102];

// Windows Defender
const DEFENDER_DETECTION: u32 = 1116;
const DEFENDER_ACTION: u32 = 1117;

// SMB share access
const SHARE_ACCESS: u32 = 5140;
const SHARE_MAPPED: u32 = 5145;

/// Check if an entry is from Sysmon.
fn is_sysmon(entry: &EvtxEntry) -> bool {
    entry.provider.contains("Sysmon")
}

/// Map a parsed EVTX entry to the appropriate EventType.
pub fn map_event_type(entry: &EvtxEntry) -> EventType {
    let eid = entry.event_id;

    // Sysmon events use low EIDs that would collide with other logs,
    // so check provider first
    if is_sysmon(entry) {
        return match eid {
            1 => EventType::ProcessCreate,
            3 => EventType::NetworkConnection,
            8 => EventType::Other("RemoteThread".to_string()),
            11 => EventType::FileCreate,
            12 | 13 | 14 => EventType::RegistryModify,
            _ => EventType::Other(format!("Sysmon:{}", eid)),
        };
    }

    if SECURITY_LOGON.contains(&eid) {
        EventType::UserLogon
    } else if SECURITY_LOGOFF.contains(&eid) {
        EventType::UserLogoff
    } else if eid == SECURITY_PROCESS_CREATE {
        EventType::ProcessCreate
    } else if SECURITY_SCHEDULED_TASK.contains(&eid) {
        EventType::ScheduledTaskCreate
    } else if (eid == SECURITY_LOG_CLEARED || eid == SYSTEM_LOG_CLEARED)
        && !entry.channel.contains("RDPClient")
    {
        EventType::Other("LogCleared".to_string())
    } else if eid == SYSTEM_SERVICE_INSTALL {
        EventType::ServiceInstall
    } else if RDP_SESSION_IDS.contains(&eid) && entry.provider.contains("TerminalServices") {
        EventType::RdpSession
    } else if eid == POWERSHELL_SCRIPTBLOCK {
        EventType::Execute
    } else if BITS_TRANSFER_IDS.contains(&eid) {
        EventType::BitsTransfer
    } else if FIREWALL_CONNECTION.contains(&eid) {
        EventType::NetworkConnection
    } else if eid == ACCOUNT_CREATED {
        EventType::Other("AccountCreated".to_string())
    } else if eid == GROUP_MEMBER_ADD {
        EventType::Other("GroupMemberAdd".to_string())
    } else if eid == TASK_REGISTERED || eid == TASK_ACTION_STARTED || eid == TASK_COMPLETED {
        EventType::ScheduledTaskCreate
    } else if WMI_ACTIVITY_IDS.contains(&eid) {
        EventType::Other("WmiActivity".to_string())
    } else if RDP_CLIENT_IDS.contains(&eid) && entry.channel.contains("RDPClient") {
        EventType::RdpSession
    } else if eid == DEFENDER_DETECTION || eid == DEFENDER_ACTION {
        EventType::Other("Defender".to_string())
    } else if eid == SHARE_ACCESS || eid == SHARE_MAPPED {
        EventType::Other("ShareAccess".to_string())
    } else {
        EventType::Other(format!("EID:{}", eid))
    }
}

// ─── Description building ────────────────────────────────────────────────────

/// Build a human-readable description from an EVTX entry.
pub fn build_description(entry: &EvtxEntry) -> String {
    match entry.event_id {
        4624 | 4625 => {
            let user = entry.event_data.get("TargetUserName").map(|s| s.as_str()).unwrap_or("?");
            let domain = entry.event_data.get("TargetDomainName").map(|s| s.as_str()).unwrap_or("");
            let logon_type = entry.event_data.get("LogonType").map(|s| s.as_str()).unwrap_or("?");
            let ip = entry.event_data.get("IpAddress").map(|s| s.as_str()).unwrap_or("-");
            let status = if entry.event_id == 4624 { "Logon" } else { "FailedLogon" };
            format!("[{}] {}\\{} Type:{} from {}", status, domain, user, logon_type, ip)
        }
        4634 | 4647 => {
            let user = entry.event_data.get("TargetUserName").map(|s| s.as_str()).unwrap_or("?");
            format!("[Logoff] {}", user)
        }
        4688 => {
            let process = entry.event_data.get("NewProcessName").map(|s| s.as_str()).unwrap_or("?");
            let cmdline = entry.event_data.get("CommandLine").map(|s| s.as_str()).unwrap_or("");
            let user = entry.event_data.get("SubjectUserName").map(|s| s.as_str()).unwrap_or("?");
            if cmdline.is_empty() {
                format!("[Process] {} ({})", process, user)
            } else {
                format!("[Process] {} -> {} ({})", process, cmdline, user)
            }
        }
        7045 => {
            let name = entry.event_data.get("ServiceName").map(|s| s.as_str()).unwrap_or("?");
            let path = entry.event_data.get("ImagePath").map(|s| s.as_str()).unwrap_or("?");
            format!("[Service] {} -> {}", name, path)
        }
        1102 if entry.channel.contains("RDPClient") => {
            let server = entry.event_data.get("Value").map(|s| s.as_str()).unwrap_or("?");
            format!("[RDPClient] Connected to {}", server)
        }
        1102 | 104 => {
            format!("[LogCleared] {} on {}", entry.channel, entry.computer)
        }
        21..=25 if entry.provider.contains("TerminalServices") => {
            let user = entry.event_data.get("User").map(|s| s.as_str()).unwrap_or("?");
            let addr = entry.event_data.get("Address").map(|s| s.as_str()).unwrap_or("-");
            format!("[RDP] {} from {} (EID:{})", user, addr, entry.event_id)
        }
        4104 => {
            let script = entry.event_data.get("ScriptBlockText").map(|s| s.as_str()).unwrap_or("?");
            let path = entry.event_data.get("Path").map(|s| s.as_str()).unwrap_or("");
            // Truncate long scripts to first 200 chars for readability
            let truncated = if script.len() > 200 {
                format!("{}...", &script[..200])
            } else {
                script.to_string()
            };
            if path.is_empty() {
                format!("[PowerShell] {}", truncated)
            } else {
                format!("[PowerShell] {} -> {}", path, truncated)
            }
        }
        59 | 60 | 61 => {
            let url = entry.event_data.get("url").map(|s| s.as_str()).unwrap_or("?");
            let bytes = entry.event_data.get("bytesTransferred").map(|s| s.as_str()).unwrap_or("0");
            format!("[BITS] {} ({} bytes)", url, bytes)
        }
        5156 | 5157 => {
            let app = entry.event_data.get("Application").map(|s| s.as_str()).unwrap_or("?");
            let src = entry.event_data.get("SourceAddress").map(|s| s.as_str()).unwrap_or("?");
            let src_port = entry.event_data.get("SourcePort").map(|s| s.as_str()).unwrap_or("?");
            let dst = entry.event_data.get("DestAddress").map(|s| s.as_str()).unwrap_or("?");
            let dst_port = entry.event_data.get("DestPort").map(|s| s.as_str()).unwrap_or("?");
            let action = if entry.event_id == 5156 { "Allowed" } else { "Blocked" };
            format!("[Net:{}] {}:{} -> {}:{} ({})", action, src, src_port, dst, dst_port, app)
        }
        4720 => {
            let target = entry.event_data.get("TargetUserName").map(|s| s.as_str()).unwrap_or("?");
            let domain = entry.event_data.get("TargetDomainName").map(|s| s.as_str()).unwrap_or("");
            let subject = entry.event_data.get("SubjectUserName").map(|s| s.as_str()).unwrap_or("?");
            format!("[AccountCreated] {}\\{} by {}", domain, target, subject)
        }
        4732 => {
            let group = entry.event_data.get("TargetUserName").map(|s| s.as_str()).unwrap_or("?");
            let member = entry.event_data.get("MemberSid").map(|s| s.as_str()).unwrap_or("?");
            let subject = entry.event_data.get("SubjectUserName").map(|s| s.as_str()).unwrap_or("?");
            format!("[GroupMemberAdd] {} added to {} by {}", member, group, subject)
        }
        // Sysmon events
        1 if is_sysmon(entry) => {
            let image = entry.event_data.get("Image").map(|s| s.as_str()).unwrap_or("?");
            let cmdline = entry.event_data.get("CommandLine").map(|s| s.as_str()).unwrap_or("");
            let user = entry.event_data.get("User").map(|s| s.as_str()).unwrap_or("?");
            let parent = entry.event_data.get("ParentImage").map(|s| s.as_str()).unwrap_or("");
            if cmdline.is_empty() {
                format!("[Sysmon:Process] {} (parent: {}, user: {})", image, parent, user)
            } else {
                format!("[Sysmon:Process] {} -> {} (parent: {}, user: {})", image, cmdline, parent, user)
            }
        }
        3 if is_sysmon(entry) => {
            let image = entry.event_data.get("Image").map(|s| s.as_str()).unwrap_or("?");
            let src_ip = entry.event_data.get("SourceIp").map(|s| s.as_str()).unwrap_or("?");
            let src_port = entry.event_data.get("SourcePort").map(|s| s.as_str()).unwrap_or("?");
            let dst_ip = entry.event_data.get("DestinationIp").map(|s| s.as_str()).unwrap_or("?");
            let dst_port = entry.event_data.get("DestinationPort").map(|s| s.as_str()).unwrap_or("?");
            format!("[Sysmon:Net] {} {}:{} -> {}:{}", image, src_ip, src_port, dst_ip, dst_port)
        }
        8 if is_sysmon(entry) => {
            let src = entry.event_data.get("SourceImage").map(|s| s.as_str()).unwrap_or("?");
            let target = entry.event_data.get("TargetImage").map(|s| s.as_str()).unwrap_or("?");
            format!("[Sysmon:RemoteThread] {} -> {}", src, target)
        }
        11 if is_sysmon(entry) => {
            let image = entry.event_data.get("Image").map(|s| s.as_str()).unwrap_or("?");
            let target = entry.event_data.get("TargetFilename").map(|s| s.as_str()).unwrap_or("?");
            format!("[Sysmon:FileCreate] {} created {}", image, target)
        }
        12 | 13 | 14 if is_sysmon(entry) => {
            let image = entry.event_data.get("Image").map(|s| s.as_str()).unwrap_or("?");
            let target = entry.event_data.get("TargetObject").map(|s| s.as_str()).unwrap_or("?");
            let details = entry.event_data.get("Details").map(|s| s.as_str()).unwrap_or("");
            if details.is_empty() {
                format!("[Sysmon:Registry] {} -> {}", image, target)
            } else {
                format!("[Sysmon:Registry] {} -> {} = {}", image, target, details)
            }
        }
        // Task Scheduler Operational
        106 => {
            let task = entry.event_data.get("TaskName").map(|s| s.as_str()).unwrap_or("?");
            let user = entry.event_data.get("UserContext").map(|s| s.as_str()).unwrap_or("");
            format!("[TaskRegistered] {} (user: {})", task, user)
        }
        200 => {
            let task = entry.event_data.get("TaskName").map(|s| s.as_str()).unwrap_or("?");
            let action = entry.event_data.get("ActionName").map(|s| s.as_str()).unwrap_or("");
            format!("[TaskStarted] {} -> {}", task, action)
        }
        201 => {
            let task = entry.event_data.get("TaskName").map(|s| s.as_str()).unwrap_or("?");
            let result = entry.event_data.get("ResultCode").map(|s| s.as_str()).unwrap_or("?");
            format!("[TaskCompleted] {} (result: {})", task, result)
        }
        // WMI-Activity
        5857..=5861 => {
            let operation = entry.event_data.get("Operation").map(|s| s.as_str()).unwrap_or("");
            let query = entry.event_data.get("Query").map(|s| s.as_str())
                .or_else(|| entry.event_data.get("PossibleCause").map(|s| s.as_str()))
                .unwrap_or("");
            format!("[WMI:{}] {} {}", entry.event_id, operation, query)
        }
        // RDP Client outbound
        1024 if entry.channel.contains("RDPClient") => {
            let server = entry.event_data.get("Value").map(|s| s.as_str()).unwrap_or("?");
            format!("[RDPClient] Connecting to {}", server)
        }
        // Windows Defender
        1116 => {
            let threat = entry.event_data.get("Threat Name").map(|s| s.as_str())
                .or_else(|| entry.event_data.get("ThreatName").map(|s| s.as_str()))
                .unwrap_or("?");
            let path = entry.event_data.get("Path").map(|s| s.as_str()).unwrap_or("");
            format!("[Defender:Detection] {} at {}", threat, path)
        }
        1117 => {
            let threat = entry.event_data.get("Threat Name").map(|s| s.as_str())
                .or_else(|| entry.event_data.get("ThreatName").map(|s| s.as_str()))
                .unwrap_or("?");
            let action = entry.event_data.get("Action Name").map(|s| s.as_str())
                .or_else(|| entry.event_data.get("ActionName").map(|s| s.as_str()))
                .unwrap_or("?");
            format!("[Defender:Action] {} -> {}", threat, action)
        }
        // SMB share access
        5140 | 5145 => {
            let share = entry.event_data.get("ShareName").map(|s| s.as_str()).unwrap_or("?");
            let path = entry.event_data.get("RelativeTargetName").map(|s| s.as_str()).unwrap_or("");
            let user = entry.event_data.get("SubjectUserName").map(|s| s.as_str()).unwrap_or("?");
            let ip = entry.event_data.get("IpAddress").map(|s| s.as_str()).unwrap_or("-");
            format!("[Share] {}\\{} by {} from {}", share, path, user, ip)
        }
        _ => {
            format!("[EVT:{}] EID:{} on {}", entry.channel, entry.event_id, entry.computer)
        }
    }
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse all EVTX event log files from the collection and populate the timeline.
pub fn parse_event_logs(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    let evtx_files = manifest.event_logs();
    if evtx_files.is_empty() {
        debug!("No EVTX files found in manifest");
        return Ok(());
    }

    debug!("Parsing {} EVTX files", evtx_files.len());
    let mut total_events = 0u32;
    let mut error_count = 0u32;

    for evtx_path in evtx_files {
        let data = match provider.open_file(evtx_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read EVTX file {}: {}", evtx_path, e);
                error_count += 1;
                continue;
            }
        };

        let mut parser = match evtx::EvtxParser::from_buffer(data) {
            Ok(p) => p,
            Err(e) => {
                debug!("Could not parse EVTX file {}: {}", evtx_path, e);
                error_count += 1;
                continue;
            }
        };

        let settings = evtx::ParserSettings::default().num_threads(1);
        parser = parser.with_configuration(settings);

        for record in parser.records() {
            let record = match record {
                Ok(r) => r,
                Err(_) => continue,
            };

            let parsed = match parse_evtx_record_xml(&record.data) {
                Some(e) => e,
                None => continue,
            };

            let event_type = map_event_type(&parsed);

            // Filter: only keep forensically interesting events
            if matches!(event_type, EventType::Other(ref s) if s.starts_with("EID:")) {
                continue;
            }

            let desc = build_description(&parsed);

            let entry = TimelineEntry {
                entity_id: EntityId::Generated(next_evtx_id()),
                path: desc,
                primary_timestamp: parsed.timestamp,
                event_type,
                timestamps: TimestampSet {
                    evtx_timestamp: Some(parsed.timestamp),
                    ..TimestampSet::default()
                },
                sources: smallvec![ArtifactSource::Evtx(parsed.channel.clone())],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
            };

            store.push(entry);
            total_events += 1;
        }
    }

    debug!(
        "EVTX parsing complete: {} events extracted, {} file errors",
        total_events, error_count
    );
    Ok(())
}

/// Parse all EVTX files and return raw EvtxEntry objects (for Sigma detection).
/// Also populates the timeline store.
pub fn parse_event_logs_with_entries(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<Vec<EvtxEntry>> {
    let evtx_files = manifest.event_logs();
    if evtx_files.is_empty() {
        return Ok(Vec::new());
    }

    let mut all_entries = Vec::new();

    for evtx_path in evtx_files {
        let data = match provider.open_file(evtx_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read EVTX file {}: {}", evtx_path, e);
                continue;
            }
        };

        let mut parser = match evtx::EvtxParser::from_buffer(data) {
            Ok(p) => p,
            Err(e) => {
                debug!("Could not parse EVTX file {}: {}", evtx_path, e);
                continue;
            }
        };

        let settings = evtx::ParserSettings::default().num_threads(1);
        parser = parser.with_configuration(settings);

        for record in parser.records() {
            let record = match record {
                Ok(r) => r,
                Err(_) => continue,
            };

            let parsed = match parse_evtx_record_xml(&record.data) {
                Some(e) => e,
                None => continue,
            };

            let event_type = map_event_type(&parsed);

            // Keep the raw entry for detection regardless of filter
            all_entries.push(parsed.clone());

            if matches!(event_type, EventType::Other(ref s) if s.starts_with("EID:")) {
                continue;
            }

            let desc = build_description(&parsed);

            let entry = TimelineEntry {
                entity_id: EntityId::Generated(next_evtx_id()),
                path: desc,
                primary_timestamp: parsed.timestamp,
                event_type,
                timestamps: TimestampSet {
                    evtx_timestamp: Some(parsed.timestamp),
                    ..TimestampSet::default()
                },
                sources: smallvec![ArtifactSource::Evtx(parsed.channel.clone())],
                anomalies: AnomalyFlags::empty(),
                metadata: EntryMetadata::default(),
            };

            store.push(entry);
        }
    }

    Ok(all_entries)
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Timelike, TimeZone};

    fn security_logon_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2025-06-15T10:30:00.1234567Z" />
    <Computer>WORKSTATION01</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">192.168.1.100</Data>
  </EventData>
</Event>"#
    }

    fn process_create_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2025-08-20T14:00:00.0000000Z" />
    <Computer>WORKSTATION01</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
    <Data Name="SubjectUserName">admin</Data>
  </EventData>
</Event>"#
    }

    fn service_install_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager" />
    <EventID>7045</EventID>
    <TimeCreated SystemTime="2025-03-01T08:00:00.0000000Z" />
    <Computer>WORKSTATION01</Computer>
    <Channel>System</Channel>
  </System>
  <EventData>
    <Data Name="ServiceName">SuspiciousService</Data>
    <Data Name="ImagePath">C:\temp\backdoor.exe</Data>
    <Data Name="ServiceType">user mode service</Data>
    <Data Name="StartType">auto start</Data>
  </EventData>
</Event>"#
    }

    fn log_cleared_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog" />
    <EventID>1102</EventID>
    <TimeCreated SystemTime="2025-07-04T03:00:00.0000000Z" />
    <Computer>WORKSTATION01</Computer>
    <Channel>Security</Channel>
  </System>
  <UserData>
    <LogFileCleared>
      <SubjectUserName>admin</SubjectUserName>
    </LogFileCleared>
  </UserData>
</Event>"#
    }

    #[test]
    fn test_parse_event_id_from_xml() {
        let entry = parse_evtx_record_xml(security_logon_xml()).unwrap();
        assert_eq!(entry.event_id, 4624);
    }

    #[test]
    fn test_parse_timestamp_from_xml() {
        let entry = parse_evtx_record_xml(security_logon_xml()).unwrap();
        let expected = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        assert_eq!(entry.timestamp.date_naive(), expected.date_naive());
        assert_eq!(entry.timestamp.time().hour(), 10);
        assert_eq!(entry.timestamp.time().minute(), 30);
    }

    #[test]
    fn test_parse_channel_from_xml() {
        let entry = parse_evtx_record_xml(security_logon_xml()).unwrap();
        assert_eq!(entry.channel, "Security");
    }

    #[test]
    fn test_parse_computer_from_xml() {
        let entry = parse_evtx_record_xml(security_logon_xml()).unwrap();
        assert_eq!(entry.computer, "WORKSTATION01");
    }

    #[test]
    fn test_parse_provider_from_xml() {
        let entry = parse_evtx_record_xml(security_logon_xml()).unwrap();
        assert_eq!(entry.provider, "Microsoft-Windows-Security-Auditing");
    }

    #[test]
    fn test_parse_event_data_fields() {
        let entry = parse_evtx_record_xml(security_logon_xml()).unwrap();
        assert_eq!(entry.event_data.get("TargetUserName").unwrap(), "admin");
        assert_eq!(entry.event_data.get("LogonType").unwrap(), "10");
        assert_eq!(entry.event_data.get("IpAddress").unwrap(), "192.168.1.100");
    }

    #[test]
    fn test_map_4624_to_user_logon() {
        let entry = parse_evtx_record_xml(security_logon_xml()).unwrap();
        assert_eq!(map_event_type(&entry), EventType::UserLogon);
    }

    #[test]
    fn test_map_4688_to_process_create() {
        let entry = parse_evtx_record_xml(process_create_xml()).unwrap();
        assert_eq!(map_event_type(&entry), EventType::ProcessCreate);
    }

    #[test]
    fn test_map_7045_to_service_install() {
        let entry = parse_evtx_record_xml(service_install_xml()).unwrap();
        assert_eq!(map_event_type(&entry), EventType::ServiceInstall);
    }

    #[test]
    fn test_build_description_logon() {
        let entry = parse_evtx_record_xml(security_logon_xml()).unwrap();
        let desc = build_description(&entry);
        assert!(desc.contains("admin"));
        assert!(desc.contains("192.168.1.100"));
    }

    #[test]
    fn test_build_description_process_create() {
        let entry = parse_evtx_record_xml(process_create_xml()).unwrap();
        let desc = build_description(&entry);
        assert!(desc.contains("cmd.exe"));
    }

    #[test]
    fn test_build_description_service_install() {
        let entry = parse_evtx_record_xml(service_install_xml()).unwrap();
        let desc = build_description(&entry);
        assert!(desc.contains("SuspiciousService"));
    }

    #[test]
    fn test_log_cleared_event() {
        let entry = parse_evtx_record_xml(log_cleared_xml()).unwrap();
        assert_eq!(entry.event_id, 1102);
        assert_eq!(map_event_type(&entry), EventType::Other("LogCleared".to_string()));
    }

    #[test]
    fn test_parse_malformed_xml_returns_none() {
        assert!(parse_evtx_record_xml("<not valid").is_none());
        assert!(parse_evtx_record_xml("").is_none());
    }

    #[test]
    fn test_parse_xml_missing_event_id_returns_none() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <TimeCreated SystemTime="2025-01-01T00:00:00.0000000Z" />
    <Channel>Security</Channel>
  </System>
</Event>"#;
        assert!(parse_evtx_record_xml(xml).is_none());
    }

    #[test]
    fn test_parse_xml_missing_timestamp_returns_none() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4624</EventID>
    <Channel>Security</Channel>
  </System>
</Event>"#;
        assert!(parse_evtx_record_xml(xml).is_none());
    }

    #[test]
    fn test_logoff_event() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4634</EventID>
    <TimeCreated SystemTime="2025-06-15T11:00:00.0000000Z" />
    <Computer>WORKSTATION01</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="LogonType">10</Data>
  </EventData>
</Event>"#;
        let entry = parse_evtx_record_xml(xml).unwrap();
        assert_eq!(map_event_type(&entry), EventType::UserLogoff);
    }

    #[test]
    fn test_rdp_session_event() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-TerminalServices-LocalSessionManager" />
    <EventID>21</EventID>
    <TimeCreated SystemTime="2025-06-15T09:00:00.0000000Z" />
    <Computer>SERVER01</Computer>
    <Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel>
  </System>
  <UserData>
    <EventXML>
      <User>CORP\admin</User>
      <Address>10.0.0.5</Address>
    </EventXML>
  </UserData>
</Event>"#;
        let entry = parse_evtx_record_xml(xml).unwrap();
        assert_eq!(map_event_type(&entry), EventType::RdpSession);
    }

    #[test]
    fn test_timeline_entry_from_evtx() {
        let parsed = parse_evtx_record_xml(security_logon_xml()).unwrap();
        let event_type = map_event_type(&parsed);
        let desc = build_description(&parsed);

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_evtx_id()),
            path: desc,
            primary_timestamp: parsed.timestamp,
            event_type,
            timestamps: TimestampSet {
                evtx_timestamp: Some(parsed.timestamp),
                ..TimestampSet::default()
            },
            sources: smallvec![ArtifactSource::Evtx(parsed.channel.clone())],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        assert_eq!(entry.event_type, EventType::UserLogon);
        assert!(entry.path.contains("admin"));
        assert!(entry.timestamps.evtx_timestamp.is_some());
    }

    // ─── Phase 11: Enhanced EVTX event fixtures ───────────────────────────────

    fn powershell_scriptblock_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PowerShell" />
    <EventID>4104</EventID>
    <TimeCreated SystemTime="2025-06-15T14:00:00.000000Z" />
    <Computer>WORKSTATION01</Computer>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  </System>
  <EventData>
    <Data Name="ScriptBlockText">Invoke-Mimikatz -DumpCreds</Data>
    <Data Name="Path">C:\temp\payload.ps1</Data>
  </EventData>
</Event>"#
    }

    fn bits_transfer_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Bits-Client" />
    <EventID>59</EventID>
    <TimeCreated SystemTime="2025-06-15T15:00:00.000000Z" />
    <Computer>WORKSTATION01</Computer>
    <Channel>Microsoft-Windows-Bits-Client/Operational</Channel>
  </System>
  <EventData>
    <Data Name="url">https://evil.com/payload.exe</Data>
    <Data Name="fileTime">2025-06-15T15:00:00.000Z</Data>
    <Data Name="bytesTransferred">1048576</Data>
  </EventData>
</Event>"#
    }

    fn firewall_connection_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>5156</EventID>
    <TimeCreated SystemTime="2025-06-15T16:00:00.000000Z" />
    <Computer>WORKSTATION01</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="Application">\device\harddiskvolume2\windows\system32\svchost.exe</Data>
    <Data Name="SourceAddress">192.168.1.100</Data>
    <Data Name="SourcePort">49152</Data>
    <Data Name="DestAddress">10.0.0.1</Data>
    <Data Name="DestPort">443</Data>
    <Data Name="Protocol">6</Data>
  </EventData>
</Event>"#
    }

    fn account_created_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4720</EventID>
    <TimeCreated SystemTime="2025-06-15T17:00:00.000000Z" />
    <Computer>DC01</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">backdoor_user</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="SubjectUserName">admin</Data>
  </EventData>
</Event>"#
    }

    fn group_membership_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4732</EventID>
    <TimeCreated SystemTime="2025-06-15T17:05:00.000000Z" />
    <Computer>DC01</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="MemberSid">S-1-5-21-1234-5678-9012-1001</Data>
    <Data Name="TargetUserName">Administrators</Data>
    <Data Name="SubjectUserName">admin</Data>
  </EventData>
</Event>"#
    }

    // ─── Phase 11: PowerShell ScriptBlock tests ──────────────────────────────

    #[test]
    fn test_parse_powershell_scriptblock() {
        let parsed = parse_evtx_record_xml(powershell_scriptblock_xml()).unwrap();
        assert_eq!(parsed.event_id, 4104);
        assert_eq!(parsed.channel, "Microsoft-Windows-PowerShell/Operational");
        assert!(parsed.event_data.contains_key("ScriptBlockText"));
    }

    #[test]
    fn test_map_4104_to_execute() {
        let parsed = parse_evtx_record_xml(powershell_scriptblock_xml()).unwrap();
        assert_eq!(map_event_type(&parsed), EventType::Execute);
    }

    #[test]
    fn test_build_description_powershell_scriptblock() {
        let parsed = parse_evtx_record_xml(powershell_scriptblock_xml()).unwrap();
        let desc = build_description(&parsed);
        assert!(desc.contains("PowerShell"), "should contain PowerShell: {}", desc);
        assert!(desc.contains("Invoke-Mimikatz"), "should contain script text: {}", desc);
    }

    // ─── Phase 11: BITS transfer tests ───────────────────────────────────────

    #[test]
    fn test_parse_bits_transfer() {
        let parsed = parse_evtx_record_xml(bits_transfer_xml()).unwrap();
        assert_eq!(parsed.event_id, 59);
        assert!(parsed.event_data.contains_key("url"));
    }

    #[test]
    fn test_map_bits_to_bits_transfer() {
        let parsed = parse_evtx_record_xml(bits_transfer_xml()).unwrap();
        assert_eq!(map_event_type(&parsed), EventType::BitsTransfer);
    }

    #[test]
    fn test_build_description_bits() {
        let parsed = parse_evtx_record_xml(bits_transfer_xml()).unwrap();
        let desc = build_description(&parsed);
        assert!(desc.contains("BITS"), "should contain BITS: {}", desc);
        assert!(desc.contains("evil.com"), "should contain URL: {}", desc);
    }

    // ─── Phase 11: Network connection tests ──────────────────────────────────

    #[test]
    fn test_parse_firewall_connection() {
        let parsed = parse_evtx_record_xml(firewall_connection_xml()).unwrap();
        assert_eq!(parsed.event_id, 5156);
        assert!(parsed.event_data.contains_key("DestAddress"));
    }

    #[test]
    fn test_map_5156_to_network_connection() {
        let parsed = parse_evtx_record_xml(firewall_connection_xml()).unwrap();
        assert_eq!(map_event_type(&parsed), EventType::NetworkConnection);
    }

    #[test]
    fn test_build_description_firewall() {
        let parsed = parse_evtx_record_xml(firewall_connection_xml()).unwrap();
        let desc = build_description(&parsed);
        assert!(desc.contains("192.168.1.100"), "should contain src IP: {}", desc);
        assert!(desc.contains("10.0.0.1"), "should contain dst IP: {}", desc);
        assert!(desc.contains("443"), "should contain dst port: {}", desc);
    }

    // ─── Phase 11: Account management tests ──────────────────────────────────

    #[test]
    fn test_map_4720_to_other_account_created() {
        let parsed = parse_evtx_record_xml(account_created_xml()).unwrap();
        let et = map_event_type(&parsed);
        assert!(matches!(et, EventType::Other(ref s) if s.contains("AccountCreated")),
            "expected AccountCreated, got {:?}", et);
    }

    #[test]
    fn test_build_description_account_created() {
        let parsed = parse_evtx_record_xml(account_created_xml()).unwrap();
        let desc = build_description(&parsed);
        assert!(desc.contains("backdoor_user"), "should contain target user: {}", desc);
        assert!(desc.contains("admin"), "should contain subject user: {}", desc);
    }

    #[test]
    fn test_map_4732_to_other_group_add() {
        let parsed = parse_evtx_record_xml(group_membership_xml()).unwrap();
        let et = map_event_type(&parsed);
        assert!(matches!(et, EventType::Other(ref s) if s.contains("GroupMemberAdd")),
            "expected GroupMemberAdd, got {:?}", et);
    }

    #[test]
    fn test_build_description_group_membership() {
        let parsed = parse_evtx_record_xml(group_membership_xml()).unwrap();
        let desc = build_description(&parsed);
        assert!(desc.contains("Administrators"), "should contain group name: {}", desc);
    }

    // ─── Phase 13: Sysmon event fixtures ────────────────────────────────────

    fn sysmon_process_create_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
    <EventID>1</EventID>
    <TimeCreated SystemTime="2025-06-15T12:00:00.000000Z" />
    <Computer>WORKSTATION01</Computer>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="User">CORP\admin</Data>
    <Data Name="ParentImage">C:\Windows\explorer.exe</Data>
    <Data Name="ParentCommandLine">C:\Windows\explorer.exe</Data>
  </EventData>
</Event>"#
    }

    fn sysmon_network_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>3</EventID>
    <TimeCreated SystemTime="2025-06-15T12:30:00.000000Z" />
    <Computer>WORKSTATION01</Computer>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\powershell.exe</Data>
    <Data Name="User">CORP\admin</Data>
    <Data Name="SourceIp">10.0.0.50</Data>
    <Data Name="SourcePort">52431</Data>
    <Data Name="DestinationIp">203.0.113.1</Data>
    <Data Name="DestinationPort">443</Data>
  </EventData>
</Event>"#
    }

    fn sysmon_file_create_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>11</EventID>
    <TimeCreated SystemTime="2025-06-15T13:00:00.000000Z" />
    <Computer>WORKSTATION01</Computer>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\powershell.exe</Data>
    <Data Name="TargetFilename">C:\temp\payload.exe</Data>
  </EventData>
</Event>"#
    }

    fn sysmon_registry_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>13</EventID>
    <TimeCreated SystemTime="2025-06-15T13:30:00.000000Z" />
    <Computer>WORKSTATION01</Computer>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\reg.exe</Data>
    <Data Name="TargetObject">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\backdoor</Data>
    <Data Name="Details">C:\temp\evil.exe</Data>
  </EventData>
</Event>"#
    }

    fn sysmon_create_remote_thread_xml() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>8</EventID>
    <TimeCreated SystemTime="2025-06-15T14:30:00.000000Z" />
    <Computer>WORKSTATION01</Computer>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="SourceImage">C:\temp\injector.exe</Data>
    <Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
  </EventData>
</Event>"#
    }

    // ─── Phase 13: Sysmon tests ──────────────────────────────────────────────

    #[test]
    fn test_map_sysmon_1_to_process_create() {
        let parsed = parse_evtx_record_xml(sysmon_process_create_xml()).unwrap();
        assert_eq!(map_event_type(&parsed), EventType::ProcessCreate);
    }

    #[test]
    fn test_build_description_sysmon_process() {
        let parsed = parse_evtx_record_xml(sysmon_process_create_xml()).unwrap();
        let desc = build_description(&parsed);
        assert!(desc.contains("Sysmon"), "should contain Sysmon: {}", desc);
        assert!(desc.contains("cmd.exe"), "should contain image: {}", desc);
        assert!(desc.contains("whoami"), "should contain cmdline: {}", desc);
    }

    #[test]
    fn test_map_sysmon_3_to_network_connection() {
        let parsed = parse_evtx_record_xml(sysmon_network_xml()).unwrap();
        assert_eq!(map_event_type(&parsed), EventType::NetworkConnection);
    }

    #[test]
    fn test_build_description_sysmon_network() {
        let parsed = parse_evtx_record_xml(sysmon_network_xml()).unwrap();
        let desc = build_description(&parsed);
        assert!(desc.contains("203.0.113.1"), "should contain dst IP: {}", desc);
        assert!(desc.contains("443"), "should contain dst port: {}", desc);
        assert!(desc.contains("powershell"), "should contain image: {}", desc);
    }

    #[test]
    fn test_map_sysmon_11_to_file_create() {
        let parsed = parse_evtx_record_xml(sysmon_file_create_xml()).unwrap();
        assert_eq!(map_event_type(&parsed), EventType::FileCreate);
    }

    #[test]
    fn test_build_description_sysmon_file_create() {
        let parsed = parse_evtx_record_xml(sysmon_file_create_xml()).unwrap();
        let desc = build_description(&parsed);
        assert!(desc.contains("payload.exe"), "should contain target file: {}", desc);
    }

    #[test]
    fn test_map_sysmon_13_to_registry_modify() {
        let parsed = parse_evtx_record_xml(sysmon_registry_xml()).unwrap();
        assert_eq!(map_event_type(&parsed), EventType::RegistryModify);
    }

    #[test]
    fn test_build_description_sysmon_registry() {
        let parsed = parse_evtx_record_xml(sysmon_registry_xml()).unwrap();
        let desc = build_description(&parsed);
        assert!(desc.contains("CurrentVersion\\Run"), "should contain reg path: {}", desc);
        assert!(desc.contains("evil.exe"), "should contain details: {}", desc);
    }

    #[test]
    fn test_map_sysmon_8_to_other_remote_thread() {
        let parsed = parse_evtx_record_xml(sysmon_create_remote_thread_xml()).unwrap();
        let et = map_event_type(&parsed);
        assert!(matches!(et, EventType::Other(ref s) if s.contains("RemoteThread")),
            "expected RemoteThread, got {:?}", et);
    }

    #[test]
    fn test_build_description_sysmon_remote_thread() {
        let parsed = parse_evtx_record_xml(sysmon_create_remote_thread_xml()).unwrap();
        let desc = build_description(&parsed);
        assert!(desc.contains("injector.exe"), "should contain source: {}", desc);
        assert!(desc.contains("lsass.exe"), "should contain target: {}", desc);
    }

    // ─── Phase 19: Additional EVTX event tests ────────────────────────────

    fn make_entry(event_id: u32, provider: &str, channel: &str, data: Vec<(&str, &str)>) -> EvtxEntry {
        let mut event_data = std::collections::HashMap::new();
        for (k, v) in data {
            event_data.insert(k.to_string(), v.to_string());
        }
        EvtxEntry {
            event_id,
            timestamp: chrono::Utc::now(),
            provider: provider.to_string(),
            channel: channel.to_string(),
            computer: "WS01".to_string(),
            event_data,
        }
    }

    #[test]
    fn test_map_task_registered_106() {
        let e = make_entry(106, "Microsoft-Windows-TaskScheduler", "TaskScheduler/Operational", vec![]);
        assert!(matches!(map_event_type(&e), EventType::ScheduledTaskCreate));
    }

    #[test]
    fn test_map_task_started_200() {
        let e = make_entry(200, "Microsoft-Windows-TaskScheduler", "TaskScheduler/Operational", vec![]);
        assert!(matches!(map_event_type(&e), EventType::ScheduledTaskCreate));
    }

    #[test]
    fn test_map_task_completed_201() {
        let e = make_entry(201, "Microsoft-Windows-TaskScheduler", "TaskScheduler/Operational", vec![]);
        assert!(matches!(map_event_type(&e), EventType::ScheduledTaskCreate));
    }

    #[test]
    fn test_build_description_task_registered() {
        let e = make_entry(106, "TaskScheduler", "TaskScheduler/Operational",
            vec![("TaskName", r"\EvilTask"), ("UserContext", "SYSTEM")]);
        let desc = build_description(&e);
        assert!(desc.contains("[TaskRegistered]"), "got: {}", desc);
        assert!(desc.contains("EvilTask"), "got: {}", desc);
    }

    #[test]
    fn test_build_description_task_completed() {
        let e = make_entry(201, "TaskScheduler", "TaskScheduler/Operational",
            vec![("TaskName", r"\UpdateTask"), ("ResultCode", "0")]);
        let desc = build_description(&e);
        assert!(desc.contains("[TaskCompleted]"), "got: {}", desc);
        assert!(desc.contains("result: 0"), "got: {}", desc);
    }

    #[test]
    fn test_map_wmi_activity_5861() {
        let e = make_entry(5861, "Microsoft-Windows-WMI-Activity", "WMI-Activity/Operational", vec![]);
        let et = map_event_type(&e);
        assert!(matches!(et, EventType::Other(ref s) if s == "WmiActivity"), "got: {:?}", et);
    }

    #[test]
    fn test_build_description_wmi_activity() {
        let e = make_entry(5861, "WMI-Activity", "WMI-Activity/Operational",
            vec![("Operation", "ExecQuery"), ("Query", "SELECT * FROM Win32_Process")]);
        let desc = build_description(&e);
        assert!(desc.contains("[WMI:5861]"), "got: {}", desc);
        assert!(desc.contains("ExecQuery"), "got: {}", desc);
    }

    #[test]
    fn test_map_rdp_client_1024() {
        let e = make_entry(1024, "Microsoft-Windows-TerminalServices-RDPClient",
            "Microsoft-Windows-TerminalServices-RDPClient/Operational", vec![]);
        assert!(matches!(map_event_type(&e), EventType::RdpSession));
    }

    #[test]
    fn test_build_description_rdp_client() {
        let e = make_entry(1024, "TerminalServices-RDPClient",
            "Microsoft-Windows-TerminalServices-RDPClient/Operational",
            vec![("Value", "10.0.0.5")]);
        let desc = build_description(&e);
        assert!(desc.contains("[RDPClient]"), "got: {}", desc);
        assert!(desc.contains("10.0.0.5"), "got: {}", desc);
    }

    #[test]
    fn test_map_defender_1116() {
        let e = make_entry(1116, "Microsoft-Windows-Windows Defender", "Windows Defender/Operational", vec![]);
        let et = map_event_type(&e);
        assert!(matches!(et, EventType::Other(ref s) if s == "Defender"), "got: {:?}", et);
    }

    #[test]
    fn test_build_description_defender_detection() {
        let e = make_entry(1116, "Windows Defender", "Windows Defender/Operational",
            vec![("ThreatName", "Trojan:Win32/Emotet"), ("Path", r"C:\Users\admin\malware.exe")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Defender:Detection]"), "got: {}", desc);
        assert!(desc.contains("Emotet"), "got: {}", desc);
    }

    #[test]
    fn test_build_description_defender_action() {
        let e = make_entry(1117, "Windows Defender", "Windows Defender/Operational",
            vec![("ThreatName", "Trojan:Win32/Emotet"), ("ActionName", "Quarantine")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Defender:Action]"), "got: {}", desc);
        assert!(desc.contains("Quarantine"), "got: {}", desc);
    }

    #[test]
    fn test_map_share_access_5140() {
        let e = make_entry(5140, "Microsoft-Windows-Security-Auditing", "Security", vec![]);
        let et = map_event_type(&e);
        assert!(matches!(et, EventType::Other(ref s) if s == "ShareAccess"), "got: {:?}", et);
    }

    #[test]
    fn test_build_description_share_access() {
        let e = make_entry(5140, "Security", "Security",
            vec![("ShareName", r"\\*\C$"), ("RelativeTargetName", "Windows\\System32"),
                 ("SubjectUserName", "admin"), ("IpAddress", "10.0.0.1")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Share]"), "got: {}", desc);
        assert!(desc.contains("C$"), "got: {}", desc);
        assert!(desc.contains("admin"), "got: {}", desc);
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
        let result = parse_event_logs(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_local_name_with_namespace() {
        assert_eq!(local_name(b"ns:EventID"), "EventID");
    }

    #[test]
    fn test_local_name_without_namespace() {
        assert_eq!(local_name(b"EventID"), "EventID");
    }

    #[test]
    fn test_local_name_empty() {
        assert_eq!(local_name(b""), "");
    }

    #[test]
    fn test_parse_evtx_timestamp_rfc3339() {
        let ts = parse_evtx_timestamp("2025-06-15T10:30:00Z").unwrap();
        assert_eq!(ts.format("%Y-%m-%d").to_string(), "2025-06-15");
    }

    #[test]
    fn test_parse_evtx_timestamp_7digit_frac() {
        let ts = parse_evtx_timestamp("2025-06-15T10:30:00.1234567Z").unwrap();
        assert_eq!(ts.format("%Y-%m-%d").to_string(), "2025-06-15");
    }

    #[test]
    fn test_parse_evtx_timestamp_6digit_frac() {
        let ts = parse_evtx_timestamp("2025-06-15T10:30:00.123456Z").unwrap();
        assert!(ts.timestamp_subsec_nanos() > 0);
    }

    #[test]
    fn test_parse_evtx_timestamp_invalid() {
        assert!(parse_evtx_timestamp("not-a-timestamp").is_none());
        assert!(parse_evtx_timestamp("").is_none());
    }

    #[test]
    fn test_parse_evtx_timestamp_no_frac() {
        let ts = parse_evtx_timestamp("2025-01-01T00:00:00Z").unwrap();
        assert_eq!(ts.timestamp_subsec_nanos(), 0);
    }

    #[test]
    fn test_is_sysmon_true() {
        let e = make_entry(1, "Microsoft-Windows-Sysmon", "Sysmon/Operational", vec![]);
        assert!(is_sysmon(&e));
    }

    #[test]
    fn test_is_sysmon_false() {
        let e = make_entry(4624, "Microsoft-Windows-Security-Auditing", "Security", vec![]);
        assert!(!is_sysmon(&e));
    }

    #[test]
    fn test_map_4625_to_user_logon() {
        let e = make_entry(4625, "Security-Auditing", "Security", vec![]);
        assert_eq!(map_event_type(&e), EventType::UserLogon);
    }

    #[test]
    fn test_map_4647_to_user_logoff() {
        let e = make_entry(4647, "Security-Auditing", "Security", vec![]);
        assert_eq!(map_event_type(&e), EventType::UserLogoff);
    }

    #[test]
    fn test_map_4698_to_scheduled_task_create() {
        let e = make_entry(4698, "Security-Auditing", "Security", vec![]);
        assert_eq!(map_event_type(&e), EventType::ScheduledTaskCreate);
    }

    #[test]
    fn test_map_4702_to_scheduled_task_create() {
        let e = make_entry(4702, "Security-Auditing", "Security", vec![]);
        assert_eq!(map_event_type(&e), EventType::ScheduledTaskCreate);
    }

    #[test]
    fn test_map_1102_log_cleared_not_rdp() {
        let e = make_entry(1102, "Eventlog", "Security", vec![]);
        assert_eq!(map_event_type(&e), EventType::Other("LogCleared".to_string()));
    }

    #[test]
    fn test_map_1102_rdp_client_not_log_cleared() {
        // EID 1102 on RDPClient channel should be RdpSession, not LogCleared
        let e = make_entry(1102, "TerminalServices-RDPClient",
            "Microsoft-Windows-TerminalServices-RDPClient/Operational", vec![]);
        assert_eq!(map_event_type(&e), EventType::RdpSession);
    }

    #[test]
    fn test_map_104_system_log_cleared() {
        let e = make_entry(104, "Eventlog", "System", vec![]);
        assert_eq!(map_event_type(&e), EventType::Other("LogCleared".to_string()));
    }

    #[test]
    fn test_map_60_bits_transfer() {
        let e = make_entry(60, "BITS", "BITS/Operational", vec![]);
        assert_eq!(map_event_type(&e), EventType::BitsTransfer);
    }

    #[test]
    fn test_map_61_bits_transfer() {
        let e = make_entry(61, "BITS", "BITS/Operational", vec![]);
        assert_eq!(map_event_type(&e), EventType::BitsTransfer);
    }

    #[test]
    fn test_map_5157_to_network_connection() {
        let e = make_entry(5157, "Security-Auditing", "Security", vec![]);
        assert_eq!(map_event_type(&e), EventType::NetworkConnection);
    }

    #[test]
    fn test_map_5145_to_share_access() {
        let e = make_entry(5145, "Security-Auditing", "Security", vec![]);
        let et = map_event_type(&e);
        assert!(matches!(et, EventType::Other(ref s) if s == "ShareAccess"));
    }

    #[test]
    fn test_map_1117_to_defender() {
        let e = make_entry(1117, "Windows Defender", "Windows Defender/Operational", vec![]);
        let et = map_event_type(&e);
        assert!(matches!(et, EventType::Other(ref s) if s == "Defender"));
    }

    #[test]
    fn test_map_unknown_eid() {
        let e = make_entry(99999, "Unknown", "Unknown", vec![]);
        let et = map_event_type(&e);
        assert!(matches!(et, EventType::Other(ref s) if s.starts_with("EID:")));
    }

    #[test]
    fn test_map_sysmon_unknown_eid() {
        let e = make_entry(255, "Microsoft-Windows-Sysmon", "Sysmon/Operational", vec![]);
        let et = map_event_type(&e);
        assert!(matches!(et, EventType::Other(ref s) if s.starts_with("Sysmon:")));
    }

    #[test]
    fn test_map_sysmon_12_to_registry_modify() {
        let e = make_entry(12, "Microsoft-Windows-Sysmon", "Sysmon/Operational", vec![]);
        assert_eq!(map_event_type(&e), EventType::RegistryModify);
    }

    #[test]
    fn test_map_sysmon_14_to_registry_modify() {
        let e = make_entry(14, "Microsoft-Windows-Sysmon", "Sysmon/Operational", vec![]);
        assert_eq!(map_event_type(&e), EventType::RegistryModify);
    }

    #[test]
    fn test_map_rdp_session_ids() {
        for eid in [22, 23, 24, 25] {
            let e = make_entry(eid, "Microsoft-Windows-TerminalServices-LocalSessionManager",
                "TerminalServices", vec![]);
            assert_eq!(map_event_type(&e), EventType::RdpSession, "EID {} should be RdpSession", eid);
        }
    }

    #[test]
    fn test_map_wmi_activity_range() {
        for eid in [5857, 5858, 5859, 5860] {
            let e = make_entry(eid, "WMI-Activity", "WMI-Activity/Operational", vec![]);
            let et = map_event_type(&e);
            assert!(matches!(et, EventType::Other(ref s) if s == "WmiActivity"),
                "EID {} should be WmiActivity, got {:?}", eid, et);
        }
    }

    #[test]
    fn test_build_description_logoff() {
        let e = make_entry(4634, "Security", "Security",
            vec![("TargetUserName", "admin")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Logoff]"));
        assert!(desc.contains("admin"));
    }

    #[test]
    fn test_build_description_4647_logoff() {
        let e = make_entry(4647, "Security", "Security",
            vec![("TargetUserName", "user1")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Logoff]"));
    }

    #[test]
    fn test_build_description_process_no_cmdline() {
        let e = make_entry(4688, "Security", "Security",
            vec![("NewProcessName", r"C:\calc.exe"), ("SubjectUserName", "admin")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Process]"));
        assert!(desc.contains("calc.exe"));
        assert!(!desc.contains("->"));
    }

    #[test]
    fn test_build_description_4625_failed_logon() {
        let e = make_entry(4625, "Security", "Security",
            vec![("TargetUserName", "baduser"), ("TargetDomainName", "CORP"),
                 ("LogonType", "3"), ("IpAddress", "10.0.0.1")]);
        let desc = build_description(&e);
        assert!(desc.contains("[FailedLogon]"));
        assert!(desc.contains("baduser"));
    }

    #[test]
    fn test_build_description_log_cleared_104() {
        let e = make_entry(104, "Eventlog", "System", vec![]);
        let desc = build_description(&e);
        assert!(desc.contains("[LogCleared]"));
        assert!(desc.contains("System"));
    }

    #[test]
    fn test_build_description_rdp_session() {
        let e = make_entry(21, "Microsoft-Windows-TerminalServices-LocalSessionManager",
            "TerminalServices",
            vec![("User", r"CORP\admin"), ("Address", "192.168.1.100")]);
        let desc = build_description(&e);
        assert!(desc.contains("[RDP]"));
        assert!(desc.contains("admin"));
        assert!(desc.contains("192.168.1.100"));
    }

    #[test]
    fn test_build_description_powershell_long_script() {
        let long_script = "A".repeat(300);
        let e = make_entry(4104, "PowerShell", "PowerShell/Operational",
            vec![("ScriptBlockText", &long_script)]);
        let desc = build_description(&e);
        assert!(desc.contains("..."));
        assert!(desc.len() < 300);
    }

    #[test]
    fn test_build_description_powershell_no_path() {
        let e = make_entry(4104, "PowerShell", "PowerShell/Operational",
            vec![("ScriptBlockText", "Get-Process")]);
        let desc = build_description(&e);
        assert!(desc.contains("[PowerShell]"));
        assert!(!desc.contains("->"));
    }

    #[test]
    fn test_build_description_firewall_blocked() {
        let e = make_entry(5157, "Security", "Security",
            vec![("Application", "evil.exe"),
                 ("SourceAddress", "10.0.0.1"), ("SourcePort", "1234"),
                 ("DestAddress", "10.0.0.2"), ("DestPort", "80")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Net:Blocked]"));
    }

    #[test]
    fn test_build_description_group_member_add() {
        let e = make_entry(4732, "Security", "Security",
            vec![("MemberSid", "S-1-5-123"), ("TargetUserName", "Admins"),
                 ("SubjectUserName", "hacker")]);
        let desc = build_description(&e);
        assert!(desc.contains("[GroupMemberAdd]"));
        assert!(desc.contains("hacker"));
    }

    #[test]
    fn test_build_description_task_started_200() {
        let e = make_entry(200, "TaskScheduler", "TaskScheduler/Operational",
            vec![("TaskName", r"\MyTask"), ("ActionName", "cmd.exe")]);
        let desc = build_description(&e);
        assert!(desc.contains("[TaskStarted]"));
        assert!(desc.contains("cmd.exe"));
    }

    #[test]
    fn test_build_description_wmi_with_possible_cause() {
        let e = make_entry(5858, "WMI-Activity", "WMI-Activity/Operational",
            vec![("PossibleCause", "Provider load failure")]);
        let desc = build_description(&e);
        assert!(desc.contains("[WMI:5858]"));
        assert!(desc.contains("Provider load failure"));
    }

    #[test]
    fn test_build_description_defender_action_alt_keys() {
        let e = make_entry(1117, "Defender", "Defender/Operational",
            vec![("Threat Name", "Malware.Gen"), ("Action Name", "Remove")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Defender:Action]"));
        assert!(desc.contains("Malware.Gen"));
        assert!(desc.contains("Remove"));
    }

    #[test]
    fn test_build_description_share_access_5145() {
        let e = make_entry(5145, "Security", "Security",
            vec![("ShareName", r"\\*\IPC$"), ("RelativeTargetName", "srvsvc"),
                 ("SubjectUserName", "admin"), ("IpAddress", "10.0.0.5")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Share]"));
        assert!(desc.contains("IPC$"));
    }

    #[test]
    fn test_build_description_unknown_event() {
        let e = make_entry(77777, "SomeProvider", "SomeChannel", vec![]);
        let desc = build_description(&e);
        assert!(desc.contains("[EVT:SomeChannel]"));
        assert!(desc.contains("EID:77777"));
    }

    #[test]
    fn test_build_description_sysmon_process_no_cmdline() {
        let e = make_entry(1, "Microsoft-Windows-Sysmon", "Sysmon/Operational",
            vec![("Image", r"C:\calc.exe"), ("User", "admin"),
                 ("ParentImage", r"C:\explorer.exe")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Sysmon:Process]"));
        assert!(!desc.contains("->"));
    }

    #[test]
    fn test_build_description_sysmon_registry_no_details() {
        let e = make_entry(12, "Microsoft-Windows-Sysmon", "Sysmon/Operational",
            vec![("Image", r"C:\reg.exe"),
                 ("TargetObject", r"HKLM\Test")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Sysmon:Registry]"));
        assert!(!desc.contains("="));
    }

    #[test]
    fn test_build_description_rdp_client_1102() {
        // EID 1102 on RDPClient channel
        let e = make_entry(1102, "TerminalServices-RDPClient",
            "Microsoft-Windows-TerminalServices-RDPClient/Operational",
            vec![("Value", "remote-server.corp.local")]);
        let desc = build_description(&e);
        assert!(desc.contains("[RDPClient]"));
        assert!(desc.contains("remote-server"));
    }

    #[test]
    fn test_build_description_defender_detection_alt_key() {
        let e = make_entry(1116, "Defender", "Defender/Operational",
            vec![("Threat Name", "Trojan.Gen"), ("Path", r"C:\bad.exe")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Defender:Detection]"));
        assert!(desc.contains("Trojan.Gen"));
    }

    #[test]
    fn test_next_evtx_id_increments() {
        let id1 = next_evtx_id();
        let id2 = next_evtx_id();
        assert!(id2 > id1);
        assert_eq!(id1 >> 48, 0x4558);
    }

    #[test]
    fn test_evtx_entry_clone_debug() {
        let e = make_entry(4624, "Security", "Security",
            vec![("TargetUserName", "admin")]);
        let cloned = e.clone();
        assert_eq!(cloned.event_id, 4624);
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("4624"));
    }

    // ─── Pipeline tests for parse_event_logs ─────────────────────────────

    fn make_evtx_manifest() -> ArtifactManifest {
        use crate::collection::path::NormalizedPath;
        let mut manifest = ArtifactManifest::default();
        manifest.event_logs.push(
            NormalizedPath::from_image_path("/Windows/System32/winevt/Logs/Security.evtx", 'C'),
        );
        manifest
    }

    #[test]
    fn test_parse_event_logs_open_file_error() {
        let manifest = make_evtx_manifest();
        let mut store = TimelineStore::new();

        struct FailOpenProvider;
        impl CollectionProvider for FailOpenProvider {
            fn discover(&self) -> ArtifactManifest { ArtifactManifest::default() }
            fn open_file(&self, _path: &crate::collection::path::NormalizedPath) -> Result<Vec<u8>> {
                anyhow::bail!("Cannot read EVTX file")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_event_logs(&FailOpenProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_event_logs_invalid_evtx_data() {
        let manifest = make_evtx_manifest();
        let mut store = TimelineStore::new();

        struct GarbageProvider;
        impl CollectionProvider for GarbageProvider {
            fn discover(&self) -> ArtifactManifest { ArtifactManifest::default() }
            fn open_file(&self, _path: &crate::collection::path::NormalizedPath) -> Result<Vec<u8>> {
                Ok(vec![0xFFu8; 512])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_event_logs(&GarbageProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_event_logs_multiple_files_all_fail() {
        use crate::collection::path::NormalizedPath;
        let mut manifest = ArtifactManifest::default();
        manifest.event_logs.push(
            NormalizedPath::from_image_path("/Windows/System32/winevt/Logs/Security.evtx", 'C'),
        );
        manifest.event_logs.push(
            NormalizedPath::from_image_path("/Windows/System32/winevt/Logs/System.evtx", 'C'),
        );
        let mut store = TimelineStore::new();

        struct FailProvider;
        impl CollectionProvider for FailProvider {
            fn discover(&self) -> ArtifactManifest { ArtifactManifest::default() }
            fn open_file(&self, _path: &crate::collection::path::NormalizedPath) -> Result<Vec<u8>> {
                anyhow::bail!("read error")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_event_logs(&FailProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── Pipeline tests for parse_event_logs_with_entries ────────────────

    #[test]
    fn test_parse_event_logs_with_entries_empty_manifest() {
        let manifest = ArtifactManifest::default();
        let mut store = TimelineStore::new();

        struct MockProvider;
        impl CollectionProvider for MockProvider {
            fn discover(&self) -> ArtifactManifest { ArtifactManifest::default() }
            fn open_file(&self, _path: &crate::collection::path::NormalizedPath) -> Result<Vec<u8>> {
                anyhow::bail!("should not be called")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_event_logs_with_entries(&MockProvider, &manifest, &mut store);
        assert!(result.is_ok());
        let entries = result.unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_event_logs_with_entries_open_file_error() {
        let manifest = make_evtx_manifest();
        let mut store = TimelineStore::new();

        struct FailOpenProvider;
        impl CollectionProvider for FailOpenProvider {
            fn discover(&self) -> ArtifactManifest { ArtifactManifest::default() }
            fn open_file(&self, _path: &crate::collection::path::NormalizedPath) -> Result<Vec<u8>> {
                anyhow::bail!("Cannot read EVTX file")
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_event_logs_with_entries(&FailOpenProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_parse_event_logs_with_entries_invalid_evtx_data() {
        let manifest = make_evtx_manifest();
        let mut store = TimelineStore::new();

        struct GarbageProvider;
        impl CollectionProvider for GarbageProvider {
            fn discover(&self) -> ArtifactManifest { ArtifactManifest::default() }
            fn open_file(&self, _path: &crate::collection::path::NormalizedPath) -> Result<Vec<u8>> {
                Ok(vec![0xDE, 0xAD, 0xBE, 0xEF])
            }
            fn metadata(&self) -> crate::collection::provider::CollectionMetadata {
                crate::collection::provider::CollectionMetadata::default()
            }
        }

        let result = parse_event_logs_with_entries(&GarbageProvider, &manifest, &mut store);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    // ─── Additional build_description edge cases ────────────────────────

    #[test]
    fn test_build_description_4648_explicit_logon() {
        let e = make_entry(4648, "Security-Auditing", "Security",
            vec![("SubjectUserName", "admin"), ("TargetUserName", "svcaccount"),
                 ("TargetServerName", "DC01")]);
        let desc = build_description(&e);
        // EID 4648 falls into the default catch-all branch
        assert!(desc.contains("EVT:") || desc.contains("EID:4648"));
    }

    #[test]
    fn test_build_description_process_with_cmdline() {
        let e = make_entry(4688, "Security", "Security",
            vec![("NewProcessName", r"C:\Windows\System32\cmd.exe"),
                 ("CommandLine", "cmd /c ipconfig"),
                 ("SubjectUserName", "admin")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Process]"));
        assert!(desc.contains("cmd /c ipconfig"));
        assert!(desc.contains("->"));
    }

    #[test]
    fn test_build_description_service_install_v2() {
        let e = make_entry(7045, "Service Control Manager", "System",
            vec![("ServiceName", "EvilService"), ("ImagePath", r"C:\temp\backdoor.exe")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Service]"));
        assert!(desc.contains("EvilService"));
        assert!(desc.contains("backdoor.exe"));
    }

    #[test]
    fn test_build_description_1102_log_cleared_non_rdp() {
        let e = make_entry(1102, "Eventlog", "Security", vec![]);
        let desc = build_description(&e);
        assert!(desc.contains("[LogCleared]"));
        assert!(desc.contains("Security"));
        assert!(desc.contains("WS01"));
    }

    #[test]
    fn test_build_description_rdp_22_to_25() {
        for eid in [22, 23, 24, 25] {
            let e = make_entry(eid, "Microsoft-Windows-TerminalServices-LocalSessionManager",
                "TerminalServices",
                vec![("User", "admin"), ("Address", "10.0.0.1")]);
            let desc = build_description(&e);
            assert!(desc.contains("[RDP]"), "EID {} desc should contain [RDP]: {}", eid, desc);
            assert!(desc.contains(&format!("EID:{}", eid)), "desc should have EID: {}", desc);
        }
    }

    #[test]
    fn test_build_description_bits_60_61() {
        for eid in [60, 61] {
            let e = make_entry(eid, "BITS", "BITS/Operational",
                vec![("url", "https://example.com/file.bin"), ("bytesTransferred", "999")]);
            let desc = build_description(&e);
            assert!(desc.contains("[BITS]"), "EID {} desc should contain [BITS]: {}", eid, desc);
            assert!(desc.contains("example.com"), "desc should have URL: {}", desc);
        }
    }

    #[test]
    fn test_build_description_sysmon_process_with_cmdline() {
        let e = make_entry(1, "Microsoft-Windows-Sysmon", "Sysmon/Operational",
            vec![("Image", r"C:\powershell.exe"),
                 ("CommandLine", "powershell -enc ZQBj"),
                 ("User", "admin"),
                 ("ParentImage", r"C:\cmd.exe")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Sysmon:Process]"));
        assert!(desc.contains("->"));
        assert!(desc.contains("powershell -enc ZQBj"));
    }

    #[test]
    fn test_build_description_sysmon_file_create_v2() {
        let e = make_entry(11, "Microsoft-Windows-Sysmon", "Sysmon/Operational",
            vec![("Image", r"C:\cmd.exe"), ("TargetFilename", r"C:\temp\dropped.exe")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Sysmon:FileCreate]"));
        assert!(desc.contains("dropped.exe"));
    }

    #[test]
    fn test_build_description_sysmon_registry_with_details() {
        let e = make_entry(13, "Microsoft-Windows-Sysmon", "Sysmon/Operational",
            vec![("Image", r"C:\reg.exe"),
                 ("TargetObject", r"HKLM\SOFTWARE\Run\evil"),
                 ("Details", r"C:\bad.exe")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Sysmon:Registry]"));
        assert!(desc.contains("="));
        assert!(desc.contains("bad.exe"));
    }

    #[test]
    fn test_build_description_sysmon_registry_14() {
        let e = make_entry(14, "Microsoft-Windows-Sysmon", "Sysmon/Operational",
            vec![("Image", r"C:\reg.exe"), ("TargetObject", r"HKLM\Test")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Sysmon:Registry]"));
    }

    #[test]
    fn test_build_description_sysmon_net() {
        let e = make_entry(3, "Microsoft-Windows-Sysmon", "Sysmon/Operational",
            vec![("Image", r"C:\app.exe"),
                 ("SourceIp", "10.0.0.1"), ("SourcePort", "12345"),
                 ("DestinationIp", "8.8.8.8"), ("DestinationPort", "53")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Sysmon:Net]"));
        assert!(desc.contains("8.8.8.8"));
        assert!(desc.contains("53"));
    }

    #[test]
    fn test_build_description_sysmon_remote_thread_v2() {
        let e = make_entry(8, "Microsoft-Windows-Sysmon", "Sysmon/Operational",
            vec![("SourceImage", r"C:\inject.exe"), ("TargetImage", r"C:\victim.exe")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Sysmon:RemoteThread]"));
        assert!(desc.contains("inject.exe"));
        assert!(desc.contains("victim.exe"));
    }

    #[test]
    fn test_build_description_wmi_no_query() {
        let e = make_entry(5857, "WMI-Activity", "WMI-Activity/Operational", vec![]);
        let desc = build_description(&e);
        assert!(desc.contains("[WMI:5857]"));
    }

    #[test]
    fn test_build_description_defender_detection_threat_name_key() {
        let e = make_entry(1116, "Defender", "Defender/Operational",
            vec![("Threat Name", "Backdoor.Win32"), ("Path", r"C:\evil.exe")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Defender:Detection]"));
        assert!(desc.contains("Backdoor.Win32"));
        assert!(desc.contains("evil.exe"));
    }

    #[test]
    fn test_build_description_rdp_client_1024() {
        let e = make_entry(1024, "TerminalServices-RDPClient",
            "Microsoft-Windows-TerminalServices-RDPClient/Operational",
            vec![("Value", "remote-server")]);
        let desc = build_description(&e);
        assert!(desc.contains("[RDPClient]"));
        assert!(desc.contains("Connecting to remote-server"));
    }

    #[test]
    fn test_build_description_account_created_4720() {
        let e = make_entry(4720, "Security", "Security",
            vec![("TargetUserName", "newuser"),
                 ("TargetDomainName", "DOMAIN"),
                 ("SubjectUserName", "admin")]);
        let desc = build_description(&e);
        assert!(desc.contains("[AccountCreated]"));
        assert!(desc.contains("DOMAIN"));
        assert!(desc.contains("newuser"));
    }

    #[test]
    fn test_build_description_share_5145() {
        let e = make_entry(5145, "Security", "Security",
            vec![("ShareName", r"\\*\ADMIN$"),
                 ("RelativeTargetName", "System32"),
                 ("SubjectUserName", "admin"),
                 ("IpAddress", "192.168.1.1")]);
        let desc = build_description(&e);
        assert!(desc.contains("[Share]"));
        assert!(desc.contains("ADMIN$"));
    }

    #[test]
    fn test_parse_evtx_record_xml_empty() {
        assert!(parse_evtx_record_xml("").is_none());
    }

    #[test]
    fn test_parse_evtx_record_xml_malformed() {
        assert!(parse_evtx_record_xml("<Event><broken").is_none());
    }

    #[test]
    fn test_parse_evtx_record_xml_no_event_id() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <TimeCreated SystemTime="2025-06-15T10:30:00Z" />
    <Computer>WS01</Computer>
    <Channel>Security</Channel>
  </System>
</Event>"#;
        assert!(parse_evtx_record_xml(xml).is_none());
    }

    #[test]
    fn test_parse_evtx_record_xml_no_timestamp() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4624</EventID>
    <Computer>WS01</Computer>
    <Channel>Security</Channel>
  </System>
</Event>"#;
        assert!(parse_evtx_record_xml(xml).is_none());
    }

    #[test]
    fn test_parse_evtx_timestamp_invalid_no_z() {
        // Has dot but no 'Z'
        assert!(parse_evtx_timestamp("2025-06-15T10:30:00.1234567").is_none());
    }

    #[test]
    fn test_parse_evtx_timestamp_short_frac() {
        // 3-digit fractional seconds (valid RFC3339)
        let ts = parse_evtx_timestamp("2025-06-15T10:30:00.123Z");
        assert!(ts.is_some());
    }

    #[test]
    fn test_map_4634_to_logoff() {
        let e = make_entry(4634, "Security", "Security", vec![]);
        assert_eq!(map_event_type(&e), EventType::UserLogoff);
    }

    #[test]
    fn test_map_4688_to_process_create_v2() {
        let e = make_entry(4688, "Security", "Security", vec![]);
        assert_eq!(map_event_type(&e), EventType::ProcessCreate);
    }

    #[test]
    fn test_map_7045_to_service_install_v2() {
        let e = make_entry(7045, "SCM", "System", vec![]);
        assert_eq!(map_event_type(&e), EventType::ServiceInstall);
    }

    #[test]
    fn test_map_21_rdp_session_terminal_services() {
        let e = make_entry(21, "Microsoft-Windows-TerminalServices-LocalSessionManager",
            "TerminalServices", vec![]);
        assert_eq!(map_event_type(&e), EventType::RdpSession);
    }

    #[test]
    fn test_map_21_non_terminal_services() {
        // EID 21 but not from TerminalServices provider -- should NOT be RdpSession
        let e = make_entry(21, "SomeOtherProvider", "SomeChannel", vec![]);
        let et = map_event_type(&e);
        assert!(matches!(et, EventType::Other(_)));
    }
}
