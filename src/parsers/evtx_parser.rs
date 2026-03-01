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
    } else if eid == SECURITY_LOG_CLEARED || eid == SYSTEM_LOG_CLEARED {
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
}
