use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, Utc};
use log::{debug, warn};
use quick_xml::events::Event;
use quick_xml::Reader;
use smallvec::smallvec;

use crate::collection::manifest::ArtifactManifest;
use crate::collection::provider::CollectionProvider;
use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;

// ─── ID Generation ───────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static SCHTASK_ID_COUNTER: AtomicU64 = AtomicU64::new(0x5354_0000_0000_0000); // "ST" prefix

fn next_schtask_id() -> u64 {
    SCHTASK_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── Parsed scheduled task ──────────────────────────────────────────────────

/// A parsed Windows scheduled task definition.
#[derive(Debug, Clone)]
pub struct ScheduledTaskEntry {
    pub uri: String,
    pub author: String,
    pub registration_date: DateTime<Utc>,
    pub command: String,
    pub arguments: Option<String>,
}

// ─── XML Parsing ─────────────────────────────────────────────────────────────

/// Parse a Windows scheduled task XML file into a ScheduledTaskEntry.
///
/// Task XML uses the schema:
/// `http://schemas.microsoft.com/windows/2004/02/mit/task`
///
/// We extract RegistrationInfo (Date, Author, URI) and the first
/// Exec action (Command, Arguments) or ComHandler (ClassId).
pub fn parse_task_xml(xml: &str) -> Option<ScheduledTaskEntry> {
    if xml.is_empty() {
        return None;
    }

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut uri = String::new();
    let mut author = String::new();
    let mut date_str = String::new();
    let mut command = String::new();
    let mut arguments: Option<String> = None;

    let mut in_registration = false;
    let mut in_actions = false;
    let mut in_exec = false;
    let mut in_com_handler = false;
    let mut got_command = false; // take first action only

    // Track which text element we're inside
    #[derive(PartialEq)]
    enum Reading {
        None,
        Date,
        Author,
        Uri,
        Command,
        Arguments,
        ClassId,
    }
    let mut reading = Reading::None;

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(ref e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name(&name_bytes);
                match local {
                    "RegistrationInfo" => in_registration = true,
                    "Actions" => in_actions = true,
                    "Exec" if in_actions && !got_command => in_exec = true,
                    "ComHandler" if in_actions && !got_command => in_com_handler = true,
                    "Date" if in_registration => reading = Reading::Date,
                    "Author" if in_registration => reading = Reading::Author,
                    "URI" if in_registration => reading = Reading::Uri,
                    "Command" if in_exec => reading = Reading::Command,
                    "Arguments" if in_exec => reading = Reading::Arguments,
                    "ClassId" if in_com_handler => reading = Reading::ClassId,
                    _ => {}
                }
            }
            Ok(Event::Text(ref t)) => {
                let text = t.unescape().ok().map(|s| s.to_string()).unwrap_or_default();
                match reading {
                    Reading::Date => date_str = text.trim().to_string(),
                    Reading::Author => author = text.trim().to_string(),
                    Reading::Uri => uri = text.trim().to_string(),
                    Reading::Command => {
                        command = text.trim().to_string();
                        got_command = true;
                    }
                    Reading::Arguments => arguments = Some(text.trim().to_string()),
                    Reading::ClassId => {
                        command = format!("COM:{}", text.trim());
                        got_command = true;
                    }
                    Reading::None => {}
                }
                reading = Reading::None;
            }
            Ok(Event::End(ref e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name(&name_bytes);
                match local {
                    "RegistrationInfo" => in_registration = false,
                    "Actions" => in_actions = false,
                    "Exec" => in_exec = false,
                    "ComHandler" => in_com_handler = false,
                    _ => {}
                }
                reading = Reading::None;
            }
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }

    if command.is_empty() {
        return None;
    }

    let registration_date = parse_task_date(&date_str)?;

    Some(ScheduledTaskEntry {
        uri,
        author,
        registration_date,
        command,
        arguments,
    })
}

/// Strip namespace prefix from XML element name.
fn local_name(name: &[u8]) -> &str {
    let s = std::str::from_utf8(name).unwrap_or("");
    s.rsplit(':').next().unwrap_or(s)
}

/// Parse a task registration date string.
///
/// Formats seen: "2025-06-15T10:30:00", "2025-06-15T10:30:00.1234567"
/// These are local times (no timezone); we treat them as UTC for consistency.
fn parse_task_date(s: &str) -> Option<DateTime<Utc>> {
    if s.is_empty() {
        return None;
    }

    // Try with fractional seconds (truncate to 6 digits)
    let normalized = if let Some(dot_pos) = s.find('.') {
        let frac_end = s.len();
        let frac = &s[dot_pos + 1..frac_end];
        if frac.len() > 6 {
            format!("{}.{}", &s[..dot_pos], &frac[..6])
        } else {
            s.to_string()
        }
    } else {
        s.to_string()
    };

    // Try "2025-06-15T10:30:00.123456" format
    if let Ok(ndt) = NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(ndt.and_utc());
    }

    // Try "2025-06-15T10:30:00" format
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(ndt.and_utc());
    }

    None
}

// ─── Description building ────────────────────────────────────────────────────

/// Build a description string for a scheduled task timeline entry.
pub fn build_schtask_description(task: &ScheduledTaskEntry) -> String {
    let args = task.arguments.as_deref().unwrap_or("");
    if args.is_empty() {
        format!("[SchedTask] {} -> {} ({})", task.uri, task.command, task.author)
    } else {
        format!(
            "[SchedTask] {} -> {} {} ({})",
            task.uri, task.command, args, task.author
        )
    }
}

// ─── Main Parser ─────────────────────────────────────────────────────────────

/// Parse scheduled task XML files from the collection and populate the timeline.
pub fn parse_scheduled_tasks(
    provider: &dyn CollectionProvider,
    manifest: &ArtifactManifest,
    store: &mut TimelineStore,
) -> Result<()> {
    if manifest.scheduled_tasks.is_empty() {
        debug!("No scheduled task files found in manifest");
        return Ok(());
    }

    debug!(
        "Parsing {} scheduled task files",
        manifest.scheduled_tasks.len()
    );
    let mut count = 0u32;

    for task_path in &manifest.scheduled_tasks {
        let data = match provider.open_file(task_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read scheduled task {}: {}", task_path, e);
                continue;
            }
        };

        // Task XML files may be UTF-16LE encoded; convert to UTF-8
        let xml = decode_task_xml(&data);

        let task = match parse_task_xml(&xml) {
            Some(t) => t,
            None => continue,
        };

        let desc = build_schtask_description(&task);

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_schtask_id()),
            path: desc,
            primary_timestamp: task.registration_date,
            event_type: EventType::ScheduledTaskCreate,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::ScheduledTask],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        store.push(entry);
        count += 1;
    }

    debug!("Parsed {} scheduled tasks", count);
    Ok(())
}

/// Decode task XML bytes, handling UTF-16LE BOM if present.
fn decode_task_xml(data: &[u8]) -> String {
    // Check for UTF-16LE BOM (0xFF 0xFE)
    if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE {
        let u16_iter = data[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
        return String::from_utf16_lossy(&u16_iter.collect::<Vec<u16>>());
    }
    // Check for UTF-16BE BOM (0xFE 0xFF)
    if data.len() >= 2 && data[0] == 0xFE && data[1] == 0xFF {
        let u16_iter = data[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]));
        return String::from_utf16_lossy(&u16_iter.collect::<Vec<u16>>());
    }
    // Assume UTF-8
    String::from_utf8_lossy(data).to_string()
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn basic_task_xml() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-06-15T10:30:00</Date>
    <Author>CORP\admin</Author>
    <URI>\Microsoft\Windows\Maintenance\SuspTask</URI>
  </RegistrationInfo>
  <Actions Context="Author">
    <Exec>
      <Command>C:\temp\backdoor.exe</Command>
      <Arguments>-hidden</Arguments>
    </Exec>
  </Actions>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2025-06-15T11:00:00</StartBoundary>
    </TimeTrigger>
  </Triggers>
</Task>"#
    }

    fn task_with_com_handler_xml() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-01-01T00:00:00</Date>
    <Author>SYSTEM</Author>
    <URI>\Microsoft\Windows\UpdateTask</URI>
  </RegistrationInfo>
  <Actions>
    <ComHandler>
      <ClassId>{ABCD-1234-EF56}</ClassId>
    </ComHandler>
  </Actions>
</Task>"#
    }

    fn task_multiple_actions_xml() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-03-20T14:00:00.1234567</Date>
    <Author>CORP\admin</Author>
    <URI>\CustomTask</URI>
  </RegistrationInfo>
  <Actions>
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c net user hacker P@ss /add</Arguments>
    </Exec>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-ep bypass -f C:\temp\payload.ps1</Arguments>
    </Exec>
  </Actions>
</Task>"#
    }

    #[test]
    fn test_parse_task_command() {
        let task = parse_task_xml(basic_task_xml()).unwrap();
        assert_eq!(task.command, r"C:\temp\backdoor.exe");
    }

    #[test]
    fn test_parse_task_arguments() {
        let task = parse_task_xml(basic_task_xml()).unwrap();
        assert_eq!(task.arguments, Some("-hidden".to_string()));
    }

    #[test]
    fn test_parse_task_uri() {
        let task = parse_task_xml(basic_task_xml()).unwrap();
        assert_eq!(task.uri, r"\Microsoft\Windows\Maintenance\SuspTask");
    }

    #[test]
    fn test_parse_task_author() {
        let task = parse_task_xml(basic_task_xml()).unwrap();
        assert_eq!(task.author, r"CORP\admin");
    }

    #[test]
    fn test_parse_task_registration_date() {
        let task = parse_task_xml(basic_task_xml()).unwrap();
        let expected = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        assert_eq!(task.registration_date.date_naive(), expected.date_naive());
    }

    #[test]
    fn test_parse_task_com_handler() {
        let task = parse_task_xml(task_with_com_handler_xml()).unwrap();
        assert!(task.command.contains("ABCD-1234-EF56"));
    }

    #[test]
    fn test_parse_task_first_action_wins() {
        // When multiple Exec actions exist, we take the first
        let task = parse_task_xml(task_multiple_actions_xml()).unwrap();
        assert_eq!(task.command, "cmd.exe");
        assert!(task.arguments.as_ref().unwrap().contains("net user"));
    }

    #[test]
    fn test_parse_empty_xml_returns_none() {
        assert!(parse_task_xml("").is_none());
    }

    #[test]
    fn test_parse_invalid_xml_returns_none() {
        assert!(parse_task_xml("<not valid task").is_none());
    }

    #[test]
    fn test_parse_xml_no_actions_returns_none() {
        let xml = r#"<?xml version="1.0"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-01-01T00:00:00</Date>
    <URI>\EmptyTask</URI>
  </RegistrationInfo>
</Task>"#;
        // No actions → no command → None
        assert!(parse_task_xml(xml).is_none());
    }

    #[test]
    fn test_timeline_entry_from_schtask() {
        let task = parse_task_xml(basic_task_xml()).unwrap();

        let desc = build_schtask_description(&task);
        assert!(desc.contains("backdoor.exe"));
        assert!(desc.contains("SuspTask"));

        let entry = TimelineEntry {
            entity_id: EntityId::Generated(next_schtask_id()),
            path: desc,
            primary_timestamp: task.registration_date,
            event_type: EventType::ScheduledTaskCreate,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::ScheduledTask],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        };

        assert_eq!(entry.event_type, EventType::ScheduledTaskCreate);
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
        let result = parse_scheduled_tasks(&provider, &manifest, &mut store);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    // ─── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn test_local_name_with_namespace() {
        assert_eq!(local_name(b"ns:Task"), "Task");
    }

    #[test]
    fn test_local_name_no_namespace() {
        assert_eq!(local_name(b"Task"), "Task");
    }

    #[test]
    fn test_local_name_empty() {
        assert_eq!(local_name(b""), "");
    }

    #[test]
    fn test_parse_task_date_empty() {
        assert!(parse_task_date("").is_none());
    }

    #[test]
    fn test_parse_task_date_no_fractional() {
        let dt = parse_task_date("2025-06-15T10:30:00").unwrap();
        let expected = Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        assert_eq!(dt, expected);
    }

    #[test]
    fn test_parse_task_date_short_fractional() {
        let dt = parse_task_date("2025-06-15T10:30:00.123").unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2025-06-15");
    }

    #[test]
    fn test_parse_task_date_7_digit_fractional() {
        // Should truncate to 6 digits
        let dt = parse_task_date("2025-06-15T10:30:00.1234567").unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2025-06-15");
    }

    #[test]
    fn test_parse_task_date_6_digit_fractional() {
        let dt = parse_task_date("2025-06-15T10:30:00.123456").unwrap();
        assert!(dt.timestamp_subsec_nanos() > 0);
    }

    #[test]
    fn test_parse_task_date_invalid() {
        assert!(parse_task_date("not a date").is_none());
    }

    #[test]
    fn test_build_schtask_description_no_arguments() {
        let task = ScheduledTaskEntry {
            uri: r"\TestTask".to_string(),
            author: "admin".to_string(),
            registration_date: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            command: "cmd.exe".to_string(),
            arguments: None,
        };
        let desc = build_schtask_description(&task);
        assert!(desc.contains("[SchedTask]"));
        assert!(desc.contains("TestTask"));
        assert!(desc.contains("cmd.exe"));
        assert!(desc.contains("admin"));
        // No arguments, so no extra space in the format
        assert!(!desc.contains("  "));
    }

    #[test]
    fn test_build_schtask_description_with_arguments() {
        let task = ScheduledTaskEntry {
            uri: r"\MyTask".to_string(),
            author: "SYSTEM".to_string(),
            registration_date: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            command: "powershell.exe".to_string(),
            arguments: Some("-ep bypass".to_string()),
        };
        let desc = build_schtask_description(&task);
        assert!(desc.contains("powershell.exe"));
        assert!(desc.contains("-ep bypass"));
    }

    #[test]
    fn test_build_schtask_description_empty_arguments() {
        let task = ScheduledTaskEntry {
            uri: r"\TestTask".to_string(),
            author: "admin".to_string(),
            registration_date: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            command: "cmd.exe".to_string(),
            arguments: Some("".to_string()),
        };
        let desc = build_schtask_description(&task);
        // Empty arguments should be treated like None
        assert!(!desc.contains("  "));
    }

    #[test]
    fn test_parse_task_com_handler_command_format() {
        let task = parse_task_xml(task_with_com_handler_xml()).unwrap();
        assert!(task.command.starts_with("COM:"));
    }

    #[test]
    fn test_parse_task_no_date_returns_none() {
        let xml = r#"<?xml version="1.0"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>admin</Author>
    <URI>\NoDateTask</URI>
  </RegistrationInfo>
  <Actions>
    <Exec>
      <Command>cmd.exe</Command>
    </Exec>
  </Actions>
</Task>"#;
        // No date => parse_task_date("") => None => parse_task_xml returns None
        assert!(parse_task_xml(xml).is_none());
    }

    #[test]
    fn test_parse_task_no_command_returns_none() {
        let xml = r#"<?xml version="1.0"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-01-01T00:00:00</Date>
    <URI>\NoCommandTask</URI>
  </RegistrationInfo>
  <Actions>
    <Exec>
      <Arguments>-hidden</Arguments>
    </Exec>
  </Actions>
</Task>"#;
        // No Command element => command is empty => None
        assert!(parse_task_xml(xml).is_none());
    }

    #[test]
    fn test_decode_task_xml_utf8() {
        let data = b"<?xml version=\"1.0\"?><Task/>";
        let result = decode_task_xml(data);
        assert!(result.contains("Task"));
    }

    #[test]
    fn test_decode_task_xml_utf16le_bom() {
        let xml_str = "<Task/>";
        let mut data: Vec<u8> = vec![0xFF, 0xFE]; // UTF-16LE BOM
        for c in xml_str.encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        let result = decode_task_xml(&data);
        assert!(result.contains("Task"));
    }

    #[test]
    fn test_decode_task_xml_utf16be_bom() {
        let xml_str = "<Task/>";
        let mut data: Vec<u8> = vec![0xFE, 0xFF]; // UTF-16BE BOM
        for c in xml_str.encode_utf16() {
            data.extend_from_slice(&c.to_be_bytes());
        }
        let result = decode_task_xml(&data);
        assert!(result.contains("Task"));
    }

    #[test]
    fn test_next_schtask_id_increments() {
        let id1 = next_schtask_id();
        let id2 = next_schtask_id();
        assert!(id2 > id1);
        assert_eq!(id1 >> 48, 0x5354);
    }

    #[test]
    fn test_scheduled_task_entry_debug_clone() {
        let task = ScheduledTaskEntry {
            uri: r"\test".to_string(),
            author: "admin".to_string(),
            registration_date: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            command: "cmd.exe".to_string(),
            arguments: Some("/c dir".to_string()),
        };
        let cloned = task.clone();
        assert_eq!(cloned.uri, task.uri);
        let debug_str = format!("{:?}", task);
        assert!(debug_str.contains("cmd.exe"));
    }

    #[test]
    fn test_parse_task_xml_error_returns_none() {
        // Malformed XML that quick_xml will error on
        let xml = "<<<<<";
        assert!(parse_task_xml(xml).is_none());
    }

    #[test]
    fn test_parse_task_with_exec_no_arguments() {
        let xml = r#"<?xml version="1.0"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-01-01T00:00:00</Date>
    <Author>admin</Author>
    <URI>\SimpleTask</URI>
  </RegistrationInfo>
  <Actions>
    <Exec>
      <Command>notepad.exe</Command>
    </Exec>
  </Actions>
</Task>"#;
        let task = parse_task_xml(xml).unwrap();
        assert_eq!(task.command, "notepad.exe");
        assert!(task.arguments.is_none());
    }
}
