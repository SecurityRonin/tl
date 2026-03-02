/// Detection engine — loads Sigma rules and evaluates them against event streams.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;

use crate::detection::matcher::matches_rule;
use crate::detection::sigma_rule::{SigmaLevel, SigmaRule};
use crate::parsers::evtx_parser::EvtxEntry;

/// A detection hit — one rule matched one event.
#[derive(Debug, Clone)]
pub struct Detection {
    /// The rule title.
    pub rule_title: String,
    /// The rule ID (if present).
    pub rule_id: Option<String>,
    /// Severity level.
    pub level: SigmaLevel,
    /// The event that triggered the detection.
    pub event: EvtxEntry,
}

/// The Sigma detection engine. Holds loaded rules and evaluates events.
pub struct DetectionEngine {
    rules: Vec<SigmaRule>,
}

impl DetectionEngine {
    /// Create an engine with no rules.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a single rule.
    pub fn add_rule(&mut self, rule: SigmaRule) {
        self.rules.push(rule);
    }

    /// Load all `.yml` / `.yaml` files from a directory (non-recursive).
    pub fn load_rules_from_dir(&mut self, dir: &Path) -> Result<usize> {
        let mut count = 0;
        for pattern in &["*.yml", "*.yaml"] {
            let full = format!("{}/{}", dir.display(), pattern);
            for path in glob::glob(&full).unwrap_or_else(|_| glob::glob("").unwrap()) {
                if let Ok(path) = path {
                    match SigmaRule::from_file(&path) {
                        Ok(rule) => {
                            self.rules.push(rule);
                            count += 1;
                        }
                        Err(e) => {
                            log::warn!("skipping {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }
        Ok(count)
    }

    /// Returns the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Convert an EvtxEntry into the field map used by the matcher.
    fn event_to_fields(event: &EvtxEntry) -> HashMap<String, String> {
        let mut fields = event.event_data.clone();
        fields.insert("EventID".to_string(), event.event_id.to_string());
        fields.insert("Channel".to_string(), event.channel.clone());
        fields.insert("Computer".to_string(), event.computer.clone());
        fields.insert("Provider".to_string(), event.provider.clone());
        fields
    }

    /// Evaluate all rules against a single event. Returns all matches.
    pub fn evaluate(&self, event: &EvtxEntry) -> Vec<Detection> {
        let fields = Self::event_to_fields(event);
        let mut detections = Vec::new();

        for rule in &self.rules {
            if matches_rule(rule, &fields) {
                detections.push(Detection {
                    rule_title: rule.title.clone(),
                    rule_id: rule.id.clone(),
                    level: rule.level.clone(),
                    event: event.clone(),
                });
            }
        }

        detections
    }

    /// Evaluate all rules against a batch of events.
    pub fn evaluate_batch(&self, events: &[EvtxEntry]) -> Vec<Detection> {
        events.iter().flat_map(|e| self.evaluate(e)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn make_evtx(event_id: u32, channel: &str, data: &[(&str, &str)]) -> EvtxEntry {
        EvtxEntry {
            event_id,
            timestamp: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            channel: channel.to_string(),
            computer: "WORKSTATION1".to_string(),
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            event_data: data.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    #[test]
    fn test_engine_no_rules_no_detections() {
        let engine = DetectionEngine::new();
        let event = make_evtx(4688, "Security", &[("NewProcessName", "cmd.exe")]);
        assert!(engine.evaluate(&event).is_empty());
    }

    #[test]
    fn test_engine_single_rule_match() {
        let mut engine = DetectionEngine::new();
        engine.add_rule(SigmaRule::from_yaml(r#"
title: Process Creation
status: test
level: low
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
"#).unwrap());

        let event = make_evtx(4688, "Security", &[]);
        let detections = engine.evaluate(&event);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].rule_title, "Process Creation");
        assert_eq!(detections[0].level, SigmaLevel::Low);
    }

    #[test]
    fn test_engine_single_rule_no_match() {
        let mut engine = DetectionEngine::new();
        engine.add_rule(SigmaRule::from_yaml(r#"
title: Process Creation
status: test
level: low
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
"#).unwrap());

        let event = make_evtx(4624, "Security", &[]);
        assert!(engine.evaluate(&event).is_empty());
    }

    #[test]
    fn test_engine_multiple_rules() {
        let mut engine = DetectionEngine::new();
        engine.add_rule(SigmaRule::from_yaml(r#"
title: Process Creation
status: test
level: low
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
"#).unwrap());
        engine.add_rule(SigmaRule::from_yaml(r#"
title: Suspicious Cmd
status: test
level: high
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
        CommandLine|contains: mimikatz
    condition: selection
"#).unwrap());

        assert_eq!(engine.rule_count(), 2);

        // Event that matches rule 1 but not rule 2
        let event1 = make_evtx(4688, "Security", &[("CommandLine", "notepad.exe")]);
        let d1 = engine.evaluate(&event1);
        assert_eq!(d1.len(), 1);
        assert_eq!(d1[0].rule_title, "Process Creation");

        // Event that matches both rules
        let event2 = make_evtx(4688, "Security", &[("CommandLine", "mimikatz.exe")]);
        let d2 = engine.evaluate(&event2);
        assert_eq!(d2.len(), 2);
    }

    #[test]
    fn test_engine_batch_evaluation() {
        let mut engine = DetectionEngine::new();
        engine.add_rule(SigmaRule::from_yaml(r#"
title: Logon
status: test
level: informational
logsource:
    product: windows
detection:
    selection:
        EventID: 4624
    condition: selection
"#).unwrap());

        let events = vec![
            make_evtx(4624, "Security", &[]),
            make_evtx(4688, "Security", &[]),
            make_evtx(4624, "Security", &[]),
        ];
        let detections = engine.evaluate_batch(&events);
        assert_eq!(detections.len(), 2);
    }

    #[test]
    fn test_engine_complex_rule_with_filter() {
        let mut engine = DetectionEngine::new();
        engine.add_rule(SigmaRule::from_yaml(r#"
title: Suspicious Service
status: test
level: critical
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    filter:
        ServiceName:
            - 'Windows Update'
            - 'Windows Defender'
    condition: selection and not filter
"#).unwrap());

        // Suspicious service -> match
        let evil = make_evtx(7045, "System", &[("ServiceName", "EvilSvc")]);
        assert_eq!(engine.evaluate(&evil).len(), 1);
        assert_eq!(engine.evaluate(&evil)[0].level, SigmaLevel::Critical);

        // Legitimate service -> no match
        let legit = make_evtx(7045, "System", &[("ServiceName", "Windows Update")]);
        assert!(engine.evaluate(&legit).is_empty());
    }

    #[test]
    fn test_engine_detection_preserves_event() {
        let mut engine = DetectionEngine::new();
        engine.add_rule(SigmaRule::from_yaml(r#"
title: test
status: test
level: high
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
"#).unwrap());

        let event = make_evtx(4688, "Security", &[("CommandLine", "evil.exe")]);
        let detections = engine.evaluate(&event);
        assert_eq!(detections[0].event.event_id, 4688);
        assert_eq!(detections[0].event.event_data.get("CommandLine").unwrap(), "evil.exe");
    }

    #[test]
    fn test_engine_event_to_fields_includes_metadata() {
        let event = make_evtx(4688, "Security", &[("Key", "Value")]);
        let fields = DetectionEngine::event_to_fields(&event);
        assert_eq!(fields.get("EventID").unwrap(), "4688");
        assert_eq!(fields.get("Channel").unwrap(), "Security");
        assert_eq!(fields.get("Computer").unwrap(), "WORKSTATION1");
        assert_eq!(fields.get("Key").unwrap(), "Value");
    }
}
