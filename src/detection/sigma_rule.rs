/// Sigma rule data model — parses Sigma YAML into typed Rust structures.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_yaml::Value;

/// Severity level of a Sigma rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigmaLevel {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl SigmaLevel {
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "informational" => Ok(Self::Informational),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => bail!("unknown Sigma level: {}", other),
        }
    }
}

/// Logsource definition from a Sigma rule.
#[derive(Debug, Clone, Default)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

/// A single field match within a detection selection.
#[derive(Debug, Clone)]
pub struct FieldMatch {
    /// The field name (e.g. "CommandLine", "EventID").
    pub field: String,
    /// Modifiers applied to the match (e.g. ["contains", "all"]).
    pub modifiers: Vec<String>,
    /// Values to match against (OR logic unless "all" modifier present).
    pub values: Vec<String>,
}

/// A parsed Sigma rule.
#[derive(Debug, Clone)]
pub struct SigmaRule {
    pub title: String,
    pub id: Option<String>,
    pub level: SigmaLevel,
    pub logsource: LogSource,
    /// Named detection selections. Key = selection name, Value = list of field matches (AND within selection).
    pub detection: HashMap<String, Vec<FieldMatch>>,
    /// The condition expression (e.g. "selection and not filter").
    pub condition: String,
}

impl SigmaRule {
    /// Parse a Sigma rule from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let doc: Value = serde_yaml::from_str(yaml).context("invalid YAML")?;
        let map = doc.as_mapping().context("Sigma rule must be a YAML mapping")?;

        let title = map
            .get(&Value::String("title".into()))
            .and_then(|v| v.as_str())
            .context("Sigma rule must have a 'title' field")?
            .to_string();

        let id = map
            .get(&Value::String("id".into()))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let level_str = map
            .get(&Value::String("level".into()))
            .and_then(|v| v.as_str())
            .unwrap_or("medium");
        let level = SigmaLevel::from_str(level_str)?;

        // Parse logsource
        let logsource = if let Some(ls) = map.get(&Value::String("logsource".into())) {
            let empty = serde_yaml::Mapping::new();
            let ls_map = ls.as_mapping().unwrap_or(&empty);
            LogSource {
                category: ls_map
                    .get(&Value::String("category".into()))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                product: ls_map
                    .get(&Value::String("product".into()))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                service: ls_map
                    .get(&Value::String("service".into()))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            }
        } else {
            LogSource::default()
        };

        // Parse detection block
        let detection_val = map
            .get(&Value::String("detection".into()))
            .context("Sigma rule must have a 'detection' field")?;
        let detection_map = detection_val
            .as_mapping()
            .context("'detection' must be a mapping")?;

        let condition = detection_map
            .get(&Value::String("condition".into()))
            .and_then(|v| v.as_str())
            .context("'detection' must have a 'condition' field")?
            .to_string();

        let mut detection = HashMap::new();
        for (key, val) in detection_map {
            let name = key.as_str().unwrap_or_default();
            if name == "condition" {
                continue;
            }
            let fields = parse_selection(val)?;
            detection.insert(name.to_string(), fields);
        }

        Ok(SigmaRule {
            title,
            id,
            level,
            logsource,
            detection,
            condition,
        })
    }

    /// Load a Sigma rule from a YAML file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read Sigma rule: {}", path.display()))?;
        Self::from_yaml(&content)
    }
}

/// Parse a detection selection mapping into a list of FieldMatch entries.
fn parse_selection(val: &Value) -> Result<Vec<FieldMatch>> {
    let mut fields = Vec::new();
    let map = match val.as_mapping() {
        Some(m) => m,
        None => return Ok(fields),
    };

    for (key, value) in map {
        let raw_key = key.as_str().unwrap_or_default();

        // Split field name from modifiers: "CommandLine|contains|all" -> ("CommandLine", ["contains", "all"])
        let parts: Vec<&str> = raw_key.split('|').collect();
        let field = parts[0].to_string();
        let modifiers: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

        // Parse values — can be scalar or list
        let values = match value {
            Value::Sequence(seq) => seq
                .iter()
                .map(|v| value_to_string(v))
                .collect(),
            other => vec![value_to_string(other)],
        };

        fields.push(FieldMatch {
            field,
            modifiers,
            values,
        });
    }

    Ok(fields)
}

/// Convert a YAML value to a string for matching purposes.
fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => format!("{:?}", v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Cycle 1: Parse minimal Sigma rule ──────────────────────────────

    #[test]
    fn test_parse_minimal_sigma_rule() {
        let yaml = r#"
title: Mimikatz Execution
id: f018b7f4-1c2e-4d2e-a3c8-1b1b1b1b1b1b
status: test
level: critical
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: mimikatz
    condition: selection
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        assert_eq!(rule.title, "Mimikatz Execution");
        assert_eq!(rule.id, Some("f018b7f4-1c2e-4d2e-a3c8-1b1b1b1b1b1b".into()));
        assert_eq!(rule.level, SigmaLevel::Critical);
        assert_eq!(rule.logsource.category, Some("process_creation".into()));
        assert_eq!(rule.logsource.product, Some("windows".into()));
        assert_eq!(rule.condition, "selection");
    }

    #[test]
    fn test_parse_sigma_rule_with_multiple_selections() {
        let yaml = r#"
title: Suspicious Service Install
status: test
level: high
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    filter:
        ServiceName: 'Windows Update'
    condition: selection and not filter
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        assert_eq!(rule.title, "Suspicious Service Install");
        assert_eq!(rule.level, SigmaLevel::High);
        assert!(rule.detection.contains_key("selection"));
        assert!(rule.detection.contains_key("filter"));
        assert_eq!(rule.condition, "selection and not filter");
    }

    #[test]
    fn test_parse_sigma_level_variants() {
        for (yaml_val, expected) in [
            ("informational", SigmaLevel::Informational),
            ("low", SigmaLevel::Low),
            ("medium", SigmaLevel::Medium),
            ("high", SigmaLevel::High),
            ("critical", SigmaLevel::Critical),
        ] {
            let yaml = format!(
                "title: test\nstatus: test\nlevel: {}\nlogsource:\n    product: windows\ndetection:\n    sel:\n        EventID: 1\n    condition: sel\n",
                yaml_val
            );
            let rule = SigmaRule::from_yaml(&yaml).unwrap();
            assert_eq!(rule.level, expected, "failed for level: {}", yaml_val);
        }
    }

    #[test]
    fn test_parse_sigma_detection_field_with_modifier() {
        let yaml = r#"
title: test
status: test
level: medium
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - whoami
            - /priv
    condition: selection
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        let sel = &rule.detection["selection"];
        assert_eq!(sel.len(), 1);
        let field = &sel[0];
        assert_eq!(field.field, "CommandLine");
        assert_eq!(field.modifiers, vec!["contains", "all"]);
        assert_eq!(field.values, vec!["whoami", "/priv"]);
    }

    #[test]
    fn test_parse_sigma_detection_field_plain_string() {
        let yaml = r#"
title: test
status: test
level: low
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        let sel = &rule.detection["selection"];
        assert_eq!(sel.len(), 1);
        let field = &sel[0];
        assert_eq!(field.field, "EventID");
        assert!(field.modifiers.is_empty());
        assert_eq!(field.values, vec!["4688"]);
    }

    #[test]
    fn test_parse_sigma_detection_multiple_values_or() {
        let yaml = r#"
title: test
status: test
level: high
logsource:
    product: windows
detection:
    selection:
        EventID:
            - 4624
            - 4625
    condition: selection
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        let sel = &rule.detection["selection"];
        let field = &sel[0];
        assert_eq!(field.field, "EventID");
        assert_eq!(field.values, vec!["4624", "4625"]);
    }

    #[test]
    fn test_parse_sigma_rule_missing_title_fails() {
        let yaml = r#"
status: test
level: low
logsource:
    product: windows
detection:
    sel:
        EventID: 1
    condition: sel
"#;
        assert!(SigmaRule::from_yaml(yaml).is_err());
    }

    #[test]
    fn test_parse_sigma_rule_missing_detection_fails() {
        let yaml = r#"
title: broken
status: test
level: low
logsource:
    product: windows
"#;
        assert!(SigmaRule::from_yaml(yaml).is_err());
    }
}
