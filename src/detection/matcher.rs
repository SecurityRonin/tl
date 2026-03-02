/// Sigma rule matcher — evaluates detection logic against event field maps.

use std::collections::HashMap;

use crate::detection::sigma_rule::{FieldMatch, SigmaRule};

/// Check whether an event (represented as field key-value pairs) matches a Sigma rule.
pub fn matches_rule(rule: &SigmaRule, event: &HashMap<String, String>) -> bool {
    evaluate_condition(&rule.condition, &rule.detection, event)
}

/// Evaluate a Sigma condition expression against named selections.
///
/// Supports: `selection`, `sel1 and sel2`, `sel1 or sel2`,
/// `selection and not filter`, and parenthesised groups.
fn evaluate_condition(
    condition: &str,
    detection: &HashMap<String, Vec<FieldMatch>>,
    event: &HashMap<String, String>,
) -> bool {
    let tokens = tokenize_condition(condition);
    let mut parser = ConditionParser::new(&tokens, detection, event);
    parser.parse_or()
}

// ─── Condition tokenizer ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

fn tokenize_condition(s: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = s.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '(' {
            tokens.push(Token::LParen);
            chars.next();
        } else if c == ')' {
            tokens.push(Token::RParen);
            chars.next();
        } else {
            // Read a word
            let mut word = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() || c == '(' || c == ')' {
                    break;
                }
                word.push(c);
                chars.next();
            }
            match word.as_str() {
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                "not" => tokens.push(Token::Not),
                _ => tokens.push(Token::Ident(word)),
            }
        }
    }
    tokens
}

// ─── Recursive descent parser for conditions ────────────────────────────────

struct ConditionParser<'a> {
    tokens: &'a [Token],
    pos: usize,
    detection: &'a HashMap<String, Vec<FieldMatch>>,
    event: &'a HashMap<String, String>,
}

impl<'a> ConditionParser<'a> {
    fn new(
        tokens: &'a [Token],
        detection: &'a HashMap<String, Vec<FieldMatch>>,
        event: &'a HashMap<String, String>,
    ) -> Self {
        Self { tokens, pos: 0, detection, event }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<&Token> {
        let tok = self.tokens.get(self.pos);
        self.pos += 1;
        tok
    }

    /// OR has lowest precedence.
    fn parse_or(&mut self) -> bool {
        let mut result = self.parse_and();
        while self.peek() == Some(&Token::Or) {
            self.advance();
            let rhs = self.parse_and();
            result = result || rhs;
        }
        result
    }

    /// AND has higher precedence than OR.
    fn parse_and(&mut self) -> bool {
        let mut result = self.parse_not();
        while self.peek() == Some(&Token::And) {
            self.advance();
            let rhs = self.parse_not();
            result = result && rhs;
        }
        result
    }

    /// NOT is a unary prefix operator.
    fn parse_not(&mut self) -> bool {
        if self.peek() == Some(&Token::Not) {
            self.advance();
            return !self.parse_primary();
        }
        self.parse_primary()
    }

    /// Primary: identifier (selection name) or parenthesised expression.
    fn parse_primary(&mut self) -> bool {
        match self.peek().cloned() {
            Some(Token::Ident(name)) => {
                self.advance();
                self.evaluate_selection(&name)
            }
            Some(Token::LParen) => {
                self.advance();
                let result = self.parse_or();
                // consume RParen
                self.advance();
                result
            }
            _ => {
                self.advance();
                false
            }
        }
    }

    /// Evaluate a named selection: all field matches must be true (AND logic).
    fn evaluate_selection(&self, name: &str) -> bool {
        let fields = match self.detection.get(name) {
            Some(f) => f,
            None => return false,
        };

        // All fields within a selection must match (AND)
        fields.iter().all(|field_match| match_field(field_match, self.event))
    }
}

// ─── Field matching ─────────────────────────────────────────────────────────

/// Check if a single FieldMatch matches the event data.
fn match_field(fm: &FieldMatch, event: &HashMap<String, String>) -> bool {
    let event_value = match event.get(&fm.field) {
        Some(v) => v,
        None => return false,
    };

    let has_contains = fm.modifiers.iter().any(|m| m == "contains");
    let has_startswith = fm.modifiers.iter().any(|m| m == "startswith");
    let has_endswith = fm.modifiers.iter().any(|m| m == "endswith");
    let has_all = fm.modifiers.iter().any(|m| m == "all");
    let has_re = fm.modifiers.iter().any(|m| m == "re");

    let ev_lower = event_value.to_lowercase();

    let check_value = |pattern: &str| -> bool {
        let pat_lower = pattern.to_lowercase();
        if has_re {
            regex::Regex::new(pattern)
                .map(|re| re.is_match(event_value))
                .unwrap_or(false)
        } else if has_contains {
            ev_lower.contains(&pat_lower)
        } else if has_startswith {
            ev_lower.starts_with(&pat_lower)
        } else if has_endswith {
            ev_lower.ends_with(&pat_lower)
        } else {
            // Exact match (case-insensitive for strings, exact for numbers/IDs)
            ev_lower == pat_lower
        }
    };

    if has_all {
        // ALL values must match
        fm.values.iter().all(|v| check_value(v))
    } else {
        // ANY value can match (OR)
        fm.values.iter().any(|v| check_value(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::sigma_rule::SigmaRule;

    fn make_event(fields: &[(&str, &str)]) -> HashMap<String, String> {
        fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    // ─── Cycle 2: Basic field equality ──────────────────────────────────

    #[test]
    fn test_match_exact_field_value() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: low
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
"#).unwrap();

        let event = make_event(&[("EventID", "4688")]);
        assert!(matches_rule(&rule, &event));
    }

    #[test]
    fn test_no_match_wrong_value() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: low
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
"#).unwrap();

        let event = make_event(&[("EventID", "4624")]);
        assert!(!matches_rule(&rule, &event));
    }

    #[test]
    fn test_no_match_missing_field() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: low
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
"#).unwrap();

        let event = make_event(&[("Channel", "Security")]);
        assert!(!matches_rule(&rule, &event));
    }

    #[test]
    fn test_match_multiple_values_or() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: low
logsource:
    product: windows
detection:
    selection:
        EventID:
            - 4624
            - 4625
    condition: selection
"#).unwrap();

        assert!(matches_rule(&rule, &make_event(&[("EventID", "4624")])));
        assert!(matches_rule(&rule, &make_event(&[("EventID", "4625")])));
        assert!(!matches_rule(&rule, &make_event(&[("EventID", "4688")])));
    }

    // ─── Cycle 3: String modifiers ──────────────────────────────────────

    #[test]
    fn test_match_contains_modifier() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: medium
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: mimikatz
    condition: selection
"#).unwrap();

        assert!(matches_rule(&rule, &make_event(&[("CommandLine", "C:\\temp\\mimikatz.exe sekurlsa::logonpasswords")])));
        assert!(!matches_rule(&rule, &make_event(&[("CommandLine", "notepad.exe")])));
    }

    #[test]
    fn test_match_contains_case_insensitive() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: medium
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: MIMIKATZ
    condition: selection
"#).unwrap();

        assert!(matches_rule(&rule, &make_event(&[("CommandLine", "mimikatz.exe")])));
    }

    #[test]
    fn test_match_startswith_modifier() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: medium
logsource:
    product: windows
detection:
    selection:
        Image|startswith: 'C:\Windows\Temp'
    condition: selection
"#).unwrap();

        assert!(matches_rule(&rule, &make_event(&[("Image", "C:\\Windows\\Temp\\evil.exe")])));
        assert!(!matches_rule(&rule, &make_event(&[("Image", "C:\\Program Files\\app.exe")])));
    }

    #[test]
    fn test_match_endswith_modifier() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: medium
logsource:
    product: windows
detection:
    selection:
        Image|endswith: '.ps1'
    condition: selection
"#).unwrap();

        assert!(matches_rule(&rule, &make_event(&[("Image", "C:\\temp\\script.ps1")])));
        assert!(!matches_rule(&rule, &make_event(&[("Image", "C:\\temp\\script.bat")])));
    }

    #[test]
    fn test_match_contains_all_modifier() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: high
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - whoami
            - /priv
    condition: selection
"#).unwrap();

        assert!(matches_rule(&rule, &make_event(&[("CommandLine", "cmd /c whoami /priv")])));
        assert!(!matches_rule(&rule, &make_event(&[("CommandLine", "cmd /c whoami")])));
        assert!(!matches_rule(&rule, &make_event(&[("CommandLine", "cmd /c /priv")])));
    }

    // ─── Cycle 4: AND / OR / NOT conditions ─────────────────────────────

    #[test]
    fn test_match_multiple_fields_and_within_selection() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: high
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
        NewProcessName|endswith: '\cmd.exe'
    condition: selection
"#).unwrap();

        assert!(matches_rule(&rule, &make_event(&[
            ("EventID", "4688"),
            ("NewProcessName", "C:\\Windows\\System32\\cmd.exe"),
        ])));
        // Missing one field
        assert!(!matches_rule(&rule, &make_event(&[
            ("EventID", "4688"),
            ("NewProcessName", "C:\\Windows\\System32\\notepad.exe"),
        ])));
    }

    #[test]
    fn test_condition_selection_and_not_filter() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: high
logsource:
    product: windows
detection:
    selection:
        EventID: 7045
    filter:
        ServiceName: 'Windows Update'
    condition: selection and not filter
"#).unwrap();

        // Matches selection, doesn't match filter -> should match
        assert!(matches_rule(&rule, &make_event(&[
            ("EventID", "7045"),
            ("ServiceName", "EvilService"),
        ])));
        // Matches selection AND filter -> should NOT match
        assert!(!matches_rule(&rule, &make_event(&[
            ("EventID", "7045"),
            ("ServiceName", "Windows Update"),
        ])));
        // Doesn't match selection -> should NOT match
        assert!(!matches_rule(&rule, &make_event(&[
            ("EventID", "4688"),
        ])));
    }

    #[test]
    fn test_condition_selection1_or_selection2() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: medium
logsource:
    product: windows
detection:
    sel1:
        EventID: 4688
    sel2:
        EventID: 1
    condition: sel1 or sel2
"#).unwrap();

        assert!(matches_rule(&rule, &make_event(&[("EventID", "4688")])));
        assert!(matches_rule(&rule, &make_event(&[("EventID", "1")])));
        assert!(!matches_rule(&rule, &make_event(&[("EventID", "7045")])));
    }

    #[test]
    fn test_condition_not_filter_only() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: low
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    filter:
        NewProcessName|endswith: '\svchost.exe'
    condition: selection and not filter
"#).unwrap();

        assert!(matches_rule(&rule, &make_event(&[
            ("EventID", "4688"),
            ("NewProcessName", "C:\\temp\\evil.exe"),
        ])));
        assert!(!matches_rule(&rule, &make_event(&[
            ("EventID", "4688"),
            ("NewProcessName", "C:\\Windows\\System32\\svchost.exe"),
        ])));
    }

    // ─── Edge cases ─────────────────────────────────────────────────────

    #[test]
    fn test_match_empty_event_data() {
        let rule = SigmaRule::from_yaml(r#"
title: test
status: test
level: low
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
"#).unwrap();

        let event: HashMap<String, String> = HashMap::new();
        assert!(!matches_rule(&rule, &event));
    }
}
