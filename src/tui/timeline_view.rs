use chrono::{DateTime, Utc};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::timeline::entry::*;
use crate::tui::app::{App, AppMode};

/// Main render function: draws header, timeline table, optional detail pane, and status bar.
pub fn render(f: &mut Frame, app: &App) {
    let area = f.area();

    // Build layout: Header (3) | Table (fill) | optional Detail (10) | Status (1)
    let detail_height = if app.detail_expanded { 10u16 } else { 0u16 };
    let chunks = Layout::vertical([
        Constraint::Length(3),                              // header
        Constraint::Min(5),                                // table
        Constraint::Length(detail_height),                  // detail pane
        Constraint::Length(1),                              // status bar
    ])
    .split(area);

    render_header(f, app, chunks[0]);
    render_table(f, app, chunks[1]);
    if app.detail_expanded {
        render_detail(f, app, chunks[2]);
    }
    render_status_bar(f, app, chunks[3]);
}

/// Render the header bar: " tl " badge, hostname, collection date, entry count.
fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let badge = Span::styled(
        " tl ",
        Style::default().bg(Color::Cyan).fg(Color::Black).add_modifier(Modifier::BOLD),
    );
    let separator = Span::raw("  ");
    let host = Span::styled(
        &app.hostname,
        Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
    );
    let date_span = Span::styled(
        format!("  {}  ", app.collection_date),
        Style::default().fg(Color::DarkGray),
    );
    let count = Span::styled(
        format!("{} entries", app.store.len()),
        Style::default().fg(Color::Green),
    );

    let header_line = Line::from(vec![badge, separator, host, date_span, count]);
    let header = Paragraph::new(header_line)
        .block(Block::default().borders(Borders::BOTTOM));

    f.render_widget(header, area);
}

/// Render the main timeline table.
fn render_table(f: &mut Frame, app: &App, area: Rect) {
    let header_cells = [
        Cell::from("Timestamp").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Cell::from("Event").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Cell::from("Path").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Cell::from("Sources").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Cell::from("Anomaly").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    ];
    let header_row = Row::new(header_cells);

    // Calculate path column width: total width minus fixed columns minus spacing
    // Timestamp(19) + Event(8) + Sources(12) + Anomaly(10) + spacing(4*1) = 53
    let path_width = area.width.saturating_sub(53);

    let widths = [
        Constraint::Length(19),
        Constraint::Length(8),
        Constraint::Min(path_width),
        Constraint::Length(12),
        Constraint::Length(10),
    ];

    // Build visible rows
    let rows: Vec<Row> = (app.scroll_offset..app.store.len())
        .take(app.visible_rows + 1)
        .filter_map(|i| {
            let entry = app.store.get(i)?;
            let is_selected = i == app.selected_index;

            let ts_str = fmt_ts(Some(entry.primary_timestamp));
            let event_str = format!("{}", entry.event_type);
            let path_str = truncate_path(&entry.path, path_width as usize);
            let sources_str: String = entry
                .sources
                .iter()
                .map(|s| format!("{}", s))
                .collect::<Vec<_>>()
                .join(",");
            let anomaly_str = format_anomalies(entry.anomalies);

            // Color the event type
            let event_style = match entry.event_type {
                EventType::Execute => Style::default().fg(Color::Yellow),
                EventType::FileCreate => Style::default().fg(Color::Green),
                EventType::FileDelete => Style::default().fg(Color::Red),
                EventType::FileRename => Style::default().fg(Color::Cyan),
                _ => Style::default().fg(Color::White),
            };

            // Color timestomped entries in red
            let row_style = if entry.anomalies.contains(AnomalyFlags::TIMESTOMPED_SI_LT_FN)
                || entry.anomalies.contains(AnomalyFlags::TIMESTOMPED_ZERO_NANOS)
            {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            };

            let cells = vec![
                Cell::from(ts_str),
                Cell::from(event_str).style(event_style),
                Cell::from(path_str),
                Cell::from(sources_str),
                Cell::from(anomaly_str),
            ];

            let mut row = Row::new(cells).style(row_style);
            if is_selected {
                row = row.style(row_style.add_modifier(Modifier::REVERSED));
            }
            Some(row)
        })
        .collect();

    let table = Table::new(rows, widths)
        .header(header_row);

    f.render_widget(table, area);
}

/// Render the detail pane showing full entry info.
fn render_detail(f: &mut Frame, app: &App, area: Rect) {
    let entry = match app.selected_entry() {
        Some(e) => e,
        None => {
            let empty = Paragraph::new("No entry selected")
                .block(Block::default().borders(Borders::TOP));
            f.render_widget(empty, area);
            return;
        }
    };

    let mut lines: Vec<Line> = Vec::new();

    // Entity path
    lines.push(Line::from(vec![
        Span::styled("Path: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(&entry.path),
    ]));

    // MFT info
    if let Some(mft_num) = entry.metadata.mft_entry_number {
        let seq = entry.metadata.mft_sequence.unwrap_or(0);
        let size = entry
            .metadata
            .file_size
            .map(|s| format!("  Size: {}", format_size(s)))
            .unwrap_or_default();
        let dir_flag = if entry.metadata.is_directory { " [DIR]" } else { "" };
        lines.push(Line::from(vec![
            Span::styled("MFT:  ", Style::default().fg(Color::Yellow)),
            Span::raw(format!("Entry {} Seq {}{}{}", mft_num, seq, size, dir_flag)),
        ]));
    }

    // SI timestamps
    let ts = &entry.timestamps;
    lines.push(Line::from(vec![
        Span::styled("SI:   ", Style::default().fg(Color::Cyan)),
        Span::raw(format!(
            "C:{} M:{} A:{} E:{}",
            fmt_ts(ts.si_created),
            fmt_ts(ts.si_modified),
            fmt_ts(ts.si_accessed),
            fmt_ts(ts.si_entry_modified),
        )),
    ]));

    // FN timestamps
    lines.push(Line::from(vec![
        Span::styled("FN:   ", Style::default().fg(Color::Cyan)),
        Span::raw(format!(
            "C:{} M:{} A:{} E:{}",
            fmt_ts(ts.fn_created),
            fmt_ts(ts.fn_modified),
            fmt_ts(ts.fn_accessed),
            fmt_ts(ts.fn_entry_modified),
        )),
    ]));

    // Anomaly flags
    if !entry.anomalies.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("FLAGS: ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled(
                format_anomalies_detail(entry.anomalies),
                Style::default().fg(Color::Red),
            ),
        ]));
    }

    let detail = Paragraph::new(lines)
        .block(Block::default().borders(Borders::TOP));

    f.render_widget(detail, area);
}

/// Render the status bar at the bottom.
fn render_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let content = match app.mode {
        AppMode::Search => {
            let mut spans = vec![
                Span::styled("/", Style::default().fg(Color::Yellow)),
                Span::raw(&app.search_query),
                Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
            ];
            if !app.status_message.is_empty() {
                spans.push(Span::raw("  "));
                let color = if app.search_results.is_empty() && !app.search_query.is_empty() {
                    Color::Red
                } else {
                    Color::Green
                };
                spans.push(Span::styled(&app.status_message, Style::default().fg(color)));
            }
            Line::from(spans)
        }
        AppMode::Normal => {
            let position = if app.store.is_empty() {
                "0/0".to_string()
            } else {
                format!("{}/{}", app.selected_index + 1, app.store.len())
            };

            let msg = if !app.status_message.is_empty() {
                format!("  {}", app.status_message)
            } else {
                String::new()
            };

            Line::from(vec![
                Span::styled(
                    format!(" {} ", position),
                    Style::default().fg(Color::White),
                ),
                Span::styled(msg, Style::default().fg(Color::Green)),
                Span::styled(
                    "  q:quit  j/k:nav  J/K:x10  Enter:detail  /:search  n/N:next/prev  x:export",
                    Style::default().fg(Color::DarkGray),
                ),
            ])
        }
    };

    let bar = Paragraph::new(content)
        .style(Style::default().bg(Color::DarkGray).fg(Color::White));

    f.render_widget(bar, area);
}

// -- Helper functions --

/// Truncate a path to fit in max_width, adding "..." prefix if needed.
fn truncate_path(path: &str, max_width: usize) -> String {
    if path.len() <= max_width || max_width < 4 {
        return path.to_string();
    }
    let keep = max_width.saturating_sub(3);
    format!("...{}", &path[path.len() - keep..])
}

/// Format an optional timestamp as "YYYY-MM-DD HH:MM:SS" or "-".
fn fmt_ts(ts: Option<DateTime<Utc>>) -> String {
    match ts {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "-".to_string(),
    }
}

/// Format anomaly flags into a compact string for the table column.
fn format_anomalies(flags: AnomalyFlags) -> String {
    if flags.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    if flags.contains(AnomalyFlags::TIMESTOMPED_SI_LT_FN)
        || flags.contains(AnomalyFlags::TIMESTOMPED_ZERO_NANOS)
    {
        parts.push("STOMP");
    }
    if flags.contains(AnomalyFlags::TIMESTOMPED_ZERO_NANOS) {
        parts.push("0NANO");
    }
    if flags.contains(AnomalyFlags::HIDDEN_ADS) {
        parts.push("ADS");
    }
    if flags.contains(AnomalyFlags::LOG_CLEARED) {
        parts.push("CLEAR");
    }
    parts.join(",")
}

/// Format anomaly flags with full descriptions for the detail pane.
fn format_anomalies_detail(flags: AnomalyFlags) -> String {
    let mut parts = Vec::new();
    if flags.contains(AnomalyFlags::TIMESTOMPED_SI_LT_FN) {
        parts.push("SI_CREATED < FN_CREATED (timestomping)");
    }
    if flags.contains(AnomalyFlags::TIMESTOMPED_ZERO_NANOS) {
        parts.push("SI has zero nanoseconds (tool artifact)");
    }
    if flags.contains(AnomalyFlags::METADATA_BACKDATED) {
        parts.push("Metadata timestamps backdated");
    }
    if flags.contains(AnomalyFlags::NO_USN_CREATE) {
        parts.push("No USN Journal create record");
    }
    if flags.contains(AnomalyFlags::LOG_GAP_DETECTED) {
        parts.push("$LogFile gap detected");
    }
    if flags.contains(AnomalyFlags::LOG_CLEARED) {
        parts.push("Event log cleared");
    }
    if flags.contains(AnomalyFlags::EXECUTION_NO_PREFETCH) {
        parts.push("Execution without prefetch");
    }
    if flags.contains(AnomalyFlags::HIDDEN_ADS) {
        parts.push("Hidden Alternate Data Stream");
    }
    parts.join(" | ")
}

/// Format a file size in human-readable form.
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline::store::TimelineStore;
    use crate::tui::app::{App, AppMode};
    use chrono::{TimeZone, Utc};
    use ratatui::{backend::TestBackend, Terminal};
    use smallvec::smallvec;

    // ─── Test helpers ───────────────────────────────────────────────────

    fn make_entry(path: &str, event_type: EventType, anomalies: AnomalyFlags) -> TimelineEntry {
        TimelineEntry {
            entity_id: EntityId::MftEntry(42),
            path: path.to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 12, 30, 0).unwrap(),
            event_type,
            timestamps: TimestampSet {
                si_created: Some(Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap()),
                si_modified: Some(Utc.with_ymd_and_hms(2025, 6, 15, 12, 10, 0).unwrap()),
                si_accessed: Some(Utc.with_ymd_and_hms(2025, 6, 15, 12, 20, 0).unwrap()),
                si_entry_modified: Some(Utc.with_ymd_and_hms(2025, 6, 15, 12, 25, 0).unwrap()),
                fn_created: Some(Utc.with_ymd_and_hms(2025, 6, 15, 11, 0, 0).unwrap()),
                fn_modified: Some(Utc.with_ymd_and_hms(2025, 6, 15, 11, 10, 0).unwrap()),
                fn_accessed: Some(Utc.with_ymd_and_hms(2025, 6, 15, 11, 20, 0).unwrap()),
                fn_entry_modified: Some(Utc.with_ymd_and_hms(2025, 6, 15, 11, 25, 0).unwrap()),
                ..TimestampSet::default()
            },
            sources: smallvec![ArtifactSource::Mft, ArtifactSource::UsnJrnl],
            anomalies,
            metadata: EntryMetadata {
                file_size: Some(2048),
                mft_entry_number: Some(42),
                mft_sequence: Some(5),
                is_directory: false,
                has_ads: false,
                parent_path: Some("C:\\Windows".to_string()),
                sha256: None,
                sha1: None,
            },
        }
    }

    fn make_app_with_entries(entries: Vec<TimelineEntry>) -> App {
        let mut store = TimelineStore::new();
        for e in entries {
            store.push(e);
        }
        store.sort();
        App::new(store, "WORKSTATION1".into(), "2025-06-15".into())
    }

    fn make_default_app() -> App {
        let entries = vec![
            make_entry("C:\\Windows\\System32\\cmd.exe", EventType::Execute, AnomalyFlags::empty()),
            make_entry("C:\\temp\\evil.exe", EventType::FileCreate, AnomalyFlags::TIMESTOMPED_SI_LT_FN),
            make_entry("C:\\Users\\admin\\Desktop\\notes.txt", EventType::FileModify, AnomalyFlags::empty()),
        ];
        make_app_with_entries(entries)
    }

    // ─── Helper: render to test terminal ────────────────────────────────

    fn render_to_terminal(app: &App, width: u16, height: u16) -> Terminal<TestBackend> {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, app)).unwrap();
        terminal
    }

    // ─── render() main function ─────────────────────────────────────────

    #[test]
    fn test_render_does_not_panic_with_entries() {
        let app = make_default_app();
        let _terminal = render_to_terminal(&app, 120, 30);
    }

    #[test]
    fn test_render_does_not_panic_with_empty_store() {
        let app = make_app_with_entries(vec![]);
        let _terminal = render_to_terminal(&app, 120, 30);
    }

    #[test]
    fn test_render_does_not_panic_with_small_terminal() {
        let app = make_default_app();
        let _terminal = render_to_terminal(&app, 20, 10);
    }

    #[test]
    fn test_render_with_detail_expanded() {
        let mut app = make_default_app();
        app.detail_expanded = true;
        let _terminal = render_to_terminal(&app, 120, 40);
    }

    #[test]
    fn test_render_with_detail_expanded_no_entry() {
        let mut app = make_app_with_entries(vec![]);
        app.detail_expanded = true;
        let _terminal = render_to_terminal(&app, 120, 40);
    }

    // ─── render_header ──────────────────────────────────────────────────

    #[test]
    fn test_render_header_shows_hostname() {
        let app = make_default_app();
        let terminal = render_to_terminal(&app, 120, 30);
        let buf = terminal.backend().buffer();
        let content: String = (0..buf.area.width)
            .map(|x| buf.cell((x, 0)).unwrap().symbol().to_string())
            .collect();
        assert!(content.contains("tl"), "Header should contain 'tl': {}", content);
        assert!(content.contains("WORKSTATION1"), "Header should contain hostname: {}", content);
    }

    #[test]
    fn test_render_header_shows_entry_count() {
        let app = make_default_app();
        let terminal = render_to_terminal(&app, 120, 30);
        let buf = terminal.backend().buffer();
        let content: String = (0..buf.area.width)
            .map(|x| buf.cell((x, 0)).unwrap().symbol().to_string())
            .collect();
        assert!(content.contains("3 entries"), "Header should contain entry count: {}", content);
    }

    // ─── render_table ───────────────────────────────────────────────────

    #[test]
    fn test_render_table_shows_column_headers() {
        let app = make_default_app();
        let terminal = render_to_terminal(&app, 120, 30);
        let buf = terminal.backend().buffer();
        // Check row 3 (after header block with borders)
        let row3: String = (0..buf.area.width)
            .map(|x| buf.cell((x, 3)).unwrap().symbol().to_string())
            .collect();
        assert!(row3.contains("Timestamp"), "Expected 'Timestamp' in table header: {}", row3);
    }

    #[test]
    fn test_render_table_shows_event_data() {
        let app = make_default_app();
        let terminal = render_to_terminal(&app, 120, 30);
        let buf = terminal.backend().buffer();
        // Collect all text content
        let mut all_text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                all_text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            all_text.push('\n');
        }
        // Should contain at least one event type
        assert!(
            all_text.contains("EXEC") || all_text.contains("CREATE") || all_text.contains("MOD"),
            "Table should show events: {}",
            all_text
        );
    }

    // ─── render_table with timestomped entries ──────────────────────────

    #[test]
    fn test_render_table_with_timestomped_entry() {
        let entries = vec![
            make_entry("C:\\stomped.exe", EventType::FileCreate, AnomalyFlags::TIMESTOMPED_SI_LT_FN),
        ];
        let app = make_app_with_entries(entries);
        let _terminal = render_to_terminal(&app, 120, 30);
        // Just checking it doesn't panic with timestomped entries
    }

    #[test]
    fn test_render_table_with_zero_nanos_anomaly() {
        let entries = vec![
            make_entry("C:\\zero_nanos.exe", EventType::FileCreate, AnomalyFlags::TIMESTOMPED_ZERO_NANOS),
        ];
        let app = make_app_with_entries(entries);
        let _terminal = render_to_terminal(&app, 120, 30);
    }

    // ─── render_table with different event types ────────────────────────

    #[test]
    fn test_render_table_event_type_colors() {
        let entries = vec![
            make_entry("exec.exe", EventType::Execute, AnomalyFlags::empty()),
            make_entry("created.txt", EventType::FileCreate, AnomalyFlags::empty()),
            make_entry("deleted.txt", EventType::FileDelete, AnomalyFlags::empty()),
            make_entry("renamed.txt", EventType::FileRename, AnomalyFlags::empty()),
            make_entry("other.txt", EventType::Other("CUSTOM".to_string()), AnomalyFlags::empty()),
        ];
        let app = make_app_with_entries(entries);
        let _terminal = render_to_terminal(&app, 120, 30);
    }

    // ─── render_detail ──────────────────────────────────────────────────

    #[test]
    fn test_render_detail_shows_path() {
        let mut app = make_default_app();
        app.detail_expanded = true;
        let terminal = render_to_terminal(&app, 120, 40);
        let buf = terminal.backend().buffer();
        let mut all_text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                all_text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            all_text.push('\n');
        }
        assert!(all_text.contains("Path:"), "Detail should show Path: {}", all_text);
    }

    #[test]
    fn test_render_detail_shows_mft_info() {
        let mut app = make_default_app();
        app.detail_expanded = true;
        let terminal = render_to_terminal(&app, 120, 40);
        let buf = terminal.backend().buffer();
        let mut all_text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                all_text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            all_text.push('\n');
        }
        assert!(all_text.contains("MFT:"), "Detail should show MFT info: {}", all_text);
    }

    #[test]
    fn test_render_detail_shows_si_timestamps() {
        let mut app = make_default_app();
        app.detail_expanded = true;
        let terminal = render_to_terminal(&app, 120, 40);
        let buf = terminal.backend().buffer();
        let mut all_text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                all_text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            all_text.push('\n');
        }
        assert!(all_text.contains("SI:"), "Detail should show SI timestamps: {}", all_text);
    }

    #[test]
    fn test_render_detail_shows_fn_timestamps() {
        let mut app = make_default_app();
        app.detail_expanded = true;
        let terminal = render_to_terminal(&app, 120, 40);
        let buf = terminal.backend().buffer();
        let mut all_text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                all_text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            all_text.push('\n');
        }
        assert!(all_text.contains("FN:"), "Detail should show FN timestamps: {}", all_text);
    }

    #[test]
    fn test_render_detail_with_anomaly_flags() {
        let entries = vec![
            make_entry("C:\\stomped.exe", EventType::FileCreate, AnomalyFlags::TIMESTOMPED_SI_LT_FN | AnomalyFlags::HIDDEN_ADS),
        ];
        let mut app = make_app_with_entries(entries);
        app.detail_expanded = true;
        let terminal = render_to_terminal(&app, 120, 40);
        let buf = terminal.backend().buffer();
        let mut all_text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                all_text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            all_text.push('\n');
        }
        assert!(all_text.contains("FLAGS:"), "Detail should show FLAGS: {}", all_text);
    }

    #[test]
    fn test_render_detail_with_directory_entry() {
        let mut entry = make_entry("C:\\Windows", EventType::FileCreate, AnomalyFlags::empty());
        entry.metadata.is_directory = true;
        let mut app = make_app_with_entries(vec![entry]);
        app.detail_expanded = true;
        let terminal = render_to_terminal(&app, 120, 40);
        let buf = terminal.backend().buffer();
        let mut all_text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                all_text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            all_text.push('\n');
        }
        assert!(all_text.contains("[DIR]"), "Detail should show [DIR]: {}", all_text);
    }

    #[test]
    fn test_render_detail_without_mft_info() {
        let mut entry = make_entry("C:\\test.txt", EventType::FileCreate, AnomalyFlags::empty());
        entry.metadata.mft_entry_number = None;
        let mut app = make_app_with_entries(vec![entry]);
        app.detail_expanded = true;
        let _terminal = render_to_terminal(&app, 120, 40);
    }

    #[test]
    fn test_render_detail_without_file_size() {
        let mut entry = make_entry("C:\\test.txt", EventType::FileCreate, AnomalyFlags::empty());
        entry.metadata.file_size = None;
        let mut app = make_app_with_entries(vec![entry]);
        app.detail_expanded = true;
        let _terminal = render_to_terminal(&app, 120, 40);
    }

    // ─── render_status_bar ──────────────────────────────────────────────

    #[test]
    fn test_render_status_bar_normal_mode() {
        let app = make_default_app();
        let terminal = render_to_terminal(&app, 120, 30);
        let buf = terminal.backend().buffer();
        let last_row = buf.area.height - 1;
        let content: String = (0..buf.area.width)
            .map(|x| buf.cell((x, last_row)).unwrap().symbol().to_string())
            .collect();
        assert!(content.contains("1/3"), "Status bar should show position: {}", content);
        assert!(content.contains("q:quit"), "Status bar should show keybinds: {}", content);
    }

    #[test]
    fn test_render_status_bar_search_mode() {
        let mut app = make_default_app();
        app.mode = AppMode::Search;
        app.search_query = "test".to_string();
        let terminal = render_to_terminal(&app, 120, 30);
        let buf = terminal.backend().buffer();
        let last_row = buf.area.height - 1;
        let content: String = (0..buf.area.width)
            .map(|x| buf.cell((x, last_row)).unwrap().symbol().to_string())
            .collect();
        assert!(content.contains("/"), "Search mode should show /: {}", content);
        assert!(content.contains("test"), "Search mode should show query: {}", content);
    }

    #[test]
    fn test_render_status_bar_search_mode_with_status() {
        let mut app = make_default_app();
        app.mode = AppMode::Search;
        app.search_query = "nonexistent".to_string();
        app.search_results = vec![];
        app.status_message = "No matches".to_string();
        let terminal = render_to_terminal(&app, 120, 30);
        let buf = terminal.backend().buffer();
        let last_row = buf.area.height - 1;
        let content: String = (0..buf.area.width)
            .map(|x| buf.cell((x, last_row)).unwrap().symbol().to_string())
            .collect();
        assert!(content.contains("No matches"), "Should show status: {}", content);
    }

    #[test]
    fn test_render_status_bar_search_mode_with_results_status() {
        let mut app = make_default_app();
        app.mode = AppMode::Search;
        app.search_query = "cmd".to_string();
        app.search_results = vec![0];
        app.status_message = "1/1 \"cmd\"".to_string();
        let _terminal = render_to_terminal(&app, 120, 30);
    }

    #[test]
    fn test_render_status_bar_normal_mode_empty_store() {
        let app = make_app_with_entries(vec![]);
        let terminal = render_to_terminal(&app, 120, 30);
        let buf = terminal.backend().buffer();
        let last_row = buf.area.height - 1;
        let content: String = (0..buf.area.width)
            .map(|x| buf.cell((x, last_row)).unwrap().symbol().to_string())
            .collect();
        assert!(content.contains("0/0"), "Empty store should show 0/0: {}", content);
    }

    #[test]
    fn test_render_status_bar_normal_mode_with_status_message() {
        let mut app = make_default_app();
        app.status_message = "Exported to output.csv".to_string();
        let terminal = render_to_terminal(&app, 120, 30);
        let buf = terminal.backend().buffer();
        let last_row = buf.area.height - 1;
        let content: String = (0..buf.area.width)
            .map(|x| buf.cell((x, last_row)).unwrap().symbol().to_string())
            .collect();
        assert!(content.contains("Exported"), "Should show status msg: {}", content);
    }

    // ─── truncate_path ──────────────────────────────────────────────────

    #[test]
    fn test_truncate_path_short() {
        assert_eq!(truncate_path("C:\\short.txt", 50), "C:\\short.txt");
    }

    #[test]
    fn test_truncate_path_exact_fit() {
        let path = "C:\\exactly";
        assert_eq!(truncate_path(path, path.len()), path);
    }

    #[test]
    fn test_truncate_path_long() {
        let path = "C:\\Windows\\System32\\very\\long\\path\\to\\some\\deeply\\nested\\file.exe";
        let result = truncate_path(path, 30);
        assert!(result.starts_with("..."));
        assert!(result.len() <= 30);
    }

    #[test]
    fn test_truncate_path_very_small_max() {
        let path = "C:\\Windows\\test.txt";
        let result = truncate_path(path, 3);
        // max_width < 4, returns path as-is
        assert_eq!(result, path);
    }

    #[test]
    fn test_truncate_path_zero_max() {
        let path = "C:\\test.txt";
        let result = truncate_path(path, 0);
        assert_eq!(result, path);
    }

    // ─── fmt_ts ─────────────────────────────────────────────────────────

    #[test]
    fn test_fmt_ts_some() {
        let ts = Some(Utc.with_ymd_and_hms(2025, 12, 25, 10, 30, 45).unwrap());
        assert_eq!(fmt_ts(ts), "2025-12-25 10:30:45");
    }

    #[test]
    fn test_fmt_ts_none() {
        assert_eq!(fmt_ts(None), "-");
    }

    // ─── format_anomalies (table version) ───────────────────────────────

    #[test]
    fn test_format_anomalies_table_empty() {
        assert_eq!(format_anomalies(AnomalyFlags::empty()), "");
    }

    #[test]
    fn test_format_anomalies_table_stomp() {
        assert!(format_anomalies(AnomalyFlags::TIMESTOMPED_SI_LT_FN).contains("STOMP"));
    }

    #[test]
    fn test_format_anomalies_table_zero_nanos() {
        let result = format_anomalies(AnomalyFlags::TIMESTOMPED_ZERO_NANOS);
        assert!(result.contains("STOMP"), "ZERO_NANOS also shows STOMP: {}", result);
        assert!(result.contains("0NANO"), "Should contain 0NANO: {}", result);
    }

    #[test]
    fn test_format_anomalies_table_ads() {
        assert!(format_anomalies(AnomalyFlags::HIDDEN_ADS).contains("ADS"));
    }

    #[test]
    fn test_format_anomalies_table_log_cleared() {
        assert!(format_anomalies(AnomalyFlags::LOG_CLEARED).contains("CLEAR"));
    }

    #[test]
    fn test_format_anomalies_table_multiple() {
        let flags = AnomalyFlags::TIMESTOMPED_SI_LT_FN | AnomalyFlags::LOG_CLEARED | AnomalyFlags::HIDDEN_ADS;
        let result = format_anomalies(flags);
        assert!(result.contains("STOMP"));
        assert!(result.contains("CLEAR"));
        assert!(result.contains("ADS"));
    }

    // ─── format_anomalies_detail ────────────────────────────────────────

    #[test]
    fn test_format_anomalies_detail_empty() {
        // empty flags => empty vec, join = ""
        assert_eq!(format_anomalies_detail(AnomalyFlags::empty()), "");
    }

    #[test]
    fn test_format_anomalies_detail_si_lt_fn() {
        let result = format_anomalies_detail(AnomalyFlags::TIMESTOMPED_SI_LT_FN);
        assert!(result.contains("timestomping"));
    }

    #[test]
    fn test_format_anomalies_detail_zero_nanos() {
        let result = format_anomalies_detail(AnomalyFlags::TIMESTOMPED_ZERO_NANOS);
        assert!(result.contains("zero nanoseconds"));
    }

    #[test]
    fn test_format_anomalies_detail_metadata_backdated() {
        let result = format_anomalies_detail(AnomalyFlags::METADATA_BACKDATED);
        assert!(result.contains("backdated"));
    }

    #[test]
    fn test_format_anomalies_detail_no_usn_create() {
        let result = format_anomalies_detail(AnomalyFlags::NO_USN_CREATE);
        assert!(result.contains("USN Journal"));
    }

    #[test]
    fn test_format_anomalies_detail_log_gap() {
        let result = format_anomalies_detail(AnomalyFlags::LOG_GAP_DETECTED);
        assert!(result.contains("LogFile gap"));
    }

    #[test]
    fn test_format_anomalies_detail_log_cleared() {
        let result = format_anomalies_detail(AnomalyFlags::LOG_CLEARED);
        assert!(result.contains("log cleared"));
    }

    #[test]
    fn test_format_anomalies_detail_no_prefetch() {
        let result = format_anomalies_detail(AnomalyFlags::EXECUTION_NO_PREFETCH);
        assert!(result.contains("prefetch"));
    }

    #[test]
    fn test_format_anomalies_detail_hidden_ads() {
        let result = format_anomalies_detail(AnomalyFlags::HIDDEN_ADS);
        assert!(result.contains("Alternate Data Stream"));
    }

    #[test]
    fn test_format_anomalies_detail_all_flags() {
        let all = AnomalyFlags::TIMESTOMPED_SI_LT_FN
            | AnomalyFlags::TIMESTOMPED_ZERO_NANOS
            | AnomalyFlags::METADATA_BACKDATED
            | AnomalyFlags::NO_USN_CREATE
            | AnomalyFlags::LOG_GAP_DETECTED
            | AnomalyFlags::LOG_CLEARED
            | AnomalyFlags::EXECUTION_NO_PREFETCH
            | AnomalyFlags::HIDDEN_ADS;
        let result = format_anomalies_detail(all);
        assert!(result.contains(" | "), "Flags should be pipe-separated: {}", result);
        // Count the parts
        let parts: Vec<&str> = result.split(" | ").collect();
        assert_eq!(parts.len(), 8);
    }

    // ─── format_size ────────────────────────────────────────────────────

    #[test]
    fn test_format_size_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1023), "1023 B");
    }

    #[test]
    fn test_format_size_kilobytes() {
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(10240), "10.0 KB");
    }

    #[test]
    fn test_format_size_megabytes() {
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn test_format_size_gigabytes() {
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(format_size(2 * 1024 * 1024 * 1024), "2.0 GB");
    }

    // ─── render with scrolled view ──────────────────────────────────────

    #[test]
    fn test_render_with_scroll_offset() {
        let entries: Vec<TimelineEntry> = (0..50)
            .map(|i| make_entry(&format!("C:\\file_{}.txt", i), EventType::FileCreate, AnomalyFlags::empty()))
            .collect();
        let mut app = make_app_with_entries(entries);
        app.visible_rows = 10;
        app.selected_index = 25;
        app.scroll_offset = 20;
        let _terminal = render_to_terminal(&app, 120, 30);
    }

    // ─── render with selected entry ─────────────────────────────────────

    #[test]
    fn test_render_selected_row_highlighted() {
        let mut app = make_default_app();
        app.selected_index = 1;
        let _terminal = render_to_terminal(&app, 120, 30);
    }

    // ─── render with all anomaly types in table ─────────────────────────

    #[test]
    fn test_render_table_all_anomaly_variations() {
        let entries = vec![
            make_entry("normal.txt", EventType::FileCreate, AnomalyFlags::empty()),
            make_entry("stomped.exe", EventType::FileCreate, AnomalyFlags::TIMESTOMPED_SI_LT_FN),
            make_entry("zero_nanos.exe", EventType::FileCreate, AnomalyFlags::TIMESTOMPED_ZERO_NANOS),
            make_entry("both.exe", EventType::FileCreate,
                AnomalyFlags::TIMESTOMPED_SI_LT_FN | AnomalyFlags::TIMESTOMPED_ZERO_NANOS),
            make_entry("ads.exe", EventType::FileCreate, AnomalyFlags::HIDDEN_ADS),
            make_entry("cleared.evtx", EventType::FileCreate, AnomalyFlags::LOG_CLEARED),
        ];
        let app = make_app_with_entries(entries);
        let _terminal = render_to_terminal(&app, 120, 30);
    }

    // ─── render detail pane with all anomaly flags ──────────────────────

    #[test]
    fn test_render_detail_all_anomaly_flags() {
        let all_flags = AnomalyFlags::TIMESTOMPED_SI_LT_FN
            | AnomalyFlags::TIMESTOMPED_ZERO_NANOS
            | AnomalyFlags::METADATA_BACKDATED
            | AnomalyFlags::NO_USN_CREATE
            | AnomalyFlags::LOG_GAP_DETECTED
            | AnomalyFlags::LOG_CLEARED
            | AnomalyFlags::EXECUTION_NO_PREFETCH
            | AnomalyFlags::HIDDEN_ADS;
        let entries = vec![make_entry("C:\\all_flags.exe", EventType::Execute, all_flags)];
        let mut app = make_app_with_entries(entries);
        app.detail_expanded = true;
        let _terminal = render_to_terminal(&app, 120, 40);
    }

    // ─── render detail with no anomalies (no FLAGS line) ────────────────

    #[test]
    fn test_render_detail_no_anomalies_no_flags_line() {
        let entries = vec![make_entry("C:\\clean.txt", EventType::FileCreate, AnomalyFlags::empty())];
        let mut app = make_app_with_entries(entries);
        app.detail_expanded = true;
        let terminal = render_to_terminal(&app, 120, 40);
        let buf = terminal.backend().buffer();
        let mut all_text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                all_text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            all_text.push('\n');
        }
        assert!(!all_text.contains("FLAGS:"), "Clean entry should not show FLAGS");
    }

    // ─── render detail with entry that has no MFT sequence ──────────────

    #[test]
    fn test_render_detail_mft_without_sequence() {
        let mut entry = make_entry("C:\\test.txt", EventType::FileCreate, AnomalyFlags::empty());
        entry.metadata.mft_sequence = None;
        let mut app = make_app_with_entries(vec![entry]);
        app.detail_expanded = true;
        let terminal = render_to_terminal(&app, 120, 40);
        let buf = terminal.backend().buffer();
        let mut all_text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                all_text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            all_text.push('\n');
        }
        assert!(all_text.contains("Seq 0"), "Should default to seq 0: {}", all_text);
    }
}
