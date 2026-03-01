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
            Line::from(vec![
                Span::styled("/", Style::default().fg(Color::Yellow)),
                Span::raw(&app.search_query),
                Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
            ])
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
                    "  q:quit  j/k:nav  J/K:x10  Enter:detail  /:search  x:export",
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
