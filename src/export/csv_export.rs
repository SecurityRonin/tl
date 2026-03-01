use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;
use anyhow::Result;
use std::io::Write;

pub fn export_csv<W: Write>(store: &TimelineStore, writer: &mut W) -> Result<()> {
    let mut wtr = csv::Writer::from_writer(writer);

    wtr.write_record([
        "Timestamp",
        "Event",
        "Path",
        "Sources",
        "Anomalies",
        "SI_Created",
        "SI_Modified",
        "SI_Accessed",
        "SI_EntryMod",
        "FN_Created",
        "FN_Modified",
        "FN_Accessed",
        "FN_EntryMod",
        "MFT_Entry",
        "FileSize",
        "IsDir",
    ])?;

    for entry in store.entries() {
        let sources: String = entry
            .sources
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join("|");

        let anomalies = format_anomalies(entry.anomalies);

        wtr.write_record([
            entry
                .primary_timestamp
                .format("%Y-%m-%d %H:%M:%S%.3f")
                .to_string(),
            entry.event_type.to_string(),
            entry.path.clone(),
            sources,
            anomalies,
            fmt_ts_opt(entry.timestamps.si_created),
            fmt_ts_opt(entry.timestamps.si_modified),
            fmt_ts_opt(entry.timestamps.si_accessed),
            fmt_ts_opt(entry.timestamps.si_entry_modified),
            fmt_ts_opt(entry.timestamps.fn_created),
            fmt_ts_opt(entry.timestamps.fn_modified),
            fmt_ts_opt(entry.timestamps.fn_accessed),
            fmt_ts_opt(entry.timestamps.fn_entry_modified),
            entry
                .metadata
                .mft_entry_number
                .map(|n| n.to_string())
                .unwrap_or_default(),
            entry
                .metadata
                .file_size
                .map(|n| n.to_string())
                .unwrap_or_default(),
            entry.metadata.is_directory.to_string(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

fn fmt_ts_opt(ts: Option<chrono::DateTime<chrono::Utc>>) -> String {
    ts.map(|t| t.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
        .unwrap_or_default()
}

/// Format anomaly flags into a human-readable pipe-separated string for CSV export.
fn format_anomalies(flags: AnomalyFlags) -> String {
    if flags.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    if flags.contains(AnomalyFlags::TIMESTOMPED_SI_LT_FN) {
        parts.push("STOMP");
    }
    if flags.contains(AnomalyFlags::TIMESTOMPED_ZERO_NANOS) {
        parts.push("ZERO_NANOS");
    }
    if flags.contains(AnomalyFlags::METADATA_BACKDATED) {
        parts.push("BACKDATED");
    }
    if flags.contains(AnomalyFlags::NO_USN_CREATE) {
        parts.push("NO_USN");
    }
    if flags.contains(AnomalyFlags::LOG_GAP_DETECTED) {
        parts.push("LOG_GAP");
    }
    if flags.contains(AnomalyFlags::LOG_CLEARED) {
        parts.push("LOG_CLEARED");
    }
    if flags.contains(AnomalyFlags::EXECUTION_NO_PREFETCH) {
        parts.push("NO_PREFETCH");
    }
    if flags.contains(AnomalyFlags::HIDDEN_ADS) {
        parts.push("ADS");
    }
    parts.join("|")
}
