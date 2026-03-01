use crate::timeline::entry::*;
use crate::timeline::store::TimelineStore;
use anyhow::Result;
use bodyfile::Bodyfile3Line;
use std::io::Write;

/// Export the timeline in bodyfile (mactime) format.
///
/// The bodyfile format is: `md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime`
/// where timestamps are Unix epoch seconds (-1 = not available).
///
/// For MFT entries with SI timestamps, we map:
/// - atime  = si_accessed
/// - mtime  = si_modified
/// - ctime  = si_entry_modified (MFT entry change, closest to POSIX ctime)
/// - crtime = si_created
///
/// For non-MFT entries without SI timestamps, we use primary_timestamp as mtime
/// and -1 for the rest.
pub fn export_bodyfile<W: Write>(store: &TimelineStore, writer: &mut W) -> Result<()> {
    for entry in store.entries() {
        let name = format!(
            "{} ({})",
            entry.path,
            entry
                .sources
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join("|")
        );

        let inode = match (&entry.entity_id, entry.metadata.mft_entry_number) {
            (EntityId::MftEntry(n), _) => {
                let seq = entry.metadata.mft_sequence.unwrap_or(0);
                format!("{}-{}", n, seq)
            }
            (_, Some(n)) => {
                let seq = entry.metadata.mft_sequence.unwrap_or(0);
                format!("{}-{}", n, seq)
            }
            _ => "0".to_string(),
        };

        let size = entry.metadata.file_size.unwrap_or(0);

        let md5 = entry
            .metadata
            .sha256
            .as_deref()
            .unwrap_or("0")
            .to_string();

        let atime = ts_to_epoch(entry.timestamps.si_accessed);
        let mtime = ts_to_epoch(entry.timestamps.si_modified);
        let ctime = ts_to_epoch(entry.timestamps.si_entry_modified);
        let crtime = ts_to_epoch(entry.timestamps.si_created);

        // If no SI timestamps, use primary_timestamp as mtime
        let mtime = if mtime == -1 && atime == -1 && ctime == -1 && crtime == -1 {
            entry.primary_timestamp.timestamp()
        } else {
            mtime
        };

        let line = Bodyfile3Line::new()
            .with_owned_md5(md5)
            .with_owned_name(name)
            .with_owned_inode(inode)
            .with_size(size)
            .with_atime(atime)
            .with_mtime(mtime)
            .with_ctime(ctime)
            .with_crtime(crtime);

        writeln!(writer, "{}", line)?;
    }

    Ok(())
}

/// Convert an optional timestamp to Unix epoch seconds, or -1 if absent.
fn ts_to_epoch(ts: Option<chrono::DateTime<chrono::Utc>>) -> i64 {
    ts.map(|t| t.timestamp()).unwrap_or(-1)
}
