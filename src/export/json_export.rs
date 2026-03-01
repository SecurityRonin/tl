use crate::timeline::store::TimelineStore;
use anyhow::Result;
use std::io::Write;

pub fn export_json<W: Write>(store: &TimelineStore, writer: &mut W) -> Result<()> {
    let entries: Vec<_> = store.entries().collect();
    serde_json::to_writer_pretty(writer, &entries)?;
    Ok(())
}
