use crate::timeline::entry::TimelineEntry;

/// An in-memory store for timeline entries, supporting sorting by primary timestamp.
#[derive(Debug)]
pub struct TimelineStore {
    entries: Vec<TimelineEntry>,
    sorted: bool,
}

impl TimelineStore {
    /// Create a new empty timeline store.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            sorted: true, // empty is trivially sorted
        }
    }

    /// Create a new timeline store with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            sorted: true,
        }
    }

    /// Push a new entry into the store. Marks the store as unsorted.
    pub fn push(&mut self, entry: TimelineEntry) {
        self.sorted = false;
        self.entries.push(entry);
    }

    /// Sort all entries by primary_timestamp (ascending).
    pub fn sort(&mut self) {
        if !self.sorted {
            self.entries.sort_by_key(|e| e.primary_timestamp);
            self.sorted = true;
        }
    }

    /// Returns the number of entries in the store.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the store contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over the entries.
    pub fn entries(&self) -> impl Iterator<Item = &TimelineEntry> {
        self.entries.iter()
    }

    /// Returns a mutable iterator over the entries.
    pub fn entries_mut(&mut self) -> impl Iterator<Item = &mut TimelineEntry> {
        self.entries.iter_mut()
    }

    /// Get an entry by index.
    pub fn get(&self, index: usize) -> Option<&TimelineEntry> {
        self.entries.get(index)
    }

    /// Returns whether the store is currently sorted.
    pub fn is_sorted(&self) -> bool {
        self.sorted
    }
}

impl Default for TimelineStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline::entry::*;
    use chrono::{TimeZone, Utc};
    use smallvec::smallvec;

    fn make_entry(year: i32, month: u32, day: u32) -> TimelineEntry {
        TimelineEntry {
            entity_id: EntityId::Generated(0),
            path: format!("test_{}-{}-{}", year, month, day),
            primary_timestamp: Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap(),
            event_type: EventType::FileCreate,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        }
    }

    #[test]
    fn test_store_push_and_len() {
        let mut store = TimelineStore::new();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());

        store.push(make_entry(2025, 1, 1));
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
    }

    #[test]
    fn test_store_sort() {
        let mut store = TimelineStore::new();
        store.push(make_entry(2025, 3, 1));
        store.push(make_entry(2025, 1, 1));
        store.push(make_entry(2025, 2, 1));

        store.sort();

        let timestamps: Vec<_> = store.entries().map(|e| e.primary_timestamp).collect();
        assert!(timestamps.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn test_store_get() {
        let mut store = TimelineStore::new();
        store.push(make_entry(2025, 1, 1));
        store.push(make_entry(2025, 2, 1));

        assert!(store.get(0).is_some());
        assert!(store.get(1).is_some());
        assert!(store.get(2).is_none());
    }
}
