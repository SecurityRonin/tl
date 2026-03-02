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

    // ─── new() ──────────────────────────────────────────────

    #[test]
    fn test_new_is_empty_and_sorted() {
        let store = TimelineStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.is_sorted());
    }

    // ─── with_capacity ──────────────────────────────────────

    #[test]
    fn test_with_capacity_is_empty() {
        let store = TimelineStore::with_capacity(100);
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.is_sorted());
    }

    // ─── push marks unsorted ────────────────────────────────

    #[test]
    fn test_push_marks_unsorted() {
        let mut store = TimelineStore::new();
        assert!(store.is_sorted());
        store.push(make_entry(2025, 1, 1));
        assert!(!store.is_sorted());
    }

    // ─── sort idempotent ────────────────────────────────────

    #[test]
    fn test_sort_marks_sorted() {
        let mut store = TimelineStore::new();
        store.push(make_entry(2025, 3, 1));
        store.push(make_entry(2025, 1, 1));
        assert!(!store.is_sorted());

        store.sort();
        assert!(store.is_sorted());

        // Calling sort again on already-sorted store should be fine
        store.sort();
        assert!(store.is_sorted());
    }

    #[test]
    fn test_sort_produces_chronological_order() {
        let mut store = TimelineStore::new();
        store.push(make_entry(2025, 12, 31));
        store.push(make_entry(2020, 1, 1));
        store.push(make_entry(2023, 6, 15));

        store.sort();

        let paths: Vec<&str> = store.entries().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["test_2020-1-1", "test_2023-6-15", "test_2025-12-31"]);
    }

    // ─── get returns correct entry ──────────────────────────

    #[test]
    fn test_get_returns_correct_path() {
        let mut store = TimelineStore::new();
        store.push(make_entry(2025, 1, 1));
        store.push(make_entry(2025, 6, 15));

        let e0 = store.get(0).unwrap();
        assert_eq!(e0.path, "test_2025-1-1");

        let e1 = store.get(1).unwrap();
        assert_eq!(e1.path, "test_2025-6-15");
    }

    #[test]
    fn test_get_out_of_bounds() {
        let store = TimelineStore::new();
        assert!(store.get(0).is_none());
    }

    // ─── entries iterator ───────────────────────────────────

    #[test]
    fn test_entries_returns_all() {
        let mut store = TimelineStore::new();
        store.push(make_entry(2020, 1, 1));
        store.push(make_entry(2021, 1, 1));
        store.push(make_entry(2022, 1, 1));

        let paths: Vec<&str> = store.entries().map(|e| e.path.as_str()).collect();
        assert_eq!(paths.len(), 3);
    }

    // ─── entries_mut iterator ───────────────────────────────

    #[test]
    fn test_entries_mut_allows_modification() {
        let mut store = TimelineStore::new();
        store.push(make_entry(2020, 1, 1));
        store.push(make_entry(2021, 1, 1));

        for entry in store.entries_mut() {
            entry.path = format!("modified_{}", entry.path);
        }

        assert!(store.get(0).unwrap().path.starts_with("modified_"));
        assert!(store.get(1).unwrap().path.starts_with("modified_"));
    }

    // ─── default trait ──────────────────────────────────────

    #[test]
    fn test_default_creates_empty_store() {
        let store = TimelineStore::default();
        assert!(store.is_empty());
        assert!(store.is_sorted());
    }

    // ─── len after multiple operations ──────────────────────

    #[test]
    fn test_len_tracks_pushes() {
        let mut store = TimelineStore::new();
        assert_eq!(store.len(), 0);
        store.push(make_entry(2020, 1, 1));
        assert_eq!(store.len(), 1);
        store.push(make_entry(2021, 1, 1));
        assert_eq!(store.len(), 2);
        store.push(make_entry(2022, 1, 1));
        assert_eq!(store.len(), 3);
    }
}
