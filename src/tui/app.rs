use crate::timeline::entry::TimelineEntry;
use crate::timeline::store::TimelineStore;

pub enum AppMode {
    Normal,
    Search,
}

pub struct App {
    pub store: TimelineStore,
    pub mode: AppMode,
    pub selected_index: usize,
    pub scroll_offset: usize,
    pub detail_expanded: bool,
    pub search_query: String,
    pub search_results: Vec<usize>,
    pub search_cursor: usize,
    pub pre_search_index: usize,
    pub pre_search_offset: usize,
    pub status_message: String,
    pub should_quit: bool,
    pub visible_rows: usize,
    pub hostname: String,
    pub collection_date: String,
}

impl App {
    pub fn new(store: TimelineStore, hostname: String, collection_date: String) -> Self {
        Self {
            store,
            mode: AppMode::Normal,
            selected_index: 0,
            scroll_offset: 0,
            detail_expanded: false,
            search_query: String::new(),
            search_results: Vec::new(),
            search_cursor: 0,
            pre_search_index: 0,
            pre_search_offset: 0,
            status_message: String::new(),
            should_quit: false,
            visible_rows: 20,
            hostname,
            collection_date,
        }
    }

    pub fn move_down(&mut self, n: usize) {
        let max = self.store.len().saturating_sub(1);
        self.selected_index = (self.selected_index + n).min(max);
        self.ensure_visible();
    }

    pub fn move_up(&mut self, n: usize) {
        self.selected_index = self.selected_index.saturating_sub(n);
        self.ensure_visible();
    }

    pub fn goto_top(&mut self) {
        self.selected_index = 0;
        self.scroll_offset = 0;
    }

    pub fn goto_bottom(&mut self) {
        self.selected_index = self.store.len().saturating_sub(1);
        self.ensure_visible();
    }

    pub fn page_down(&mut self) {
        self.move_down(self.visible_rows / 2);
    }

    pub fn page_up(&mut self) {
        self.move_up(self.visible_rows / 2);
    }

    pub fn full_page_down(&mut self) {
        self.move_down(self.visible_rows);
    }

    pub fn full_page_up(&mut self) {
        self.move_up(self.visible_rows);
    }

    pub fn toggle_detail(&mut self) {
        self.detail_expanded = !self.detail_expanded;
    }

    fn ensure_visible(&mut self) {
        if self.selected_index < self.scroll_offset {
            self.scroll_offset = self.selected_index;
        }
        if self.selected_index >= self.scroll_offset + self.visible_rows {
            self.scroll_offset = self.selected_index - self.visible_rows + 1;
        }
    }

    pub fn selected_entry(&self) -> Option<&TimelineEntry> {
        self.store.get(self.selected_index)
    }

    /// Save position before entering search mode (so Esc can restore it).
    pub fn begin_search(&mut self) {
        self.pre_search_index = self.selected_index;
        self.pre_search_offset = self.scroll_offset;
        self.search_query.clear();
        self.search_results.clear();
        self.search_cursor = 0;
        self.status_message.clear();
    }

    /// Cancel search and restore the pre-search position.
    pub fn cancel_search(&mut self) {
        self.selected_index = self.pre_search_index;
        self.scroll_offset = self.pre_search_offset;
        self.search_query.clear();
        self.search_results.clear();
        self.status_message.clear();
    }

    /// Incremental search: rebuild results and jump to the nearest forward match
    /// from the pre-search position. Called on every keystroke in search mode.
    pub fn incremental_search(&mut self) {
        let query = self.search_query.to_lowercase();
        self.search_results.clear();

        if query.is_empty() {
            // Restore position when query is cleared
            self.selected_index = self.pre_search_index;
            self.scroll_offset = self.pre_search_offset;
            self.status_message.clear();
            return;
        }

        for (i, entry) in self.store.entries().enumerate() {
            if entry.path.to_lowercase().contains(&query) {
                self.search_results.push(i);
            }
        }

        if self.search_results.is_empty() {
            self.status_message = format!("No matches for \"{}\"", self.search_query);
            return;
        }

        // Find the nearest match at or after the pre-search position
        let start = self.pre_search_index;
        self.search_cursor = self.search_results
            .iter()
            .position(|&idx| idx >= start)
            .unwrap_or(0); // wrap to first match if none after

        self.selected_index = self.search_results[self.search_cursor];
        self.ensure_visible();
        self.update_search_status();
    }

    /// Confirm search — stay at current match position, return to normal mode.
    pub fn confirm_search(&mut self) {
        if !self.search_results.is_empty() {
            self.update_search_status();
        }
    }

    /// Jump to the next search match (n in normal mode).
    pub fn next_match(&mut self) {
        if self.search_results.is_empty() {
            return;
        }
        self.search_cursor = (self.search_cursor + 1) % self.search_results.len();
        self.selected_index = self.search_results[self.search_cursor];
        self.ensure_visible();
        self.update_search_status();
    }

    /// Jump to the previous search match (N in normal mode).
    pub fn prev_match(&mut self) {
        if self.search_results.is_empty() {
            return;
        }
        if self.search_cursor == 0 {
            self.search_cursor = self.search_results.len() - 1;
        } else {
            self.search_cursor -= 1;
        }
        self.selected_index = self.search_results[self.search_cursor];
        self.ensure_visible();
        self.update_search_status();
    }

    fn update_search_status(&mut self) {
        self.status_message = format!(
            "{}/{} \"{}\"",
            self.search_cursor + 1,
            self.search_results.len(),
            self.search_query
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline::entry::*;
    use chrono::{TimeZone, Utc};
    use smallvec::smallvec;

    /// Helper: create a TimelineEntry with a given path and year for sorting.
    fn make_entry(path: &str, year: i32) -> TimelineEntry {
        TimelineEntry {
            entity_id: EntityId::Generated(0),
            path: path.to_string(),
            primary_timestamp: Utc.with_ymd_and_hms(year, 1, 1, 0, 0, 0).unwrap(),
            event_type: EventType::FileCreate,
            timestamps: TimestampSet::default(),
            sources: smallvec![ArtifactSource::Mft],
            anomalies: AnomalyFlags::empty(),
            metadata: EntryMetadata::default(),
        }
    }

    /// Helper: build a TimelineStore with numbered paths.
    fn make_store(count: usize) -> TimelineStore {
        let mut store = TimelineStore::new();
        for i in 0..count {
            store.push(make_entry(&format!("file_{}", i), 2020 + (i as i32)));
        }
        store
    }

    /// Helper: build an App with a store of `count` entries and default visible_rows.
    fn make_app(count: usize) -> App {
        App::new(make_store(count), "TESTHOST".into(), "2025-01-01".into())
    }

    // ─── App::new ───────────────────────────────────────────

    #[test]
    fn new_creates_correct_initial_state() {
        let app = make_app(5);
        assert_eq!(app.selected_index, 0);
        assert_eq!(app.scroll_offset, 0);
        assert!(!app.detail_expanded);
        assert!(app.search_query.is_empty());
        assert!(app.search_results.is_empty());
        assert_eq!(app.search_cursor, 0);
        assert!(!app.should_quit);
        assert_eq!(app.visible_rows, 20);
        assert_eq!(app.hostname, "TESTHOST");
        assert_eq!(app.collection_date, "2025-01-01");
        assert!(matches!(app.mode, AppMode::Normal));
    }

    // ─── move_down / move_up ────────────────────────────────

    #[test]
    fn move_down_increments_selected_index() {
        let mut app = make_app(10);
        app.move_down(1);
        assert_eq!(app.selected_index, 1);
        app.move_down(3);
        assert_eq!(app.selected_index, 4);
    }

    #[test]
    fn move_down_clamps_at_last_entry() {
        let mut app = make_app(5);
        app.move_down(100);
        assert_eq!(app.selected_index, 4); // 5 entries, max index = 4
    }

    #[test]
    fn move_up_decrements_selected_index() {
        let mut app = make_app(10);
        app.selected_index = 5;
        app.move_up(2);
        assert_eq!(app.selected_index, 3);
    }

    #[test]
    fn move_up_clamps_at_zero() {
        let mut app = make_app(10);
        app.selected_index = 2;
        app.move_up(100);
        assert_eq!(app.selected_index, 0);
    }

    #[test]
    fn move_down_on_empty_store_stays_at_zero() {
        let mut app = make_app(0);
        app.move_down(1);
        // saturating_sub(1) on 0 = 0, min(0,0) = 0
        assert_eq!(app.selected_index, 0);
    }

    // ─── page_down / page_up ────────────────────────────────

    #[test]
    fn page_down_moves_half_visible_rows() {
        let mut app = make_app(50);
        app.visible_rows = 20;
        app.page_down();
        assert_eq!(app.selected_index, 10); // 20/2 = 10
    }

    #[test]
    fn page_up_moves_half_visible_rows() {
        let mut app = make_app(50);
        app.visible_rows = 20;
        app.selected_index = 30;
        app.scroll_offset = 20;
        app.page_up();
        assert_eq!(app.selected_index, 20);
    }

    #[test]
    fn full_page_down_moves_full_visible_rows() {
        let mut app = make_app(50);
        app.visible_rows = 20;
        app.full_page_down();
        assert_eq!(app.selected_index, 20);
    }

    #[test]
    fn full_page_up_moves_full_visible_rows() {
        let mut app = make_app(50);
        app.visible_rows = 20;
        app.selected_index = 30;
        app.scroll_offset = 20;
        app.full_page_up();
        assert_eq!(app.selected_index, 10);
    }

    // ─── goto_top / goto_bottom ─────────────────────────────

    #[test]
    fn goto_top_resets_to_zero() {
        let mut app = make_app(10);
        app.selected_index = 7;
        app.scroll_offset = 3;
        app.goto_top();
        assert_eq!(app.selected_index, 0);
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn goto_bottom_jumps_to_last_entry() {
        let mut app = make_app(10);
        app.goto_bottom();
        assert_eq!(app.selected_index, 9);
    }

    // ─── toggle_detail ──────────────────────────────────────

    #[test]
    fn toggle_detail_flips_state() {
        let mut app = make_app(5);
        assert!(!app.detail_expanded);
        app.toggle_detail();
        assert!(app.detail_expanded);
        app.toggle_detail();
        assert!(!app.detail_expanded);
    }

    // ─── ensure_visible (scroll tracking) ───────────────────

    #[test]
    fn move_down_past_visible_rows_updates_scroll_offset() {
        let mut app = make_app(30);
        app.visible_rows = 5;
        // Move to index 5 => should scroll so that index 5 is visible
        app.move_down(5);
        assert_eq!(app.selected_index, 5);
        // scroll_offset should be 5 - 5 + 1 = 1
        assert_eq!(app.scroll_offset, 1);
    }

    #[test]
    fn move_up_before_scroll_offset_updates_scroll_offset() {
        let mut app = make_app(30);
        app.visible_rows = 5;
        app.selected_index = 10;
        app.scroll_offset = 10;
        app.move_up(3);
        assert_eq!(app.selected_index, 7);
        assert_eq!(app.scroll_offset, 7);
    }

    // ─── selected_entry ─────────────────────────────────────

    #[test]
    fn selected_entry_returns_correct_entry() {
        let app = make_app(3);
        let entry = app.selected_entry().unwrap();
        assert_eq!(entry.path, "file_0");
    }

    #[test]
    fn selected_entry_returns_none_for_empty_store() {
        let app = make_app(0);
        assert!(app.selected_entry().is_none());
    }

    // ─── begin_search / cancel_search / confirm_search ──────

    #[test]
    fn begin_search_saves_position_and_clears_query() {
        let mut app = make_app(10);
        app.selected_index = 5;
        app.scroll_offset = 2;
        app.search_query = "old".to_string();
        app.search_results = vec![1, 2, 3];
        app.begin_search();

        assert_eq!(app.pre_search_index, 5);
        assert_eq!(app.pre_search_offset, 2);
        assert!(app.search_query.is_empty());
        assert!(app.search_results.is_empty());
        assert_eq!(app.search_cursor, 0);
    }

    #[test]
    fn cancel_search_restores_position() {
        let mut app = make_app(10);
        app.selected_index = 3;
        app.scroll_offset = 1;
        app.begin_search();

        // Simulate search moving position
        app.selected_index = 8;
        app.scroll_offset = 5;
        app.search_query = "test".to_string();

        app.cancel_search();
        assert_eq!(app.selected_index, 3);
        assert_eq!(app.scroll_offset, 1);
        assert!(app.search_query.is_empty());
        assert!(app.search_results.is_empty());
    }

    #[test]
    fn confirm_search_updates_status_when_results_exist() {
        let mut app = make_app(5);
        app.search_query = "file".to_string();
        app.search_results = vec![0, 1, 2];
        app.search_cursor = 1;
        app.confirm_search();
        assert!(app.status_message.contains("2/3"));
    }

    #[test]
    fn confirm_search_does_nothing_when_no_results() {
        let mut app = make_app(5);
        app.search_results.clear();
        app.status_message.clear();
        app.confirm_search();
        assert!(app.status_message.is_empty());
    }

    // ─── incremental_search ─────────────────────────────────

    #[test]
    fn incremental_search_finds_matches() {
        let mut app = make_app(5);
        app.begin_search();
        app.search_query = "file_2".to_string();
        app.incremental_search();

        assert_eq!(app.search_results, vec![2]);
        assert_eq!(app.selected_index, 2);
        assert!(app.status_message.contains("1/1"));
    }

    #[test]
    fn incremental_search_case_insensitive() {
        let mut store = TimelineStore::new();
        store.push(make_entry("Alpha.TXT", 2020));
        store.push(make_entry("bravo.txt", 2021));
        let mut app = App::new(store, "H".into(), "D".into());
        app.begin_search();
        app.search_query = "alpha".to_string();
        app.incremental_search();
        assert_eq!(app.search_results, vec![0]);
    }

    #[test]
    fn incremental_search_no_matches_sets_status() {
        let mut app = make_app(5);
        app.begin_search();
        app.search_query = "nonexistent".to_string();
        app.incremental_search();

        assert!(app.search_results.is_empty());
        assert!(app.status_message.contains("No matches"));
    }

    #[test]
    fn incremental_search_empty_query_restores_position() {
        let mut app = make_app(5);
        app.selected_index = 3;
        app.scroll_offset = 1;
        app.begin_search();
        app.search_query.clear();
        app.incremental_search();

        assert_eq!(app.selected_index, 3);
        assert_eq!(app.scroll_offset, 1);
        assert!(app.status_message.is_empty());
    }

    #[test]
    fn incremental_search_nearest_forward_match() {
        // Entries: file_0..file_4. Start search from index 3.
        let mut app = make_app(5);
        app.selected_index = 3;
        app.begin_search();
        app.search_query = "file_".to_string();
        app.incremental_search();

        // Nearest match at or after pre_search_index=3 is index 3 itself
        assert_eq!(app.selected_index, 3);
        assert_eq!(app.search_cursor, 3);
    }

    #[test]
    fn incremental_search_wraps_when_no_forward_match() {
        // All entries match, but if pre_search_index is past last match, wraps to 0
        let mut store = TimelineStore::new();
        store.push(make_entry("alpha", 2020));
        store.push(make_entry("bravo", 2021));
        store.push(make_entry("charlie", 2022));
        let mut app = App::new(store, "H".into(), "D".into());

        app.selected_index = 2;
        app.begin_search();
        app.search_query = "alpha".to_string(); // only matches index 0
        app.incremental_search();

        // No match at or after index 2, so wraps to first match (index 0)
        assert_eq!(app.selected_index, 0);
        assert_eq!(app.search_cursor, 0);
    }

    // ─── next_match / prev_match ────────────────────────────

    #[test]
    fn next_match_cycles_forward() {
        let mut app = make_app(5);
        app.search_query = "file".to_string();
        app.search_results = vec![0, 2, 4];
        app.search_cursor = 0;

        app.next_match();
        assert_eq!(app.search_cursor, 1);
        assert_eq!(app.selected_index, 2);

        app.next_match();
        assert_eq!(app.search_cursor, 2);
        assert_eq!(app.selected_index, 4);

        // Wraps around
        app.next_match();
        assert_eq!(app.search_cursor, 0);
        assert_eq!(app.selected_index, 0);
    }

    #[test]
    fn prev_match_cycles_backward() {
        let mut app = make_app(5);
        app.search_query = "file".to_string();
        app.search_results = vec![0, 2, 4];
        app.search_cursor = 0;

        // Wraps to end
        app.prev_match();
        assert_eq!(app.search_cursor, 2);
        assert_eq!(app.selected_index, 4);

        app.prev_match();
        assert_eq!(app.search_cursor, 1);
        assert_eq!(app.selected_index, 2);
    }

    #[test]
    fn next_match_does_nothing_when_no_results() {
        let mut app = make_app(5);
        app.search_results.clear();
        app.selected_index = 2;
        app.next_match();
        assert_eq!(app.selected_index, 2); // unchanged
    }

    #[test]
    fn prev_match_does_nothing_when_no_results() {
        let mut app = make_app(5);
        app.search_results.clear();
        app.selected_index = 2;
        app.prev_match();
        assert_eq!(app.selected_index, 2); // unchanged
    }

    // ─── visible_rows ───────────────────────────────────────

    #[test]
    fn visible_rows_affects_page_navigation() {
        let mut app = make_app(100);
        app.visible_rows = 10;
        app.page_down();
        assert_eq!(app.selected_index, 5); // 10/2

        app.visible_rows = 40;
        app.page_down();
        assert_eq!(app.selected_index, 25); // 5 + 40/2
    }
}
