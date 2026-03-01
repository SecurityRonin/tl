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
