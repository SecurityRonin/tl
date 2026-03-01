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

    /// Execute a case-insensitive path substring search and jump to the first result.
    pub fn execute_search(&mut self) {
        let query = self.search_query.to_lowercase();
        if query.is_empty() {
            self.search_results.clear();
            self.status_message = String::new();
            return;
        }

        self.search_results.clear();
        for (i, entry) in self.store.entries().enumerate() {
            if entry.path.to_lowercase().contains(&query) {
                self.search_results.push(i);
            }
        }

        if self.search_results.is_empty() {
            self.status_message = format!("No matches for \"{}\"", self.search_query);
        } else {
            self.search_cursor = 0;
            self.selected_index = self.search_results[0];
            self.ensure_visible();
            self.status_message = format!(
                "Match 1/{} for \"{}\"",
                self.search_results.len(),
                self.search_query
            );
        }
    }
}
