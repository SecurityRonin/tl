use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::app::{App, AppMode};

/// Handle a key event, dispatching to the appropriate mode handler.
pub fn handle_key(app: &mut App, key: KeyEvent) {
    match app.mode {
        AppMode::Normal => handle_normal_mode(app, key),
        AppMode::Search => handle_search_mode(app, key),
    }
}

fn handle_normal_mode(app: &mut App, key: KeyEvent) {
    match key.code {
        // Quit
        KeyCode::Char('q') => {
            app.should_quit = true;
        }

        // Navigation: down
        KeyCode::Char('j') | KeyCode::Down => {
            app.move_down(1);
        }
        // Navigation: up
        KeyCode::Char('k') | KeyCode::Up => {
            app.move_up(1);
        }

        // Fast navigation: down 10
        KeyCode::Char('J') => {
            app.move_down(10);
        }
        // Fast navigation: up 10
        KeyCode::Char('K') => {
            app.move_up(10);
        }

        // Half-page down (Ctrl-d)
        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.page_down();
        }
        // Half-page up (Ctrl-u)
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.page_up();
        }

        // Full page down (Ctrl-f)
        KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.full_page_down();
        }
        // Full page up (Ctrl-b)
        KeyCode::Char('b') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.full_page_up();
        }

        // Go to top
        KeyCode::Char('g') => {
            app.goto_top();
        }
        // Go to bottom
        KeyCode::Char('G') => {
            app.goto_bottom();
        }

        // Toggle detail pane
        KeyCode::Enter => {
            app.toggle_detail();
        }

        // Enter search mode
        KeyCode::Char('/') => {
            app.begin_search();
            app.mode = AppMode::Search;
        }

        // Next search match
        KeyCode::Char('n') => {
            app.next_match();
        }
        // Previous search match
        KeyCode::Char('N') => {
            app.prev_match();
        }

        // Export placeholder
        KeyCode::Char('x') => {
            app.status_message = "Export: use --export-csv flag (coming soon)".to_string();
        }

        _ => {}
    }
}

fn handle_search_mode(app: &mut App, key: KeyEvent) {
    match key.code {
        // Confirm search — stay at current match
        KeyCode::Enter => {
            app.confirm_search();
            app.mode = AppMode::Normal;
        }

        // Cancel search — restore pre-search position
        KeyCode::Esc => {
            app.cancel_search();
            app.mode = AppMode::Normal;
        }

        // Delete character — re-search incrementally
        KeyCode::Backspace => {
            app.search_query.pop();
            app.incremental_search();
        }

        // Type character — search incrementally as you type
        KeyCode::Char(c) => {
            app.search_query.push(c);
            app.incremental_search();
        }

        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline::entry::*;
    use crate::timeline::store::TimelineStore;
    use chrono::{TimeZone, Utc};
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use smallvec::smallvec;

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

    fn make_app(count: usize) -> App {
        let mut store = TimelineStore::new();
        for i in 0..count {
            store.push(make_entry(&format!("file_{}", i), 2020 + (i as i32)));
        }
        App::new(store, "HOST".into(), "DATE".into())
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn key_with_mod(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    // ─── Normal mode: quit ──────────────────────────────────

    #[test]
    fn normal_q_quits() {
        let mut app = make_app(5);
        handle_key(&mut app, key(KeyCode::Char('q')));
        assert!(app.should_quit);
    }

    // ─── Normal mode: basic navigation ──────────────────────

    #[test]
    fn normal_j_moves_down() {
        let mut app = make_app(10);
        handle_key(&mut app, key(KeyCode::Char('j')));
        assert_eq!(app.selected_index, 1);
    }

    #[test]
    fn normal_down_arrow_moves_down() {
        let mut app = make_app(10);
        handle_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.selected_index, 1);
    }

    #[test]
    fn normal_k_moves_up() {
        let mut app = make_app(10);
        app.selected_index = 3;
        handle_key(&mut app, key(KeyCode::Char('k')));
        assert_eq!(app.selected_index, 2);
    }

    #[test]
    fn normal_up_arrow_moves_up() {
        let mut app = make_app(10);
        app.selected_index = 3;
        handle_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.selected_index, 2);
    }

    // ─── Normal mode: fast navigation ───────────────────────

    #[test]
    fn normal_shift_j_moves_down_10() {
        let mut app = make_app(20);
        handle_key(&mut app, key(KeyCode::Char('J')));
        assert_eq!(app.selected_index, 10);
    }

    #[test]
    fn normal_shift_k_moves_up_10() {
        let mut app = make_app(20);
        app.selected_index = 15;
        handle_key(&mut app, key(KeyCode::Char('K')));
        assert_eq!(app.selected_index, 5);
    }

    // ─── Normal mode: half-page & full-page ─────────────────

    #[test]
    fn normal_ctrl_d_pages_down() {
        let mut app = make_app(50);
        app.visible_rows = 20;
        handle_key(&mut app, key_with_mod(KeyCode::Char('d'), KeyModifiers::CONTROL));
        assert_eq!(app.selected_index, 10);
    }

    #[test]
    fn normal_ctrl_u_pages_up() {
        let mut app = make_app(50);
        app.visible_rows = 20;
        app.selected_index = 30;
        app.scroll_offset = 20;
        handle_key(&mut app, key_with_mod(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert_eq!(app.selected_index, 20);
    }

    #[test]
    fn normal_ctrl_f_full_page_down() {
        let mut app = make_app(50);
        app.visible_rows = 10;
        handle_key(&mut app, key_with_mod(KeyCode::Char('f'), KeyModifiers::CONTROL));
        assert_eq!(app.selected_index, 10);
    }

    #[test]
    fn normal_ctrl_b_full_page_up() {
        let mut app = make_app(50);
        app.visible_rows = 10;
        app.selected_index = 20;
        app.scroll_offset = 15;
        handle_key(&mut app, key_with_mod(KeyCode::Char('b'), KeyModifiers::CONTROL));
        assert_eq!(app.selected_index, 10);
    }

    // ─── Normal mode: goto top/bottom ───────────────────────

    #[test]
    fn normal_g_goes_to_top() {
        let mut app = make_app(10);
        app.selected_index = 8;
        app.scroll_offset = 3;
        handle_key(&mut app, key(KeyCode::Char('g')));
        assert_eq!(app.selected_index, 0);
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn normal_shift_g_goes_to_bottom() {
        let mut app = make_app(10);
        handle_key(&mut app, key(KeyCode::Char('G')));
        assert_eq!(app.selected_index, 9);
    }

    // ─── Normal mode: toggle detail ─────────────────────────

    #[test]
    fn normal_enter_toggles_detail() {
        let mut app = make_app(5);
        assert!(!app.detail_expanded);
        handle_key(&mut app, key(KeyCode::Enter));
        assert!(app.detail_expanded);
        handle_key(&mut app, key(KeyCode::Enter));
        assert!(!app.detail_expanded);
    }

    // ─── Normal mode: enter search ──────────────────────────

    #[test]
    fn normal_slash_enters_search_mode() {
        let mut app = make_app(5);
        app.selected_index = 2;
        handle_key(&mut app, key(KeyCode::Char('/')));
        assert!(matches!(app.mode, AppMode::Search));
        assert_eq!(app.pre_search_index, 2);
    }

    // ─── Normal mode: search cycling ────────────────────────

    #[test]
    fn normal_n_cycles_next_match() {
        let mut app = make_app(10);
        app.search_query = "file".to_string();
        app.search_results = vec![1, 3, 5];
        app.search_cursor = 0;
        handle_key(&mut app, key(KeyCode::Char('n')));
        assert_eq!(app.search_cursor, 1);
        assert_eq!(app.selected_index, 3);
    }

    #[test]
    fn normal_shift_n_cycles_prev_match() {
        let mut app = make_app(10);
        app.search_query = "file".to_string();
        app.search_results = vec![1, 3, 5];
        app.search_cursor = 2;
        handle_key(&mut app, key(KeyCode::Char('N')));
        assert_eq!(app.search_cursor, 1);
        assert_eq!(app.selected_index, 3);
    }

    // ─── Normal mode: export placeholder ────────────────────

    #[test]
    fn normal_x_sets_export_status() {
        let mut app = make_app(5);
        handle_key(&mut app, key(KeyCode::Char('x')));
        assert!(app.status_message.contains("Export"));
    }

    // ─── Normal mode: unknown key does nothing ──────────────

    #[test]
    fn normal_unknown_key_no_change() {
        let mut app = make_app(5);
        let idx = app.selected_index;
        handle_key(&mut app, key(KeyCode::Char('z')));
        assert_eq!(app.selected_index, idx);
        assert!(!app.should_quit);
    }

    // ─── Search mode: typing characters ─────────────────────

    #[test]
    fn search_typing_updates_query_and_searches() {
        let mut app = make_app(5);
        app.mode = AppMode::Search;
        app.begin_search();
        handle_key(&mut app, key(KeyCode::Char('f')));
        assert_eq!(app.search_query, "f");
        handle_key(&mut app, key(KeyCode::Char('i')));
        assert_eq!(app.search_query, "fi");
        // All entries contain "fi" (file_0..file_4)
        assert_eq!(app.search_results.len(), 5);
    }

    // ─── Search mode: backspace ─────────────────────────────

    #[test]
    fn search_backspace_removes_character() {
        let mut app = make_app(5);
        app.mode = AppMode::Search;
        app.begin_search();
        app.search_query = "fil".to_string();
        handle_key(&mut app, key(KeyCode::Backspace));
        assert_eq!(app.search_query, "fi");
    }

    #[test]
    fn search_backspace_on_empty_query_is_safe() {
        let mut app = make_app(5);
        app.mode = AppMode::Search;
        app.begin_search();
        handle_key(&mut app, key(KeyCode::Backspace));
        assert!(app.search_query.is_empty());
    }

    // ─── Search mode: enter confirms ────────────────────────

    #[test]
    fn search_enter_confirms_and_returns_to_normal() {
        let mut app = make_app(5);
        app.mode = AppMode::Search;
        app.begin_search();
        app.search_query = "file_3".to_string();
        app.incremental_search();
        handle_key(&mut app, key(KeyCode::Enter));
        assert!(matches!(app.mode, AppMode::Normal));
        assert_eq!(app.selected_index, 3);
    }

    // ─── Search mode: esc cancels ───────────────────────────

    #[test]
    fn search_esc_cancels_and_restores_position() {
        let mut app = make_app(10);
        app.selected_index = 5;
        app.scroll_offset = 2;
        app.begin_search();
        app.mode = AppMode::Search;

        // Type and search
        app.search_query = "file_8".to_string();
        app.incremental_search();
        assert_eq!(app.selected_index, 8);

        handle_key(&mut app, key(KeyCode::Esc));
        assert!(matches!(app.mode, AppMode::Normal));
        assert_eq!(app.selected_index, 5);
        assert_eq!(app.scroll_offset, 2);
    }

    // ─── Search mode: unknown key does nothing ──────────────

    #[test]
    fn search_unknown_key_no_change() {
        let mut app = make_app(5);
        app.mode = AppMode::Search;
        app.begin_search();
        let query_before = app.search_query.clone();
        handle_key(&mut app, key(KeyCode::Tab));
        assert_eq!(app.search_query, query_before);
        assert!(matches!(app.mode, AppMode::Search));
    }

    // ─── Dispatch routes to correct mode ────────────────────

    #[test]
    fn handle_key_dispatches_based_on_mode() {
        let mut app = make_app(5);

        // Normal mode: 'q' should quit
        app.mode = AppMode::Normal;
        handle_key(&mut app, key(KeyCode::Char('q')));
        assert!(app.should_quit);

        // Reset
        app.should_quit = false;

        // Search mode: 'q' should be typed, not quit
        app.mode = AppMode::Search;
        app.begin_search();
        handle_key(&mut app, key(KeyCode::Char('q')));
        assert!(!app.should_quit);
        assert_eq!(app.search_query, "q");
    }
}
