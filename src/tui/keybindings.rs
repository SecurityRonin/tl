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
            app.mode = AppMode::Search;
            app.search_query.clear();
            app.status_message.clear();
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
        // Execute search and return to Normal
        KeyCode::Enter => {
            app.execute_search();
            app.mode = AppMode::Normal;
        }

        // Cancel search
        KeyCode::Esc => {
            app.search_query.clear();
            app.mode = AppMode::Normal;
            app.status_message.clear();
        }

        // Delete character
        KeyCode::Backspace => {
            app.search_query.pop();
        }

        // Append character
        KeyCode::Char(c) => {
            app.search_query.push(c);
        }

        _ => {}
    }
}
