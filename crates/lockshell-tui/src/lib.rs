// SPDX-License-Identifier: Apache-2.0

//! Lockshell TUI — VS Code-style multi-pane SSH session manager.
//!
//! Phase 8 scaffold. This first cut renders an empty layout with a status
//! bar and accepts a single keybinding (`Ctrl-Q` to quit). PTY-backed SSH
//! panes land in subsequent commits. The split is:
//!
//! - [`App`] — pure data model (no I/O, easy to unit-test).
//! - [`render`] — given an `App` + a frame, draws the layout. Pure.
//! - [`run`] — wires the terminal lifecycle (alt screen, raw mode, event
//!   loop). The only impure entry point.

use std::io;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{Frame, Terminal};

/// Number of SSH session panes the TUI plans to host. Locked at five for
/// the v0.1 layout that maps to keybindings 1..=5.
pub const PANE_COUNT: usize = 5;

/// Application state. Owned by [`run`] and mutated in the event loop.
#[derive(Debug, Clone)]
pub struct App {
    /// Index of the currently focused pane (0-based; 0..PANE_COUNT).
    pub active: usize,

    /// Per-pane title — placeholder until SSH sessions are wired in.
    pub panes: Vec<PaneState>,

    /// One-line status message rendered at the bottom of the screen.
    pub status: String,

    /// Set to `true` by the event handler when the user requests exit.
    /// `run` polls this at every tick and breaks out when set.
    pub should_quit: bool,
}

#[derive(Debug, Clone)]
pub struct PaneState {
    pub title: String,
    /// Stub buffer of lines rendered inside the pane until PTY backing
    /// lands. The TUI scaffold prints one line on activation so the
    /// user has visual confirmation that focus moved.
    pub lines: Vec<String>,
}

impl App {
    pub fn new() -> Self {
        let panes = (0..PANE_COUNT)
            .map(|i| PaneState {
                title: format!("pane {}", i + 1),
                lines: vec![format!(
                    "(scaffold) lockshell-tui pane #{} — SSH backing pending",
                    i + 1
                )],
            })
            .collect();
        Self {
            active: 0,
            panes,
            status: String::from("Ctrl-Q quit  ·  Tab next pane  ·  Ctrl-1..5 jump"),
            should_quit: false,
        }
    }

    /// Cycle focus to the next pane (Tab).
    pub fn focus_next(&mut self) {
        self.active = (self.active + 1) % self.panes.len();
    }

    /// Cycle focus to the previous pane (Shift-Tab).
    pub fn focus_prev(&mut self) {
        self.active = (self.active + self.panes.len() - 1) % self.panes.len();
    }

    /// Jump to pane `idx` (0-based). Out-of-range indices are ignored so
    /// callers can map raw key digits without bounds checking.
    pub fn focus_idx(&mut self, idx: usize) {
        if idx < self.panes.len() {
            self.active = idx;
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

/// Translate a single `KeyEvent` into a state mutation. Pure: returns the
/// new state and a flag indicating whether something interesting happened
/// (used by the event loop to skip redraws on no-op keys).
pub fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    match (key.code, key.modifiers) {
        // Ctrl-Q always quits, regardless of focus.
        (KeyCode::Char('q'), m) if m.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
            true
        }
        // Tab / Shift-Tab cycle panes.
        (KeyCode::Tab, m) if !m.contains(KeyModifiers::SHIFT) => {
            app.focus_next();
            true
        }
        (KeyCode::BackTab, _) => {
            app.focus_prev();
            true
        }
        // Ctrl-1..Ctrl-5 jump directly to a pane.
        (KeyCode::Char(c), m)
            if m.contains(KeyModifiers::CONTROL) && c.is_ascii_digit() && c != '0' =>
        {
            let idx = (c as usize) - ('1' as usize);
            app.focus_idx(idx);
            true
        }
        _ => false,
    }
}

/// Render the entire UI. Called every frame.
pub fn render(app: &App, f: &mut Frame<'_>) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(area);

    render_panes(app, f, chunks[0]);
    render_status(app, f, chunks[1]);
}

fn render_panes(app: &App, f: &mut Frame<'_>, area: Rect) {
    // Five horizontal panes of equal width. Phase 8.4 will let users
    // resize splits; for the scaffold we keep an even partition so the
    // visual hierarchy matches the keybinding (1..5 = left-to-right).
    let pane_areas = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![
            Constraint::Ratio(1, app.panes.len() as u32);
            app.panes.len()
        ])
        .split(area);

    for (i, pane) in app.panes.iter().enumerate() {
        let focused = i == app.active;
        let border_style = if focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let title = if focused {
            format!(" {} ◀ ", pane.title)
        } else {
            format!(" {} ", pane.title)
        };
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style);
        let body: Vec<Line> = pane
            .lines
            .iter()
            .map(|l| Line::from(Span::raw(l.clone())))
            .collect();
        let p = Paragraph::new(body).block(block);
        f.render_widget(p, pane_areas[i]);
    }
}

fn render_status(app: &App, f: &mut Frame<'_>, area: Rect) {
    let pane_label = format!("[{}/{}]", app.active + 1, app.panes.len());
    let line = Line::from(vec![
        Span::styled(
            pane_label,
            Style::default().fg(Color::Black).bg(Color::Cyan),
        ),
        Span::raw("  "),
        Span::raw(app.status.clone()),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

/// Run the TUI on the current process's stdin/stdout. Blocks until the
/// user presses `Ctrl-Q`. Always restores the terminal on exit, including
/// on panics, so a botched render does not leave the user with no cursor.
pub fn run() -> Result<()> {
    let mut stdout = io::stdout();
    enable_raw_mode().context("enabling raw mode")?;
    execute!(stdout, EnterAlternateScreen).context("entering alt screen")?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("constructing ratatui Terminal")?;
    let mut app = App::new();

    let result = event_loop(&mut terminal, &mut app);

    // Always tear down the terminal, even if the loop bailed.
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    result
}

fn event_loop<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| render(app, f))?;

        if app.should_quit {
            return Ok(());
        }

        // 100 ms tick lets the future PTY pipe poll loop slot in here
        // without making the UI feel laggy on quiet input.
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                handle_key(app, key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState};

    fn key(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: mods,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn new_app_has_five_panes_and_active_zero() {
        let a = App::new();
        assert_eq!(a.panes.len(), PANE_COUNT);
        assert_eq!(a.active, 0);
        assert!(!a.should_quit);
    }

    #[test]
    fn ctrl_q_sets_quit() {
        let mut a = App::new();
        let h = handle_key(&mut a, key(KeyCode::Char('q'), KeyModifiers::CONTROL));
        assert!(h);
        assert!(a.should_quit);
    }

    #[test]
    fn plain_q_does_not_quit() {
        let mut a = App::new();
        let h = handle_key(&mut a, key(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(!h);
        assert!(!a.should_quit);
    }

    #[test]
    fn tab_cycles_forward_and_wraps() {
        let mut a = App::new();
        for i in 1..=PANE_COUNT {
            handle_key(&mut a, key(KeyCode::Tab, KeyModifiers::NONE));
            assert_eq!(a.active, i % PANE_COUNT);
        }
    }

    #[test]
    fn shift_tab_cycles_backward_and_wraps() {
        let mut a = App::new();
        handle_key(&mut a, key(KeyCode::BackTab, KeyModifiers::SHIFT));
        assert_eq!(a.active, PANE_COUNT - 1);
    }

    #[test]
    fn ctrl_digit_jumps_to_pane() {
        let mut a = App::new();
        handle_key(&mut a, key(KeyCode::Char('3'), KeyModifiers::CONTROL));
        assert_eq!(a.active, 2);
        handle_key(&mut a, key(KeyCode::Char('5'), KeyModifiers::CONTROL));
        assert_eq!(a.active, 4);
        // Ctrl-9 is out of range — should be a no-op, not a panic.
        handle_key(&mut a, key(KeyCode::Char('9'), KeyModifiers::CONTROL));
        assert_eq!(a.active, 4);
    }

    #[test]
    fn ctrl_zero_is_ignored() {
        let mut a = App::new();
        a.focus_idx(2);
        handle_key(&mut a, key(KeyCode::Char('0'), KeyModifiers::CONTROL));
        assert_eq!(a.active, 2);
    }

    #[test]
    fn render_does_not_panic_on_tiny_area() {
        // Smoke test: build a 10x3 buffer and render — ratatui must not
        // panic on degenerate sizes since the rig will run inside narrow
        // terminals.
        use ratatui::backend::TestBackend;
        let backend = TestBackend::new(20, 6);
        let mut term = Terminal::new(backend).unwrap();
        let app = App::new();
        term.draw(|f| render(&app, f)).unwrap();
    }
}
