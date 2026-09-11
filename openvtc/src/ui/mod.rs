use crate::{
    Interrupted,
    state_handler::{actions::Action, main_page::content::SettingsMode, state::State},
    theme::{self, live},
    ui::{
        component::{Component, ComponentRender},
        pages::AppRouter,
    },
};
use anyhow::{Context, Result};
use crossterm::{
    event::{DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, Event, EventStream},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, prelude::CrosstermBackend};
use std::io::{self, Stdout};
use tokio::sync::{broadcast, mpsc, mpsc::UnboundedReceiver, watch};
use tokio::time::MissedTickBehavior;
use tokio_stream::StreamExt;

pub mod component;
pub mod pages;

pub struct UiManager {
    action_tx: mpsc::UnboundedSender<Action>,
    /// Follows the theme in use, so a change to it is drawn without a restart.
    theme_watcher: live::Watcher,
}

impl UiManager {
    pub fn new(theme_watcher: live::Watcher) -> (Self, UnboundedReceiver<Action>) {
        let (action_tx, action_rx) = mpsc::unbounded_channel();

        (
            Self {
                action_tx,
                theme_watcher,
            },
            action_rx,
        )
    }

    pub async fn main_loop(
        self,
        mut state_rx: watch::Receiver<State>,
        mut interrupt_rx: broadcast::Receiver<Interrupted>,
    ) -> Result<Interrupted> {
        let Self {
            action_tx,
            mut theme_watcher,
        } = self;
        let mut terminal = setup_terminal()?;

        let mut crossterm_events = EventStream::new();
        // let mut ticker = tokio::time::interval(Duration::from_millis(250));

        // Theme changes are looked for on a blocking thread — the check stats
        // files, which a slow home directory could stall — and come back here.
        let (theme_tx, mut theme_rx) = mpsc::unbounded_channel();
        let mut theme_poll = tokio::time::interval(live::POLL_INTERVAL);
        theme_poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut theme_checking = false;
        // Counts states that arrive with the theme picker open. A check that
        // ran while this moved may have raced a preview or a choice, so what it
        // found is left to be found again.
        let mut picker_epoch: u64 = 0;
        let mut check_epoch: u64 = 0;

        // consume the first state to initialize the ui app
        let mut app_router = {
            let state = state_rx.borrow_and_update().clone();
            AppRouter::new(&state, action_tx.clone())
        };

        let mut redraw = true;
        let result: anyhow::Result<Interrupted> = loop {
            if redraw
                && let Err(err) = terminal
                    .draw(|frame| {
                        app_router.render(frame, ());
                        // Every panel draws with colour roles; the active theme
                        // colours the finished frame (docs/themes.md).
                        theme::paint(frame.buffer_mut());
                    })
                    .context("could not render to the terminal")
            {
                break Err(err);
            }
            redraw = true;

            tokio::select! {
                // Tick to terminate the select every N milliseconds
                // _ = ticker.tick() => (),
                // Catch and handle crossterm events
               maybe_event = crossterm_events.next() => match maybe_event {
                    Some(Ok(Event::Key(key)))  => {
                        app_router.handle_key_event(key);
                    },
                    Some(Ok(Event::Paste(text))) => {
                        app_router.handle_paste_event(&text);
                    },
                    None => break Ok(Interrupted::UserInt),
                    _ => (),
                },
                // Handle state updates
                Ok(()) = state_rx.changed() => {
                    let state = state_rx.borrow_and_update().clone();
                    if theme_picker_open(&state) {
                        picker_epoch += 1;
                    }
                    app_router = app_router.move_with_state(&state);
                },
                // Look for a theme change, unless a look is already under way
                // or the picker is open.
                _ = theme_poll.tick() => {
                    redraw = false;
                    let picker_open = theme_picker_open(&state_rx.borrow());
                    if !theme_checking && !picker_open {
                        theme_checking = true;
                        check_epoch = picker_epoch;
                        let watcher = theme_watcher.clone();
                        let theme_tx = theme_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let _ = theme_tx.send(watcher.check());
                        });
                    }
                },
                // Draw a theme change, unless the picker opened meanwhile: its
                // preview is the person's, and the change is seen again once
                // the picker closes.
                Some(found) = theme_rx.recv() => {
                    theme_checking = false;
                    redraw = false;
                    let picker_open = theme_picker_open(&state_rx.borrow());
                    if let Some(update) = found
                        && check_epoch == picker_epoch
                        && !picker_open
                        && let Some(changed) = theme_watcher.accept(update)
                    {
                        theme::set_active(&changed);
                        redraw = true;
                    }
                },
                // Catch and handle interrupt signal to gracefully shutdown
                Ok(interrupted) = interrupt_rx.recv() => {
                    break Ok(interrupted);
                }
            }
        };

        restore_terminal(&mut terminal)?;

        result
    }
}

/// Whether the theme picker is open, previewing themes.
fn theme_picker_open(state: &State) -> bool {
    matches!(
        state.main_page.content_panel.settings.mode,
        SettingsMode::ThemePicker { .. }
    )
}

fn setup_terminal() -> anyhow::Result<Terminal<CrosstermBackend<Stdout>>> {
    let mut stdout = io::stdout();

    enable_raw_mode()?;

    execute!(
        stdout,
        EnterAlternateScreen,
        DisableMouseCapture,
        EnableBracketedPaste
    )?;

    // Ensure a panic anywhere in the render loop or a spawned task still
    // returns the terminal to a usable state instead of leaving it in raw
    // mode on the alternate screen.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    terminal.clear()?;

    Ok(terminal)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> anyhow::Result<()> {
    disable_raw_mode()?;

    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
        DisableBracketedPaste
    )?;

    Ok(terminal.show_cursor()?)
}
