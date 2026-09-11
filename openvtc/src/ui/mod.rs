use crate::{
    Interrupted,
    state_handler::{actions::Action, state::State},
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
use tokio_stream::StreamExt;

pub mod component;
pub mod pages;

pub struct UiManager {
    action_tx: mpsc::UnboundedSender<Action>,
}

impl UiManager {
    pub fn new() -> (Self, UnboundedReceiver<Action>) {
        let (action_tx, action_rx) = mpsc::unbounded_channel();

        (Self { action_tx }, action_rx)
    }

    pub async fn main_loop(
        self,
        mut state_rx: watch::Receiver<State>,
        mut interrupt_rx: broadcast::Receiver<Interrupted>,
    ) -> Result<Interrupted> {
        let mut terminal = setup_terminal()?;

        let mut crossterm_events = EventStream::new();
        // let mut ticker = tokio::time::interval(Duration::from_millis(250));

        // consume the first state to initialize the ui app
        let mut app_router = {
            let state = state_rx.borrow_and_update().clone();
            AppRouter::new(&state, self.action_tx.clone())
        };

        let result: anyhow::Result<Interrupted> = loop {
            if let Err(err) = terminal
                .draw(|frame| {
                    app_router.render(frame, ());
                    // Every panel draws with colour roles; the active theme
                    // colours the finished frame (docs/themes.md).
                    crate::theme::paint(frame.buffer_mut());
                })
                .context("could not render to the terminal")
            {
                break Err(err);
            }

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
                    app_router = app_router.move_with_state(&state);
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
