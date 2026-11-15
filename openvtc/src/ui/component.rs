use std::sync::Arc;

use crate::state_handler::{actions::Action, state::State};
use crossterm::event::KeyEvent;
use ratatui::Frame;
use tokio::sync::mpsc::UnboundedSender;

pub trait Component {
    fn new(state: &Arc<State>, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized;
    fn move_with_state(self, state: &Arc<State>) -> Self
    where
        Self: Sized;

    fn handle_key_event(&mut self, key: KeyEvent);

    /// Handle a bracketed paste event (entire paste as a single string).
    /// Default implementation does nothing.
    fn handle_paste_event(&mut self, _text: &str) {}
}

pub trait ComponentRender<Props> {
    fn render(&self, frame: &mut Frame, props: Props);
}
