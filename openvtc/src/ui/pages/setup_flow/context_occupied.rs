//! Shown when the chosen Trust Context already holds an account (D5).
//!
//! Setup used to write into whatever context it was given without looking. A
//! fresh install pointed at a context already in use would quietly mint a
//! *second* set of personas beside the first, and a mistyped context id was
//! indistinguishable from a deliberate one until much later.
//!
//! This page turns that into a decision. It is reached only when the probe
//! found something, so a genuine first run never sees it.
//!
//! # What it deliberately does not offer yet
//!
//! **Recover.** Rebuilding an existing context needs the rebuild path and the
//! application-state store behind it. Offering a "Recover" option that cannot
//! complete would be worse than not offering one, so the page says plainly that
//! recovery is not available yet and points at the export instead — the thing
//! that does work today.
//!
//! **Delete.** Destroying a context takes its persona DIDs and their keys with
//! it, irreversibly. That must never be one keypress from someone who re-ran
//! setup, so it is not on this screen at all (D11).

use crate::{
    colors::{
        COLOR_BORDER, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_TEXT_DEFAULT,
        COLOR_WARNING_ACCESSIBLE_RED,
    },
    state_handler::{
        actions::Action,
        setup_sequence::{SetupPage, SetupState},
    },
    ui::pages::setup_flow::{
        SetupFlow,
        navigation::{SetupEvent, handle_nav_result, navigate},
        render_setup_header,
    },
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout,
    },
    style::Style,
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};

#[derive(Clone, Debug, Default)]
pub struct ContextOccupied;

impl ContextOccupied {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            // Go back and choose a different context. The existing one is left
            // completely alone — the non-destructive way to "start fresh".
            KeyCode::Esc | KeyCode::Char('b') | KeyCode::Char('B') => {
                state.props.state.active_page = SetupPage::VtaEnterDid;
            }
            // Recover this context into a working account. Read-only until
            // confirmed — the handler builds a plan and shows it.
            KeyCode::Char('r') | KeyCode::Char('R') => {
                let _ = state.action_tx.send(Action::RecoverPlanContext);
            }
            // Continue into this context anyway. Not the default, and not
            // Enter: continuing means adding a second account beside the first,
            // and that should take a deliberate keystroke rather than the one
            // the user has been pressing to advance every page so far.
            KeyCode::Char('c') | KeyCode::Char('C') => {
                let result = navigate(SetupEvent::ContextOccupiedAccepted, &state.props.state);
                handle_nav_result(result, state);
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame<'_>) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        let context = state.vta.context_id.as_deref().unwrap_or("(unknown)");
        let summary = state
            .vta
            .context_probe
            .as_ref()
            .and_then(|p| p.contents())
            .map(openvtc_core::context_probe::ContextContents::summary)
            .unwrap_or_else(|| "existing data".to_string());

        let mut lines: Vec<Line> = vec![
            Line::styled(
                "This Trust Context is already in use",
                Style::new().fg(COLOR_ORANGE).bold(),
            ),
            Line::default(),
        ];

        // D7: counts, not "content found". The user is deciding whether this is
        // *their* account, and needs enough detail to tell.
        lines.push(Line::from(vec![
            Span::styled("  Context   ", Style::new().fg(COLOR_BORDER)),
            Span::styled(context.to_string(), Style::new().fg(COLOR_SOFT_PURPLE)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Contains  ", Style::new().fg(COLOR_BORDER)),
            Span::styled(summary, Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));

        if let Some(dids) = state
            .vta
            .context_probe
            .as_ref()
            .and_then(|p| p.contents())
            .map(|c| &c.persona_dids)
            && !dids.is_empty()
        {
            lines.push(Line::default());
            for did in dids.iter().take(4) {
                lines.push(Line::styled(
                    format!(
                        "    {}",
                        openvtc_core::display::shorten_for_display(did, 58)
                    ),
                    Style::new().fg(COLOR_BORDER),
                ));
            }
            if dids.len() > 4 {
                lines.push(Line::styled(
                    format!("    … and {} more", dids.len() - 4),
                    Style::new().fg(COLOR_BORDER),
                ));
            }
        }

        lines.push(Line::default());
        lines.push(Line::styled(
            "If this is your account, setup is not the way back into it. \
             Continuing does NOT recover it — it creates a second, separate \
             account alongside the existing one in the same context.",
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ));

        lines.push(Line::default());
        lines.push(Line::styled(
            "What would you like to do?",
            Style::new().fg(COLOR_BORDER).bold(),
        ));
        lines.push(Line::from(vec![
            Span::styled("  [R] ", Style::new().fg(COLOR_SOFT_PURPLE).bold()),
            Span::styled(
                "Recover this account — restores its identities and memberships",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  [B] ", Style::new().fg(COLOR_SOFT_PURPLE).bold()),
            Span::styled(
                "Use a different context — leaves this one untouched",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled(
                "  [C] ",
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
            ),
            Span::styled(
                "Continue anyway, adding a second account to this context",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
        ]));

        let body = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::new().padding(Padding::new(2, 2, 1, 0)));
        frame.render_widget(body, middle);

        let bottom_line = Line::from(vec![
            Span::styled("[R]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" recover  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[B]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(
                " different context  |  ",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Span::styled("[C]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" continue anyway  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]);
        frame.render_widget(
            Paragraph::new(bottom_line).block(Block::new().padding(Padding::new(2, 0, 1, 0))),
            bottom,
        );
    }
}

#[cfg(test)]
mod tests {
    //! Rendered for real and read back, because the value of this page is
    //! entirely in what it says: a warning the user misreads as "recovery
    //! happened" would be worse than no warning at all.
    use super::*;
    use crate::state_handler::setup_sequence::SetupState;
    use openvtc_core::context_probe::{ContextContents, ProbeOutcome};
    use ratatui::{Terminal, backend::TestBackend};

    fn occupied_state(personas: usize) -> SetupState {
        let mut state = SetupState {
            active_page: SetupPage::ContextOccupied,
            ..Default::default()
        };
        state.vta.context_id = Some("openvtc".to_string());
        state.vta.context_probe = Some(ProbeOutcome::Occupied(Box::new(ContextContents {
            persona_dids: (0..personas)
                .map(|i| format!("did:webvh:QmAAAAAAAAAAAA:example.com:persona{i}"))
                .collect(),
            sub_context_count: 2,
        })));
        state
    }

    fn rows(state: &SetupState, width: u16, height: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|frame| ContextOccupied.render(state, frame))
            .expect("render");
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(width as usize)
            .map(|row| {
                row.iter()
                    .map(|c| c.symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    fn flat(state: &SetupState) -> String {
        rows(state, 100, 40)
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// D7 — concrete counts, so the user can tell whether this is their account.
    #[test]
    fn the_page_names_the_context_and_counts_what_is_in_it() {
        let text = flat(&occupied_state(3));
        assert!(text.contains("already in use"), "{text}");
        assert!(text.contains("openvtc"), "{text}");
        assert!(text.contains("3 personas and 2 sub-contexts"), "{text}");
    }

    /// The misreading that would make this page actively harmful.
    #[test]
    fn the_page_says_continuing_is_not_recovery() {
        let text = flat(&occupied_state(1));
        assert!(text.contains("does NOT recover"), "{text}");
        assert!(text.contains("second"), "{text}");
        assert!(
            text.contains("Recover this account"),
            "recovery must be offered now that it works: {text}"
        );
    }

    /// D11 — destroying a context takes persona keys with it. It must not be
    /// reachable from this screen at all.
    #[test]
    fn the_page_offers_no_destructive_option() {
        let text = flat(&occupied_state(2)).to_lowercase();
        assert!(!text.contains("delete"), "{text}");
        assert!(!text.contains("wipe"), "{text}");
        assert!(!text.contains("erase"), "{text}");
    }

    /// A long persona list must not push the choices off the screen — the
    /// actions are the part the page exists for.
    #[test]
    fn many_personas_do_not_crowd_out_the_choices() {
        let text = flat(&occupied_state(12));
        assert!(
            text.contains("and 8 more"),
            "the list must be capped: {text}"
        );
        assert!(text.contains("Use a different context"), "{text}");
        assert!(text.contains("Continue anyway"), "{text}");
    }

    #[test]
    fn nothing_overflows_the_terminal_width() {
        for row in rows(&occupied_state(3), 80, 40) {
            assert!(row.chars().count() <= 80, "row overflows: {row:?}");
        }
    }
}
