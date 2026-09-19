//! Join flow — step 2: live progress of the automated mint + join sequence.
//!
//! Renders the `JoinState.messages` log plus the terminal outcome. On success
//! it shows the created persona DID and the pending community, and prompts the
//! operator to restart OpenVTC to activate the new community (hot-start is a
//! deliberate follow-up). `Enter` returns to the main page.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crossterm::event::{KeyCode, KeyEvent};
use openvtc_core::display::display_identifier;
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};

use crate::{
    state_handler::{
        actions::Action,
        join::{JoinState, PresentedInvitation},
        setup_sequence::{Completion, MessageType},
    },
    ui::pages::join_flow::JoinFlow,
};

/// Width the success page renders the invitation's bound-to identifier at. The
/// page has never truncated this DID, so this only bounds an agent name shown in
/// its place.
const BOUND_TO_WIDTH: usize = 256;

/// What the success page's `Bound to:` row shows for the invitation's subject —
/// the verified agent name of the persona the VIC binds when one is cached,
/// otherwise the DID itself.
fn bound_to_display(vic: &PresentedInvitation, subject: &str) -> String {
    display_identifier(vic.subject_agent_name.as_deref(), subject, BOUND_TO_WIDTH).into_owned()
}

#[derive(Clone, Copy, Debug, Default)]
pub struct JoinProgress;

impl JoinProgress {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter if !state.props.state.processing => {
                // Return to the main page once the sequence has settled.
                let _ = state.action_tx.send(Action::JoinCancel);
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &JoinState, frame: &mut Frame<'_>) {
        let [middle, bottom] = Layout::vertical([Min(0), Length(3)]).areas(frame.area());

        let block = Block::bordered()
            .fg(COLOR_BORDER)
            .padding(Padding::proportional(1))
            .title(" Joining community ");

        let mut lines = Vec::new();

        for msg in &state.messages {
            match msg {
                MessageType::Info(info) => lines.push(Line::styled(
                    format!("INFO: {info}"),
                    Style::new().fg(COLOR_SUCCESS),
                )),
                MessageType::Error(err) => lines.push(Line::styled(
                    format!("ERROR: {err}"),
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                )),
            }
        }

        match state.completed {
            Completion::NotFinished => {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Working… please wait.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
            }
            Completion::CompletedOK => {
                lines.push(Line::default());
                // "Sent", not "submitted" or "delivered". What completed is our
                // half: the request left this client and our mediator accepted
                // it. Whether the community received it is a separate, later
                // fact, carried by the acknowledgement (`receipt_at`) — and
                // wording this as an accomplished submit is what let a join that
                // never reached its community read here as a success.
                lines.push(Line::styled(
                    "Join request sent.",
                    Style::new().fg(COLOR_SUCCESS).bold(),
                ));
                if let Some(rec) = &state.created_community {
                    lines.push(Line::default());
                    // Only show a friendly name when one actually resolved —
                    // otherwise it would just duplicate the DID below.
                    if let Some(name) = &rec.display_name {
                        lines.push(Line::from(vec![
                            Span::styled("  Community:     ", Style::new().fg(COLOR_SUCCESS)),
                            Span::styled(name.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
                        ]));
                    }
                    lines.push(Line::from(vec![
                        Span::styled("  Community DID: ", Style::new().fg(COLOR_SUCCESS)),
                        Span::styled(rec.vtc_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
                    ]));
                    if let Some(persona_did) = &state.created_persona_did {
                        lines.push(Line::from(vec![
                            Span::styled("  Your persona:  ", Style::new().fg(COLOR_SUCCESS)),
                            Span::styled(persona_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
                        ]));
                    }
                    lines.push(Line::from(vec![
                        Span::styled("  Status:        ", Style::new().fg(COLOR_SUCCESS)),
                        Span::styled(
                            "Pending  ·  not yet acknowledged",
                            Style::new().fg(COLOR_ORANGE),
                        ),
                    ]));
                    // Which wire carried it. When a join goes unanswered this is
                    // the first thing worth knowing, and reading it off the
                    // record means it names the transport actually used rather
                    // than the one the community advertises.
                    if let Some(transport) = &rec.submit_transport {
                        lines.push(Line::from(vec![
                            Span::styled("  Sent over:     ", Style::new().fg(COLOR_SUCCESS)),
                            Span::styled(transport.to_string(), Style::new().fg(COLOR_SOFT_PURPLE)),
                        ]));
                    }
                    // Whether an invitation was actually presented (auto-admit
                    // path) or this is an open request (manual approval) — the
                    // distinction that determines what happens next.
                    match &state.presented_invitation {
                        Some(vic) => {
                            lines.push(Line::from(vec![
                                Span::styled("  Invitation:    ", Style::new().fg(COLOR_SUCCESS)),
                                Span::styled(
                                    format!("Presented  ·  {}", vic.id),
                                    Style::new().fg(COLOR_SOFT_PURPLE),
                                ),
                            ]));
                            if let Some(subject) = &vic.subject {
                                lines.push(Line::from(vec![
                                    Span::styled(
                                        "  Bound to:      ",
                                        Style::new().fg(COLOR_SUCCESS),
                                    ),
                                    Span::styled(
                                        bound_to_display(vic, subject),
                                        Style::new().fg(COLOR_SOFT_PURPLE),
                                    ),
                                ]));
                            }
                        }
                        None => {
                            lines.push(Line::from(vec![
                                Span::styled("  Invitation:    ", Style::new().fg(COLOR_SUCCESS)),
                                Span::styled(
                                    "None  ·  open request (awaiting approval)",
                                    Style::new().fg(COLOR_ORANGE),
                                ),
                            ]));
                        }
                    }
                }
                lines.push(Line::default());
                lines.push(Line::styled(
                    "It's now in your Communities list, marked Pending — it will update \
                     there as the community responds.",
                    Style::new().fg(COLOR_SUCCESS),
                ));
                lines.push(Line::styled(
                    "The community hasn't acknowledged it yet. That normally takes seconds; \
                     if it doesn't arrive, the Communities list will flag the request as \
                     possibly not received.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
            }
            Completion::CompletedFail => {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Join failed. Nothing was activated.",
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
                ));
            }
        }

        if !matches!(state.completed, Completion::NotFinished) {
            lines.push(Line::default());
            lines.push(Line::from(vec![
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to return", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]));
        }

        frame.render_widget(
            Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false }),
            middle,
        );

        let bottom_line = Line::from(vec![
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
    use super::*;

    const PERSONA_DID: &str = "did:webvh:QmScidAliceAAAAAAAAAAAAAAAAAAAA:example.com:alice";

    /// The `Bound to:` row shows the verified name of the persona the invitation
    /// binds, in place of that persona's DID.
    #[test]
    fn bound_to_prefers_the_verified_agent_name() {
        let vic = PresentedInvitation {
            id: "urn:vic:1".to_string(),
            subject: Some(PERSONA_DID.to_string()),
            subject_agent_name: Some("example.com/@alice".to_string()),
        };
        assert_eq!(bound_to_display(&vic, PERSONA_DID), "example.com/@alice");
    }

    /// No cached name — including a cached *negative* lookup, which reads the
    /// same as uncached — leaves the DID on screen.
    #[test]
    fn bound_to_falls_back_to_the_did() {
        let vic = PresentedInvitation {
            id: "urn:vic:1".to_string(),
            subject: Some(PERSONA_DID.to_string()),
            subject_agent_name: None,
        };
        // No name, so the DID — shortened at its SCID, which is the part
        // nobody reads.
        let shown = bound_to_display(&vic, PERSONA_DID);
        assert!(shown.ends_with(":example.com:alice"), "{shown}");
        assert!(
            !shown.contains("QmScidAliceAAAA"),
            "the SCID gives way: {shown}"
        );
    }
}
