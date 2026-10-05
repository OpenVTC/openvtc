//! Join flow — invitation choice.
//!
//! Reached whenever the operator picks an existing identity to present, whether
//! or not an invitation (VIC) was found for it. Each known invitation is listed
//! with its details (Issued / Expires); the operator presents one — auto-joining
//! on a valid, trusted invitation — pastes one the vault has never seen, or
//! chooses the trailing "join without it" row to send an open request the
//! community approves manually. The default highlight is the first invitation, so
//! Enter preserves the auto-join behaviour.
//!
//! The step used to be skipped when no VIC was found for the chosen identity,
//! which made "do you have an invitation?" a question the flow only asked when it
//! already knew the answer. An operator holding one — sent by email, sitting in a
//! file, issued to a different persona — was never given anywhere to put it and
//! silently submitted an open request instead. Hence the paste row, and hence the
//! step being unconditional: an empty list is a question, not a decision.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT,
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout, Margin,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};

use crate::{
    state_handler::{actions::Action, join::JoinState, main_page::shorten_did},
    ui::pages::join_flow::JoinFlow,
};

#[derive(Clone, Debug, Default)]
pub struct InvitationChoice;

/// Trim an RFC 3339 timestamp to its date for compact display; empty stays as a
/// dash. Falls back to the full string if it is shorter than a date.
fn short_date(ts: &str) -> String {
    if ts.is_empty() {
        "—".to_string()
    } else {
        // Character-aligned: the timestamp comes off a credential we did not
        // mint, so a byte cut here would panic on a multi-byte scalar.
        openvtc_core::display::truncate_chars(ts, 10).to_string()
    }
}

impl InvitationChoice {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        if state.props.state.processing {
            return;
        }
        let selected = state.props.state.invitation_use_selected;
        // The "join without it" row is the last one, so it is the clamp ceiling.
        let without_row = state.props.state.invitation_without_row();
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Up => {
                let _ = state
                    .action_tx
                    .send(Action::JoinInvitationSelect(selected.saturating_sub(1)));
            }
            KeyCode::Down => {
                let _ = state.action_tx.send(Action::JoinInvitationSelect(
                    (selected + 1).min(without_row),
                ));
            }
            KeyCode::Enter => {
                let _ = state.action_tx.send(Action::JoinInvitationChoose);
            }
            KeyCode::Esc => {
                let _ = state.action_tx.send(Action::JoinCancel);
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &JoinState, frame: &mut Frame<'_>) {
        let [middle, bottom] = Layout::vertical([Min(0), Length(3)]).areas(frame.area());

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(if state.vetting_in_hand.is_some() {
                    " Also present an invitation? "
                } else {
                    " Use an invitation for this community? "
                }),
            middle,
        );
        let inner = middle.inner(Margin::new(3, 2));

        let mut lines = vec![
            Line::styled(
                "Choose an invitation to present, or join without one:",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
        ];
        // Holding vetting changes what this question is: the statements go with
        // the request either way, so an invitation is in addition to them, not
        // the only alternative to an open request.
        if let Some(vetting) = &state.vetting_in_hand {
            lines.insert(
                1,
                Line::styled(
                    {
                        // One statement, or a proof (always one), is singular.
                        let one = vetting.hidden || vetting.count == 1;
                        format!(
                            "Your {} {} with this request either way. An invitation is optional \
                             on top of {}.",
                            vetting_words(vetting),
                            if one { "goes" } else { "go" },
                            if one { "it" } else { "them" }
                        )
                    },
                    Style::new().fg(COLOR_SOFT_PURPLE),
                ),
            );
        }

        // With nothing found, say so plainly rather than showing a bare list —
        // the step is still worth asking, because the paste row below answers it.
        if state.invitation_options.is_empty() {
            lines.push(Line::styled(
                "  No invitation found for this identity in your credential vault.",
                Style::new().fg(COLOR_DARK_GRAY).italic(),
            ));
            lines.push(Line::default());
        }

        // One selectable row per available invitation, with its details.
        for (i, vic) in state.invitation_options.iter().enumerate() {
            let is_sel = i == state.invitation_use_selected;
            let marker = if is_sel { "▸ " } else { "  " };
            let style = if is_sel {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            };
            lines.push(Line::from(Span::styled(
                format!("{marker}Invitation {}", vic.id),
                style,
            )));
            lines.push(Line::styled(
                format!(
                    "    Issued {}  ·  Expires {}",
                    short_date(&vic.valid_from),
                    short_date(&vic.valid_until),
                ),
                Style::new().fg(COLOR_DARK_GRAY),
            ));
            // An invitation bound to a *different* DID is still presentable — the
            // join builds a subject-linkage proof for it — but only if we hold
            // that persona's key, so flag it rather than letting it look routine.
            if let (Some(subject), Some(persona)) = (
                vic.subject.as_deref(),
                state.invitation_persona_did.as_deref(),
            ) && subject != persona
            {
                lines.push(Line::styled(
                    format!(
                        "    Issued to {} — shown with a proof that links the two",
                        shorten_did(subject, 40)
                    ),
                    Style::new().fg(COLOR_ORANGE),
                ));
            }
        }

        // The paste row: an invitation the vault has never seen.
        let paste_row = state.invitation_paste_row();
        let paste_sel = state.invitation_use_selected == paste_row;
        let marker = if paste_sel { "▸ " } else { "  " };
        let style = if paste_sel {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_SOFT_PURPLE)
        };
        lines.push(Line::from(Span::styled(
            format!("{marker}⎘ Paste an invitation credential (VIC)"),
            style,
        )));
        lines.push(Line::styled(
            "    [ENTER] to read your clipboard, or paste the JSON straight in.",
            Style::new().fg(COLOR_DARK_GRAY),
        ));

        // Trailing "join without it" row.
        let without_sel = state.invitation_use_selected >= state.invitation_without_row();
        let marker = if without_sel { "▸ " } else { "  " };
        let style = if without_sel {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_SOFT_PURPLE)
        };
        // What joining without an invitation actually sends. With vetting in
        // hand it is not an open request: the statements decide it, under the
        // community's own admission rule.
        match &state.vetting_in_hand {
            Some(vetting) => {
                lines.push(Line::from(Span::styled(
                    format!(
                        "{marker}Join without one — with your {} only",
                        vetting_words(vetting)
                    ),
                    style,
                )));
                lines.push(Line::styled(
                    format!(
                        "    {}.",
                        vetting
                            .decision
                            .clone()
                            .unwrap_or_else(|| "The community decides on your vetting".to_string())
                    ),
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
            }
            None => {
                lines.push(Line::from(Span::styled(
                    format!("{marker}Join without it — send an open request"),
                    style,
                )));
                lines.push(Line::styled(
                    "    The community reviews and approves the request manually.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
            }
        }

        // Why a paste was refused (bad JSON / wrong community / expired). Without
        // this the row simply never appears and the paste looks like it worked.
        for msg in &state.messages {
            if let crate::state_handler::setup_sequence::MessageType::Error(err) = msg {
                lines.push(Line::default());
                lines.push(Line::styled(
                    format!("ERROR: {err}"),
                    Style::new().fg(crate::colors::COLOR_WARNING_ACCESSIBLE_RED),
                ));
            }
        }

        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled("[↑/↓]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" select   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" choose   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" cancel", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));

        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);

        let bottom_line = Line::from(vec![
            Span::styled("[F10]", Style::new().fg(COLOR_ORANGE).bold()),
            Span::styled(" to quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]);
        frame.render_widget(
            Paragraph::new(bottom_line).block(Block::new().padding(Padding::new(2, 0, 1, 0))),
            bottom,
        );
    }
}

/// The vetting held, in words: "2 vetting statements", or "PCS ZKP proof
/// from 2 vetter attestations".
fn vetting_words(vetting: &crate::state_handler::join::VettingInHand) -> String {
    let plural = if vetting.count == 1 { "" } else { "s" };
    if vetting.hidden {
        format!(
            "zero-knowledge (PCS ZKP) proof from {} vetter attestation{plural}",
            vetting.count
        )
    } else {
        format!("{} vetting statement{plural}", vetting.count)
    }
}

#[cfg(test)]
mod tests {
    //! Key-routing tests for the invitation-choice page. `Action` derives neither
    //! `PartialEq` nor `Debug`, so assertions pattern-match the variant.
    use super::*;
    use crate::state_handler::{
        join::{AvailableVic, JoinPage, JoinState},
        state::State,
    };
    use crate::ui::component::Component;
    use crossterm::event::KeyModifiers;
    use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

    fn vic(id: &str) -> AvailableVic {
        AvailableVic {
            id: id.to_string(),
            subject: Some("did:webvh:alice".to_string()),
            valid_from: "2026-06-01T00:00:00Z".to_string(),
            valid_until: "2026-12-01T00:00:00Z".to_string(),
            body: serde_json::json!({ "id": id }),
        }
    }

    fn flow_with(mutate: impl FnOnce(&mut JoinState)) -> (JoinFlow, UnboundedReceiver<Action>) {
        let (tx, rx) = unbounded_channel();
        let mut state = State::default();
        state.join.page = JoinPage::InvitationChoice;
        state.join.invitation_options = vec![vic("urn:uuid:one")];
        mutate(&mut state.join);
        (JoinFlow::new(&state, tx), rx)
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn drawn(state: &JoinState) -> String {
        use ratatui::{Terminal, backend::TestBackend};
        let (width, height) = (160u16, 40u16);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|frame| InvitationChoice.render(state, frame))
            .expect("render");
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(width as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Holding vetting, joining without an invitation is not an open request:
    /// the page says the statements go either way and how the community
    /// decides on them, instead of promising a manual review.
    #[test]
    fn with_vetting_in_hand_the_invitation_is_optional_on_top() {
        use crate::state_handler::join::VettingInHand;
        let state = JoinState {
            vetting_in_hand: Some(VettingInHand {
                count: 2,
                hidden: false,
                decision: Some("meeting its vetting requirements admits you automatically".into()),
            }),
            ..JoinState::default()
        };
        let page = drawn(&state);
        assert!(page.contains("Also present an invitation?"), "{page}");
        assert!(
            page.contains("Your 2 vetting statements go with this request"),
            "{page}"
        );
        assert!(
            page.contains("with your 2 vetting statements only"),
            "{page}"
        );
        assert!(page.contains("admits you automatically"), "{page}");
        assert!(
            !page.contains("reviews and approves the request manually"),
            "{page}"
        );

        // Without vetting, it is the open request it always was.
        let plain = drawn(&JoinState::default());
        assert!(plain.contains("send an open request"), "{plain}");
        assert!(
            plain.contains("reviews and approves the request manually"),
            "{plain}"
        );
    }

    #[test]
    fn down_moves_toward_the_paste_row() {
        // One invitation (row 0), the paste row (1), then "without" (2).
        let (mut flow, mut rx) = flow_with(|_| {});
        InvitationChoice::handle_key_event(&mut flow, press(KeyCode::Down));
        match rx.try_recv() {
            Ok(Action::JoinInvitationSelect(1)) => {}
            _ => panic!("expected JoinInvitationSelect(1)"),
        }
    }

    #[test]
    fn down_clamps_at_the_without_row() {
        let (mut flow, mut rx) = flow_with(|js| js.invitation_use_selected = 2);
        InvitationChoice::handle_key_event(&mut flow, press(KeyCode::Down));
        match rx.try_recv() {
            // len == 1, so rows are 0 (the VIC), 1 (paste), 2 ("without").
            Ok(Action::JoinInvitationSelect(2)) => {}
            _ => panic!("expected JoinInvitationSelect(2)"),
        }
    }

    #[test]
    fn the_paste_row_is_reachable_with_no_invitations() {
        // The empty-list case is the whole point of the step being unconditional:
        // row 0 must be the paste row, not "join without it".
        let (mut flow, mut rx) = flow_with(|js| js.invitation_options.clear());
        assert_eq!(flow.props.state.invitation_paste_row(), 0);
        assert_eq!(flow.props.state.invitation_without_row(), 1);
        InvitationChoice::handle_key_event(&mut flow, press(KeyCode::Down));
        match rx.try_recv() {
            Ok(Action::JoinInvitationSelect(1)) => {}
            _ => panic!("expected JoinInvitationSelect(1)"),
        }
    }

    #[test]
    fn a_pasted_credential_is_offered_as_an_invitation() {
        // Bracketed paste on this page is the SSH-safe half of the paste row: it
        // must reach the handler as a VIC, not be swallowed as a keystroke.
        let (mut flow, mut rx) = flow_with(|_| {});
        flow.handle_paste_event("  {\"id\":\"urn:uuid:two\"}  ");
        match rx.try_recv() {
            Ok(Action::JoinPasteVic(text)) => assert_eq!(text, "{\"id\":\"urn:uuid:two\"}"),
            _ => panic!("expected JoinPasteVic"),
        }
    }

    #[test]
    fn enter_chooses_the_highlight() {
        let (mut flow, mut rx) = flow_with(|_| {});
        InvitationChoice::handle_key_event(&mut flow, press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::JoinInvitationChoose) => {}
            _ => panic!("expected JoinInvitationChoose"),
        }
    }

    #[test]
    fn esc_cancels_the_flow() {
        let (mut flow, mut rx) = flow_with(|_| {});
        InvitationChoice::handle_key_event(&mut flow, press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::JoinCancel) => {}
            _ => panic!("expected JoinCancel"),
        }
    }
}
