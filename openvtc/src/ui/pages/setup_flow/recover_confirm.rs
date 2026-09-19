//! What recovering this Trust Context would restore — and what it would not.
//!
//! Reached from [`SetupPage::ContextOccupied`] with `[R]`. Nothing has been
//! written when this page appears: [`openvtc_core::rebuild::plan`] only lists
//! and verifies,
//! and `rebuild_apply::apply` is pure. The write happens when the operator
//! confirms here, and not before (D5).
//!
//! # Why the gaps are as prominent as the wins
//!
//! The page shows what comes back *and* what does not, at the same weight. A
//! user who expects their contacts and relationships to reappear and finds them
//! missing will conclude the recovery failed — and may re-run setup, which is
//! the one thing that would make it worse. Naming the gap up front is the
//! difference between a partial recovery and an apparently broken one.
//!
//! Rejected credentials and skipped personas are shown for the same reason: the
//! rebuild refuses to silently drop or silently trust, so anything it could not
//! use is named here where the decision is being made.

use crate::{
    colors::{
        COLOR_BORDER, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
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
pub struct RecoverConfirm;

impl RecoverConfirm {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        // Nothing to confirm until the plan has arrived, and nothing to confirm
        // if it failed or found nothing usable — Enter must not silently do
        // nothing on a page that looks ready.
        let can_confirm = state
            .props
            .state
            .vta
            .rebuild
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .is_some_and(|o| !o.account.account.personas.is_empty());

        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Esc | KeyCode::Char('b') | KeyCode::Char('B') => {
                state.props.state.active_page = SetupPage::ContextOccupied;
            }
            KeyCode::Enter if can_confirm => {
                let result = navigate(SetupEvent::RecoverConfirmed, &state.props.state);
                handle_nav_result(result, state);
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame<'_>) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        let body = Style::new().fg(COLOR_TEXT_DEFAULT);
        let dim = Style::new().fg(COLOR_BORDER);
        let mut lines: Vec<Line> = Vec::new();
        let mut ready = false;

        match state.vta.rebuild.as_ref() {
            None => {
                lines.push(Line::styled(
                    "Working out what this context holds…",
                    Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                ));
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Reading the context's identities, keys and credentials. \
                     Nothing is being written.",
                    body,
                ));
            }
            Some(Err(reason)) => {
                lines.push(Line::styled(
                    "This context could not be read",
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
                ));
                lines.push(Line::default());
                lines.push(Line::styled(reason.clone(), body));
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Nothing has been changed. Go back and choose a different context, \
                     or check that this VTA still grants you access to it.",
                    body,
                ));
            }
            Some(Ok(outcome)) => {
                let account = &outcome.account;
                if account.account.personas.is_empty() {
                    lines.push(Line::styled(
                        "Nothing here can be recovered",
                        Style::new().fg(COLOR_ORANGE).bold(),
                    ));
                    lines.push(Line::default());
                    lines.push(Line::styled(
                        "The context holds identities, but none of their keys could be \
                         matched, so none of them could sign or receive messages. \
                         Recovering would produce an account that does not work.",
                        body,
                    ));
                } else {
                    ready = true;
                    lines.push(Line::styled(
                        "Ready to recover this account",
                        Style::new().fg(COLOR_SUCCESS).bold(),
                    ));
                    lines.push(Line::default());
                    lines.push(Line::from(vec![
                        Span::styled("  Restores  ", dim),
                        Span::styled(account.summary(), body),
                    ]));

                    lines.push(Line::default());
                    lines.push(Line::styled("This will NOT bring back", dim.bold()));
                    for gap in openvtc_core::rebuild::RebuildPlan::known_gaps() {
                        lines.push(Line::from(vec![
                            Span::styled("  • ", dim),
                            Span::styled((*gap).to_string(), body),
                        ]));
                    }
                }

                // Anything the rebuild could not use is named here, where the
                // decision is being made — never dropped quietly.
                if !account.skipped.is_empty() {
                    lines.push(Line::default());
                    lines.push(Line::styled("Identities that cannot be used", dim.bold()));
                    for s in &account.skipped {
                        lines.push(Line::from(vec![
                            Span::styled("  • ", dim),
                            Span::styled(
                                format!(
                                    "{} — {}",
                                    openvtc_core::display::shorten_for_display(&s.did, 44),
                                    s.reason.summary()
                                ),
                                Style::new().fg(COLOR_ORANGE),
                            ),
                        ]));
                    }
                }

                if !outcome.plan.rejected.is_empty() {
                    lines.push(Line::default());
                    lines.push(Line::styled("Credentials that did not verify", dim.bold()));
                    for r in outcome.plan.rejected.iter().take(4) {
                        lines.push(Line::from(vec![
                            Span::styled("  • ", dim),
                            Span::styled(
                                format!(
                                    "{} — {}",
                                    r.id.as_deref().unwrap_or("(unnamed credential)"),
                                    r.reason.summary()
                                ),
                                Style::new().fg(COLOR_ORANGE),
                            ),
                        ]));
                    }
                    if outcome.plan.rejected.len() > 4 {
                        lines.push(Line::styled(
                            format!("    … and {} more", outcome.plan.rejected.len() - 4),
                            dim,
                        ));
                    }
                }
            }
        }

        lines.push(Line::default());
        lines.push(Line::styled(
            if ready {
                "Nothing has been written yet. Press [ENTER] to recover."
            } else {
                "Nothing has been written."
            },
            dim,
        ));

        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(Block::new().padding(Padding::new(2, 2, 1, 0))),
            middle,
        );

        let mut footer = Vec::new();
        if ready {
            footer.push(Span::styled("[ENTER]", dim.bold()));
            footer.push(Span::styled(" recover  |  ", body));
        }
        footer.push(Span::styled("[B]", dim.bold()));
        footer.push(Span::styled(" back  |  ", body));
        footer.push(Span::styled("[F10]", dim.bold()));
        footer.push(Span::styled(" to quit", body));

        frame.render_widget(
            Paragraph::new(Line::from(footer))
                .block(Block::new().padding(Padding::new(2, 0, 1, 0))),
            bottom,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::setup_sequence::RebuildOutcome;
    use openvtc_core::{
        rebuild::{
            RebuildPlan, RebuiltMembership, RebuiltPersona, RejectedCredential, RejectionReason,
        },
        rebuild_apply::{self, KeyCandidate, KeyPurposeHint},
    };
    use ratatui::{Terminal, backend::TestBackend};

    const ALICE: &str = "did:webvh:QmA:example.com:alice";
    const VTC: &str = "did:webvh:QmV:vtc.example.com:acme";

    fn outcome(personas: usize, rejected: usize) -> RebuildOutcome {
        let plan = RebuildPlan {
            top_context_id: "openvtc".to_string(),
            personas: (0..personas)
                .map(|i| RebuiltPersona {
                    did: format!("{ALICE}{i}"),
                    context_id: "openvtc".to_string(),
                    mediator_did: None,
                })
                .collect(),
            memberships: (0..personas)
                .map(|i| RebuiltMembership {
                    vtc_did: VTC.to_string(),
                    persona_did: format!("{ALICE}{i}"),
                    credential: serde_json::json!({ "id": format!("vmc-{i}") }),
                })
                .collect(),
            rejected: (0..rejected)
                .map(|i| RejectedCredential {
                    id: Some(format!("bad-{i}")),
                    reason: RejectionReason::Expired {
                        valid_until: "2020-01-01T00:00:00Z".to_string(),
                    },
                })
                .collect(),
            other_credential_count: 0,
        };
        let keys: Vec<KeyCandidate> = (0..personas)
            .flat_map(|i| {
                [
                    KeyCandidate {
                        key_id: format!("{ALICE}{i}#key-0"),
                        label: None,
                        key_type: KeyPurposeHint::Signing,
                        created_at: chrono::Utc::now(),
                    },
                    KeyCandidate {
                        key_id: format!("{ALICE}{i}#key-1"),
                        label: None,
                        key_type: KeyPurposeHint::Encryption,
                        created_at: chrono::Utc::now(),
                    },
                ]
            })
            .collect();
        let account = rebuild_apply::apply(&plan, &keys, chrono::Utc::now());
        RebuildOutcome { plan, account }
    }

    fn state_with(rebuild: Option<Result<RebuildOutcome, String>>) -> SetupState {
        let mut state = SetupState {
            active_page: SetupPage::RecoverConfirm,
            ..Default::default()
        };
        state.vta.context_id = Some("openvtc".to_string());
        state.vta.rebuild = rebuild;
        state
    }

    fn flat(state: &SetupState) -> String {
        let width = 100u16;
        let mut terminal = Terminal::new(TestBackend::new(width, 44)).expect("terminal");
        terminal
            .draw(|frame| RecoverConfirm.render(state, frame))
            .expect("render");
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(width as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The page must be explicit that nothing has happened yet — this is a
    /// confirmation, and the write comes after it (D5).
    #[test]
    fn every_state_says_nothing_has_been_written() {
        for s in [
            state_with(None),
            state_with(Some(Err("refused".to_string()))),
            state_with(Some(Ok(outcome(1, 0)))),
            state_with(Some(Ok(outcome(0, 0)))),
        ] {
            let text = flat(&s);
            assert!(
                text.contains("Nothing has been written")
                    || text.contains("Nothing is being written"),
                "{text}"
            );
        }
    }

    /// The gaps carry the same weight as the wins. A user who expects contacts
    /// back and does not get them concludes the recovery failed.
    #[test]
    fn a_ready_plan_shows_both_what_returns_and_what_does_not() {
        let text = flat(&state_with(Some(Ok(outcome(2, 0)))));
        assert!(text.contains("Ready to recover"), "{text}");
        assert!(text.contains("2 personas, 2 memberships"), "{text}");
        assert!(text.contains("will NOT bring back"), "{text}");
        assert!(text.contains("Relationships"), "{text}");
        assert!(text.contains("Contacts"), "{text}");
    }

    /// Rejected credentials are named where the decision is made, never
    /// dropped quietly.
    #[test]
    fn rejections_are_shown_with_their_reason() {
        let text = flat(&state_with(Some(Ok(outcome(1, 2)))));
        assert!(text.contains("did not verify"), "{text}");
        assert!(text.contains("bad-0"), "{text}");
        assert!(text.contains("expired"), "{text}");
    }

    #[test]
    fn many_rejections_are_capped_and_counted() {
        let text = flat(&state_with(Some(Ok(outcome(1, 9)))));
        assert!(text.contains("and 5 more"), "{text}");
    }

    /// An account whose personas cannot sign would not work. Offering to
    /// "recover" it would be a lie.
    #[test]
    fn a_plan_with_no_usable_personas_does_not_offer_to_recover() {
        let mut o = outcome(1, 0);
        o.account.account.personas.clear();
        let text = flat(&state_with(Some(Ok(o))));
        assert!(text.contains("Nothing here can be recovered"), "{text}");
        assert!(!text.contains("[ENTER] recover"), "{text}");
    }

    #[test]
    fn a_failed_plan_explains_itself_and_offers_a_way_out() {
        let text = flat(&state_with(Some(Err("access denied".to_string()))));
        assert!(text.contains("could not be read"), "{text}");
        assert!(text.contains("access denied"), "{text}");
        assert!(text.contains("different context"), "{text}");
    }

    #[test]
    fn a_pending_plan_says_it_is_working() {
        let text = flat(&state_with(None));
        assert!(text.contains("Working out"), "{text}");
        assert!(!text.contains("[ENTER] recover"), "{text}");
    }
}
