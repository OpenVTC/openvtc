//! Join flow — may the community publish your membership in its trust registry?
//!
//! A community can publish its members in a trust registry: a public record
//! that anyone can look up to check that an identity belongs to it. It does so
//! only for members who consented, and consent is the applicant's
//! `registryConsent` on the join request — approval does not give it for them.
//!
//! So this page asks, on every join, as the last thing before the request goes
//! out. The box starts unticked and only a keypress here ticks it: the answer
//! is the person's privacy decision, and nothing — the community, the persona,
//! an earlier join — is allowed to pre-fill it. The page says plainly what
//! ticking it means, and that leaving it unticked is a complete answer.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
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
    state_handler::{
        actions::Action,
        join::{JoinReview, JoinState, RegistryChoice, ReviewVetting},
    },
    ui::{badges, pages::join_flow::JoinFlow},
};

/// The opt-in, worded as the thing it permits. Shared with the tests so the
/// label on screen is the label checked.
pub(crate) const OPT_IN_LABEL: &str = "Publish my membership in this community's trust registry";

#[derive(Clone, Copy, Debug, Default)]
pub struct RegistryConsentPage;

impl RegistryConsentPage {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        if state.props.state.processing || state.props.state.registry.is_none() {
            return;
        }
        let action = match key.code {
            KeyCode::F(10) => Action::Exit,
            // Space is the checkbox key everywhere else a terminal has one.
            // No letter answers "yes": a stray `y` meant for another prompt
            // must not publish someone's membership.
            KeyCode::Char(' ') => Action::JoinRegistryToggle,
            KeyCode::Enter => Action::JoinRegistryConfirm,
            KeyCode::Esc => Action::JoinCancel,
            _ => return,
        };
        let _ = state.action_tx.send(action);
    }

    pub fn render(&self, state: &JoinState, frame: &mut Frame<'_>) {
        let [middle, bottom] = Layout::vertical([Min(0), Length(3)]).areas(frame.area());
        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Review and send "),
            middle,
        );
        let inner = middle.inner(Margin::new(3, 2));
        let lines = match state.registry.as_ref() {
            Some(choice) => lines(choice),
            None => vec![Line::styled(
                "Nothing to decide.",
                Style::new().fg(COLOR_DARK_GRAY),
            )],
        };
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        frame.render_widget(
            Paragraph::new(Line::styled(
                "Space tick / untick   Enter continue and send the request   Esc cancel",
                Style::new().fg(COLOR_DARK_GRAY),
            ))
            .block(Block::bordered().fg(COLOR_BORDER)),
            bottom,
        );
    }
}

/// What the request will carry, before anything about publication: the
/// person reads what they are sending, then decides the one thing still open.
///
/// Vetting gets the most words because it is where the two kinds of community
/// differ most for the people who vouched: named statements put each vetter's
/// DID in front of the community, a PCS zero-knowledge proof does not.
fn review_lines(community: &str, review: &JoinReview) -> Vec<Line<'static>> {
    let label =
        |text: &str| Span::styled(format!("  {text:<17}"), Style::new().fg(COLOR_DARK_GRAY));
    let value = |text: String| Span::styled(text, Style::new().fg(COLOR_TEXT_DEFAULT));
    let mut lines = vec![
        Line::styled(
            format!("What {community} will receive"),
            Style::new().fg(COLOR_BORDER).bold(),
        ),
        Line::from(vec![label("Your identity"), value(review.persona.clone())]),
        Line::from(vec![
            label("Invitation"),
            value(
                review
                    .invitation
                    .clone()
                    .unwrap_or_else(|| "none".to_string()),
            ),
        ]),
    ];
    match &review.vetting {
        ReviewVetting::None => {
            lines.push(Line::from(vec![
                label("Vetting"),
                value("none".to_string()),
            ]));
        }
        ReviewVetting::Hidden { attestations } => {
            lines.push(Line::from(vec![
                label("Vetting"),
                badges::pcs_zkp(),
                value(format!(
                    "  a zero-knowledge proof built from {attestations} vetter attestation{}",
                    if *attestations == 1 { "" } else { "s" }
                )),
            ]));
            lines.push(Line::from(vec![
                label(""),
                Span::styled(
                    "it learns that enough vetters vouched for you — not who they were",
                    Style::new().fg(COLOR_SOFT_PURPLE),
                ),
            ]));
        }
        ReviewVetting::Named(statements) => {
            lines.push(Line::from(vec![
                label("Vetting"),
                value(format!(
                    "{} named statement{} — it sees who vouched for you",
                    statements.len(),
                    if statements.len() == 1 { "" } else { "s" }
                )),
            ]));
            for statement in statements {
                lines.push(Line::from(vec![
                    label(""),
                    Span::styled(format!("• {statement}"), Style::new().fg(COLOR_SOFT_PURPLE)),
                ]));
            }
        }
    }
    if review.face.is_empty() {
        lines.push(Line::from(vec![
            label("Your face sends"),
            value("nothing".to_string()),
        ]));
    } else {
        for (i, (claim, shown)) in review.face.iter().enumerate() {
            lines.push(Line::from(vec![
                label(if i == 0 { "Your face sends" } else { "" }),
                Span::styled(format!("{claim}  "), Style::new().fg(COLOR_DARK_GRAY)),
                value(shown.clone()),
            ]));
        }
    }
    if let Some(decision) = &review.decision {
        lines.push(Line::from(vec![
            label("How it decides"),
            value(decision.clone()),
        ]));
    }
    lines.push(Line::default());
    lines
}

/// The page body. Separate from `render` so it is testable as text.
pub(crate) fn lines(choice: &RegistryChoice) -> Vec<Line<'static>> {
    let community = choice
        .community_name
        .clone()
        .unwrap_or_else(|| "this community".to_string());
    let mut body = choice
        .review
        .as_ref()
        .map(|r| review_lines(&community, r))
        .unwrap_or_default();
    let (mark, mark_style) = if choice.publish {
        ("[x]", Style::new().fg(COLOR_SUCCESS).bold())
    } else {
        ("[ ]", Style::new().fg(COLOR_TEXT_DEFAULT).bold())
    };
    body.extend([
        Line::from(vec![
            Span::styled("Joining ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled(community.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
        ]),
        Line::styled(choice.community.clone(), Style::new().fg(COLOR_DARK_GRAY)),
        Line::default(),
        Line::styled(
            "A community can keep a trust registry: a public record that anyone can look up \
             to check that an identity is one of its members.",
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ),
        Line::default(),
        Line::styled(
            "If you tick this and you are admitted, the community may publish a public record \
             that the identity you join with is a member. Anyone will be able to see it.",
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ),
        Line::styled(
            "If you leave it unticked, you have not consented, and the community will not \
             publish your membership. Being admitted does not change that.",
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ),
        Line::default(),
        Line::styled(
            "This is your decision, not the community's. Ticking it permits publication; the \
             community may still choose not to publish.",
            Style::new().fg(COLOR_DARK_GRAY),
        ),
        Line::styled(
            "OpenVTC cannot change this answer once you have joined — today only leaving and \
             joining again can.",
            Style::new().fg(COLOR_DARK_GRAY),
        ),
        Line::default(),
        Line::from(vec![
            Span::styled(format!("  {mark} "), mark_style),
            Span::styled(OPT_IN_LABEL, Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]),
    ]);
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::join::IdentityPick;
    use crossterm::event::KeyModifiers;
    use tokio::sync::mpsc::unbounded_channel;

    fn choice(publish: bool) -> RegistryChoice {
        RegistryChoice {
            publish,
            community: "did:webvh:QmScid:vtc.example".into(),
            community_name: None,
            confirmed: false,
            parked: Some((
                IdentityPick::Mint,
                "did:webvh:QmScid:vtc.example".into(),
                "acct/co-op".into(),
            )),
            review: None,
        }
    }

    /// The review says what the community receives before the publication
    /// question — and for vetting, whether it learns who vouched.
    #[test]
    fn the_review_says_what_the_community_receives_and_who_it_learns_vouched() {
        let with = |vetting| RegistryChoice {
            review: Some(JoinReview {
                persona: "did:webvh:QmP:persona".into(),
                invitation: None,
                vetting,
                face: vec![("name.legal".into(), "Alice Example".into())],
                decision: Some("meeting its vetting requirements admits you automatically".into()),
            }),
            ..choice(false)
        };
        let named = text(&with(ReviewVetting::Named(vec![
            "did:key:zVetter — vetted you in person, checking your legal name, valid until 1 Feb 2027"
                .into(),
        ])));
        assert!(
            named.contains("What this community will receive"),
            "{named}"
        );
        assert!(named.contains("did:webvh:QmP:persona"), "{named}");
        assert!(
            named.contains("1 named statement — it sees who vouched for you"),
            "{named}"
        );
        assert!(
            named.contains("did:key:zVetter — vetted you in person"),
            "{named}"
        );
        assert!(named.contains("name.legal  Alice Example"), "{named}");
        assert!(named.contains("admits you automatically"), "{named}");
        // The review comes first; the publication question is still there after it.
        assert!(
            named.find("will receive") < named.find(OPT_IN_LABEL),
            "{named}"
        );

        let hidden = text(&with(ReviewVetting::Hidden { attestations: 2 }));
        assert!(hidden.contains("PCS ZKP"), "{hidden}");
        assert!(hidden.contains("not who they were"), "{hidden}");
        assert!(!hidden.contains("sees who vouched"), "{hidden}");
    }

    fn text(choice: &RegistryChoice) -> String {
        lines(choice)
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The page says what ticking the box means — a public record that this
    /// identity is a member — and what leaving it means, before it is ticked.
    #[test]
    fn the_page_states_plainly_what_publishing_means() {
        let shown = text(&choice(false));
        assert!(shown.contains("public record"), "{shown}");
        assert!(shown.contains("is a member"), "{shown}");
        assert!(
            shown.contains("will not publish your membership"),
            "{shown}"
        );
        assert!(
            shown.contains(&format!("[ ] {OPT_IN_LABEL}")),
            "unticked when opened: {shown}"
        );
    }

    #[test]
    fn a_ticked_box_shows_ticked() {
        let shown = text(&choice(true));
        assert!(shown.contains(&format!("[x] {OPT_IN_LABEL}")), "{shown}");
    }

    /// Space toggles and Enter confirms; no letter key answers yes, so a stray
    /// keystroke cannot publish a membership.
    #[test]
    fn only_space_toggles_and_enter_confirms() {
        let (tx, mut rx) = unbounded_channel();
        let mut state = crate::state_handler::state::State::default();
        state.join.registry = Some(choice(false));
        let mut flow = <JoinFlow as crate::ui::component::Component>::new(&state, tx);
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        for c in ['y', 'Y', 'p', 'x'] {
            RegistryConsentPage::handle_key_event(&mut flow, press(KeyCode::Char(c)));
        }
        assert!(rx.try_recv().is_err(), "no letter answers the question");

        RegistryConsentPage::handle_key_event(&mut flow, press(KeyCode::Char(' ')));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinRegistryToggle)));
        RegistryConsentPage::handle_key_event(&mut flow, press(KeyCode::Enter));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinRegistryConfirm)));
    }
}
