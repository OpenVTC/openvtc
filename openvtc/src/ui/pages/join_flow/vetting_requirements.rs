//! Join flow — what a vetting community asks, and the ways in it leaves open.
//!
//! Shown after the community's DID when that community vets its members
//! (`docs/design/vetting-process.md` §6.1, §12.3). It says in plain words what
//! the community requires before anything about the applicant is sent, and
//! then lists every way in at once — present an invitation, be vetted, or send
//! an open request — each said to be available or not, and why.
//!
//! Listing them together is the point. Which way in is open depends on the
//! community's manifest *and* on what this account already holds, and neither
//! is knowable before the community has been asked; walking one path and
//! leaving the rest to be found later is how an applicant ends up sending an
//! open request while holding an invitation that would have admitted them.
//!
//! While the community is still being asked, this page is drawn by the runtime
//! loop rather than the join flow, because that loop is the one that hears the
//! answer. So only the two keys that loop handles are offered then: join
//! without waiting, and cancel.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crossterm::event::{KeyCode, KeyEvent};
use openvtc_core::config::community_context::ContextOption;
use openvtc_core::display::display_identifier;
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

use crate::state_handler::{
    actions::Action,
    join::{JoinState, JoinVettingView, KnownVetting, VettingPhase},
    setup_sequence::MessageType,
};
use crate::ui::pages::join_flow::JoinFlow;
use crate::ui::pages::main::components::vetting_panel::accent_swatch;

/// Width of the routes list's label column, so the details line up under each
/// other rather than under whichever label happened to be longest.
const LABEL_WIDTH: usize = 30;

#[derive(Clone, Debug, Default)]
pub struct VettingPage;

impl VettingPage {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        if state.props.state.processing {
            return;
        }
        let Some(view) = &state.props.state.vetting else {
            if key.code == KeyCode::Esc {
                let _ = state.action_tx.send(Action::JoinCancel);
            }
            return;
        };
        let action = match (&view.phase, key.code) {
            (_, KeyCode::F(10)) => Action::Exit,
            (_, KeyCode::Esc) => Action::JoinCancel,
            (_, KeyCode::Char('j' | 'J')) => Action::JoinVettingJoin,
            // Asking again needs a loop that can hear the answer. The State-A
            // loop cannot, so there the key is not offered at all rather than
            // offered and silently ineffective.
            (
                VettingPhase::Unknown { can_retry, .. },
                KeyCode::Enter | KeyCode::Char('r' | 'R'),
            ) if *can_retry => Action::JoinVettingAskAgain,
            (VettingPhase::Known(_), KeyCode::Enter) => Action::JoinVettingTake,
            (VettingPhase::Known(_), KeyCode::Char('a' | 'A')) => Action::JoinVettingApply,
            (VettingPhase::Known(_), KeyCode::Up | KeyCode::BackTab) => {
                Action::JoinVettingRow(false)
            }
            (VettingPhase::Known(_), KeyCode::Down | KeyCode::Tab) => Action::JoinVettingRow(true),
            (VettingPhase::Known(_), KeyCode::Left) => Action::JoinVettingCycle(false),
            (VettingPhase::Known(_), KeyCode::Right) => Action::JoinVettingCycle(true),
            _ => return,
        };
        let _ = state.action_tx.send(action);
    }

    pub fn render(&self, state: &JoinState, frame: &mut Frame<'_>) {
        let [middle, bottom] = Layout::vertical([Min(0), Length(3)]).areas(frame.area());
        let Some(view) = &state.vetting else {
            return;
        };
        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(format!(" Joining {} ", view.name)),
            middle,
        );
        let inner = middle.inner(Margin::new(3, 2));
        frame.render_widget(
            Paragraph::new(body_lines(state, view)).wrap(Wrap { trim: false }),
            inner,
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]))
            .block(Block::new().padding(Padding::new(2, 0, 1, 0))),
            bottom,
        );
    }
}

fn text() -> Style {
    Style::new().fg(COLOR_TEXT_DEFAULT)
}

fn dim() -> Style {
    Style::new().fg(COLOR_DARK_GRAY)
}

fn keys(pairs: &[(&str, &str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (key, what) in pairs {
        spans.push(Span::styled(
            format!("[{key}]"),
            Style::new().fg(COLOR_BORDER).bold(),
        ));
        spans.push(Span::styled(format!(" {what}   "), text()));
    }
    Line::from(spans)
}

fn cursor(focused: bool) -> Span<'static> {
    Span::styled(
        if focused { "▸ " } else { "  " },
        Style::new().fg(COLOR_SUCCESS).bold(),
    )
}

fn choice(name: &str, shown: String, focused: bool) -> Line<'static> {
    Line::from(vec![
        cursor(focused),
        Span::styled(format!("{name:<10}"), text()),
        Span::styled(shown, Style::new().fg(COLOR_SOFT_PURPLE)),
        Span::styled(if focused { "  ←/→" } else { "" }, dim()),
    ])
}

/// The routes list: every way in, available or not.
///
/// A blocked route keeps its row and reads dim, with the reason where its
/// detail would be. Dropping it would leave "why can I not use my invitation?"
/// unanswered — and the answer ("you hold none", "this community admits nobody
/// that way") is exactly what the page exists to give.
fn route_lines(known: &KnownVetting) -> Vec<Line<'static>> {
    known
        .routes
        .iter()
        .enumerate()
        .map(|(i, option)| {
            let focused = known.row == i;
            let (label_style, detail_style, detail) = match &option.blocked {
                Some(why) => (dim(), dim(), why.clone()),
                None => (
                    text().bold(),
                    Style::new().fg(COLOR_SOFT_PURPLE),
                    option.detail.clone(),
                ),
            };
            Line::from(vec![
                cursor(focused),
                Span::styled(format!("{:<LABEL_WIDTH$}", option.label), label_style),
                Span::styled(detail, detail_style),
            ])
        })
        .collect()
}

/// The page's lines, below its border.
pub(crate) fn body_lines(state: &JoinState, view: &JoinVettingView) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match &view.phase {
        VettingPhase::Asking => {
            lines.push(Line::from(vec![
                accent_swatch(view.accent),
                Span::styled(
                    format!("Asking {} what it requires before you join…", view.name),
                    Style::new().fg(COLOR_ORANGE).bold(),
                ),
            ]));
            lines.push(Line::default());
            lines.push(Line::styled(
                "This takes a few seconds and gives up after 15. The question comes from your \
                 active persona; nothing else about you is sent.",
                dim(),
            ));
            lines.push(Line::default());
            lines.push(keys(&[("J", "join without waiting"), ("ESC", "cancel")]));
        }
        VettingPhase::Unknown { reason, can_retry } => {
            lines.push(Line::from(vec![
                accent_swatch(view.accent),
                Span::styled(
                    format!(
                        "Could not learn whether {} vets the people who join — {reason}.",
                        view.name
                    ),
                    Style::new().fg(COLOR_ORANGE),
                ),
            ]));
            lines.push(Line::default());
            lines.push(Line::styled(
                "If it does, a request that arrives without vetting statements goes to its \
                 moderators to decide.",
                dim(),
            ));
            // What this account holds is knowable even when the community is
            // not, and it changes what joining now means.
            let held = state.available_vics.len();
            if held > 0 {
                lines.push(Line::styled(
                    format!(
                        "You hold {held} invitation{} from this community; joining now offers \
                         {} to it.",
                        if held == 1 { "" } else { "s" },
                        if held == 1 { "it" } else { "one" },
                    ),
                    Style::new().fg(COLOR_SUCCESS),
                ));
            }
            lines.push(Line::default());
            let mut offered = Vec::new();
            if *can_retry {
                offered.push(("ENTER/R", "ask again"));
            }
            offered.push(("J", "join anyway"));
            offered.push(("ESC", "cancel"));
            lines.push(keys(&offered));
        }
        VettingPhase::Known(known) => {
            lines.push(Line::from(vec![
                accent_swatch(view.accent),
                Span::styled(view.name.clone(), text().bold()),
                Span::styled(" vets the people who join.", text()),
            ]));
            lines.push(Line::default());
            lines.push(Line::styled(
                "Before it admits you, it asks for:",
                Style::new().fg(COLOR_BORDER).bold(),
            ));
            for requirement in &known.requirements {
                lines.push(Line::styled(
                    format!("  • {requirement}"),
                    Style::new().fg(COLOR_SOFT_PURPLE),
                ));
            }
            if let Some(url) = &known.governance_url {
                lines.push(Line::styled(format!("How it decides: {url}"), dim()));
            }
            lines.push(Line::default());
            lines.push(Line::styled(
                format!(
                    "Nothing about you has been sent to {}. Each vetter sees the card you show \
                     them; the community sees only their statements.",
                    view.name
                ),
                dim(),
            ));
            lines.push(Line::default());
            lines.push(Line::styled(
                "Your ways in",
                Style::new().fg(COLOR_BORDER).bold(),
            ));
            lines.extend(route_lines(known));

            if known.shows_selectors() {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Applying as",
                    Style::new().fg(COLOR_BORDER).bold(),
                ));
                let persona = known.personas.get(known.persona_index).map_or_else(
                    || "no persona yet — create one under My Identity".to_string(),
                    |p| format!("{}  ({})", p.label, p.did),
                );
                lines.push(choice("Apply as", persona, known.selector() == Some(0)));
                let context = known
                    .context_options
                    .get(known.context_index)
                    .map_or_else(|| "—".to_string(), ContextOption::summary);
                lines.push(choice("Context", context, known.selector() == Some(1)));
                lines.push(Line::styled(
                    "The persona is fixed for the whole application: every card is signed by it, \
                     and it is the DID the community admits.",
                    dim(),
                ));
            } else if let Some(app) = &known.application {
                lines.push(Line::default());
                lines.push(Line::styled(
                    format!(
                        "Your application, as {} — next: {}",
                        app.persona_label, app.next_step
                    ),
                    Style::new().fg(COLOR_SUCCESS),
                ));
            }
            lines.push(Line::default());
            lines.push(keys(&[
                ("↑/↓", "choose"),
                ("ENTER", "take it"),
                ("A", "open the application"),
                ("J", "join now"),
                ("ESC", "cancel"),
            ]));
        }
    }
    // The DID under the name, so the community being joined is never only a
    // name it gave itself.
    if !lines.is_empty() {
        lines.insert(
            1,
            Line::styled(
                display_identifier(None, &view.community, 96).into_owned(),
                dim(),
            ),
        );
    }
    for message in &state.messages {
        if let MessageType::Error(error) = message {
            lines.push(Line::default());
            lines.push(Line::styled(
                error.clone(),
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
            ));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::join::{
        AvailableVic, JoinApplication, JoinPage, JoinRoute, RouteOption,
    };
    use crate::state_handler::state::State;
    use crate::ui::component::Component;
    use crossterm::event::KeyModifiers;
    use openvtc_core::config::account::PersonaId;
    use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

    fn view(phase: VettingPhase) -> JoinVettingView {
        JoinVettingView {
            community: "did:web:kernel".into(),
            name: "Kernel".into(),
            accent: Some((0x33, 0x66, 0x99)),
            phase,
        }
    }

    fn route(route: JoinRoute, label: &str, blocked: Option<&str>) -> RouteOption {
        RouteOption {
            route,
            label: label.into(),
            detail: "detail".into(),
            blocked: blocked.map(Into::into),
        }
    }

    fn routes() -> Vec<RouteOption> {
        vec![
            route(
                JoinRoute::Invitation,
                "Use an invitation",
                Some("none held"),
            ),
            route(JoinRoute::Vetting, "Apply for vetting", None),
            route(JoinRoute::OpenRequest, "Send an open request", None),
        ]
    }

    fn known(satisfied: Option<bool>) -> VettingPhase {
        VettingPhase::Known(Box::new(KnownVetting {
            requirements: vec!["2 vetting statements".into()],
            routes: routes(),
            row: 1,
            application: satisfied.map(|satisfied| JoinApplication {
                id: "a1".into(),
                persona: PersonaId::new(),
                persona_label: "alice".into(),
                statements: 2,
                progress: None,
                next_step: "join".into(),
                satisfied,
            }),
            ..KnownVetting::default()
        }))
    }

    fn flow(phase: VettingPhase) -> (JoinFlow, UnboundedReceiver<Action>) {
        let (tx, rx) = unbounded_channel();
        let mut state = State::default();
        state.join.page = JoinPage::Vetting;
        state.join.vetting = Some(view(phase));
        (JoinFlow::new(&state, tx), rx)
    }

    fn press(flow: &mut JoinFlow, code: KeyCode) {
        VettingPage::handle_key_event(flow, KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn text_of(lines: &[Line<'_>]) -> String {
        lines
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

    #[test]
    fn enter_takes_the_highlighted_route_whatever_it_is() {
        // One key for the list, rather than a key whose meaning depends on
        // whether an application happens to be satisfied.
        for satisfied in [None, Some(false), Some(true)] {
            let (mut f, mut rx) = flow(known(satisfied));
            press(&mut f, KeyCode::Enter);
            assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingTake)));
        }
        let (mut f, mut rx) = flow(known(None));
        press(&mut f, KeyCode::Down);
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingRow(true))));
        press(&mut f, KeyCode::Right);
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingCycle(true))));
        press(&mut f, KeyCode::Char('a'));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingApply)));
        press(&mut f, KeyCode::Char('j'));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingJoin)));
    }

    #[test]
    fn while_asking_or_unknown_only_the_ways_on_are_offered() {
        let (mut f, mut rx) = flow(VettingPhase::Asking);
        press(&mut f, KeyCode::Enter);
        assert!(rx.try_recv().is_err(), "nothing to confirm while asking");
        press(&mut f, KeyCode::Char('j'));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingJoin)));
        press(&mut f, KeyCode::Esc);
        assert!(matches!(rx.try_recv(), Ok(Action::JoinCancel)));

        let (mut f, mut rx) = flow(VettingPhase::Unknown {
            reason: "no answer".into(),
            can_retry: true,
        });
        press(&mut f, KeyCode::Char('r'));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingAskAgain)));
    }

    /// The State-A loop cannot hear an answer, so "ask again" is neither drawn
    /// nor bound — a key that can only ever fail is worse than no key.
    #[test]
    fn asking_again_is_withheld_when_no_answer_could_be_heard() {
        let phase = || VettingPhase::Unknown {
            reason: "it was not asked".into(),
            can_retry: false,
        };
        let (mut f, mut rx) = flow(phase());
        press(&mut f, KeyCode::Char('r'));
        assert!(rx.try_recv().is_err());
        press(&mut f, KeyCode::Enter);
        assert!(rx.try_recv().is_err());
        press(&mut f, KeyCode::Char('j'));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingJoin)));

        let shown = text_of(&body_lines(&JoinState::default(), &view(phase())));
        assert!(!shown.contains("ask again"));
        assert!(shown.contains("join anyway"));
    }

    #[test]
    fn the_page_says_what_is_required_and_lists_every_way_in() {
        let state = JoinState::default();
        let shown = text_of(&body_lines(&state, &view(known(Some(true)))));
        assert!(shown.contains("Kernel vets the people who join."));
        assert!(shown.contains("• 2 vetting statements"));
        assert!(shown.contains("Nothing about you has been sent"));
        assert!(shown.contains("Your ways in"));
        assert!(shown.contains("Apply for vetting"));
        assert!(shown.contains("Send an open request"));
    }

    /// A route that cannot be taken is still listed, with the reason in place
    /// of its detail: "why not?" is the question the page answers.
    #[test]
    fn a_blocked_route_keeps_its_row_and_says_why() {
        let shown = text_of(&body_lines(&JoinState::default(), &view(known(None))));
        assert!(shown.contains("Use an invitation"));
        assert!(shown.contains("none held"));
    }

    /// Held invitations are a fact about this account, so they are worth saying
    /// even when the community itself could not be reached.
    #[test]
    fn invitations_held_are_named_even_when_the_community_is_unknown() {
        let state = JoinState {
            available_vics: vec![AvailableVic {
                id: "urn:uuid:a".into(),
                subject: None,
                valid_from: String::new(),
                valid_until: String::new(),
                body: serde_json::Value::Null,
            }],
            ..JoinState::default()
        };
        let shown = text_of(&body_lines(
            &state,
            &view(VettingPhase::Unknown {
                reason: "no answer".into(),
                can_retry: true,
            }),
        ));
        assert!(shown.contains("You hold 1 invitation from this community"));
    }
}
