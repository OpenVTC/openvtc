//! Join flow — what a vetting community asks, and the ways in it leaves open.
//!
//! Shown after the community's DID when that community vets its members
//! (`docs/design/vetting-process.md` §6.1, §12.3). It says in plain words what
//! the community requires before anything about the applicant is sent, and
//! then lists every way in at once — be vetted as one of your personas or as a
//! new one, present an invitation, or send an open request — each said to be
//! available or not, and why. Each row is one whole choice: the vetting rows
//! name the persona they are taken as, because a persona's statements count
//! for that persona alone.
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
    join::{
        Applicant, JoinRoute, JoinState, JoinVettingView, KnownVetting, RouteGroup, VettingPhase,
        VettingRow,
    },
    setup_sequence::MessageType,
};
use crate::ui::badges;
use crate::ui::pages::join_flow::JoinFlow;
use crate::ui::pages::main::components::vetting_panel::accent_swatch;

/// The widest the routes list's label column grows. The column is as wide as
/// the longest label, so the details line up under each other; a persona's
/// name is part of its row's label now, and without a ceiling one long name
/// would push every detail off the right of the screen. The persona name in a
/// label is already shortened (`ROW_PERSONA_WIDTH` in the join flow), so this
/// is only ever reached by a label that is long through and through.
const MAX_LABEL_WIDTH: usize = 64;

/// How far a row sits in from its group heading.
const ROW_INDENT: usize = 2;

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
            // `j` is the only way on while the community is being asked or
            // could not be. Once the ways in are listed, one of them *is* the
            // open request, and a second key for it was a shorter, differently
            // worded copy of a row already on screen.
            // Not offered when the DID resolves to nothing: the join would
            // address a request to an identifier that names no document, no
            // endpoint and no mediator route, and then wait for an answer
            // nobody can send. The page says so in place of the key.
            (VettingPhase::Asking, KeyCode::Char('j' | 'J')) => Action::JoinVettingJoin,
            (
                VettingPhase::Unknown {
                    resolvable: true, ..
                },
                KeyCode::Char('j' | 'J'),
            ) => Action::JoinVettingJoin,
            // Asking again needs a loop that can hear the answer. The State-A
            // loop cannot, so there the key is not offered at all rather than
            // offered and silently ineffective.
            (
                VettingPhase::Unknown { can_retry, .. },
                KeyCode::Enter | KeyCode::Char('r' | 'R'),
            ) if *can_retry => Action::JoinVettingAskAgain,
            (VettingPhase::Known(_), KeyCode::Enter) => Action::JoinVettingTake,
            // Reading an application before sending it is the one thing the
            // list cannot reach, so it keeps a key — named under the row it
            // belongs to rather than in a menu at the foot of the page.
            (VettingPhase::Known(known), KeyCode::Char('a' | 'A'))
                if known.selected_application().is_some() =>
            {
                Action::JoinVettingApply
            }
            // No `n`: making a persona is a row of its own — "Apply for
            // vetting as a new persona". A key for it as well meant the page
            // offered the same thing twice in two different vocabularies.
            //
            // No ←/→ either. Each row is one complete choice, way in and
            // persona together, so there is nothing to cycle inside a row; a
            // cycled value hid the alternatives and what set them apart.
            (VettingPhase::Known(_), KeyCode::Up | KeyCode::BackTab) => {
                Action::JoinVettingRow(false)
            }
            (VettingPhase::Known(_), KeyCode::Down | KeyCode::Tab) => Action::JoinVettingRow(true),
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

/// The routes list: every way in, available or not, under its group heading.
///
/// Every row is one complete choice — the way in and, for vetting, the persona
/// it is taken as — so the alternatives and what sets them apart are all on
/// screen at once. The "Apply as" value this replaced was cycled with ←/→,
/// which hid every persona but one and let a row read one way while Enter did
/// another.
///
/// A blocked route keeps its row and reads dim, with the reason where its
/// detail would be. Dropping it would leave "why can I not use my invitation?"
/// unanswered — and the answer ("you hold none", "this community admits nobody
/// that way") is exactly what the page exists to give.
fn route_lines(known: &KnownVetting) -> Vec<Line<'static>> {
    let width = known
        .routes
        .iter()
        .map(|r| r.label.chars().count())
        .max()
        .unwrap_or(0)
        .min(MAX_LABEL_WIDTH);
    // Under the detail column: past the indent, the cursor and the label, plus
    // the one space that keeps the longest label off its own detail.
    let under = " ".repeat(ROW_INDENT + 2 + width + 1);
    let mut lines = Vec::new();
    for row in known.rows() {
        let i = match row {
            VettingRow::Heading(group) => {
                let mut spans = vec![Span::styled(
                    format!("  {}", group.heading()),
                    Style::new().fg(COLOR_BORDER),
                )];
                // A requirement on top of the statements is a fact about the
                // community, said once beside the group it bears on.
                if group == RouteGroup::Vetting
                    && let Some(note) = &known.vetting_note
                {
                    spans.push(Span::styled(format!("  — {note}"), dim()));
                }
                lines.push(Line::from(spans));
                continue;
            }
            VettingRow::Route(i) => i,
        };
        let Some(option) = known.routes.get(i) else {
            continue;
        };
        let focused = known.row == i;
        let (label_style, detail_style, detail) = match option.blocked() {
            Some(why) => (dim(), dim(), why.to_string()),
            None => (
                text().bold(),
                Style::new().fg(COLOR_SOFT_PURPLE),
                option.detail.clone(),
            ),
        };
        lines.push(Line::from(vec![
            Span::raw(" ".repeat(ROW_INDENT)),
            cursor(focused),
            Span::styled(format!("{:<w$}", option.label, w = width + 1), label_style),
            Span::styled(detail, detail_style),
        ]));
        // What taking it starts with, under the row and past the label
        // column. Phrased as what happens next rather than as a reason the row
        // is off — which is the point of it not being dim.
        if let Some(step) = option.first_step() {
            lines.push(Line::from(vec![
                Span::raw(under.clone()),
                Span::styled("First: ", Style::new().fg(COLOR_SUCCESS).bold()),
                Span::styled(step.to_string(), Style::new().fg(COLOR_SUCCESS)),
            ]));
        }
        if !focused {
            continue;
        }
        // The DID the highlighted vetting row joins as. The community admits
        // a DID, not a label, and two personas can share a label.
        if let Some(Applicant::Persona(persona)) = option.applicant
            && let Some(p) = known.personas.iter().find(|p| p.persona == persona)
        {
            lines.push(Line::from(vec![
                Span::raw(under.clone()),
                Span::styled(
                    format!(
                        "as {}",
                        openvtc_core::display::shorten_for_display(&p.did, 64)
                    ),
                    dim(),
                ),
            ]));
        }
        // The one thing this page cannot otherwise reach: reading an
        // application before presenting it. Named where it applies rather than
        // in a row of keys at the foot of the page.
        if known.selected_application().is_some() {
            lines.push(Line::from(vec![
                Span::raw(under.clone()),
                Span::styled("[a]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" read it before you send it", dim()),
            ]));
        }
    }
    lines
}

/// What this community does to protect the people in it: whether vetters are
/// hidden behind a zero-knowledge proof, and whether it signs post-quantum.
///
/// Both are said either way. A badge that only appears when present leaves its
/// absence unread, and "your vetters will be named to this community" is
/// exactly what someone asking a friend to vet them should know first.
fn protection_lines(known: &KnownVetting) -> Vec<Line<'static>> {
    let row = |label: &str, badge: Option<Span<'static>>, said: String, style: Style| {
        let mut spans = vec![Span::styled(format!("  {label:<10}"), text())];
        if let Some(badge) = badge {
            spans.push(badge);
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(said, style));
        Line::from(spans)
    };
    let mut lines = vec![Line::styled(
        "How it protects you",
        Style::new().fg(COLOR_BORDER).bold(),
    )];
    lines.push(if known.pcs_zkp {
        row(
            "Vetters",
            Some(badges::pcs_zkp()),
            badges::PCS_ZKP_MEANING.to_string(),
            Style::new().fg(COLOR_SOFT_PURPLE),
        )
    } else {
        row(
            "Vetters",
            None,
            "named — the community sees which vetters vouched for you".to_string(),
            dim(),
        )
    });
    lines.push(match known.post_quantum {
        Some(true) => row(
            "Signing",
            Some(badges::pqc()),
            "its DID lists a post-quantum key, so what it issues is signed with ML-DSA as well"
                .to_string(),
            Style::new().fg(COLOR_SOFT_PURPLE),
        ),
        Some(false) => row(
            "Signing",
            None,
            "classical keys only — not post-quantum".to_string(),
            dim(),
        ),
        None => row(
            "Signing",
            None,
            "not checked — its DID document could not be resolved".to_string(),
            dim(),
        ),
    });
    lines
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
        VettingPhase::Unknown {
            reason,
            can_retry,
            resolvable,
        } => {
            lines.push(Line::from(vec![
                accent_swatch(view.accent),
                Span::styled(
                    if *resolvable {
                        format!(
                            "Could not learn whether {} vets the people who join — {reason}.",
                            view.name
                        )
                    } else {
                        // Not the same problem at all, and it must not read as
                        // one: there is no community here to have a policy.
                        format!("Nothing answers at {} — {reason}.", view.name)
                    },
                    Style::new().fg(COLOR_ORANGE),
                ),
            ]));
            lines.push(Line::default());
            // What to do about it, which differs by why the asking stopped.
            // Without this the page states a problem and offers a key, leaving
            // the one thing the person actually wants to know — is joining now
            // a dead end? — to be guessed at.
            if !*resolvable {
                lines.push(Line::styled(
                    "That identifier does not resolve to anything, so there is no community \
                     behind it to join: a request sent to it would reach nobody and be answered \
                     by nobody. Check the DID with whoever gave it to you — a single wrong \
                     character is enough — or paste an invitation credential (VIC), which \
                     carries the community's own DID.",
                    dim(),
                ));
                lines.push(Line::default());
                lines.push(keys(&[("ESC", "go back and re-enter it")]));
                return lines;
            }
            lines.push(Line::styled(
                "If it does, a request that arrives without vetting statements goes to its \
                 moderators to decide.",
                dim(),
            ));
            lines.push(Line::default());
            if *can_retry {
                lines.push(Line::styled(
                    "Ask again if the community was only briefly unreachable. Joining anyway \
                     costs nothing you cannot recover: a request its moderators refer is still \
                     a request, and you are told what it was decided on.",
                    dim(),
                ));
            } else {
                lines.push(Line::styled(
                    "Joining anyway is the way forward here, not a last resort. It records the \
                     request and brings your messaging online — so straight afterwards this \
                     community can be asked what it requires, and if it does vet you can apply \
                     then and take this join up again from the application.",
                    dim(),
                ));
            }
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
                // Not "before it admits you": a 0.3 community may refer a
                // request that meets this to its administrators instead.
                "To decide on your request, it asks for:",
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
            lines.extend(protection_lines(known));
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
                "Choose how to join",
                Style::new().fg(COLOR_BORDER).bold(),
            ));
            lines.extend(route_lines(known));
            // Only while a vetting row is highlighted — the note is about the
            // decision being made, not a fact about the page.
            if known
                .selected_route()
                .is_some_and(|r| r.route == JoinRoute::Vetting)
            {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "The persona is fixed for the whole application: every card is signed by it, \
                     and it is the DID the community admits. Statements count only for the \
                     persona they were made for.",
                    dim(),
                ));
            }
            // Every application, not only the highlighted row's: a second
            // persona's application is a fact about this community that should
            // not go dark because the cursor moved. The next step names the
            // row it is taken from — the Vetting panel's keys mean nothing
            // here.
            for app in &known.applications {
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
            // Three keys: move, commit, leave. Every other way in used to have
            // a key of its own down here as well as a row up there, so the foot
            // of the page was a second, shorter, differently-worded menu of the
            // same choices — and one of them (`n`) contradicted the row it
            // duplicated. What a row does is the row's business now.
            lines.push(keys(&[
                ("↑/↓", "choose"),
                ("ENTER", "continue"),
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
        ApplyAs, AvailableVic, FirstStepKind, JoinApplication, JoinPage, JoinRoute, RouteOption,
        RouteState,
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

    fn route(route: JoinRoute, label: &str, state: RouteState) -> RouteOption {
        RouteOption {
            route,
            applicant: None,
            label: label.into(),
            detail: "detail".into(),
            state,
        }
    }

    /// The vetting row for `persona`, as `vetting_view` builds it.
    fn vetting_row(persona: Applicant, label: &str, state: RouteState) -> RouteOption {
        RouteOption {
            applicant: Some(persona),
            ..route(JoinRoute::Vetting, label, state)
        }
    }

    /// alice's vetting row, a new persona's, then the other ways in — the
    /// order `build_routes` draws them in.
    fn routes(alice: PersonaId) -> Vec<RouteOption> {
        vec![
            vetting_row(
                Applicant::Persona(alice),
                "Apply for vetting as alice",
                RouteState::Ready,
            ),
            vetting_row(
                Applicant::NewPersona,
                "Apply for vetting as a new persona",
                RouteState::FirstStep {
                    note: "this starts by creating the persona".into(),
                    kind: FirstStepKind::CreatePersona,
                },
            ),
            route(
                JoinRoute::Invitation,
                "Use an invitation",
                RouteState::Blocked("none held".into()),
            ),
            route(
                JoinRoute::OpenRequest,
                "Send an open request",
                RouteState::Ready,
            ),
        ]
    }

    /// A page on alice's vetting row. `satisfied` is her application's
    /// standing: `None` for none at all.
    fn known(satisfied: Option<bool>) -> VettingPhase {
        // The persona has to exist in `personas` and have a row as well as an
        // application: which application the page is showing follows from the
        // row the cursor is on.
        let persona = PersonaId::new();
        VettingPhase::Known(Box::new(KnownVetting {
            requirements: vec!["2 vetting statements".into()],
            routes: routes(persona),
            row: 0,
            personas: vec![ApplyAs {
                persona,
                label: "alice".into(),
                did: "did:key:zA".into(),
            }],
            applications: satisfied
                .into_iter()
                .map(|satisfied| JoinApplication {
                    id: "a1".into(),
                    persona,
                    persona_label: "alice".into(),
                    statements: 2,
                    progress: None,
                    next_step: "join — Enter on \"Present your vetting statements as alice\""
                        .into(),
                    satisfied,
                })
                .collect(),
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
        // Nothing to cycle: every row is a whole choice.
        for key in [KeyCode::Left, KeyCode::Right] {
            press(&mut f, key);
            assert!(rx.try_recv().is_err(), "{key:?} does nothing here");
        }
    }

    /// The page offers one door per thing, so the keys that were a second,
    /// shorter menu of the rows are gone. `j` duplicated *Send an open
    /// request*; `n` duplicated the vetting route's first step and described it
    /// differently. Neither does anything here now.
    #[test]
    fn the_keys_that_duplicated_rows_are_gone() {
        for key in ['j', 'J', 'n', 'N'] {
            let (mut f, mut rx) = flow(known(None));
            press(&mut f, KeyCode::Char(key));
            assert!(
                rx.try_recv().is_err(),
                "`{key}` should be a row, not a key, once the ways in are listed"
            );
        }
    }

    /// Reading an application before sending it is the one thing the list
    /// cannot reach, so it keeps a key — and only while there is one to read.
    #[test]
    fn reading_an_application_keeps_its_key_only_when_there_is_one() {
        let (mut f, mut rx) = flow(known(Some(false)));
        press(&mut f, KeyCode::Char('a'));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingApply)));

        let (mut f, mut rx) = flow(known(None));
        press(&mut f, KeyCode::Char('a'));
        assert!(rx.try_recv().is_err(), "nothing to read yet");
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
            resolvable: true,
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
            resolvable: true,
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

    /// A DID that resolves to nothing is not a community that would not
    /// answer, and the page must not offer the same way forward for both.
    /// Typing garbage produced "Joining anyway is the way forward here" over an
    /// identifier that names nothing — an offer to send a request nobody can
    /// receive, let alone answer.
    #[test]
    fn an_unresolvable_did_is_not_offered_a_join() {
        let phase = || VettingPhase::Unknown {
            reason: "it could not be resolved (DID must start with 'did:')".into(),
            can_retry: true,
            resolvable: false,
        };
        let (mut f, mut rx) = flow(phase());
        press(&mut f, KeyCode::Char('j'));
        assert!(
            rx.try_recv().is_err(),
            "there is nothing at this DID to send a join request to"
        );
        press(&mut f, KeyCode::Esc);
        assert!(matches!(rx.try_recv(), Ok(Action::JoinCancel)));

        let shown = text_of(&body_lines(&JoinState::default(), &view(phase())));
        assert!(!shown.contains("join anyway"), "{shown}");
        assert!(!shown.contains("way forward here"), "{shown}");
        assert!(shown.contains("does not resolve"), "{shown}");
        assert!(
            shown.contains("go back and re-enter it"),
            "and the one thing that can be done is named: {shown}"
        );
    }

    /// The page has to say what to do, and the answer differs by why the
    /// asking stopped: a community that was briefly unreachable is worth
    /// asking again, while a first join cannot ask at all until the request
    /// it is about to send brings messaging up.
    #[test]
    fn the_page_says_what_to_do_about_not_knowing() {
        let unknown = |can_retry| {
            text_of(&body_lines(
                &JoinState::default(),
                &view(VettingPhase::Unknown {
                    reason: "its endpoint could not be reached".into(),
                    can_retry,
                    resolvable: true,
                }),
            ))
        };
        let retryable = unknown(true);
        assert!(retryable.contains("Ask again"));
        assert!(!retryable.contains("brings your messaging online"));

        let first_join = unknown(false);
        assert!(first_join.contains("not a last resort"));
        assert!(first_join.contains("brings your messaging online"));
        assert!(
            first_join.contains("take this join up again from the application"),
            "the way back into the join is named"
        );
    }

    /// Three keys: move, commit, leave. Everything else a row does is the
    /// row's business — the foot of the page used to repeat the list in a
    /// second vocabulary.
    #[test]
    fn the_foot_of_the_page_offers_only_moving_committing_and_leaving() {
        let shown = text_of(&body_lines(&JoinState::default(), &view(known(None))));
        assert!(shown.contains("[↑/↓] choose"));
        assert!(shown.contains("[ENTER] continue"));
        assert!(shown.contains("[ESC] cancel"));
        for gone in ["[J]", "[N]", "join now", "create a persona", "take it"] {
            assert!(!shown.contains(gone), "{gone} is still offered: {shown}");
        }
    }

    /// Every way in is its own row, grouped: being vetted — as each persona,
    /// or as a new one — under one heading, the other ways in under another.
    /// Nothing is hidden behind a value cycled with ←/→, which showed one
    /// persona at a time and hid what set the others apart.
    #[test]
    fn every_choice_is_a_row_under_its_group() {
        let shown = text_of(&body_lines(&JoinState::default(), &view(known(None))));
        let line_of = |needle: &str| {
            shown
                .lines()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle} not drawn:\n{shown}"))
        };
        assert!(line_of("Choose how to join") < line_of("With vetting"));
        assert!(line_of("With vetting") < line_of("Apply for vetting as alice"));
        assert!(
            line_of("Apply for vetting as alice") < line_of("Apply for vetting as a new persona")
        );
        assert!(line_of("Apply for vetting as a new persona") < line_of("Other ways in"));
        assert!(line_of("Other ways in") < line_of("Use an invitation"));
        assert!(line_of("Use an invitation") < line_of("Send an open request"));
        assert!(!shown.contains("Apply as"), "no nested chooser: {shown}");
        assert!(!shown.contains("←/→"), "nothing to cycle: {shown}");
        // The highlighted row says which DID it joins as.
        assert!(shown.contains("as did:key:zA"), "{shown}");
    }

    /// The application's next step names the row it is taken from. It used to
    /// borrow the Vetting panel's "j — join now", and the join page has no `j`.
    #[test]
    fn the_next_step_names_the_row_rather_than_a_key_from_another_page() {
        let shown = text_of(&body_lines(&JoinState::default(), &view(known(Some(true)))));
        assert!(
            shown.contains("next: join — Enter on \"Present your vetting statements as alice\""),
            "{shown}"
        );
        assert!(!shown.contains("j — join now"), "{shown}");
    }

    /// How the community protects people is said either way: hidden vetters
    /// and post-quantum signing with their badges, and their absence in words.
    #[test]
    fn the_page_says_whether_vetters_are_hidden_and_how_it_signs() {
        let with = |pcs_zkp, post_quantum| {
            let mut phase = known(None);
            if let VettingPhase::Known(k) = &mut phase {
                k.pcs_zkp = pcs_zkp;
                k.post_quantum = post_quantum;
            }
            text_of(&body_lines(&JoinState::default(), &view(phase)))
        };
        let protected = with(true, Some(true));
        assert!(protected.contains("PCS ZKP"), "{protected}");
        assert!(protected.contains("PQC-SIGNED"), "{protected}");

        let plain = with(false, Some(false));
        assert!(
            plain.contains("named — the community sees which vetters"),
            "{plain}"
        );
        assert!(plain.contains("classical keys only"), "{plain}");
        assert!(
            !plain.contains("PCS ZKP") && !plain.contains("PQC-SIGNED"),
            "{plain}"
        );

        assert!(with(false, None).contains("not checked"));
    }

    #[test]
    fn the_page_says_what_is_required_and_lists_every_way_in() {
        let state = JoinState::default();
        let shown = text_of(&body_lines(&state, &view(known(Some(true)))));
        assert!(shown.contains("Kernel vets the people who join."));
        assert!(shown.contains("• 2 vetting statements"));
        assert!(shown.contains("Nothing about you has been sent"));
        assert!(shown.contains("Choose how to join"));
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

    /// A route that starts with a step says so under its row, as what happens
    /// next — not as a reason it is off.
    #[test]
    fn a_route_that_starts_with_a_step_says_what_it_starts_with() {
        let phase = VettingPhase::Known(Box::new(KnownVetting {
            routes: vec![route(
                JoinRoute::Vetting,
                "Apply for vetting",
                RouteState::FirstStep {
                    note: "you have no persona yet".into(),
                    kind: FirstStepKind::CreatePersona,
                },
            )],
            ..KnownVetting::default()
        }));
        let shown = text_of(&body_lines(&JoinState::default(), &view(phase)));
        assert!(shown.contains("Apply for vetting"));
        assert!(shown.contains("First: you have no persona yet"), "{shown}");
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
                resolvable: true,
            }),
        ));
        assert!(shown.contains("You hold 1 invitation from this community"));
    }
}
