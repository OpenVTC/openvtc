//! Online VTA provisioning — **step 2 of 2: connect.** Live diagnostics while
//! `provision_client::run_connection_test` runs against the VTA as the setup
//! DID the operator granted in step 1.
//!
//! On success we emit `VtaAuthCompleted` so the keys-fetch / webvh-server-pick
//! flow takes over.
//!
//! On failure the page says *which kind* of failure it was and offers the move
//! that fixes it, per [`provision_failure::classify`] (R6.4 — never one fixed
//! hint for every failure):
//!
//! - **the VTA refused the setup DID**, or its grant is spent — Enter goes back
//!   to step 1, which opens with a banner naming the command to run. The setup
//!   DID and context id are unchanged, so the commands there still apply.
//! - **the VTA could not be reached** — Enter retries from here. Sending the
//!   operator back to the PNM step would blame a step that was not at fault.
//! - **anything else** — the error stays on screen verbatim; Enter goes back to
//!   step 1, R retries.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
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
use vta_sdk::provision_client::DiagStatus;

use crate::{
    state_handler::{
        actions::Action,
        setup_sequence::{
            Completion, MessageType, SetupPage, SetupState,
            provision_failure::{self, GrantProblem, ProvisionFailure},
        },
    },
    ui::pages::setup_flow::{
        SetupFlow,
        navigation::{SetupEvent, handle_nav_result, navigate},
        render_setup_header,
        vta_acl_instructions::RetryReason,
    },
};

#[derive(Clone, Debug, Default)]
pub struct VtaProvisioning;

/// What a key does on a failed attempt.
#[derive(Debug, PartialEq, Eq)]
enum FailureMove {
    /// Back to step 1, carrying the failure for its banner.
    BackToStep1,
    /// Run step 2 again with the same setup DID and context.
    Retry,
    None,
}

/// The key map on a failed attempt. Enter is the move the failure calls for —
/// step 1 when the fix is in PNM, a retry when the VTA was not reached — so the
/// key the operator has pressed through every page so far does the right
/// thing. R and B are there for when they know better.
fn failure_key(failure: ProvisionFailure, code: KeyCode) -> FailureMove {
    match code {
        KeyCode::Enter if failure == ProvisionFailure::Unreachable => FailureMove::Retry,
        KeyCode::Enter => FailureMove::BackToStep1,
        KeyCode::Char('r' | 'R') => FailureMove::Retry,
        KeyCode::Char('b' | 'B') | KeyCode::Esc => FailureMove::BackToStep1,
        _ => FailureMove::None,
    }
}

/// Return to step 1 with the reason for its banner. Nothing else changes: the
/// setup DID is the one minted at the start of this run and the context id is
/// the one still in step 1's input, so the commands shown there still apply.
fn back_to_step1(state: &mut SetupFlow, failure: ProvisionFailure) {
    state.vta_acl_instructions.retry_reason =
        Some(RetryReason::from_state(failure, &state.props.state));
    state.props.state.active_page = SetupPage::VtaAclInstructions;
}

impl VtaProvisioning {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        if key.code == KeyCode::F(10) {
            let _ = state.action_tx.send(Action::Exit);
            return;
        }
        match state.props.state.vta.completed {
            Completion::CompletedOK => {
                if key.code == KeyCode::Enter {
                    let result = navigate(SetupEvent::VtaAuthCompleted, &state.props.state);
                    handle_nav_result(result, state);
                }
            }
            Completion::CompletedFail => {
                let failure = provision_failure::classify(&state.props.state.vta);
                match failure_key(failure, key.code) {
                    FailureMove::BackToStep1 => back_to_step1(state, failure),
                    FailureMove::Retry => {
                        // Same setup DID, same context: nothing on step 1 has
                        // changed, so there is nothing to go back for.
                        let context_id = state.vta_acl_instructions.chosen_context_id();
                        let _ = state.action_tx.send(Action::VtaStartProvision(context_id));
                        // Mid-flight locally until the handler's own state
                        // arrives, so a second press cannot queue a second
                        // attempt behind the first.
                        state.props.state.vta.completed = Completion::NotFinished;
                    }
                    FailureMove::None => {}
                }
            }
            // Mid-flight — keys are no-ops until the bootstrap either succeeds
            // or fails.
            Completion::NotFinished => {}
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame<'_>) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Step 2 of 2 — Connect to the VTA "),
            middle,
        );

        let mut lines = Vec::new();

        if !state.vta.vta_did.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("VTA DID: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(&state.vta.vta_did, Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));
        }
        if !state.vta.vta_url.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("VTA URL: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(&state.vta.vta_url, Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));
        }
        if let Some(setup_key) = &state.vta.setup_key {
            lines.push(Line::from(vec![
                Span::styled("Setup DID: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(&setup_key.did, Style::new().fg(COLOR_SOFT_PURPLE)),
                Span::styled(" (ephemeral)", Style::new().fg(COLOR_DARK_GRAY)),
            ]));
        }
        if !state.vta.credential_did.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("           ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("↓ rotated", Style::new().fg(COLOR_SUCCESS).bold()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Admin DID: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(
                    &state.vta.credential_did,
                    Style::new().fg(COLOR_SOFT_PURPLE),
                ),
                Span::styled(" (long-term) ", Style::new().fg(COLOR_DARK_GRAY)),
                Span::styled("✓", Style::new().fg(COLOR_SUCCESS).bold()),
            ]));
        }
        lines.push(Line::default());

        // Diagnostics list — one row per check.
        for entry in &state.vta.diagnostics {
            let (marker, marker_style, detail) = match &entry.status {
                DiagStatus::Pending => ("○", Style::new().fg(COLOR_DARK_GRAY), String::new()),
                DiagStatus::Running => (
                    "…",
                    Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                    String::new(),
                ),
                DiagStatus::Ok(s) => ("✓", Style::new().fg(COLOR_SUCCESS).bold(), s.clone()),
                DiagStatus::Skipped(s) => ("·", Style::new().fg(COLOR_DARK_GRAY), s.clone()),
                DiagStatus::Failed(s) => (
                    "✗",
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
                    s.clone(),
                ),
            };
            let mut spans = vec![
                Span::styled(format!(" {marker} "), marker_style),
                Span::styled(entry.check.label(), Style::new().fg(COLOR_TEXT_DEFAULT)),
            ];
            if !detail.is_empty() {
                spans.push(Span::styled(
                    format!(" — {detail}"),
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
            }
            lines.push(Line::from(spans));
        }

        // Backend-emitted info / error messages (shown beneath the checklist).
        if !state.vta.messages.is_empty() {
            lines.push(Line::default());
            for msg in &state.vta.messages {
                match msg {
                    MessageType::Info(info) => {
                        lines.push(Line::styled(
                            format!("  {info}"),
                            Style::new().fg(COLOR_SUCCESS),
                        ));
                    }
                    MessageType::Error(err) => {
                        lines.push(Line::styled(
                            format!("  ERROR: {err}"),
                            Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                        ));
                    }
                }
            }
        }

        match state.vta.completed {
            Completion::NotFinished => {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Connecting to the VTA — please wait.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
            }
            Completion::CompletedOK => {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Bootstrap complete — admin key rotated, ephemeral setup DID retired.",
                    Style::new().fg(COLOR_SUCCESS),
                ));
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]));
            }
            Completion::CompletedFail => {
                lines.push(Line::default());
                lines.extend(failure_lines(provision_failure::classify(&state.vta)));
            }
        }

        frame.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }),
            middle.inner(Margin::new(3, 2)),
        );

        let key = |k: &'static str| Span::styled(k, Style::new().fg(COLOR_BORDER).bold());
        let text = |t: &'static str| Span::styled(t, Style::new().fg(COLOR_TEXT_DEFAULT));
        let mut bottom_spans = Vec::new();
        if matches!(state.vta.completed, Completion::CompletedFail) {
            bottom_spans.extend([
                key("[R]"),
                text(" retry  |  "),
                key("[B]"),
                text(" back to step 1  |  "),
            ]);
        }
        bottom_spans.extend([key("[F10]"), text(" to quit")]);
        frame.render_widget(
            Paragraph::new(Line::from(bottom_spans))
                .block(Block::new().padding(Padding::new(2, 0, 1, 0))),
            bottom,
        );
    }
}

/// What the page says under the diagnostics when the attempt failed: what kind
/// of failure it was, what fixes it, and what Enter will do about it.
///
/// The error itself is already on screen verbatim, above, as the `ERROR:`
/// lines; this is the reading of it. Each class gets its own words — the PNM
/// step is named only when the VTA actually refused the DID (R6.4).
fn failure_lines(failure: ProvisionFailure) -> Vec<Line<'static>> {
    let alarm = Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold();
    let caution = Style::new().fg(COLOR_ORANGE).bold();
    let prose = Style::new().fg(COLOR_TEXT_DEFAULT);
    let key = Style::new().fg(COLOR_BORDER).bold();
    let enter = |action: &'static str| {
        Line::from(vec![
            Span::styled("[ENTER]", key),
            Span::styled(action, prose),
        ])
    };

    match failure {
        ProvisionFailure::NotAuthorised => vec![
            Line::styled("The VTA didn't accept the setup DID.", alarm),
            Line::styled(
                "This almost always means the PNM command from step 1 hasn't been run \
                 yet — or it ran against a different VTA or context, or its 1-hour grant \
                 expired.",
                prose,
            ),
            Line::default(),
            enter(" back to step 1 — same setup DID and context, so its commands still apply."),
        ],
        // The VTA's own re-grant suggestion has, in some releases, spelled
        // `pnm acl delete --did <did>` (`acl delete` takes the DID
        // positionally) and dropped `persona-holder`. Point at step 1, which
        // carries the verified commands, rather than repeating the VTA's.
        ProvisionFailure::GrantSpent(problem) => {
            let why = match problem {
                GrantProblem::Expired => "The setup DID's grant has expired (it lasts 1 hour).",
                GrantProblem::AlreadyUsed => {
                    "The setup DID's one-time grant was already used by an earlier attempt."
                }
                GrantProblem::NoHandoff => {
                    "The setup DID's entry was created without the one-time hand-off, \
                     which is fixed when an entry is created."
                }
                GrantProblem::UsedByThisAttempt => {
                    "The VTA accepted the setup DID and rolled it over, then a later step \
                     failed. Its one-time grant is used up, so a retry needs it again."
                }
            };
            vec![
                Line::styled(why, alarm),
                Line::styled(
                    "Re-grant it in PNM: delete the old entry, then re-create it.",
                    prose,
                ),
                Line::default(),
                enter(" back to step 1, where [F4] and [F3] copy those two commands."),
            ]
        }
        ProvisionFailure::Unreachable => vec![
            Line::styled("The VTA could not be reached.", caution),
            Line::styled(
                "The network, the VTA's host or its mediator did not answer — this is not \
                 about the PNM command. A grant you already ran still stands until it \
                 expires.",
                prose,
            ),
            Line::default(),
            enter(" to try again with the same setup DID.  [B] back to step 1."),
        ],
        ProvisionFailure::Other => vec![
            Line::styled(
                "Provisioning failed — the VTA's answer is shown above.",
                caution,
            ),
            Line::styled(
                "If it names the setup DID or its ACL entry, re-check the PNM step; \
                 otherwise the VTA's log has the cause.",
                prose,
            ),
            Line::default(),
            enter(" back to step 1.  [R] to try again as-is."),
        ],
    }
}

#[cfg(test)]
mod tests {
    //! Rendered for real and read back, and driven by real key events: the
    //! value of this page on failure is entirely in what it says and where
    //! Enter goes.
    use super::*;
    use crate::state_handler::state::State;
    use crate::ui::component::Component;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};
    use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

    /// The panel's side border as a blank, so a sentence that wraps reads
    /// back as one sentence.
    fn unbordered(symbol: &str) -> &str {
        if symbol == "│" { " " } else { symbol }
    }

    fn failed_with(message: &str) -> SetupState {
        let mut state = SetupState {
            active_page: SetupPage::VtaProvisioning,
            ..Default::default()
        };
        state.vta.completed = Completion::CompletedFail;
        state.vta.messages = vec![MessageType::Error(message.to_string())];
        state
    }

    const NOT_IN_ACL: &str = "AdminRotation provisioning failed after auth. (provision-integration call failed: \
         forbidden: DID not in ACL: did:key:z6MkSetup)";
    const UNREACHABLE: &str = "Could not open a TSP session to the VTA's `#tsp` mediator (did:webvh:m). Confirm \
         the mediator is reachable and that the `pnm acl create` command ran successfully \
         for setup DID did:key:z6MkSetup. (tsp transport error: connection refused)";
    const OTHER: &str = "server error (500): the keystore is sealed";

    fn flat(state: &SetupState) -> String {
        let (width, height) = (100, 40);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|frame| VtaProvisioning.render(state, frame))
            .expect("render");
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(width as usize)
            .map(|row| {
                row.iter()
                    .map(|c| unbordered(c.symbol()))
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn flow(state: SetupState) -> (SetupFlow, UnboundedReceiver<Action>) {
        let (tx, rx) = unbounded_channel();
        let mut flow = SetupFlow::new(&State::default(), tx);
        flow.props.state = state;
        (flow, rx)
    }

    fn press(flow: &mut SetupFlow, code: KeyCode) {
        VtaProvisioning::handle_key_event(
            flow,
            KeyEvent {
                code,
                modifiers: KeyModifiers::NONE,
                kind: KeyEventKind::Press,
                state: KeyEventState::NONE,
            },
        );
    }

    /// The case this page exists to catch: Enter on step 1 before the command
    /// was run. It says so, and Enter leads back to the command.
    #[test]
    fn a_refused_setup_did_points_back_at_the_pnm_command() {
        let state = failed_with(NOT_IN_ACL);
        let text = flat(&state);
        assert!(text.contains("didn't accept the setup DID"), "{text}");
        assert!(text.contains("hasn't been run yet"), "{text}");
        assert!(
            text.contains("DID not in ACL"),
            "the VTA's own words stay: {text}"
        );

        let (mut flow, mut rx) = flow(state);
        press(&mut flow, KeyCode::Enter);
        assert!(matches!(
            flow.props.state.active_page,
            SetupPage::VtaAclInstructions
        ));
        assert_eq!(
            flow.vta_acl_instructions
                .retry_reason
                .as_ref()
                .map(|r| r.failure),
            Some(ProvisionFailure::NotAuthorised)
        );
        assert!(rx.try_recv().is_err(), "going back must not start a retry");
    }

    /// R6.4: an unreachable VTA is not the PNM step's fault, so neither the
    /// words nor the Enter key send the operator there.
    #[test]
    fn an_unreachable_vta_is_retried_not_blamed_on_pnm() {
        let state = failed_with(UNREACHABLE);
        let text = flat(&state);
        assert!(text.contains("could not be reached"), "{text}");
        assert!(text.contains("not about the PNM command"), "{text}");
        assert!(!text.contains("hasn't been run"), "{text}");

        let (mut flow, mut rx) = flow(state.clone());
        press(&mut flow, KeyCode::Enter);
        assert!(matches!(
            flow.props.state.active_page,
            SetupPage::VtaProvisioning
        ));
        match rx.try_recv() {
            Ok(Action::VtaStartProvision(ctx)) => assert_eq!(ctx, "openvtc"),
            _ => panic!("Enter should retry"),
        }
        // A second press while the retry is in flight queues nothing.
        press(&mut flow, KeyCode::Enter);
        assert!(rx.try_recv().is_err(), "one retry per press-and-wait");

        // B is still there for an operator who wants to look at step 1.
        let (mut flow, _rx) = self::flow(state);
        press(&mut flow, KeyCode::Char('b'));
        assert!(matches!(
            flow.props.state.active_page,
            SetupPage::VtaAclInstructions
        ));
        assert_eq!(
            flow.vta_acl_instructions
                .retry_reason
                .as_ref()
                .map(|r| r.failure),
            Some(ProvisionFailure::Unreachable)
        );
    }

    /// Anything else stays verbatim, is blamed on nobody, and offers both
    /// moves.
    #[test]
    fn another_failure_is_shown_as_it_came() {
        let state = failed_with(OTHER);
        let text = flat(&state);
        assert!(text.contains("the keystore is sealed"), "{text}");
        assert!(!text.contains("hasn't been run"), "{text}");
        assert!(!text.contains("could not be reached"), "{text}");

        let (mut flow, mut rx) = flow(state.clone());
        press(&mut flow, KeyCode::Char('r'));
        assert!(matches!(rx.try_recv(), Ok(Action::VtaStartProvision(_))));

        let (mut flow, _rx) = self::flow(state);
        press(&mut flow, KeyCode::Enter);
        let reason = flow.vta_acl_instructions.retry_reason.expect("a reason");
        assert_eq!(reason.failure, ProvisionFailure::Other);
        assert_eq!(
            reason.detail.as_deref(),
            Some(OTHER),
            "step 1 repeats it verbatim"
        );
    }

    /// The re-grant case sends the operator to the delete-then-create pair,
    /// not to the create they already ran.
    #[test]
    fn a_spent_grant_points_at_the_regrant() {
        let state = failed_with(
            "provision-integration call failed: forbidden: ACL entry expired: did:key:z6Mk",
        );
        let text = flat(&state);
        assert!(text.contains("has expired"), "{text}");
        assert!(text.contains("[F4] and [F3]"), "{text}");
    }

    /// Mid-flight, no key does anything but quit.
    #[test]
    fn keys_wait_while_the_attempt_runs() {
        let (mut flow, mut rx) = flow(SetupState {
            active_page: SetupPage::VtaProvisioning,
            ..Default::default()
        });
        for code in [KeyCode::Enter, KeyCode::Char('r'), KeyCode::Char('b')] {
            press(&mut flow, code);
        }
        assert!(matches!(
            flow.props.state.active_page,
            SetupPage::VtaProvisioning
        ));
        assert!(rx.try_recv().is_err());
    }
}
