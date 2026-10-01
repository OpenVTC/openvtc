//! Online VTA provisioning — step 3: live diagnostics while
//! `provision_client::run_connection_test` runs against the VTA.
//!
//! On success we emit `VtaAuthCompleted` so the keys-fetch / webvh-server-pick
//! flow takes over. On failure we surface the reason and let the operator
//! press Enter to retry (which loops back to the ACL instructions screen).

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
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
        setup_sequence::{Completion, MessageType, SetupPage, SetupState},
    },
    ui::pages::setup_flow::{
        SetupFlow,
        navigation::{SetupEvent, handle_nav_result, navigate},
        render_setup_header,
    },
};

#[derive(Clone, Debug, Default)]
pub struct VtaProvisioning;

/// Whether the failure is the VTA refusing the rollover because the setup
/// entry carries no one-time hand-off (VTI-ACL-054) — matched on the VTA's
/// specific phrase, so other refusals are not sent to re-grant.
fn needs_handoff_regrant(messages: &[MessageType]) -> bool {
    messages.iter().any(|m| {
        matches!(m, MessageType::Error(e) if e.to_ascii_lowercase().contains("no one-time hand-off"))
    })
}

impl VtaProvisioning {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter => match state.props.state.vta.completed {
                Completion::CompletedFail => {
                    // Bounce back to the instructions screen so the operator
                    // can verify the ACL grant and retry.
                    state.props.state.active_page = SetupPage::VtaAclInstructions;
                }
                Completion::CompletedOK => {
                    let result = navigate(SetupEvent::VtaAuthCompleted, &state.props.state);
                    handle_nav_result(result, state);
                }
                Completion::NotFinished => {
                    // Mid-flight — Enter is a no-op until the bootstrap
                    // either succeeds or fails.
                }
            },
            _ => {}
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
                .title(" Bootstrapping with the VTA "),
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
                // The VTA's own re-grant suggestion spells `pnm acl delete
                // --did <did>`, but `acl delete` takes the DID positionally,
                // and its `acl create` drops `persona-holder`. Point at the
                // instructions page, which carries the verified commands.
                if needs_handoff_regrant(&state.vta.messages) {
                    lines.push(Line::default());
                    lines.push(Line::styled(
                        "  The setup DID's entry was created without the one-time hand-off.",
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ));
                    lines.push(Line::styled(
                        "  Use the \"Context already exists, or retrying\" commands on the next",
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ));
                    lines.push(Line::styled(
                        "  screen: delete the entry, then re-create it with --handoff.",
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ));
                }
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(
                        " to return to the ACL instructions and retry.",
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ),
                ]));
            }
        }

        frame.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }),
            middle.inner(Margin::new(3, 2)),
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

    #[test]
    fn the_missing_handoff_refusal_is_recognised() {
        let refusal = MessageType::Error(
            "provision-integration call failed: forbidden: did:key:z6Mk's entry expires at \
             1790859174 and carries no one-time hand-off, so it cannot roll over"
                .to_string(),
        );
        assert!(needs_handoff_regrant(&[refusal]));
    }

    #[test]
    fn other_failures_are_not_sent_to_regrant() {
        for other in [
            "forbidden: not authorized",
            "connection refused",
            "timed out",
        ] {
            assert!(
                !needs_handoff_regrant(&[MessageType::Error(other.to_string())]),
                "{other}"
            );
        }
        assert!(!needs_handoff_regrant(&[MessageType::Info(
            "carries no one-time hand-off".to_string()
        )]));
    }
}
