//! Online VTA provisioning — step 2: show the operator the `pnm` command they
//! need to run to grant the ephemeral admin DID access to a context, and wait
//! for them to confirm it has been done.
//!
//! The page owns an editable `Input` for the context id so the operator can
//! pick something other than the default `openvtc`. The displayed pnm command
//! reflects the live input value, so what's on screen is what they paste into
//! their PNM session.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout, Margin, Rect,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};
use tui_input::{Input, backend::crossterm::EventHandler};

use crate::{
    state_handler::{actions::Action, setup_sequence::SetupState},
    ui::pages::setup_flow::{SetupFlow, render_setup_header},
};

/// Default value seeded into the context-id input.
const DEFAULT_CONTEXT_ID: &str = "openvtc";

#[derive(Clone, Debug)]
pub struct VtaAclInstructions {
    pub context_id: Input,
    /// One-shot status from the last clipboard copy attempt; cleared on the
    /// next keystroke so it doesn't linger as the operator continues typing.
    pub copy_status: Option<CopyStatus>,
}

#[derive(Clone, Debug)]
pub enum CopyStatus {
    /// Carries the transport label (e.g. "OSC 52 (terminal)" /
    /// "system clipboard") so the operator can tell which path took.
    Copied(String),
    Failed(String),
}

impl Default for VtaAclInstructions {
    fn default() -> Self {
        Self {
            context_id: Input::new(DEFAULT_CONTEXT_ID.to_string()),
            copy_status: None,
        }
    }
}

impl VtaAclInstructions {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        // Any keystroke clears a stale "copied!" indicator so it doesn't
        // hang around while the operator is typing the context id.
        if !matches!(key.code, KeyCode::F(_)) {
            state.vta_acl_instructions.copy_status = None;
        }
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::F(2) => {
                let cmd = build_pnm_command(
                    &state.props.state,
                    state.vta_acl_instructions.context_id.value(),
                );
                state.vta_acl_instructions.copy_status =
                    Some(match crate::clipboard::copy_to_clipboard(&cmd) {
                        Ok(method) => CopyStatus::Copied(method.label().to_string()),
                        Err(e) => CopyStatus::Failed(e),
                    });
            }
            KeyCode::Enter => {
                let raw = state
                    .vta_acl_instructions
                    .context_id
                    .value()
                    .trim()
                    .to_string();
                let context_id = if raw.is_empty() {
                    DEFAULT_CONTEXT_ID.to_string()
                } else {
                    raw
                };
                let _ = state.action_tx.send(Action::VtaStartProvision(context_id));
            }
            KeyCode::Esc => {
                state.vta_acl_instructions.context_id = Input::new(DEFAULT_CONTEXT_ID.to_string());
            }
            _ => {
                state
                    .vta_acl_instructions
                    .context_id
                    .handle_event(&Event::Key(key));
            }
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
                .title(" Authorise the setup DID via PNM "),
            middle,
        );

        let setup_did = state
            .vta
            .setup_key
            .as_ref()
            .map(|k| k.did.clone())
            .unwrap_or_else(|| "<setup key not yet generated>".to_string());

        let pnm_cmd = build_pnm_command(state, self.context_id.value());

        // Vertical sections within the bordered block:
        //   intro       — prose + setup DID (5 lines + 1 spacer = 6)
        //   ctx_label   — "Context id" label
        //   ctx_input   — "> " + editable input on the same row
        //   cmd_header  — spacer + "Run this command:" header
        //   rest        — pnm command + footer prose
        let area = middle.inner(Margin::new(3, 2));
        let [intro, ctx_label, ctx_input, cmd_header, rest] =
            Layout::vertical([Length(6), Length(1), Length(1), Length(2), Min(0)]).areas(area);

        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "OpenVTC has minted a temporary admin DID for this setup session.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Line::styled(
                    "Authorise it on the VTA via your Personal Network Manager (PNM):",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Line::default(),
                Line::styled("Setup DID", Style::new().fg(COLOR_BORDER).bold()),
                Line::from(Span::styled(setup_did, Style::new().fg(COLOR_SOFT_PURPLE))),
            ]),
            intro,
        );

        frame.render_widget(
            Paragraph::new(Span::styled(
                "Context id",
                Style::new().fg(COLOR_BORDER).bold(),
            )),
            ctx_label,
        );

        let [prompt_col, input_col] = Layout::horizontal([Length(2), Min(0)]).areas(ctx_input);
        frame.render_widget(
            Paragraph::new(Span::styled(
                "> ",
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            )),
            prompt_col,
        );
        render_input(&self.context_id, frame, input_col);

        frame.render_widget(
            Paragraph::new(vec![
                Line::default(),
                Line::styled(
                    "Run this command in your PNM session:",
                    Style::new().fg(COLOR_BORDER).bold(),
                ),
            ]),
            cmd_header,
        );

        let mut footer = vec![
            Line::default(),
            Line::from(Span::styled(pnm_cmd, Style::new().fg(COLOR_ORANGE).bold())),
            Line::default(),
        ];
        match &self.copy_status {
            Some(CopyStatus::Copied(method)) => {
                footer.push(Line::styled(
                    format!("✓ Copied via {method}."),
                    Style::new().fg(COLOR_SUCCESS).bold(),
                ));
                footer.push(Line::default());
            }
            Some(CopyStatus::Failed(reason)) => {
                footer.push(Line::styled(
                    format!("Could not copy to clipboard: {reason}"),
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                ));
                footer.push(Line::default());
            }
            None => {}
        }
        footer.push(Line::styled(
            "The admin grant is short-lived (1h). Once it's in place, press [ENTER]",
            Style::new().fg(COLOR_DARK_GRAY),
        ));
        footer.push(Line::styled(
            "and OpenVTC will connect to the VTA and bootstrap itself.",
            Style::new().fg(COLOR_DARK_GRAY),
        ));
        frame.render_widget(Paragraph::new(footer).wrap(Wrap { trim: false }), rest);

        let bottom_line = Line::from(vec![
            Span::styled("[F2]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" copy command  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" reset context  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" once authorised  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]);
        frame.render_widget(
            Paragraph::new(bottom_line).block(Block::new().padding(Padding::new(2, 0, 1, 0))),
            bottom,
        );
    }
}

fn build_pnm_command(state: &SetupState, typed_ctx: &str) -> String {
    let setup_did = state
        .vta
        .setup_key
        .as_ref()
        .map(|k| k.did.as_str())
        .unwrap_or("<setup key not yet generated>");
    let trimmed = typed_ctx.trim();
    let display_ctx = if trimmed.is_empty() {
        DEFAULT_CONTEXT_ID
    } else {
        trimmed
    };
    // `--admin-holder` grants the `persona-holder` capability alongside the
    // context-scoped admin entry. Without it OpenVTC can administer its own
    // context and nothing of the holder's: the attribute pool and the profiles
    // over it sit *above* every context, so the identity pane's Attributes,
    // Profiles and Disclosures tabs are refused — correctly — by a gate a
    // context-scoped credential cannot satisfy.
    //
    // It is not a way around that boundary; it is the grant the boundary was
    // always waiting for. The entry stays scoped to this one context and gains
    // authority over the holder's own identity, which is exactly what a client
    // that *is* the holder should have and an integration should not.
    //
    // `--admin-handoff` marks the entry as a one-time hand-off (VTI-ACL-054).
    // Setup asks for `AdminRotated`: the VTA mints a long-term admin DID and
    // this one-hour setup key rolls over to it, and the VTA refuses that
    // rollover unless the entry allows it — the long-term admin outlives it.
    format!(
        "pnm contexts create --id {display_ctx} --name \"OpenVTC\" \\\n  \
         --admin-did {setup_did} --admin-expires 1h --admin-holder --admin-handoff",
    )
}

fn render_input(input: &Input, frame: &mut Frame, area: Rect) {
    let width = area.width.max(3) - 3;
    let scroll = input.visual_scroll(width as usize);
    frame.render_widget(
        Paragraph::new(Span::styled(
            input.value(),
            Style::new().fg(COLOR_SOFT_PURPLE),
        ))
        .scroll((0, scroll as u16)),
        area,
    );
    let x = input.visual_cursor().max(scroll) - scroll;
    frame.set_cursor_position((area.x + x as u16, area.y))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command is pasted, character for character, into another terminal.
    /// It has to be one clean line-continued command — a stray run of spaces
    /// from a mangled string literal is invisible in review and survives all
    /// the way to the operator's shell.
    #[test]
    fn the_pnm_command_is_clean_and_carries_the_holder_grant() {
        let state = SetupState::default();
        let cmd = build_pnm_command(&state, "openvtc");

        assert!(
            cmd.starts_with("pnm contexts create --id openvtc "),
            "{cmd}"
        );
        assert!(
            cmd.contains("--admin-holder"),
            "without it the identity pane is refused the pool: {cmd}"
        );
        assert!(
            cmd.contains("--admin-handoff"),
            "without it the VTA refuses the rollover to the long-term admin: {cmd}"
        );
        // The second line is indented by two spaces on purpose; what must not
        // appear is a run of spaces *within* a line, which is what a collapsed
        // string-literal continuation leaves behind.
        for line in cmd.lines() {
            assert!(
                !line.trim_start().contains("  "),
                "a run of spaces inside a line means the continuation collapsed: {cmd:?}"
            );
        }
        assert_eq!(cmd.lines().count(), 2, "one continued command: {cmd:?}");
    }

    /// The setup DID the operator is authorising is the one in the command.
    #[test]
    fn the_setup_did_reaches_the_command() {
        let mut state = SetupState::default();
        let key =
            vta_sdk::provision_client::EphemeralSetupKey::generate().expect("generate a setup key");
        let did = key.did.clone();
        state.vta.setup_key = Some(std::sync::Arc::new(key));

        assert!(
            build_pnm_command(&state, "openvtc").contains(&format!("--admin-did {did}")),
            "the command must authorise the key this page is showing"
        );
    }

    /// The typed context id is what ends up in the command. The page lets the
    /// operator choose one, and a command that named the default anyway would
    /// grant admin over a context they are not creating.
    #[test]
    fn the_typed_context_id_reaches_the_command() {
        let cmd = build_pnm_command(&SetupState::default(), "  my-ctx  ");
        assert!(cmd.contains("--id my-ctx "), "{cmd}");
        assert!(!cmd.contains("--id openvtc"), "{cmd}");
    }

    /// An empty input falls back to the default rather than emitting `--id `
    /// with nothing after it.
    #[test]
    fn an_empty_context_id_falls_back_to_the_default() {
        let cmd = build_pnm_command(&SetupState::default(), "   ");
        assert!(cmd.contains("--id openvtc "), "{cmd}");
    }
}
