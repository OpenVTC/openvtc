//! Online VTA provisioning — step 2: show the operator the `pnm` command they
//! need to run to grant the ephemeral admin DID access to a context, and wait
//! for them to confirm it has been done.
//!
//! The page owns an editable `Input` for the context id so the operator can
//! pick something other than the default `openvtc`. The displayed pnm commands
//! reflect the live input value, so what's on screen is what they paste into
//! their PNM session.
//!
//! Two paths, because the operator may be in either position:
//!
//! - **New context** — `pnm contexts create … --admin-did`, which creates the
//!   context and the setup entry in one step.
//! - **Existing context, or a retry** — `pnm acl create`. `contexts create`
//!   refuses a context that already exists, and a retry after a refused
//!   rollover needs the setup DID's entry re-created, since the hand-off flag
//!   is fixed when an entry is created (VTI-ACL-054).
//!
//! Both must carry the same grant: a 1h expiry, the one-time hand-off and the
//! `persona-holder` capability. The flags are spelled differently on the two
//! commands (`--admin-handoff` / `--handoff`, `--admin-holder` /
//! `--capabilities persona-holder`), which is exactly how one of them ends up
//! missing a flag — the tests below pin both.

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
            KeyCode::F(n @ (2 | 3)) => {
                let commands = PnmCommands::build(
                    &state.props.state,
                    state.vta_acl_instructions.context_id.value(),
                );
                let cmd = if n == 2 {
                    commands.create_context
                } else {
                    commands.grant_existing
                };
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

        let commands = PnmCommands::build(state, self.context_id.value());

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
                    "New context — run this in your PNM session:",
                    Style::new().fg(COLOR_BORDER).bold(),
                ),
            ]),
            cmd_header,
        );

        let command_style = Style::new().fg(COLOR_ORANGE).bold();
        let mut footer = vec![Line::default()];
        footer.extend(command_lines(&commands.create_context, command_style));
        footer.extend([
            Line::default(),
            Line::styled(
                "Context already exists, or retrying — grant the setup DID instead:",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::styled(
                "(run the delete first only if this DID already has an entry; the hand-off",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::styled(
                " is fixed when an entry is created, so a retry must re-create it)",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
            Line::from(Span::styled(commands.delete_existing, command_style)),
        ]);
        footer.extend(command_lines(&commands.grant_existing, command_style));
        footer.push(Line::default());
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
            Span::styled(
                " copy new-context  |  ",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Span::styled("[F3]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" copy acl create  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
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

/// The `pnm` commands that authorise the setup DID, for both paths.
///
/// Flags verified against `pnm-cli`'s `ContextsCommands::Create` and
/// `AclCommands::{Create, Delete}`: `acl delete` takes the DID positionally —
/// there is no `--did` flag on it, unlike `acl create`.
struct PnmCommands {
    /// `pnm contexts create` — a new context and its setup entry in one step.
    create_context: String,
    /// `pnm acl delete` — clears a previous entry for the setup DID so it can
    /// be re-created with the hand-off.
    delete_existing: String,
    /// `pnm acl create` — the same grant as `create_context`, onto a context
    /// that already exists.
    grant_existing: String,
}

impl PnmCommands {
    fn build(state: &SetupState, typed_ctx: &str) -> Self {
        let setup_did = state
            .vta
            .setup_key
            .as_ref()
            .map(|k| k.did.as_str())
            .unwrap_or("<setup key not yet generated>");
        let trimmed = typed_ctx.trim();
        let ctx = if trimmed.is_empty() {
            DEFAULT_CONTEXT_ID
        } else {
            trimmed
        };
        // `--admin-holder` grants the `persona-holder` capability alongside the
        // context-scoped admin entry. Without it OpenVTC can administer its own
        // context and nothing of the holder's: the attribute pool and the
        // profiles over it sit *above* every context, so the identity pane's
        // Attributes, Profiles and Disclosures tabs are refused — correctly —
        // by a gate a context-scoped credential cannot satisfy.
        //
        // It is not a way around that boundary; it is the grant the boundary
        // was always waiting for. The entry stays scoped to this one context
        // and gains authority over the holder's own identity, which is exactly
        // what a client that *is* the holder should have and an integration
        // should not.
        //
        // `--admin-handoff` marks the entry as a one-time hand-off
        // (VTI-ACL-054). Setup asks for `AdminRotated`: the VTA mints a
        // long-term admin DID and this one-hour setup key rolls over to it, and
        // the VTA refuses that rollover unless the entry allows it — the
        // long-term admin outlives it.
        //
        // The `acl create` form carries the same grant under its own spellings:
        // `--handoff` and `--capabilities persona-holder`. On `acl create`,
        // `persona-holder` is an additive grant, not a narrowing — the admin
        // role keeps everything else it carries.
        Self {
            create_context: format!(
                "pnm contexts create --id {ctx} --name \"OpenVTC\" \\\n  \
                 --admin-did {setup_did} --admin-expires 1h --admin-holder --admin-handoff",
            ),
            delete_existing: format!("pnm acl delete {setup_did}"),
            grant_existing: format!(
                "pnm acl create --did {setup_did} --role admin --contexts {ctx} \\\n  \
                 --expires 1h --handoff --capabilities persona-holder",
            ),
        }
    }
}

/// A line-continued command as one `Line` per physical line, so the break
/// lands where the `\\` says rather than wherever the panel wraps it.
fn command_lines(cmd: &str, style: Style) -> Vec<Line<'static>> {
    cmd.lines()
        .map(|l| Line::from(Span::styled(l.to_string(), style)))
        .collect()
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
    fn assert_clean(cmd: &str) {
        for line in cmd.lines() {
            assert!(
                !line.trim_start().contains("  "),
                "a run of spaces inside a line means the continuation collapsed: {cmd:?}"
            );
        }
        assert_eq!(cmd.lines().count(), 2, "one continued command: {cmd:?}");
    }

    #[test]
    fn the_new_context_command_is_clean_and_carries_the_full_grant() {
        let cmd = PnmCommands::build(&SetupState::default(), "openvtc").create_context;

        assert!(
            cmd.starts_with("pnm contexts create --id openvtc "),
            "{cmd}"
        );
        assert!(cmd.contains("--admin-expires 1h"), "{cmd}");
        assert!(
            cmd.contains("--admin-holder"),
            "without it the identity pane is refused the pool: {cmd}"
        );
        assert!(
            cmd.contains("--admin-handoff"),
            "without it the VTA refuses the rollover to the long-term admin: {cmd}"
        );
        assert_clean(&cmd);
    }

    /// The existing-context path grants exactly what the new-context path
    /// does, under `acl create`'s own flag names. A missing `--handoff` here is
    /// the refusal this path exists to recover from.
    #[test]
    fn the_existing_context_command_is_clean_and_carries_the_full_grant() {
        let cmd = PnmCommands::build(&SetupState::default(), "openvtc").grant_existing;

        assert!(cmd.starts_with("pnm acl create --did "), "{cmd}");
        assert!(cmd.contains("--role admin"), "{cmd}");
        assert!(cmd.contains("--contexts openvtc "), "{cmd}");
        assert!(cmd.contains("--expires 1h"), "{cmd}");
        assert!(
            cmd.contains("--handoff"),
            "without it the VTA refuses the rollover to the long-term admin: {cmd}"
        );
        assert!(
            cmd.contains("--capabilities persona-holder"),
            "without it the identity pane is refused the pool: {cmd}"
        );
        assert_clean(&cmd);
    }

    /// `did` is positional on `pnm acl delete`; there is no `--did` flag, and a
    /// command carrying one is rejected by clap before it reaches the VTA.
    #[test]
    fn the_delete_takes_the_did_positionally() {
        let cmd = PnmCommands::build(&SetupState::default(), "openvtc").delete_existing;
        assert!(cmd.starts_with("pnm acl delete "), "{cmd}");
        assert!(!cmd.contains("--did"), "{cmd}");
    }

    /// The setup DID the operator is authorising is the one in every command.
    #[test]
    fn the_setup_did_reaches_the_commands() {
        let mut state = SetupState::default();
        let key =
            vta_sdk::provision_client::EphemeralSetupKey::generate().expect("generate a setup key");
        let did = key.did.clone();
        state.vta.setup_key = Some(std::sync::Arc::new(key));

        let cmds = PnmCommands::build(&state, "openvtc");
        assert!(cmds.create_context.contains(&format!("--admin-did {did}")));
        assert!(cmds.grant_existing.contains(&format!("--did {did}")));
        assert_eq!(cmds.delete_existing, format!("pnm acl delete {did}"));
    }

    /// The typed context id is what ends up in the commands. The page lets the
    /// operator choose one, and a command that named the default anyway would
    /// grant admin over a context they are not using.
    #[test]
    fn the_typed_context_id_reaches_the_commands() {
        let cmds = PnmCommands::build(&SetupState::default(), "  my-ctx  ");
        assert!(
            cmds.create_context.contains("--id my-ctx "),
            "{}",
            cmds.create_context
        );
        assert!(!cmds.create_context.contains("--id openvtc"));
        assert!(
            cmds.grant_existing.contains("--contexts my-ctx "),
            "{}",
            cmds.grant_existing
        );
    }

    /// An empty input falls back to the default rather than emitting `--id `
    /// with nothing after it.
    #[test]
    fn an_empty_context_id_falls_back_to_the_default() {
        let cmds = PnmCommands::build(&SetupState::default(), "   ");
        assert!(
            cmds.create_context.contains("--id openvtc "),
            "{}",
            cmds.create_context
        );
        assert!(
            cmds.grant_existing.contains("--contexts openvtc "),
            "{}",
            cmds.grant_existing
        );
    }
}
