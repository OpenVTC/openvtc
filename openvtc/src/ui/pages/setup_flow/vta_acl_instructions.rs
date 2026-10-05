//! Online VTA provisioning — **step 1 of 2: run the PNM command.** Show the
//! operator the `pnm` command that grants the ephemeral setup DID access to a
//! context, and wait for them to say they have run it.
//!
//! # Why this is its own step, said that loudly
//!
//! This page used to read as information: a DID, some commands, and "`[ENTER]
//! once authorised`" at the end of a long block. People pressed Enter without
//! running anything, step 2 failed with `forbidden: DID not in ACL`, and
//! nothing on either screen connected that refusal to the command they had
//! skipped. So the page now leads with what to *do* — three numbered actions,
//! including what PNM prints when it worked — and Enter means "I've run it".
//!
//! When step 2 fails and the cause is fixed in PNM, the wizard comes back here
//! with [`VtaAclInstructions::retry_reason`] set and the page opens with a
//! banner that says what went wrong and which command fixes it
//! ([`provision_failure`](crate::state_handler::setup_sequence::provision_failure)
//! decides which). The setup DID and the context id are the ones the operator
//! already has: the key is minted once per wizard run and is never replaced
//! on the way back, so every command on the page stays valid.
//!
//! # The commands
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
//! - **Existing context, or a re-grant** — `pnm acl create`. `contexts create`
//!   refuses a context that already exists (and exits cleanly, printing that
//!   the `--admin-did` was *not* added — the page names that output, because it
//!   is the easiest way to believe the grant ran when it did not), and a
//!   re-grant after an expired or spent entry needs the entry deleted first,
//!   since the hand-off flag is fixed when an entry is created (VTI-ACL-054).
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
    state_handler::{
        actions::Action,
        setup_sequence::{
            MessageType, SetupState,
            provision_failure::{GrantProblem, ProvisionFailure},
        },
    },
    ui::pages::setup_flow::{SetupFlow, render_setup_header},
};

/// Default value seeded into the context-id input.
const DEFAULT_CONTEXT_ID: &str = "openvtc";

/// What PNM prints when the grant landed. `pnm contexts create` prints
/// `Admin ACL entry created:` after `Context created:`; `pnm acl create` prints
/// `ACL entry created:` (`vta-cli-common`'s `commands::{contexts,acl}`). The
/// shorter phrase is in both, so it is the one to look for.
const PNM_SUCCESS: &str = "ACL entry created";

#[derive(Clone, Debug)]
pub struct VtaAclInstructions {
    pub context_id: Input,
    /// One-shot status from the last clipboard copy attempt; cleared on the
    /// next keystroke so it doesn't linger as the operator continues typing.
    pub copy_status: Option<CopyStatus>,
    /// Why the wizard came back here from step 2, when it did. Drives the
    /// banner at the top of the page; cleared when the operator presses Enter
    /// to try again, so a stale reason never sits over a fresh attempt.
    pub retry_reason: Option<RetryReason>,
}

/// A failed step 2, as carried back to step 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryReason {
    pub failure: ProvisionFailure,
    /// The first error the attempt reported, verbatim. Shown only for
    /// [`ProvisionFailure::Other`], where the error itself is the hint.
    pub detail: Option<String>,
}

impl RetryReason {
    /// Capture why the attempt on `state` failed.
    pub fn from_state(failure: ProvisionFailure, state: &SetupState) -> Self {
        let detail = state.vta.messages.iter().find_map(|m| match m {
            MessageType::Error(e) => Some(e.clone()),
            MessageType::Info(_) => None,
        });
        Self { failure, detail }
    }
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
            retry_reason: None,
        }
    }
}

impl VtaAclInstructions {
    /// The context id to provision into: the input, trimmed, or the default
    /// when it is blank. Step 2's retry uses this too, so a retry provisions
    /// into exactly the context the commands on this page name.
    pub fn chosen_context_id(&self) -> String {
        let raw = self.context_id.value().trim();
        if raw.is_empty() {
            DEFAULT_CONTEXT_ID.to_string()
        } else {
            raw.to_string()
        }
    }

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
            KeyCode::F(n @ (2..=4)) => {
                let commands = PnmCommands::build(
                    &state.props.state,
                    state.vta_acl_instructions.context_id.value(),
                );
                let cmd = match n {
                    2 => commands.create_context,
                    3 => commands.grant_existing,
                    _ => commands.delete_existing,
                };
                state.vta_acl_instructions.copy_status =
                    Some(match crate::clipboard::copy_to_clipboard(&cmd) {
                        Ok(method) => CopyStatus::Copied(method.label().to_string()),
                        Err(e) => CopyStatus::Failed(e),
                    });
            }
            KeyCode::Enter => {
                // "I've run it." Whatever went wrong last time is about to be
                // re-decided by a fresh attempt.
                state.vta_acl_instructions.retry_reason = None;
                let context_id = state.vta_acl_instructions.chosen_context_id();
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
                .title(" Step 1 of 2 — Run the PNM command "),
            middle,
        );

        let setup_did = state
            .vta
            .setup_key
            .as_ref()
            .map(|k| k.did.clone())
            .unwrap_or_else(|| "<setup key not yet generated>".to_string());

        let commands = PnmCommands::build(state, self.context_id.value());

        let area = middle.inner(Margin::new(3, 2));
        let banner = self
            .retry_reason
            .as_ref()
            .map(banner_lines)
            .unwrap_or_default();
        // The banner wraps, so its height is estimated from the width rather
        // than its line count; one spare row absorbs word-wrap's raggedness and
        // separates it from the intro.
        let banner_height = if banner.is_empty() {
            0
        } else {
            wrapped_height(&banner, area.width) + 1
        };

        // Vertical sections within the bordered block:
        //   banner      — why we are back here, when we are
        //   intro       — what this step is + setup DID + new-each-run note
        //   ctx_label   — "Context id" label
        //   ctx_input   — "> " + editable input on the same row
        //   rest        — the three actions, then the commands
        let [banner_area, intro, ctx_label, ctx_input, rest] = Layout::vertical([
            Length(banner_height),
            Length(6),
            Length(1),
            Length(1),
            Min(0),
        ])
        .areas(area);

        if !banner.is_empty() {
            frame.render_widget(
                Paragraph::new(banner).wrap(Wrap { trim: false }),
                banner_area,
            );
        }

        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "The VTA will refuse OpenVTC's temporary setup DID until you grant it",
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ),
                Line::styled(
                    "from your Personal Network Manager (PNM). This step is required.",
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ),
                Line::default(),
                Line::styled("Setup DID", Style::new().fg(COLOR_BORDER).bold()),
                Line::from(Span::styled(setup_did, Style::new().fg(COLOR_SOFT_PURPLE))),
                // The key is minted per run and held only in memory, so a grant
                // made for the DID an earlier run showed is for a key that no
                // longer exists — and the VTA reports it as "DID not in ACL".
                Line::styled(
                    "New each run — a grant for an earlier run's setup DID does not carry over.",
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                ),
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

        let regrant = self
            .retry_reason
            .as_ref()
            .is_some_and(|r| matches!(r.failure, ProvisionFailure::GrantSpent(_)));
        frame.render_widget(
            Paragraph::new(self.body_lines(&commands, regrant)).wrap(Wrap { trim: false }),
            rest,
        );

        let key = |k: &'static str| Span::styled(k, Style::new().fg(COLOR_BORDER).bold());
        let text = |t: &'static str| Span::styled(t, Style::new().fg(COLOR_TEXT_DEFAULT));
        let bottom_line = Line::from(vec![
            key("[F2-F4]"),
            text(" copy  |  "),
            key("[ESC]"),
            text(" reset context  |  "),
            key("[ENTER]"),
            text(" I've run it  |  "),
            key("[F10]"),
            text(" quit"),
        ]);
        frame.render_widget(
            Paragraph::new(bottom_line).block(Block::new().padding(Padding::new(2, 0, 1, 0))),
            bottom,
        );
    }

    /// The numbered actions, then the commands they refer to.
    ///
    /// Actions first, on purpose: on a short terminal it is the commands'
    /// tail that gets cut, and the commands are also one keypress away on the
    /// clipboard. Losing "press Enter only once PNM says it worked" would
    /// bring back the failure this page exists to prevent.
    fn body_lines(&self, commands: &PnmCommands, regrant: bool) -> Vec<Line<'static>> {
        let heading = Style::new().fg(COLOR_BORDER).bold();
        let prose = Style::new().fg(COLOR_TEXT_DEFAULT);
        let quiet = Style::new().fg(COLOR_DARK_GRAY);
        let key = Style::new().fg(COLOR_ORANGE).bold();
        let command_style = Style::new().fg(COLOR_ORANGE).bold();

        let mut lines = vec![
            Line::default(),
            Line::styled("Do this now, in order:", heading),
            Line::from(vec![
                Span::styled("  1. Copy ", prose),
                Span::styled(
                    if regrant {
                        "[F4] then [F3]"
                    } else {
                        "the command for your case"
                    },
                    key,
                ),
                Span::styled(
                    if regrant {
                        " — delete the old entry, then re-create it."
                    } else {
                        " — [F2], [F3] or [F4] below."
                    },
                    prose,
                ),
            ]),
            Line::styled(
                "  2. Run it in your PNM session, in another terminal.",
                prose,
            ),
            Line::from(vec![
                Span::styled("  3. When PNM prints ", prose),
                Span::styled(format!("\"{PNM_SUCCESS}\""), Style::new().fg(COLOR_SUCCESS)),
                Span::styled(", press ", prose),
                Span::styled("[ENTER]", key),
                Span::styled(" to connect.", prose),
            ]),
            Line::styled(
                "     \"already exists … NOT added\" means it did not work: use [F3].",
                quiet,
            ),
            Line::styled(
                "The grant lasts 1 hour, and the setup DID can use it once.",
                quiet,
            ),
        ];

        // Under a re-grant the delete-then-create pair is the fix, so it is the
        // pair that is marked; a first grant leaves the choice to the operator.
        let marker = |on: bool| if on { "▶ " } else { "  " };
        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled(marker(false), key),
            Span::styled("[F2] ", key),
            Span::styled("New context:", heading),
        ]));
        lines.extend(command_lines(
            &commands.create_context,
            command_style,
            "     ",
        ));
        lines.push(Line::from(vec![
            Span::styled(marker(regrant), key),
            Span::styled("[F3] ", key),
            Span::styled("Context already exists, or re-granting:", heading),
        ]));
        lines.extend(command_lines(
            &commands.grant_existing,
            command_style,
            "     ",
        ));
        lines.push(Line::from(vec![
            Span::styled(marker(regrant), key),
            Span::styled("[F4] ", key),
            Span::styled(
                "Re-granting? Delete the old entry first, then run [F3]:",
                heading,
            ),
        ]));
        lines.extend(command_lines(
            &commands.delete_existing,
            command_style,
            "     ",
        ));

        match &self.copy_status {
            Some(CopyStatus::Copied(method)) => {
                lines.push(Line::default());
                lines.push(Line::styled(
                    format!("✓ Copied via {method}. Now run it in your PNM session."),
                    Style::new().fg(COLOR_SUCCESS).bold(),
                ));
            }
            Some(CopyStatus::Failed(reason)) => {
                lines.push(Line::default());
                lines.push(Line::styled(
                    format!("Could not copy to clipboard: {reason}"),
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                ));
            }
            None => {}
        }
        lines
    }
}

/// The banner shown when step 2 sent the operator back, saying what failed
/// and what fixes it. Each arm is one [`ProvisionFailure`] class, and none of
/// them reuses another's advice — that is R6.4's whole point.
fn banner_lines(reason: &RetryReason) -> Vec<Line<'static>> {
    let alarm = Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold();
    let caution = Style::new().fg(COLOR_ORANGE).bold();
    let prose = Style::new().fg(COLOR_TEXT_DEFAULT);
    let regrant = "Re-grant it: copy [F4] and run it, then [F3] and run that, then press [ENTER].";
    match reason.failure {
        ProvisionFailure::NotAuthorised => vec![
            Line::styled("✗ The VTA didn't accept the setup DID.", alarm),
            Line::styled(
                "The PNM command below probably hasn't been run yet — or it ran against \
                 another VTA or context, or its 1-hour grant expired. Run it, then press \
                 [ENTER]. The setup DID and context are unchanged, so these commands still \
                 apply.",
                prose,
            ),
        ],
        ProvisionFailure::GrantSpent(problem) => {
            let (headline, why) = match problem {
                GrantProblem::Expired => (
                    "✗ The setup DID's grant has expired.",
                    "It lasts 1 hour from when PNM created it.",
                ),
                GrantProblem::AlreadyUsed => (
                    "✗ The setup DID's one-time grant was already used.",
                    "Usually an earlier attempt that got through but whose answer was lost.",
                ),
                GrantProblem::NoHandoff => (
                    "✗ The setup DID's entry was created without the one-time hand-off.",
                    "The hand-off is fixed when an entry is created, so it must be re-created.",
                ),
                GrantProblem::UsedByThisAttempt => (
                    "✗ The last attempt used the setup DID's one-time grant, then failed.",
                    "The context exists now, so [F2] would not add the grant.",
                ),
            };
            vec![
                Line::styled(headline, alarm),
                Line::styled(format!("{why} {regrant}"), prose),
            ]
        }
        ProvisionFailure::Unreachable => vec![
            Line::styled("! The VTA could not be reached last time.", caution),
            Line::styled(
                "That was the network or the VTA's host, not the PNM step: a grant you \
                 already ran still stands until it expires. Press [ENTER] to try again.",
                prose,
            ),
        ],
        ProvisionFailure::Other => {
            let mut lines = vec![Line::styled(
                "! The last attempt failed for a reason other than the grant:",
                caution,
            )];
            if let Some(detail) = &reason.detail {
                lines.push(Line::styled(detail.clone(), prose));
            }
            lines.push(Line::styled(
                "If it names the setup DID or its entry, re-check the command below; \
                 otherwise the VTA's log has the cause. Press [ENTER] to try again.",
                prose,
            ));
            lines
        }
    }
}

/// Rows `lines` take when wrapped to `width`: each line's character count over
/// the width, rounded up. Word wrap can need one more; the caller pads.
fn wrapped_height(lines: &[Line<'_>], width: u16) -> u16 {
    let width = usize::from(width.max(1));
    let rows: usize = lines.iter().map(|l| l.width().div_ceil(width).max(1)).sum();
    u16::try_from(rows).unwrap_or(u16::MAX)
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
///
/// `indent` sets the command under its label. It is display only: the
/// clipboard gets the command itself, never the rendered lines.
fn command_lines(cmd: &str, style: Style, indent: &str) -> Vec<Line<'static>> {
    cmd.lines()
        .map(|l| Line::from(Span::styled(format!("{indent}{l}"), style)))
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

    // ── The page as the operator sees it ─────────────────────────────────
    //
    // Rendered for real and read back: the fix this page carries is entirely
    // in what it says, and in what is still on screen when the terminal is
    // short.

    use crate::state_handler::{setup_sequence::SetupPage, state::State};
    use crate::ui::component::Component;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};

    /// The panel's side border as a blank, so a sentence that wraps reads
    /// back as one sentence.
    fn unbordered(symbol: &str) -> &str {
        if symbol == "│" { " " } else { symbol }
    }

    fn rows(page: &VtaAclInstructions, width: u16, height: u16) -> Vec<String> {
        let mut state = SetupState {
            active_page: SetupPage::VtaAclInstructions,
            ..Default::default()
        };
        let key =
            vta_sdk::provision_client::EphemeralSetupKey::generate().expect("generate a setup key");
        state.vta.setup_key = Some(std::sync::Arc::new(key));

        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|frame| page.render(&state, frame))
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
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    fn flat(page: &VtaAclInstructions) -> String {
        rows(page, 100, 50)
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn back_with(failure: ProvisionFailure, detail: Option<&str>) -> VtaAclInstructions {
        VtaAclInstructions {
            retry_reason: Some(RetryReason {
                failure,
                detail: detail.map(str::to_string),
            }),
            ..Default::default()
        }
    }

    /// Step 1 reads as something to do: numbered, with what success looks
    /// like in PNM's output, and Enter meaning "I've run it".
    #[test]
    fn the_page_is_a_numbered_action_with_a_visible_success_signal() {
        let text = flat(&VtaAclInstructions::default());
        assert!(text.contains("Step 1 of 2"), "{text}");
        assert!(text.contains("This step is required"), "{text}");
        assert!(text.contains("1. Copy"), "{text}");
        assert!(text.contains("2. Run it in your PNM session"), "{text}");
        assert!(
            text.contains("3. When PNM prints \"ACL entry created\""),
            "{text}"
        );
        assert!(text.contains("1 hour"), "{text}");
        assert!(text.contains("I've run it"), "{text}");
        assert!(
            !text.contains("didn't accept"),
            "no banner on a first visit: {text}"
        );
    }

    /// Back from a refusal: the banner says the command probably was not run,
    /// and that the commands shown still apply.
    #[test]
    fn a_refused_attempt_opens_with_a_banner_naming_the_missed_step() {
        let text = flat(&back_with(ProvisionFailure::NotAuthorised, None));
        assert!(
            text.contains("The VTA didn't accept the setup DID"),
            "{text}"
        );
        assert!(text.contains("probably hasn't been run yet"), "{text}");
        assert!(text.contains("these commands still apply"), "{text}");
    }

    /// A spent grant asks for the re-grant pair, and marks it.
    #[test]
    fn a_spent_grant_asks_for_delete_then_create() {
        for problem in [
            GrantProblem::Expired,
            GrantProblem::AlreadyUsed,
            GrantProblem::NoHandoff,
            GrantProblem::UsedByThisAttempt,
        ] {
            let text = flat(&back_with(ProvisionFailure::GrantSpent(problem), None));
            assert!(text.contains("copy [F4] and run it, then [F3]"), "{text}");
            assert!(text.contains("1. Copy [F4] then [F3]"), "{text}");
            assert!(text.contains("▶ [F3]"), "{text}");
            assert!(text.contains("▶ [F4]"), "{text}");
        }
        let used = flat(&back_with(
            ProvisionFailure::GrantSpent(GrantProblem::UsedByThisAttempt),
            None,
        ));
        assert!(used.contains("[F2] would not add the grant"), "{used}");
    }

    /// R6.4 on the way back too: an unreachable VTA is not the PNM step.
    #[test]
    fn an_unreachable_vta_is_not_blamed_on_the_command() {
        let text = flat(&back_with(ProvisionFailure::Unreachable, None));
        assert!(text.contains("could not be reached"), "{text}");
        assert!(text.contains("not the PNM step"), "{text}");
        assert!(!text.contains("hasn't been run"), "{text}");
    }

    /// Anything else is repeated verbatim — the error is the hint.
    #[test]
    fn another_failure_is_repeated_verbatim() {
        let text = flat(&back_with(
            ProvisionFailure::Other,
            Some("server error (500): the keystore is sealed"),
        ));
        assert!(
            text.contains("server error (500): the keystore is sealed"),
            "{text}"
        );
        assert!(!text.contains("hasn't been run"), "{text}");
    }

    /// On an ordinary terminal, banner and all, the instruction to press Enter
    /// only once PNM says it worked is still on screen, and nothing overflows.
    #[test]
    fn the_steps_survive_an_80_column_terminal() {
        let page = back_with(ProvisionFailure::NotAuthorised, None);
        let rows = rows(&page, 80, 45);
        for row in &rows {
            assert!(row.chars().count() <= 80, "row overflows: {row:?}");
        }
        let text = rows.join(" ");
        assert!(text.contains("didn't accept"), "{text}");
        assert!(text.contains("3. When PNM prints"), "{text}");
    }

    fn press(flow: &mut SetupFlow, code: KeyCode) {
        VtaAclInstructions::handle_key_event(
            flow,
            KeyEvent {
                code,
                modifiers: KeyModifiers::NONE,
                kind: KeyEventKind::Press,
                state: KeyEventState::NONE,
            },
        );
    }

    /// Enter is "I've run it": it starts step 2 with the typed context and
    /// drops the old banner, which a fresh attempt is about to re-decide.
    #[test]
    fn enter_starts_step_two_and_clears_the_banner() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut flow = SetupFlow::new(&State::default(), tx);
        flow.vta_acl_instructions = back_with(ProvisionFailure::NotAuthorised, None);
        flow.vta_acl_instructions.context_id = Input::new("  my-ctx ".to_string());

        press(&mut flow, KeyCode::Enter);

        assert!(flow.vta_acl_instructions.retry_reason.is_none());
        match rx.try_recv() {
            Ok(Action::VtaStartProvision(ctx)) => assert_eq!(ctx, "my-ctx"),
            _ => panic!("Enter should start provisioning"),
        }
    }

    /// Typing a context id is not "I've run it": the banner stays until Enter.
    #[test]
    fn typing_keeps_the_banner() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut flow = SetupFlow::new(&State::default(), tx);
        flow.vta_acl_instructions = back_with(ProvisionFailure::NotAuthorised, None);
        press(&mut flow, KeyCode::Char('x'));
        assert!(flow.vta_acl_instructions.retry_reason.is_some());
        assert!(rx.try_recv().is_err());
    }
}
