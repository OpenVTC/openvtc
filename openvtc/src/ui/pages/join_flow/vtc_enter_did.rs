//! Join flow — step 1: ask for the community (VTC) DID.
//!
//! Mirrors `setup_flow::vta_enter_did`. On submit we send
//! [`Action::JoinSubmitVtc`], which kicks off the automated persona-mint +
//! sub-context + join-submit sequence. Esc cancels the whole flow.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT,
};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
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
    state_handler::{actions::Action, join::JoinState},
    ui::pages::join_flow::JoinFlow,
};

#[derive(Clone, Debug, Default)]
pub struct VtcEnterDid;

impl VtcEnterDid {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        // Input is locked while the background sequence runs.
        if state.props.state.processing {
            return;
        }
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter => {
                // Submit unconditionally, empty input included: the handler
                // answers an empty field with an on-screen reason. Swallowing
                // the keypress here made Enter look broken after a VIC paste,
                // which populates the invitation but not this input (issue #29).
                let did = state.vtc_did.value().trim().to_string();
                let _ = state.action_tx.send(Action::JoinSubmitVtc(did));
            }
            KeyCode::Esc => {
                let _ = state.action_tx.send(Action::JoinCancel);
            }
            // Ctrl+V: the discoverable paste. Intercepted ahead of the input
            // handler, then treated exactly as a bracketed paste of the same
            // text — a DID lands in the field, an invitation is loaded.
            // Bracketed paste still works and is the path that survives SSH;
            // this is the one that is visible on screen.
            KeyCode::Char('v') | KeyCode::Char('V')
                if key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                match crate::clipboard::read_clipboard() {
                    Ok(text) => state.apply_entry_paste(&text),
                    // Reading the OS clipboard cannot work over SSH, where a
                    // bracketed paste still can — so the refusal says that
                    // rather than only that it failed.
                    Err(why) => {
                        let _ = state.action_tx.send(Action::JoinClipboardFailed(why));
                    }
                }
            }
            // Ctrl+L: clear a loaded invitation and join without it. Ctrl-modified
            // so it never collides with typing the VTC DID into the input field.
            KeyCode::Char('l') | KeyCode::Char('L')
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && state.props.state.has_invitation =>
            {
                let _ = state.action_tx.send(Action::JoinClearVic);
            }
            _ => {
                state.vtc_did.handle_event(&Event::Key(key));
            }
        }
    }

    pub fn render(&self, state: &JoinState, input: &Input, frame: &mut Frame<'_>) {
        let [middle, bottom] = Layout::vertical([Min(0), Length(3)]).areas(frame.area());

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Join a community "),
            middle,
        );

        let inner = middle.inner(Margin::new(3, 2));

        // The community comes first, because entering it is what this page is
        // for and what almost everyone arriving here has in hand. The
        // invitation sits under that prompt, close enough to be seen while
        // still being the secondary answer.
        //
        // It led the page for a while (issue #29), when this was the only
        // screen that mentioned invitations at all and one pasted here was
        // easy to miss. That stopped being true once the join learned to list
        // the ways in: an invitation is now offered again — counted, matched
        // against the community, with a paste row of its own — on the step
        // after this one. What it does *here* is fill in a DID you may not
        // have, which is a shortcut, not the main road.
        let width = inner.width as usize;
        let mut header = wrapped(
            "Enter the Verifiable Trust Community (VTC) DID you want to join. OpenVTC \
             will mint a fresh persona and submit a join request on your behalf.",
            width,
            Style::new().fg(COLOR_DARK_GRAY),
        );
        header.push(Line::default());
        // Surface any pre-submit error (e.g. idempotency, empty input) inline.
        let mut had_error = false;
        for msg in &state.messages {
            if let crate::state_handler::setup_sequence::MessageType::Error(err) = msg {
                header.extend(wrapped(
                    &format!("ERROR: {err}"),
                    width,
                    Style::new().fg(crate::colors::COLOR_WARNING_ACCESSIBLE_RED),
                ));
                had_error = true;
            }
        }
        if had_error {
            header.push(Line::default());
        }
        header.push(Line::styled(
            "Enter the community's DID or agent name:",
            Style::new().fg(COLOR_BORDER).bold(),
        ));

        // Height is the line count: every line above is already wrapped (or, for
        // a DID, truncated) to `inner`, so the block cannot rewrap under the
        // renderer and push the input off its row. Clamped so a terminal too
        // short for the whole block clips the *prose* rather than the input —
        // an unreachable input field is the one failure worth ruling out.
        let header_height = u16::try_from(header.len())
            .unwrap_or(u16::MAX)
            .min(inner.height.saturating_sub(2));
        let content: [Rect; 3] =
            Layout::vertical([Length(header_height), Length(2), Min(0)]).areas(inner);

        let [prompt_col, input_col] = Layout::horizontal([Length(2), Min(0)]).areas(content[1]);

        frame.render_widget(Paragraph::new(header), content[0]);

        frame.render_widget(
            Paragraph::new(Span::styled(
                "> ",
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            )),
            prompt_col,
        );
        render_input(input, frame, input_col);

        let mut lines = invitation_lines(state, width);
        lines.extend([
            Line::styled("Examples:", Style::new().fg(COLOR_ORANGE).bold()),
            Line::styled(
                "  • did:webvh:QmRoot…:community.example.com",
                Style::new().fg(COLOR_ORANGE).italic(),
            ),
            Line::styled(
                "  • community.example.com/@acme",
                Style::new().fg(COLOR_ORANGE).italic(),
            ),
            Line::default(),
            Line::from(vec![
                Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to cancel  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to join", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]),
        ]);

        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), content[2]);

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

/// The invitation status block shown above the DID input, always ending in a
/// blank line.
///
/// Explicit VIC state so the operator knows exactly what will be presented:
///   loaded   → it will ride in the join VP (community can auto-admit)
///   cleared  → operator dropped it; joining without one (may need review)
///   none     → never had one; offer the paste tip
///
/// The "loaded" case names the issuing community. A VIC's issuer *is* the
/// community being joined, and it is the DID prefilled into the input below —
/// showing it is what makes the prefill checkable rather than magic, and answers
/// "which community did this invitation come from" without leaving the page.
///
/// Prose is wrapped to `width` and the DID centre-truncated to it — the caller
/// sizes the header block by line count, so nothing may rewrap later.
fn invitation_lines(state: &JoinState, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if state.has_invitation {
        match &state.invitation_foreign_subject {
            None => lines.extend(wrapped(
                "✓ Invitation credential loaded — it will be presented to the community.",
                width,
                Style::new().fg(COLOR_SUCCESS).bold(),
            )),
            // Said here, before Enter, because nothing later can change it: the
            // community takes an invitation only from its subject or from a DID
            // the subject signs for, and neither is in this account (#373).
            Some(subject) => lines.extend(wrapped(
                &format!(
                    "Invitation loaded, but it names {}, which is not one of your \
                     personas. The community accepts it only from that DID, so this join \
                     will go as an open request. To be admitted by invitation, create a \
                     persona under My Identity and ask the community to invite that one.",
                    openvtc_core::display::truncate_did_centered(
                        &crate::state_handler::main_page::sanitize_display(subject, 256),
                        width.saturating_sub(16).max(16),
                    )
                ),
                width,
                Style::new().fg(COLOR_ORANGE),
            )),
        }
        if let Some(issuer) = &state.invitation_issuer {
            const LABEL: &str = "  Community: ";
            lines.push(Line::from(vec![
                Span::styled(LABEL, Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(
                    openvtc_core::display::truncate_did_centered(
                        issuer,
                        width.saturating_sub(LABEL.len()),
                    )
                    .into_owned(),
                    Style::new().fg(COLOR_SOFT_PURPLE),
                ),
            ]));
        }
        lines.push(key_row(
            "[Ctrl+V]",
            " replace it from the clipboard   ·   [Ctrl+L] join without it",
            " replace   ·   [Ctrl+L] join without it",
            width,
        ));
    } else if state.vic_cleared {
        lines.extend(wrapped(
            "Invitation cleared — joining without a credential; the community may \
             require manual approval.",
            width,
            Style::new().fg(COLOR_ORANGE),
        ));
        lines.push(paste_row(width));
    } else {
        // The lead-in gets its own line: hanging it off a narrowed first line
        // wraps the body into a ragged column on small terminals.
        lines.push(Line::styled(
            "Don't have the DID?",
            Style::new().fg(COLOR_BORDER).bold(),
        ));
        lines.extend(wrapped(
            "If you were handed an invitation credential (VIC), paste the JSON here \
             instead — it names the community, so it fills the DID in for you, and it \
             rides along with the join request.",
            width,
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ));
        lines.push(paste_row(width));
    }
    lines.push(Line::default());
    lines
}

/// The explicit "paste an invitation" row.
///
/// The reason issue #29 was filed at all: bracketed paste worked the whole
/// time, but nothing on screen said so, and an affordance nobody can see is not
/// an affordance. A named key is discoverable in the way "just paste" is not —
/// and it still degrades to bracketed paste over SSH, where reading the OS
/// clipboard cannot work.
fn paste_row(width: usize) -> Line<'static> {
    key_row(
        "[Ctrl+V]",
        " paste from the clipboard — a DID goes in the field, an invitation is loaded",
        " paste from the clipboard",
        width,
    )
}

/// A `[Key] description` row, keys highlighted, falling back to `short` when
/// the long form would not fit `width`.
///
/// These rows are single `Line`s in a block sized by line count, so they clip
/// rather than wrap — a key row that loses its tail on a narrow terminal is
/// exactly the affordance this page is trying to make visible.
fn key_row(key: &str, long: &str, short: &str, width: usize) -> Line<'static> {
    let desc = if key.len() + long.chars().count() <= width {
        long
    } else {
        short
    };
    Line::from(vec![
        Span::styled(key.to_string(), Style::new().fg(COLOR_SOFT_PURPLE).bold()),
        Span::styled(desc.to_string(), Style::new().fg(COLOR_TEXT_DEFAULT)),
    ])
}

/// Hard-wrap `text` to `width` and style each resulting line.
///
/// The header block is sized by line count, so it renders unwrapped `Line`s —
/// which a `Paragraph` clips rather than wraps, losing the tail of anything too
/// long. Wrapping here keeps the count honest and the text whole. Reuses the
/// overlay wrapper, which already hard-splits DIDs and JSON (no spaces to break
/// on) rather than overflowing them.
fn wrapped(text: &str, width: usize, style: Style) -> Vec<Line<'static>> {
    crate::ui::pages::main::wrap_text(text, width)
        .into_iter()
        .map(|l| Line::styled(l, style))
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
    //! The invitation status block is sized by line count, not by wrapping, so
    //! these render the page and read the buffer back — a line that wrapped
    //! would silently push the input off its row.
    use super::*;
    use crate::state_handler::setup_sequence::MessageType;
    use ratatui::{Terminal, backend::TestBackend};

    const ISSUER: &str = "did:webvh:QmRootQmRootQmRoot:community.example.com";

    /// Render at `width`×24 and return the drawn rows, trailing spaces trimmed.
    fn rows(state: &JoinState, input: &str, width: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(width, 24)).expect("test terminal");
        let input = Input::new(input.to_string());
        terminal
            .draw(|frame| VtcEnterDid.render(state, &input, frame))
            .expect("render");
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(width as usize)
            .map(|row| {
                row.iter()
                    .map(|c| c.symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    fn row_of(rows: &[String], needle: &str) -> usize {
        rows.iter()
            .position(|r| r.contains(needle))
            .unwrap_or_else(|| panic!("{needle:?} not drawn in:\n{}", rows.join("\n")))
    }

    /// The explicit paste key is named on screen in every invitation state.
    /// Bracketed paste worked all along; nothing said so, which is why the
    /// issue was filed as "I cannot find anywhere to import a VIC".
    #[test]
    fn the_paste_key_is_named_in_every_state() {
        let states = [
            ("none", JoinState::default()),
            (
                "cleared",
                JoinState {
                    vic_cleared: true,
                    ..JoinState::default()
                },
            ),
            (
                "loaded",
                JoinState {
                    has_invitation: true,
                    invitation_issuer: Some(ISSUER.to_string()),
                    ..JoinState::default()
                },
            ),
        ];
        for (name, state) in states {
            for width in [60, 100] {
                let drawn = rows(&state, "", width).join("\n");
                assert!(
                    drawn.contains("[Ctrl+V]"),
                    "{name} at width {width} should name the paste key:\n{drawn}"
                );
            }
        }
    }

    /// Ctrl+V is a paste, not a character: whatever the clipboard holds, the
    /// key itself must never land in the DID field.
    ///
    /// Deliberately asserts nothing about what *was* pasted — that depends on
    /// the machine's clipboard, and a test that reads it would pass or fail on
    /// what the developer last copied. What the key means is pinned by
    /// [`a_pasted_did_goes_in_the_field_and_an_invitation_is_loaded`] below,
    /// which drives the same path with text of its own.
    #[test]
    fn ctrl_v_never_types_a_v() {
        use crate::ui::component::Component;
        use crate::{state_handler::state::State, ui::pages::join_flow::JoinFlow};
        use tokio::sync::mpsc::unbounded_channel;

        let (tx, _rx) = unbounded_channel();
        let mut flow = JoinFlow::new(&State::default(), tx);
        VtcEnterDid::handle_key_event(
            &mut flow,
            KeyEvent::new(KeyCode::Char('v'), KeyModifiers::CONTROL),
        );
        assert_ne!(
            flow.vtc_did.value(),
            "v",
            "the key must not reach the input"
        );
    }

    /// The thing that was broken: a pasted DID is a DID.
    ///
    /// `[Ctrl+V]` used to hand its text to the invitation loader whatever it
    /// was, so pasting the community's DID — the commonest thing anyone pastes
    /// on this page — came back "Pasted text is not valid JSON", while the
    /// identical text bracketed-pasted worked. Both routes now come through
    /// `apply_entry_paste`, so they cannot disagree again.
    #[test]
    fn a_pasted_did_goes_in_the_field_and_an_invitation_is_loaded() {
        use crate::ui::component::Component;
        use crate::{state_handler::state::State, ui::pages::join_flow::JoinFlow};
        use tokio::sync::mpsc::unbounded_channel;

        let (tx, mut rx) = unbounded_channel();
        let mut flow = JoinFlow::new(&State::default(), tx);

        flow.apply_entry_paste("  did:webvh:QmRoot:vtc.example.com  ");
        assert_eq!(flow.vtc_did.value(), "did:webvh:QmRoot:vtc.example.com");
        assert!(
            rx.try_recv().is_err(),
            "a DID is not handed to the VIC loader"
        );

        // An agent name is not JSON either, so it lands in the field too.
        flow.apply_entry_paste("example.com/@acme");
        assert_eq!(flow.vtc_did.value(), "example.com/@acme");
        assert!(rx.try_recv().is_err());

        // A JSON object is still an invitation, and does not overwrite the DID
        // being typed — the issuer it names is what prefills that, later.
        flow.apply_entry_paste(r#"{"id":"urn:uuid:one"}"#);
        assert!(
            matches!(rx.try_recv(), Ok(Action::JoinPasteVic(text)) if text.starts_with('{')),
            "a JSON object is an invitation"
        );
        assert_eq!(flow.vtc_did.value(), "example.com/@acme");
    }

    /// A plain `v` is still just a character — the guard is on the modifier.
    #[test]
    fn a_bare_v_still_types() {
        use crate::ui::component::Component;
        use crate::{state_handler::state::State, ui::pages::join_flow::JoinFlow};
        use tokio::sync::mpsc::unbounded_channel;

        let (tx, mut rx) = unbounded_channel();
        let mut flow = JoinFlow::new(&State::default(), tx);
        VtcEnterDid::handle_key_event(
            &mut flow,
            KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE),
        );
        assert!(
            rx.try_recv().is_err(),
            "no action for an ordinary keystroke"
        );
        assert_eq!(flow.vtc_did.value(), "v");
    }

    /// The community is what this page asks for, so its prompt comes first and
    /// the invitation follows the input — but still ahead of the examples.
    ///
    /// The invitation led the page for a while (issue #29), when this was the
    /// only screen that mentioned one and a VIC pasted here was easy to miss.
    /// What #29 actually caught was an affordance that was dim, unnamed and
    /// last; the fix that stuck is the named `[Ctrl+V]` row, which this keeps.
    /// The join now offers invitations again on the step after this one —
    /// counted and matched against the community — so leading with them here
    /// buys nothing and pushes the DID prompt down the page.
    #[test]
    fn the_did_prompt_leads_and_the_invitation_follows_the_input() {
        let drawn = rows(&JoinState::default(), "", 100);
        assert!(
            row_of(&drawn, "Enter the community's DID") < row_of(&drawn, "Don't have the DID?"),
            "the input prompt should precede the invitation:\n{}",
            drawn.join("\n")
        );
        // Still ahead of the examples, so it is not the dim last thing again.
        assert!(
            row_of(&drawn, "Don't have the DID?") < row_of(&drawn, "Examples:"),
            "the invitation should precede the examples:\n{}",
            drawn.join("\n")
        );
    }

    /// A loaded invitation names the community it is for — that DID is what
    /// gets prefilled into the input, so it has to be visible to be checkable.
    #[test]
    fn a_loaded_invitation_names_its_community() {
        let state = JoinState {
            has_invitation: true,
            invitation_issuer: Some(ISSUER.to_string()),
            ..JoinState::default()
        };
        let drawn = rows(&state, ISSUER, 100);
        let row = &drawn[row_of(&drawn, "Community:")];
        assert!(row.contains("community.example.com"), "got {row:?}");
    }

    /// An invitation none of your personas can present says so on this page,
    /// before Enter — not only on the progress page after the join has gone out
    /// as an open request (issue #373).
    #[test]
    fn an_invitation_for_someone_else_is_not_promised() {
        let state = JoinState {
            has_invitation: true,
            invitation_issuer: Some(ISSUER.to_string()),
            invitation_foreign_subject: Some("did:webvh:example.com:alice".to_string()),
            ..JoinState::default()
        };
        let drawn = rows(&state, ISSUER, 100).join("\n");
        assert!(!drawn.contains("it will be presented"), "{drawn}");
        assert!(drawn.contains("not one of your"), "{drawn}");
        assert!(drawn.contains("did:webvh:example.com:alice"), "{drawn}");
        assert!(drawn.contains("will go as an open"), "{drawn}");
    }

    /// On a terminal too small for the whole status block the prose clips, but
    /// the input the operator has to type into stays on screen.
    #[test]
    fn a_cramped_terminal_still_shows_the_input() {
        let mut terminal = Terminal::new(TestBackend::new(40, 14)).expect("test terminal");
        let state = JoinState {
            has_invitation: true,
            invitation_issuer: Some(ISSUER.to_string()),
            ..JoinState::default()
        };
        let input = Input::new("did:webvh:typed".to_string());
        terminal
            .draw(|frame| VtcEnterDid.render(&state, &input, frame))
            .expect("render");
        let drawn: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        assert!(drawn.contains("> did:webvh:typed"), "got:\n{drawn}");
    }

    /// The input row must stay put whatever the status block says, at a width
    /// narrow enough that an unwrapped long DID would have spilled.
    #[test]
    fn the_input_keeps_its_row_across_states_and_widths() {
        let mut with_error = JoinState {
            has_invitation: true,
            invitation_issuer: Some(ISSUER.to_string()),
            ..JoinState::default()
        };
        with_error
            .messages
            .push(MessageType::Error("something went wrong".to_string()));
        let states = [
            JoinState::default(),
            JoinState {
                vic_cleared: true,
                ..JoinState::default()
            },
            JoinState {
                has_invitation: true,
                invitation_issuer: Some(ISSUER.to_string()),
                ..JoinState::default()
            },
            with_error,
        ];
        for width in [60, 100, 160] {
            for (i, state) in states.iter().enumerate() {
                let drawn = rows(state, "did:webvh:typed", width);
                let prompt = row_of(&drawn, "Enter the community's DID");
                let input = row_of(&drawn, "> did:webvh:typed");
                assert_eq!(
                    input,
                    prompt + 1,
                    "state {i} at width {width}: input should sit directly under its \
                     prompt:\n{}",
                    drawn.join("\n")
                );
            }
        }
    }
}
