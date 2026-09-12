use super::panel::Panel;
use super::status::push_status;
use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::{
    main_page::content::{ContentPanelState, SettingsMode, SettingsState, ThemeRow},
    state::ConnectionState,
};
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Settings content panel.
pub struct SettingsPanel;

impl Panel for SettingsPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        render(&state.settings)
    }
}

/// Render the settings panel content.
pub fn render(state: &SettingsState) -> Vec<Line<'static>> {
    match &state.mode {
        SettingsMode::EditFriendlyName { input } => render_edit("Friendly Name", input),
        SettingsMode::EditOrgDid { input } => render_edit("Org DID", input),
        SettingsMode::ExportConfig {
            path_input,
            passphrase_len,
            active_field,
        } => render_export_form("Export Config", path_input, *passphrase_len, *active_field),
        SettingsMode::ImportConfig {
            path_input,
            passphrase_len,
            active_field,
        } => render_export_form("Import Config", path_input, *passphrase_len, *active_field),
        SettingsMode::ChangeProtection {
            selected_option,
            passphrase_len,
            confirm_len,
            active_field,
        } => render_change_protection(
            *selected_option,
            *passphrase_len,
            *confirm_len,
            *active_field,
        ),
        #[cfg(feature = "openpgp-card")]
        SettingsMode::TokenManagement { selected_index } => {
            render_token_management(state, *selected_index)
        }
        SettingsMode::WipeConfirm { confirm_input } => render_wipe_confirm(state, confirm_input),
        SettingsMode::ThemePicker { rows, selected, .. } => {
            render_theme_picker(state, rows, *selected)
        }
        SettingsMode::View => render_view(state),
    }
}

/// Index of the Theme row in the settings list.
pub(crate) const THEME_ROW: usize = 7;

/// The theme picker. The whole screen is the preview: moving through the list
/// draws everything in the highlighted theme.
fn render_theme_picker(
    state: &SettingsState,
    rows: &[ThemeRow],
    selected: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(""),
        Line::from("Theme").fg(COLOR_SUCCESS).bold(),
        Line::from(""),
    ];
    if let Some(msg) = &state.status_message {
        push_status(&mut lines, msg, "");
        lines.push(Line::from(""));
    }
    lines.push(
        Line::from("Moving through the list previews each theme. Enter keeps it; Esc puts back the one you had.")
            .fg(COLOR_DARK_GRAY),
    );
    if crate::theme::no_color() {
        lines.push(
            Line::from("NO_COLOR is set, so themes are not drawn. The one you choose is kept for when it is not.")
                .fg(COLOR_ORANGE),
        );
    }
    lines.push(Line::from(""));
    for (i, row) in rows.iter().enumerate() {
        let is_selected = i == selected;
        let style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(if is_selected { "▸ " } else { "  " }, style),
            Span::styled(format!("{:<32}", row.name), style),
            Span::styled(row.source.clone(), Style::new().fg(COLOR_DARK_GRAY)),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  accent ", Style::new().fg(COLOR_BORDER)),
        Span::styled("success ", Style::new().fg(COLOR_SUCCESS)),
        Span::styled("warning ", Style::new().fg(COLOR_ORANGE)),
        Span::styled("danger ", Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED)),
        Span::styled("text ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled("muted ", Style::new().fg(COLOR_DARK_GRAY)),
        Span::styled("highlight", Style::new().fg(COLOR_SOFT_PURPLE)),
    ]));
    lines.push(Line::from(""));
    lines.push(
        Line::from("Add your own: c copies the highlighted theme to edit, or run")
            .fg(COLOR_DARK_GRAY),
    );
    lines.push(
        Line::from("`openvtc theme import <scheme | Omarchy theme | nvim:colorscheme>`.")
            .fg(COLOR_DARK_GRAY),
    );
    if let Some(dir) = crate::theme::catalog::Roots::from_env().themes_dir() {
        lines
            .push(Line::from(format!("Your themes live in {}", dir.display())).fg(COLOR_DARK_GRAY));
    }
    lines.push(Line::from(""));
    lines.push(
        Line::from("↑/↓ preview  Enter: use  c: copy to edit  r: reload  Esc: cancel")
            .fg(COLOR_DARK_GRAY),
    );
    lines
}

const WIPE_CONFIRM_TOKEN: &str = "WIPE";

/// Width the settings rows truncate their values to.
const VALUE_WIDTH: usize = 50;

/// Index of the Mediator DID row in the settings list. Shared with
/// `settings_actions`, which must not open an edit mode for it.
pub(crate) const MEDIATOR_ROW: usize = 1;

fn render_wipe_confirm(state: &SettingsState, confirm_input: &str) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from(" Wipe profile")
            .fg(COLOR_WARNING_ACCESSIBLE_RED)
            .bold(),
    );
    lines.push(Line::from(""));
    lines.push(Line::styled(
        "  This will permanently remove this profile from this host:",
        Style::new().fg(COLOR_TEXT_DEFAULT),
    ));
    lines.push(Line::from(""));
    lines.push(Line::styled(
        "    • openvtc config file",
        Style::new().fg(COLOR_TEXT_DEFAULT),
    ));
    lines.push(Line::styled(
        "    • openvtc keyring entry (secured config)",
        Style::new().fg(COLOR_TEXT_DEFAULT),
    ));
    lines.push(Line::styled(
        "    • did-git-sign config + keyring entries (if installed)",
        Style::new().fg(COLOR_TEXT_DEFAULT),
    ));
    lines.push(Line::styled(
        "    • git config keys did-git-sign owns",
        Style::new().fg(COLOR_TEXT_DEFAULT),
    ));
    lines.push(Line::from(""));
    lines.push(Line::styled(
        "  Your VTA-side context, persona DID, and keys are NOT affected.",
        Style::new().fg(COLOR_DARK_GRAY),
    ));
    lines.push(Line::styled(
        "  If you want to clean those up too, run this first:",
        Style::new().fg(COLOR_DARK_GRAY),
    ));
    lines.push(Line::from(""));
    // Its own row, like every other command this TUI hands over: it is meant to
    // be retyped in another terminal, and a command sharing a line with the
    // prose around it is one an eye has to pick apart first.
    lines.push(Line::styled(
        format!("    {}", wipe_context_command(&state.context_id)),
        Style::new().fg(COLOR_ORANGE),
    ));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Type ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(
            WIPE_CONFIRM_TOKEN,
            Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
        ),
        Span::styled(
            " to confirm and press Enter:",
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  > ", Style::new().fg(COLOR_SOFT_PURPLE).bold()),
        Span::styled(
            confirm_input.to_string(),
            Style::new().fg(COLOR_SOFT_PURPLE),
        ),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from("  Esc: cancel  |  Enter: confirm").fg(COLOR_DARK_GRAY));
    lines
}

fn render_view(state: &SettingsState) -> Vec<Line<'static>> {
    // The persona row names the party, so it shows the verified agent name and
    // falls back to the DID — hence "Persona", not "Persona DID". The value was
    // already on the view model and simply never read here.
    let persona = openvtc_core::display::display_identifier(
        state.persona_agent_name.as_deref(),
        &state.persona_did,
        VALUE_WIDTH,
    )
    .into_owned();
    // The mediator is read-only: it is chosen when a persona is minted and baked
    // into that persona's published DID document (the `#public-didcomm` service
    // endpoint IS the mediator DID). Editing it here would move only where *we*
    // connect, while everyone else keeps resolving the document, finding the old
    // mediator, and delivering to a mailbox we no longer read — so the row shows
    // the value and says where it comes from rather than offering an edit that
    // silently desynchronises the profile from its own published address.
    //
    // An empty value is the no-persona case, which is a "not yet", not a blank
    // setting; say so, because a bare empty row is what read as "it did not take".
    let mediator = if state.mediator_did.is_empty() {
        "— no persona yet".to_string()
    } else {
        state.mediator_did.clone()
    };
    let settings = [
        ("Friendly Name", state.friendly_name.clone(), true),
        ("Mediator DID", mediator, false),
        ("Org DID", state.org_did.clone(), true),
        ("Persona", persona, false),
    ];

    let mut lines = vec![Line::from("")];

    if let Some(msg) = &state.status_message {
        push_status(&mut lines, msg, "");
        lines.push(Line::from(""));
    }

    for (i, (label, value, editable)) in settings.iter().enumerate() {
        let is_selected = i == state.selected_index;
        let prefix = if is_selected { "▸ " } else { "  " };
        let style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };

        let edit_hint = if *editable && is_selected {
            " [Enter to edit]"
        } else if !editable {
            " (read-only)"
        } else {
            ""
        };

        lines.push(Line::from(vec![
            Span::styled(prefix, style),
            Span::styled(format!("{}: ", label), style),
            Span::styled(
                // `&value[..47]` sliced by *bytes* — it panics when the cut
                // lands inside a multi-byte character, which a friendly name or
                // an agent name may well contain.
                openvtc_core::display::truncate_did(value, VALUE_WIDTH).into_owned(),
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
            Span::styled(edit_hint, Style::new().fg(COLOR_DARK_GRAY)),
        ]));

        // "(read-only)" answers *whether* it can be changed but not *why not*,
        // which is the question a mediator row invites. Answer it on selection,
        // where the operator is already looking, rather than in a doc nobody
        // reaches from here.
        if i == MEDIATOR_ROW && is_selected {
            lines.push(Line::from(Span::styled(
                "      set when the persona was created, and published in its DID document",
                Style::new().fg(COLOR_DARK_GRAY),
            )));
        }
    }

    lines.push(Line::from(""));

    // Protection type display (index 4)
    let prot_selected = state.selected_index == 4;
    let prot_style = if prot_selected {
        Style::new().fg(COLOR_SUCCESS).bold()
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if prot_selected { "▸ " } else { "  " }, prot_style),
        Span::styled("Protection: ", prot_style),
        Span::styled(state.protection_type.clone(), Style::new().fg(COLOR_ORANGE)),
        Span::styled(
            if prot_selected {
                " [Enter to change]"
            } else {
                ""
            },
            Style::new().fg(COLOR_DARK_GRAY),
        ),
    ]));

    // Volatile-storage warning, sitting between Protection (which fixes it)
    // and Export (which insures against it) — the two actions it asks for.
    if let Some(warning) = &state.storage_warning {
        for line in textwrap_warning(warning) {
            lines.push(Line::from(Span::styled(
                line,
                Style::new().fg(COLOR_ORANGE).bold(),
            )));
        }
    }

    // Export option (index 5)
    let export_selected = state.selected_index == 5;
    let export_style = if export_selected {
        Style::new().fg(COLOR_SUCCESS).bold()
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if export_selected { "▸ " } else { "  " }, export_style),
        Span::styled("Export Config", export_style),
    ]));

    // Import option (index 6)
    let import_selected = state.selected_index == 6;
    let import_style = if import_selected {
        Style::new().fg(COLOR_SUCCESS).bold()
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if import_selected { "▸ " } else { "  " }, import_style),
        Span::styled("Import Config", import_style),
    ]));

    // Theme (index 7)
    let theme_selected = state.selected_index == THEME_ROW;
    let theme_style = if theme_selected {
        Style::new().fg(COLOR_SUCCESS).bold()
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    let (theme_id, theme_name) = crate::theme::active_theme();
    lines.push(Line::from(vec![
        Span::styled(if theme_selected { "▸ " } else { "  " }, theme_style),
        Span::styled("Theme: ", theme_style),
        Span::styled(
            crate::theme::display_name(&theme_id, &theme_name),
            Style::new().fg(COLOR_SOFT_PURPLE),
        ),
        Span::styled(
            if theme_selected {
                " [Enter to change]"
            } else {
                ""
            },
            Style::new().fg(COLOR_DARK_GRAY),
        ),
    ]));

    // Token management option (index 8, only with openpgp-card)
    #[cfg(feature = "openpgp-card")]
    {
        let token_selected = state.selected_index == 8;
        let token_style = if token_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(if token_selected { "▸ " } else { "  " }, token_style),
            Span::styled("Hardware Token Management", token_style),
        ]));
    }

    // Wipe profile (index 8 without openpgp-card, 9 with).
    #[cfg(feature = "openpgp-card")]
    let wipe_index: usize = 9;
    #[cfg(not(feature = "openpgp-card"))]
    let wipe_index: usize = 8;
    let wipe_selected = state.selected_index == wipe_index;
    let wipe_style = if wipe_selected {
        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold()
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if wipe_selected { "▸ " } else { "  " }, wipe_style),
        Span::styled("Wipe profile", wipe_style),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from("↑/↓ navigate  Enter: edit/open").fg(COLOR_DARK_GRAY));

    lines
}

#[cfg(feature = "openpgp-card")]
fn render_token_management(state: &SettingsState, selected_index: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from("Hardware Token Management")
            .fg(COLOR_SUCCESS)
            .bold(),
    );
    lines.push(Line::from(""));

    // Token status
    let detected = state.token.detected_count;
    if detected > 0 {
        lines.push(Line::from(format!("  Tokens detected: {}", detected)).fg(COLOR_SUCCESS));
    } else {
        lines.push(Line::from("  No tokens detected").fg(COLOR_ORANGE));
    }
    lines.push(Line::from(""));

    // Action items
    let actions = ["Detect Tokens", "Factory Reset"];

    for (i, label) in actions.iter().enumerate() {
        let is_selected = i == selected_index;
        let prefix = if is_selected { "▸ " } else { "  " };
        let style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![Span::styled(
            format!("{}{}", prefix, label),
            style,
        )]));
    }

    // Messages from token operations
    if !state.token.messages.is_empty() {
        lines.push(Line::from(""));
        for msg in &state.token.messages {
            lines.push(Line::from(format!("  {}", msg)).fg(COLOR_TEXT_DEFAULT));
        }
    }

    if state.token.reset_completed {
        lines.push(Line::from(""));
        lines.push(Line::from("  Factory reset completed.").fg(COLOR_SUCCESS));
    }

    lines.push(Line::from(""));
    lines.push(Line::from("↑/↓ navigate  Enter: execute  Esc: back").fg(COLOR_DARK_GRAY));

    lines
}

/// Render inline edit for a settings field.
fn render_edit(label: &str, input: &str) -> Vec<Line<'static>> {
    vec![
        Line::from(""),
        Line::from(format!("Editing: {}", label))
            .fg(COLOR_SUCCESS)
            .bold(),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(input.to_string(), Style::new().fg(COLOR_SOFT_PURPLE)),
            Span::styled("▎", Style::new().fg(COLOR_SUCCESS)),
        ]),
        Line::from(""),
        Line::from("Enter: save  Esc: cancel").fg(COLOR_DARK_GRAY),
    ]
}

/// Render a config form (export or import) with path and passphrase fields.
fn render_export_form(
    title: &str,
    path_input: &str,
    passphrase_len: usize,
    active_field: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(""),
        Line::from(title.to_string()).fg(COLOR_SUCCESS).bold(),
        Line::from(""),
    ];

    // Path field (index 0)
    let path_active = active_field == 0;
    let path_style = if path_active {
        Style::new().fg(COLOR_SUCCESS)
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if path_active { "▸ " } else { "  " }, path_style),
        Span::styled("File path:  ", path_style),
        Span::styled(path_input.to_string(), Style::new().fg(COLOR_SOFT_PURPLE)),
        Span::styled(
            if path_active { "▎" } else { "" },
            Style::new().fg(COLOR_SUCCESS),
        ),
    ]));

    // Passphrase field (index 1) — display masked length only
    let pass_active = active_field == 1;
    let pass_style = if pass_active {
        Style::new().fg(COLOR_SUCCESS)
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if pass_active { "▸ " } else { "  " }, pass_style),
        Span::styled("Passphrase: ", pass_style),
        Span::styled(
            "*".repeat(passphrase_len),
            Style::new().fg(COLOR_SOFT_PURPLE),
        ),
        Span::styled(
            if pass_active { "▎" } else { "" },
            Style::new().fg(COLOR_SUCCESS),
        ),
    ]));

    lines.push(Line::from(""));
    lines.push(
        Line::from("Tab: switch field  Enter (on passphrase): export  Esc: cancel")
            .fg(COLOR_DARK_GRAY),
    );

    lines
}

fn render_change_protection(
    selected_option: usize,
    passphrase_len: usize,
    confirm_len: usize,
    active_field: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from("Change Config Protection")
            .fg(COLOR_SUCCESS)
            .bold(),
    );
    lines.push(Line::from(""));

    if active_field == 0 {
        // Option selection mode
        let options = ["Set Passphrase", "Remove Passphrase (keyring only)"];
        for (i, label) in options.iter().enumerate() {
            let is_selected = i == selected_option;
            let style = if is_selected {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            };
            lines.push(Line::from(vec![Span::styled(
                format!("{}{}", if is_selected { "▸ " } else { "  " }, label),
                style,
            )]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from("↑/↓ select  Enter: choose  Esc: cancel").fg(COLOR_DARK_GRAY));
    } else {
        // Passphrase input mode — display masked lengths only
        lines.push(Line::from(vec![
            Span::styled(
                if active_field == 1 { "▸ " } else { "  " },
                Style::new().fg(if active_field == 1 {
                    COLOR_SUCCESS
                } else {
                    COLOR_TEXT_DEFAULT
                }),
            ),
            Span::styled(
                "Passphrase: ",
                Style::new().fg(if active_field == 1 {
                    COLOR_SUCCESS
                } else {
                    COLOR_TEXT_DEFAULT
                }),
            ),
            Span::styled(
                "*".repeat(passphrase_len),
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
            Span::styled(
                if active_field == 1 { "▎" } else { "" },
                Style::new().fg(COLOR_SUCCESS),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled(
                if active_field == 2 { "▸ " } else { "  " },
                Style::new().fg(if active_field == 2 {
                    COLOR_SUCCESS
                } else {
                    COLOR_TEXT_DEFAULT
                }),
            ),
            Span::styled(
                "Confirm:    ",
                Style::new().fg(if active_field == 2 {
                    COLOR_SUCCESS
                } else {
                    COLOR_TEXT_DEFAULT
                }),
            ),
            Span::styled("*".repeat(confirm_len), Style::new().fg(COLOR_SOFT_PURPLE)),
            Span::styled(
                if active_field == 2 { "▎" } else { "" },
                Style::new().fg(COLOR_SUCCESS),
            ),
        ]));

        if passphrase_len > 0 && confirm_len > 0 && passphrase_len != confirm_len {
            lines.push(Line::from(""));
            lines.push(
                Line::from("  Passphrases may not match (different lengths)").fg(COLOR_ORANGE),
            );
        }

        lines.push(Line::from(""));
        lines.push(
            Line::from("Tab: next field  Enter (on confirm): save  Esc: cancel")
                .fg(COLOR_DARK_GRAY),
        );
    }

    lines
}

/// The `pnm` command that removes what this wipe deliberately leaves behind.
///
/// Named with the account's own context id when we have it. This screen is the
/// last place that id appears — the wipe takes the config file and the keyring
/// entry holding it with it — so sending the operator away to look it up is
/// sending them somewhere that will not exist in a moment. Hence "first".
///
/// `id` is positional on `pnm contexts delete` (verified against `pnm-cli`'s
/// `ContextCommands`); the placeholder is only for an account that has not been
/// loaded, where naming the wrong context would be worse than naming none.
fn wipe_context_command(context_id: &str) -> String {
    let id = if context_id.trim().is_empty() {
        "<context id>"
    } else {
        context_id
    };
    format!("pnm contexts delete {id}")
}

/// Wrap the volatile-storage warning to the settings panel's width, prefixed so
/// it reads as an aside rather than another selectable row.
///
/// A hand-rolled wrap rather than a dependency: this is the only place in the
/// panel that needs one, and the panel builds `Line`s directly rather than
/// going through a `Paragraph` that could wrap for us.
fn textwrap_warning(warning: &str) -> Vec<String> {
    const WIDTH: usize = 64;
    let mut out = vec![String::from("  ⚠ ")];
    for word in warning.split_whitespace() {
        let current = out.last_mut().expect("seeded with one line");
        if current.chars().count() + word.chars().count() + 1 > WIDTH {
            out.push(format!("    {word}"));
        } else {
            if !current.ends_with(' ') {
                current.push(' ');
            }
            current.push_str(word);
        }
    }
    out
}

#[cfg(test)]
mod wipe_confirm_tests {
    use super::*;

    fn text(lines: &[Line<'static>]) -> String {
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

    /// The wipe takes the config file and the keyring entry with it, so this
    /// screen is the last place the context id appears. A command that made the
    /// operator go and look it up would be sending them somewhere that is about
    /// to stop existing.
    #[test]
    fn the_cleanup_command_names_this_accounts_context() {
        let state = SettingsState {
            context_id: "openvtc".to_string(),
            ..SettingsState::default()
        };
        let out = text(&render_wipe_confirm(&state, ""));
        assert!(out.contains("pnm contexts delete openvtc"), "{out}");
        assert!(!out.contains("<context id>"), "{out}");
    }

    /// `id` is positional on `pnm contexts delete`. A grown `--id` flag would be
    /// a command that fails on paste — the shape that had to be fixed on the
    /// identity pane's `pnm acl update` hint.
    #[test]
    fn the_cleanup_command_passes_the_id_positionally() {
        assert_eq!(
            wipe_context_command("openvtc"),
            "pnm contexts delete openvtc"
        );
        assert!(!wipe_context_command("openvtc").contains("--id"));
    }

    /// A nested context keeps its full path: `pnm` addresses a sub-context by
    /// `<parent>/<id>`, and the leaf alone names a different context or none.
    #[test]
    fn a_nested_context_keeps_its_whole_path() {
        assert_eq!(
            wipe_context_command("acme/eng"),
            "pnm contexts delete acme/eng"
        );
    }

    /// With no account loaded there is no id to name, and inventing one would
    /// point a destructive command at the wrong context.
    #[test]
    fn an_unloaded_account_falls_back_to_a_placeholder() {
        assert_eq!(
            wipe_context_command("  "),
            "pnm contexts delete <context id>"
        );
    }

    /// The screen must keep saying what the wipe does *not* touch. The command
    /// is the remedy; the sentence above it is the fact that makes it needed.
    #[test]
    fn the_screen_still_says_what_survives_the_wipe() {
        let out = text(&render_wipe_confirm(&SettingsState::default(), ""));
        assert!(out.contains("NOT affected"), "{out}");
    }
}

#[cfg(test)]
mod storage_warning_tests {
    use super::textwrap_warning;

    #[test]
    fn warning_wraps_within_the_panel_and_keeps_every_word() {
        let warning = "This profile's keys are lost when this machine reboots and are NOT \
                       on disk. Set a passphrase to store them durably, and export a backup now.";
        let lines = textwrap_warning(warning);
        assert!(lines.len() > 1, "a long warning must wrap");
        for line in &lines {
            assert!(line.chars().count() <= 70, "line too wide: {line}");
        }
        let rejoined = lines.join(" ");
        for word in warning.split_whitespace() {
            assert!(rejoined.contains(word), "wrapping dropped {word}");
        }
    }
}
