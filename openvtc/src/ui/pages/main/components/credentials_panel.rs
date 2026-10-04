use super::panel::Panel;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::{
    main_page::content::{
        ContentPanelState, CredentialTab, CredentialsMode, CredentialsState, RelationshipsState,
    },
    state::ConnectionState,
};
use crate::ui::badges;
use openvtc_core::display::display_identifier;
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Credentials content panel.
pub struct CredentialsPanel;

impl Panel for CredentialsPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        render(&state.credentials, &state.relationships)
    }
}

/// Render the credentials panel content.
pub fn render(
    credentials: &CredentialsState,
    relationships: &RelationshipsState,
) -> Vec<Line<'static>> {
    match &credentials.mode {
        CredentialsMode::Detail { index } => render_detail(credentials, *index),
        CredentialsMode::NewRequest {
            relationship_index,
            reason_input,
        } => render_new_request(relationships, *relationship_index, reason_input),
        CredentialsMode::List => render_list(credentials),
    }
}

fn render_list(state: &CredentialsState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    if let Some(msg) = &state.status_message {
        super::status::push_status(&mut lines, msg, "");
        lines.push(Line::from(""));
    }
    if state.retired_vrcs > 0 {
        lines.push(
            Line::from(format!(
                "⚠ {} stored relationship credential(s) pre-date DTG Credentials v1 and were \
                 set aside — request fresh ones from those relationships.",
                state.retired_vrcs
            ))
            .fg(COLOR_ORANGE),
        );
        lines.push(Line::from(""));
    }

    let active_list = state.active_list();

    // Tab bar
    let tab_style = |tab: CredentialTab| {
        if state.selected_tab == tab {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_DARK_GRAY)
        }
    };
    let sep = || Span::styled(" | ", Style::new().fg(COLOR_DARK_GRAY));
    lines.push(Line::from(vec![
        Span::styled(
            format!(" Received ({}) ", state.received.len()),
            tab_style(CredentialTab::Received),
        ),
        sep(),
        Span::styled(
            format!(" Issued ({}) ", state.issued.len()),
            tab_style(CredentialTab::Issued),
        ),
        sep(),
        Span::styled(
            format!(" Membership ({}) ", state.membership.len()),
            tab_style(CredentialTab::Membership),
        ),
        sep(),
        Span::styled(
            format!(" Vetting ({}) ", state.vetting.len()),
            tab_style(CredentialTab::Vetting),
        ),
    ]));
    lines.push(Line::from(""));

    if active_list.is_empty() {
        lines.push(Line::from("No credentials").fg(COLOR_DARK_GRAY));
    } else {
        for (i, vrc) in active_list.iter().enumerate() {
            let is_selected = i == state.selected_index;
            let prefix = if is_selected { "▸ " } else { "  " };
            let style = if is_selected {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            };

            // What it is first: four rows from one community are told apart
            // by their kind and who they were issued to, not by an issuer
            // repeated four times beside two timestamps.
            let kind = vrc.kind.clone().unwrap_or_else(|| "Credential".to_string());
            // Precedence: user alias → verified agent name → the DID itself
            // (matches the relationships panel).
            let party = vrc
                .alias
                .clone()
                .or_else(|| vrc.remote_agent_name.clone())
                .unwrap_or_else(|| display_identifier(None, &vrc.remote_p_did, 40).into_owned());

            let mut row = vec![
                Span::styled(prefix, style),
                Span::styled(format!("{:<26}", truncate(&kind, 25)), style),
                Span::styled(
                    format!("{:<34}", truncate(&party, 33)),
                    Style::new().fg(COLOR_SOFT_PURPLE),
                ),
            ];
            // Which of your personas holds it — the other half of telling two
            // memberships of one community apart.
            if let Some(persona) = &vrc.subject_label {
                row.push(Span::styled(
                    format!("to {:<14}", truncate(persona, 13)),
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ));
            }
            if let Some(note) = &vrc.note {
                row.push(Span::styled(
                    format!("{note}  "),
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ));
            }
            let validity_style = if vrc.status == "valid" {
                Style::new().fg(COLOR_DARK_GRAY)
            } else {
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED)
            };
            row.push(Span::styled(
                match (&vrc.validity, &vrc.valid_until) {
                    (validity, _) if !validity.is_empty() => validity.clone(),
                    (_, Some(until)) => format!("{} → {until}", vrc.valid_from),
                    (_, None) => vrc.valid_from.clone(),
                },
                validity_style,
            ));
            if vrc.post_quantum {
                row.push(Span::raw("  "));
                row.push(badges::pqc());
            }
            lines.push(Line::from(row));
        }
    }

    lines.push(Line::from(""));
    // The badge is a promise about cryptography, so the page says once what it
    // means rather than leaving the reader to guess from four letters.
    if active_list.iter().any(|v| v.post_quantum) {
        lines.push(Line::from(vec![
            badges::pqc(),
            Span::styled(
                format!(" {}", badges::PQC_MEANING),
                Style::new().fg(COLOR_DARK_GRAY),
            ),
        ]));
    }
    lines.push(
        Line::from("Tab: switch tab  ↑/↓ navigate  Enter: details  n: request VRC")
            .fg(COLOR_DARK_GRAY),
    );

    lines
}

fn render_detail(state: &CredentialsState, index: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    let active_list = state.active_list();

    let Some(vrc) = active_list.get(index) else {
        lines.push(Line::from("Credential not found").fg(COLOR_WARNING_ACCESSIBLE_RED));
        return lines;
    };

    lines.push(Line::from("Credential Details").fg(COLOR_SUCCESS).bold());
    lines.push(Line::from(""));

    // Headline: what this credential asserts, and whether it is currently in
    // its validity window.
    let kind = vrc.kind.clone().unwrap_or_else(|| "Credential".to_string());
    let status_style = if vrc.status == "valid" {
        Style::new().fg(COLOR_SUCCESS)
    } else {
        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED)
    };
    lines.push(Line::from(vec![
        Span::styled(kind, Style::new().fg(COLOR_TEXT_DEFAULT).bold()),
        Span::styled("  ·  ", Style::new().fg(COLOR_DARK_GRAY)),
        Span::styled(vrc.status.clone(), status_style),
    ]));
    lines.push(Line::from(""));

    // Who issued it and who it is about. `Contact`/`Agent name`/`Remote DID`
    // used to sit alongside these naming the *same* party three more ways; the
    // full DIDs are in the raw credential below, so the summary keeps names.
    let party = |alias: Option<&str>, name: Option<&str>, did: &str| -> String {
        let resolved = display_identifier(name, did, 256).into_owned();
        match alias {
            // An explicit alias outranks a resolved name, but both are useful
            // here: the alias is what you call them, the name is verifiable.
            Some(a) if a != resolved => format!("{a}  ·  {resolved}"),
            _ => resolved,
        }
    };

    lines.push(Line::from(vec![
        Span::styled("Issued by   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(
            party(
                vrc.alias.as_deref(),
                vrc.issuer_agent_name.as_deref(),
                &vrc.issuer,
            ),
            Style::new().fg(COLOR_SOFT_PURPLE),
        ),
    ]));

    let mut about = vec![
        Span::styled("About       ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(
            display_identifier(vrc.subject_agent_name.as_deref(), &vrc.subject, 256).into_owned(),
            Style::new().fg(COLOR_SOFT_PURPLE),
        ),
    ];
    if vrc.subject_is_self {
        about.push(Span::styled("  (you)", Style::new().fg(COLOR_DARK_GRAY)));
    }
    lines.push(Line::from(about));

    lines.push(Line::from(vec![
        Span::styled("Valid       ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(vrc.validity.clone(), Style::new().fg(COLOR_TEXT_DEFAULT)),
    ]));
    lines.push(Line::from(if vrc.post_quantum {
        vec![
            Span::styled("Signature   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            badges::pqc(),
            Span::styled(
                format!("  {}", badges::PQC_MEANING),
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
        ]
    } else {
        vec![
            Span::styled("Signature   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled(
                "classical only — not post-quantum",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
        ]
    }));
    for (label, value) in &vrc.facts {
        lines.push(Line::from(vec![
            Span::styled(format!("{label:<12}"), Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled(value.clone(), Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled("ID          ", Style::new().fg(COLOR_DARK_GRAY)),
        Span::styled(vrc.vrc_id.clone(), Style::new().fg(COLOR_DARK_GRAY)),
    ]));

    // Raw credential JSON — pretty-printed lazily, only when this detail view
    // is rendered (not eagerly per credential on every config mutation).
    lines.push(Line::from(""));
    lines.push(Line::from(" Raw Credential").fg(COLOR_SUCCESS).bold());
    lines.push(Line::from(""));
    let raw_json = vrc.raw_json.to_pretty_json();
    for json_line in raw_json.lines() {
        lines.push(Line::from(format!("  {}", json_line)).fg(COLOR_DARK_GRAY));
    }

    lines.push(Line::from(""));
    // A pending removal confirmation replaces the footer hint (R25).
    if state.confirm_delete.is_some() {
        lines.push(
            Line::from("Remove this credential?   y: confirm    n: cancel")
                .fg(COLOR_ORANGE)
                .bold(),
        );
    } else if state.selected_tab.allows_local_removal() {
        lines.push(Line::from("d: remove  c: copy JSON  Esc: back").fg(COLOR_DARK_GRAY));
    } else {
        lines.push(Line::from("c: copy JSON  Esc: back").fg(COLOR_DARK_GRAY));
    }

    lines
}

fn render_new_request(
    relationships: &RelationshipsState,
    relationship_index: usize,
    reason_input: &str,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from("Request VRC — Select Relationship")
            .fg(COLOR_SUCCESS)
            .bold(),
    );
    lines.push(Line::from(""));

    let established: Vec<_> = relationships
        .relationships
        .iter()
        .filter(|r| r.state == "Established")
        .collect();

    if established.is_empty() {
        lines.push(
            Line::from("No established relationships available.").fg(COLOR_WARNING_ACCESSIBLE_RED),
        );
        lines.push(Line::from(""));
        lines.push(Line::from("Esc: back").fg(COLOR_DARK_GRAY));
        return lines;
    }

    for (i, rel) in established.iter().enumerate() {
        let is_selected = i == relationship_index;
        let prefix = if is_selected { "▸ " } else { "  " };
        let style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };

        // Precedence: user alias → verified agent name → the DID itself.
        let display_name = rel
            .alias
            .as_deref()
            .or(rel.agent_name.as_deref())
            .unwrap_or(&rel.remote_p_did)
            .to_string();

        lines.push(Line::from(vec![
            Span::styled(prefix, style),
            Span::styled(display_name, style),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Reason: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(reason_input.to_string(), Style::new().fg(COLOR_SOFT_PURPLE)),
        Span::styled("▎", Style::new().fg(COLOR_SUCCESS)),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from("↑/↓ select  Enter: send request  Esc: cancel").fg(COLOR_DARK_GRAY));

    lines
}

/// Cut `text` to `max` characters for a list column, marking the cut so a
/// clipped value never passes for a whole one.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let kept: String = text.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::content::{RawCredential, VrcSummary};
    use std::sync::Arc;

    fn row(kind: &str, persona: &str, post_quantum: bool) -> VrcSummary {
        VrcSummary {
            vrc_id: "id".into(),
            remote_p_did: "did:example:vtc".into(),
            remote_agent_name: None,
            raw_json: RawCredential::Value(Arc::new(serde_json::Value::Null)),
            alias: Some("first-vtc".into()),
            issuer: "did:example:vtc".into(),
            issuer_agent_name: None,
            subject: "did:example:me".into(),
            subject_agent_name: None,
            valid_from: "2026-10-03T13:29:25Z".into(),
            valid_until: None,
            kind: Some(kind.into()),
            subject_is_self: true,
            subject_label: Some(persona.into()),
            post_quantum,
            validity: "3 Oct 2026 → 2 Nov 2026 · 29 days left".into(),
            status: "valid".into(),
            note: None,
            facts: Vec::new(),
        }
    }

    fn text(lines: &[Line<'_>]) -> String {
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

    /// Two memberships of one community are told apart by what they are and
    /// whose they are, and a post-quantum signature is marked and explained.
    #[test]
    fn a_row_says_what_it_is_whose_it_is_and_how_it_is_signed() {
        let state = CredentialsState {
            selected_tab: CredentialTab::Membership,
            membership: vec![
                row("Membership", "alice", true),
                row("Role: vetter", "bob", false),
            ]
            .into(),
            ..CredentialsState::default()
        };
        let shown = text(&render_list(&state));
        let line = |needle: &str| {
            shown
                .lines()
                .find(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle} not shown:\n{shown}"))
                .to_string()
        };
        // "Membership" alone also names the tab; the selected row is marked.
        let membership = line("▸ Membership");
        assert!(membership.contains("to alice"), "{membership}");
        assert!(membership.contains("29 days left"), "{membership}");
        assert!(membership.contains("PQC-SIGNED"), "{membership}");
        let role = line("Role: vetter");
        assert!(
            role.contains("to bob") && !role.contains("PQC-SIGNED"),
            "{role}"
        );
        // The legend, once.
        assert_eq!(shown.matches(badges::PQC_MEANING).count(), 1, "{shown}");
    }
}
