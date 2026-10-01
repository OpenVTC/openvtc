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

    let active_list = match state.selected_tab {
        CredentialTab::Received => &state.received,
        CredentialTab::Issued => &state.issued,
        CredentialTab::Membership => &state.membership,
    };

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

            // Precedence: user alias → verified agent name → the DID itself
            // (matches the relationships panel).
            let display_name = vrc
                .alias
                .as_deref()
                .or(vrc.remote_agent_name.as_deref())
                .unwrap_or(&vrc.remote_p_did)
                .to_string();

            let date_display = if let Some(until) = &vrc.valid_until {
                format!("{} → {}", vrc.valid_from, until)
            } else {
                vrc.valid_from.clone()
            };

            lines.push(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(display_name, style),
                Span::styled("  ", Style::default()),
                Span::styled(date_display, Style::new().fg(COLOR_DARK_GRAY)),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(
        Line::from("Tab: switch tab  ↑/↓ navigate  Enter: details  n: request VRC")
            .fg(COLOR_DARK_GRAY),
    );

    lines
}

fn render_detail(state: &CredentialsState, index: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    let active_list = match state.selected_tab {
        CredentialTab::Received => &state.received,
        CredentialTab::Issued => &state.issued,
        CredentialTab::Membership => &state.membership,
    };

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
    } else {
        lines.push(Line::from("d: remove  c: copy JSON  Esc: back").fg(COLOR_DARK_GRAY));
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
