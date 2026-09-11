//! The Vetting page (`docs/design/vetting-process.md` §12).
//!
//! Four tabs: our applications to be vetted, requests at our vetter desk, the
//! tickets we have handed out, and the statements we have signed. Copy says
//! "meets the published requirements", never "approved": only the community
//! decides (D12).

use super::panel::Panel;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::{
    main_page::content::{
        AttestForm, CardPreview, ContentPanelState, DeskStage, VETTING_METHODS,
        VETTING_RELATIONSHIPS, VETTING_TICKET_USES, VETTING_WITHDRAWAL_REASONS, VettingMode,
        VettingState, VettingTab, method_label, reason_label, relationship_label,
    },
    state::ConnectionState,
};
use openvtc_core::config::community_context::{ContextKind, ContextOption};
use openvtc_core::display::display_identifier;
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Vetting content panel.
pub struct VettingPanel;

impl Panel for VettingPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        render(&state.vetting)
    }
}

/// The view identifier, so switching mode resets the scroll.
#[must_use]
pub fn mode_id(state: &VettingState) -> &'static str {
    match (&state.mode, state.tab) {
        (VettingMode::List, VettingTab::Applications) => "applications",
        (VettingMode::List, VettingTab::Desk) => "desk",
        (VettingMode::List, VettingTab::Tickets) => "tickets",
        (VettingMode::List, VettingTab::Issued) => "issued",
        (VettingMode::NewApplication { .. }, _) => "new-application",
        (VettingMode::ChooseFace { .. }, _) => "face",
        (VettingMode::RequestVetter { .. }, _) => "request",
        (VettingMode::SendCard { .. }, _) => "card",
        (VettingMode::NewTicket { .. }, _) => "new-ticket",
        (VettingMode::OpenSession { .. }, _) => "session",
        (VettingMode::Attest { .. }, _) => "attest",
        (VettingMode::ConfirmDecline { .. }, _) => "decline",
        (VettingMode::Withdraw { .. }, _) => "withdraw",
    }
}

fn label() -> Style {
    Style::new().fg(COLOR_TEXT_DEFAULT)
}
fn value() -> Style {
    Style::new().fg(COLOR_SOFT_PURPLE)
}
fn dim() -> Style {
    Style::new().fg(COLOR_DARK_GRAY)
}
fn heading(text: impl Into<String>) -> Line<'static> {
    Line::from(text.into()).fg(COLOR_SUCCESS).bold()
}
fn hint(text: impl Into<String>) -> Line<'static> {
    Line::from(text.into()).fg(COLOR_DARK_GRAY)
}

/// A labelled form field, marked when focused. `text` fields show a cursor.
fn field(name: &str, shown: String, focused: bool, text: bool) -> Line<'static> {
    let marker = if focused { "▸ " } else { "  " };
    let mut spans = vec![
        Span::styled(
            marker,
            if focused {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else {
                dim()
            },
        ),
        Span::styled(format!("{name:<22}"), label()),
        Span::styled(shown, value()),
    ];
    if focused && text {
        spans.push(Span::styled("▎", Style::new().fg(COLOR_SUCCESS)));
    } else if focused {
        spans.push(Span::styled("  ←/→", dim()));
    }
    Line::from(spans)
}

/// A context choice, in a line.
fn context_label(option: &ContextOption) -> String {
    let id = &option.context_id;
    match option.kind {
        ContextKind::New => format!("{id}  (a context of its own)"),
        ContextKind::Existing if option.holds_persona_keys => {
            format!("{id}  (this persona's context)")
        }
        ContextKind::Existing => match option.communities.len() {
            0 => format!("{id}  (in use)"),
            1 => format!("{id}  (shared with 1 community)"),
            n => format!("{id}  (shared with {n} communities)"),
        },
        ContextKind::Top => format!("{id}  (top context — nothing kept apart)"),
    }
}

fn tick(on: bool) -> String {
    if on { "[x]" } else { "[ ]" }.to_string()
}

/// Render the Vetting page.
pub fn render(v: &VettingState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    let tab_style = |tab: VettingTab| {
        if v.tab == tab {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            dim()
        }
    };
    let sep = || Span::styled(" | ", dim());
    lines.push(Line::from(vec![
        Span::styled(
            format!(" Applications ({}) ", v.applications.len()),
            tab_style(VettingTab::Applications),
        ),
        sep(),
        Span::styled(
            format!(" Vetter desk ({}) ", v.desk.len()),
            tab_style(VettingTab::Desk),
        ),
        sep(),
        Span::styled(
            format!(" Tickets ({}) ", v.tickets.len()),
            tab_style(VettingTab::Tickets),
        ),
        sep(),
        Span::styled(
            format!(" Issued ({}) ", v.issued.len()),
            tab_style(VettingTab::Issued),
        ),
    ]));
    lines.push(Line::from(""));

    if let Some(message) = &v.status_message {
        super::status::push_status(&mut lines, message, "");
        lines.push(Line::from(""));
    }

    match &v.mode {
        VettingMode::List => match v.tab {
            VettingTab::Applications => applications(&mut lines, v),
            VettingTab::Desk => desk(&mut lines, v),
            VettingTab::Tickets => tickets(&mut lines, v),
            VettingTab::Issued => issued(&mut lines, v),
        },
        VettingMode::NewApplication {
            community,
            persona_index,
            context_options,
            context_index,
            field: f,
        } => {
            lines.push(heading("Apply to be vetted"));
            lines.push(Line::from(""));
            lines.push(hint(
                "The community's DID, and the persona you will join with. The persona is fixed",
            ));
            lines.push(hint(
                "for the whole application: every card is signed by it, and every statement names it.",
            ));
            lines.push(Line::from(""));
            lines.push(field("Community DID", community.clone(), *f == 0, true));
            let persona = v
                .personas
                .get(*persona_index)
                .map(|p| format!("{}  ({})", p.label, p.did))
                .unwrap_or_else(|| "no personas".to_string());
            lines.push(field("Join as", persona, *f == 1, false));
            let context = context_options
                .get(*context_index)
                .map_or_else(|| "—".to_string(), context_label);
            lines.push(field("Context", context, *f == 2, false));
            lines.push(Line::from(""));
            lines.push(hint(
                "The context keeps this community's faces apart from your other communities. A",
            ));
            lines.push(hint(
                "persona minted into a context can only be presented from it.",
            ));
            lines.push(Line::from(""));
            lines.push(hint(
                "Enter: start  Tab: next field  ←/→: choose  Esc: cancel",
            ));
        }
        VettingMode::ChooseFace { faces, index, .. } => {
            lines.push(heading("The face vetters are shown"));
            lines.push(Line::from(""));
            lines.push(hint(
                "A vetter's card is read from this face, and they check it against your documents.",
            ));
            lines.push(hint(
                "It is worn in this community's context, so the community sees the same face when",
            ));
            lines.push(hint(
                "you join. Its values must match your documents exactly, and must not change later.",
            ));
            lines.push(Line::from(""));
            for (i, face) in faces.iter().enumerate() {
                let chosen = i == *index;
                let style = if chosen {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else {
                    label()
                };
                lines.push(Line::from(vec![
                    Span::styled(if chosen { "▸ " } else { "  " }, style),
                    Span::styled(face.name.clone(), style),
                    Span::styled(
                        format!(
                            "  {} attribute{}",
                            face.entries,
                            if face.entries == 1 { "" } else { "s" }
                        ),
                        dim(),
                    ),
                    Span::styled(
                        if face.worn { "  worn now" } else { "" },
                        Style::new().fg(COLOR_SUCCESS),
                    ),
                ]));
            }
            lines.push(Line::from(""));
            lines.push(hint("↑/↓: choose  Enter: wear it  Esc: cancel"));
        }
        VettingMode::RequestVetter {
            vetter,
            code,
            field: f,
            ..
        } => {
            lines.push(heading("Ask a vetter"));
            lines.push(Line::from(""));
            lines.push(hint(
                "A vetter only answers a request carrying their ticket code — ask them for one first.",
            ));
            lines.push(Line::from(""));
            lines.push(field("Vetter DID", vetter.clone(), *f == 0, true));
            lines.push(field("Ticket code", code.clone(), *f == 1, true));
            lines.push(Line::from(""));
            lines.push(hint("Enter: send  Tab: next field  Esc: cancel"));
        }
        VettingMode::SendCard {
            application_id,
            session_id,
            preview,
        } => send_card(&mut lines, v, application_id, session_id, preview.as_ref()),
        VettingMode::NewTicket {
            membership_index,
            uses_index,
            field: f,
        } => {
            lines.push(heading("Hand out a ticket"));
            lines.push(Line::from(""));
            lines.push(hint(
                "A ticket lets one person — or a queue at a desk — ask you. Requests without one",
            ));
            lines.push(hint("are never answered."));
            lines.push(Line::from(""));
            let community = v
                .memberships
                .get(*membership_index)
                .map(|m| m.name.clone())
                .unwrap_or_default();
            lines.push(field("Community", community, *f == 0, false));
            let uses = VETTING_TICKET_USES[(*uses_index).min(VETTING_TICKET_USES.len() - 1)];
            lines.push(field(
                "Admits",
                format!("{uses} request{}", if uses == 1 { "" } else { "s" }),
                *f == 1,
                false,
            ));
            lines.push(Line::from(""));
            lines.push(hint("Enter: issue  Tab: next field  Esc: cancel"));
        }
        VettingMode::OpenSession {
            request_id,
            method_index,
        } => {
            lines.push(heading("Open a session"));
            lines.push(Line::from(""));
            if let Some(row) = v.desk.iter().find(|d| &d.request_id == request_id) {
                lines.push(Line::from(vec![
                    Span::styled("With   ", label()),
                    Span::styled(
                        display_identifier(row.applicant_name.as_deref(), &row.applicant, 256)
                            .into_owned(),
                        value(),
                    ),
                ]));
            }
            lines.push(Line::from(""));
            lines.push(hint(
                "Open it with the person in front of you or on the call: both screens will show a",
            ));
            lines.push(hint(
                "code you read to each other before their card is sent.",
            ));
            lines.push(Line::from(""));
            let method = VETTING_METHODS[(*method_index).min(VETTING_METHODS.len() - 1)];
            lines.push(field(
                "Method",
                method_label(method).to_string(),
                true,
                false,
            ));
            lines.push(Line::from(""));
            lines.push(hint("Enter: open  Esc: cancel"));
        }
        VettingMode::Attest { request_id, form } => attest(&mut lines, v, request_id, form),
        VettingMode::ConfirmDecline { request_id } => {
            lines.push(heading("Decline this request?"));
            lines.push(Line::from(""));
            if let Some(row) = v.desk.iter().find(|d| &d.request_id == request_id) {
                lines.push(Line::from(vec![
                    Span::styled("Applicant  ", label()),
                    Span::styled(
                        display_identifier(row.applicant_name.as_deref(), &row.applicant, 256)
                            .into_owned(),
                        value(),
                    ),
                ]));
            }
            lines.push(Line::from(""));
            lines.push(hint(
                "You never have to give a reason, and the community is not told.",
            ));
            lines.push(Line::from(""));
            lines.push(
                Line::from("y: decline    n: keep it")
                    .fg(COLOR_ORANGE)
                    .bold(),
            );
        }
        VettingMode::Withdraw {
            statement_id,
            reason_index,
        } => {
            lines.push(heading("Withdraw a statement"));
            lines.push(Line::from(""));
            if let Some(row) = v.issued.iter().find(|s| &s.id == statement_id) {
                lines.push(Line::from(vec![
                    Span::styled("About      ", label()),
                    Span::styled(row.applicant.clone(), value()),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("Community  ", label()),
                    Span::styled(row.community.clone(), value()),
                ]));
            }
            lines.push(Line::from(""));
            lines.push(hint(
                "The community stops counting it. If it already helped someone join, the",
            ));
            lines.push(hint("community records the withdrawal for review."));
            lines.push(Line::from(""));
            let reason = VETTING_WITHDRAWAL_REASONS
                [(*reason_index).min(VETTING_WITHDRAWAL_REASONS.len() - 1)];
            lines.push(field(
                "Reason",
                reason_label(reason).to_string(),
                true,
                false,
            ));
            lines.push(Line::from(""));
            lines.push(hint("Enter: withdraw  Esc: cancel"));
        }
    }

    lines
}

fn applications(lines: &mut Vec<Line<'static>>, v: &VettingState) {
    if v.applications.is_empty() {
        lines.push(hint("You are not applying to any community."));
        lines.push(Line::from(""));
        lines.push(hint(
            "A community that vets its members publishes what it requires. Start an application,",
        ));
        lines.push(hint(
            "then ask vetters for their ticket codes and send each a request.",
        ));
        lines.push(Line::from(""));
        lines.push(hint("n: new application"));
        return;
    }
    for (i, app) in v.applications.iter().enumerate() {
        let selected = i == v.selected;
        let style = if selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            label()
        };
        let name = app
            .community_name
            .clone()
            .unwrap_or_else(|| app.community.clone());
        lines.push(Line::from(vec![
            Span::styled(if selected { "▸ " } else { "  " }, style),
            Span::styled(name, style),
            Span::styled(
                format!("  {} statement(s)", app.statements),
                if app.satisfied {
                    Style::new().fg(COLOR_SUCCESS)
                } else {
                    dim()
                },
            ),
        ]));
    }
    let Some(app) = v.applications.get(v.selected) else {
        return;
    };
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Joining as   ", label()),
        Span::styled(app.join_did.clone(), value()),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Requires     ", label()),
        match &app.requirements {
            Some(r) => Span::styled(r.clone(), value()),
            None => Span::styled(
                "not known yet — m asks the community",
                Style::new().fg(COLOR_ORANGE),
            ),
        },
    ]));
    if let Some(progress) = &app.progress {
        lines.push(Line::from(vec![
            Span::styled("Progress     ", label()),
            Span::styled(
                progress.clone(),
                if app.satisfied {
                    Style::new().fg(COLOR_SUCCESS)
                } else {
                    Style::new().fg(COLOR_ORANGE)
                },
            ),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(" Identity shown to vetters").fg(COLOR_SUCCESS));
    lines.push(Line::from(vec![
        Span::styled(format!("  {:<20}", "face"), label()),
        match v.worn_faces.get(&app.id) {
            Some(face) => Span::styled(face.clone(), value()),
            None => Span::styled("f shows or changes it", dim()),
        },
    ]));
    for (claim_type, shown) in &app.identity {
        lines.push(Line::from(vec![
            Span::styled(format!("  {claim_type:<20}"), label()),
            if shown.is_empty() {
                Span::styled(
                    "not shown yet — read from the face with your first card",
                    dim(),
                )
            } else {
                Span::styled(shown.clone(), value())
            },
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(" Vetters").fg(COLOR_SUCCESS));
    if app.requests.is_empty() {
        lines.push(hint("  none yet — r asks a vetter"));
    }
    for request in &app.requests {
        lines.push(Line::from(vec![
            Span::styled("  ", label()),
            Span::styled(
                display_identifier(request.vetter_name.as_deref(), &request.vetter, 60)
                    .into_owned(),
                value(),
            ),
        ]));
        let mut state = vec![Span::styled(format!("    {}", request.state), dim())];
        if let Some(code) = &request.match_code {
            state.push(Span::styled("   code ", label()));
            state.push(Span::styled(
                code.clone(),
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
        }
        lines.push(Line::from(state));
        if let Some((good, line)) = &request.eligibility {
            lines.push(Line::from(Span::styled(
                format!("    {line}"),
                if *good {
                    Style::new().fg(COLOR_SUCCESS)
                } else {
                    Style::new().fg(COLOR_ORANGE)
                },
            )));
        }
    }
    lines.push(Line::from(""));
    lines.push(hint(
        "n: new  f: face  r: ask a vetter  c: send card  m: refresh requirements  Tab: next tab",
    ));
}

fn send_card(
    lines: &mut Vec<Line<'static>>,
    v: &VettingState,
    application_id: &str,
    session_id: &str,
    preview: Option<&CardPreview>,
) {
    lines.push(heading("Send your card"));
    lines.push(Line::from(""));
    let Some(app) = v.applications.iter().find(|a| a.id == application_id) else {
        return;
    };
    let request = app
        .requests
        .iter()
        .find(|r| r.card_session.as_deref() == Some(session_id));
    if let Some(request) = request {
        lines.push(Line::from(vec![
            Span::styled("To      ", label()),
            Span::styled(
                display_identifier(request.vetter_name.as_deref(), &request.vetter, 256)
                    .into_owned(),
                value(),
            ),
        ]));
        if let Some(code) = &request.match_code {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Match code   ", label()),
                Span::styled(code.clone(), Style::new().fg(COLOR_SUCCESS).bold()),
            ]));
            lines.push(Line::from(""));
            lines.push(
                Line::from(
                    "Read this code to the vetter, and hear it read back. Send only if it matches.",
                )
                .fg(COLOR_ORANGE),
            );
        }
    }
    lines.push(Line::from(""));
    let face = v
        .worn_faces
        .get(application_id)
        .cloned()
        .unwrap_or_else(|| "the face this persona wears in the community".to_string());
    let Some(preview) = preview else {
        lines.push(Line::from(vec![
            Span::styled("The card is read from  ", label()),
            Span::styled(face, value()),
        ]));
        lines.push(Line::from(""));
        lines.push(hint(
            "Enter asks your VTA what that face would show this vetter. Nothing leaves until you",
        ));
        lines.push(hint("have seen it and pressed Enter again."));
        lines.push(Line::from(""));
        lines.push(hint(
            "Enter: preview  Esc: not now (f on the application changes the face)",
        ));
        return;
    };
    lines.push(Line::from(" The card will show").fg(COLOR_SUCCESS));
    for (claim_type, shown) in &preview.claims {
        lines.push(Line::from(vec![
            Span::styled(format!("  {claim_type:<20}"), label()),
            Span::styled(shown.clone(), value()),
        ]));
    }
    lines.push(Line::from(""));
    if let Some(problem) = &preview.problem {
        lines.push(Line::from(problem.clone()).fg(COLOR_WARNING_ACCESSIBLE_RED));
        lines.push(Line::from(""));
        lines.push(hint(
            "Esc, fix the face under My Identity (or choose another with f), then preview again.",
        ));
        return;
    }
    lines.push(hint(
        "No document numbers or images are sent: the vetter looks at your document, not a copy.",
    ));
    lines.push(Line::from(""));
    lines.push(hint("Enter: approve, sign and send  Esc: not now"));
}

fn desk(lines: &mut Vec<Line<'static>>, v: &VettingState) {
    if v.desk.is_empty() {
        lines.push(hint("No one has asked you to vet them."));
        lines.push(Line::from(""));
        lines.push(hint(
            "Requests arrive only with one of your tickets — hand them out from the Tickets tab.",
        ));
        return;
    }
    for (i, row) in v.desk.iter().enumerate() {
        let selected = i == v.selected;
        let style = if selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            label()
        };
        lines.push(Line::from(vec![
            Span::styled(if selected { "▸ " } else { "  " }, style),
            Span::styled(
                display_identifier(row.applicant_name.as_deref(), &row.applicant, 60).into_owned(),
                style,
            ),
            Span::styled(format!("  {}", row.state), dim()),
        ]));
    }
    let Some(row) = v.desk.get(v.selected) else {
        return;
    };
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Community    ", label()),
        Span::styled(row.community.clone(), value()),
    ]));
    if let Some(message) = &row.message {
        lines.push(Line::from(vec![
            Span::styled("Their note   ", label()),
            Span::styled(message.clone(), Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));
    }
    if let Some(method) = &row.method {
        lines.push(Line::from(vec![
            Span::styled("Method       ", label()),
            Span::styled(method.clone(), value()),
        ]));
    }
    if let Some(code) = &row.match_code {
        lines.push(Line::from(vec![
            Span::styled("Match code   ", label()),
            Span::styled(code.clone(), Style::new().fg(COLOR_SUCCESS).bold()),
        ]));
    }
    if !row.claims.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(" Their card").fg(COLOR_SUCCESS));
        for (claim_type, shown) in &row.claims {
            lines.push(Line::from(vec![
                Span::styled(format!("  {claim_type:<20}"), label()),
                Span::styled(shown.clone(), value()),
            ]));
        }
    }
    lines.push(Line::from(""));
    let keys = match row.stage {
        DeskStage::Accepted => "o: open session  x: decline  Tab: next tab",
        DeskStage::Session => "o: reopen session  x: decline  Tab: next tab",
        DeskStage::Card => "a: check and attest  x: decline  Tab: next tab",
        DeskStage::Closed => "Tab: next tab",
    };
    lines.push(hint(keys));
}

fn attest(lines: &mut Vec<Line<'static>>, v: &VettingState, request_id: &str, form: &AttestForm) {
    lines.push(heading("Check the person, then attest"));
    lines.push(Line::from(""));
    let Some(row) = v.desk.iter().find(|d| d.request_id == request_id) else {
        return;
    };
    lines.push(Line::from(vec![
        Span::styled("Applicant    ", label()),
        Span::styled(
            display_identifier(row.applicant_name.as_deref(), &row.applicant, 256).into_owned(),
            value(),
        ),
    ]));
    if let Some(code) = &row.match_code {
        lines.push(Line::from(vec![
            Span::styled("Match code   ", label()),
            Span::styled(code.clone(), Style::new().fg(COLOR_SUCCESS).bold()),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(" Their card").fg(COLOR_SUCCESS));
    for (claim_type, shown) in &row.claims {
        lines.push(Line::from(vec![
            Span::styled(format!("  {claim_type:<20}"), label()),
            Span::styled(shown.clone(), value()),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(hint(
        "Look at their document in person or on camera. Check it appears genuine, the photo is",
    ));
    lines.push(hint(
        "the person you are talking to, and the name matches the card. Do not keep a copy.",
    ));
    lines.push(Line::from(""));

    let method = VETTING_METHODS[form.method_index.min(VETTING_METHODS.len() - 1)];
    lines.push(field(
        "Method",
        method_label(method).to_string(),
        form.field == 0,
        false,
    ));
    let documentation = v
        .documentation
        .get(form.documentation_index)
        .cloned()
        .unwrap_or_default();
    lines.push(field(
        "Documentation",
        documentation,
        form.field == 1,
        false,
    ));
    let relationship =
        VETTING_RELATIONSHIPS[form.relationship_index.min(VETTING_RELATIONSHIPS.len() - 1)];
    lines.push(field(
        "Relationship",
        relationship_label(relationship).to_string(),
        form.field == 2,
        false,
    ));
    lines.push(field(
        "We read the code",
        format!(
            "{}  we read the match code to each other",
            tick(form.liveness_confirmed)
        ),
        form.field == 3,
        false,
    ));
    lines.push(Line::from(""));
    lines.push(Line::from(format!(
        "  \"I attest that I verified, by {}, that the person controlling {} presented",
        method_label(method),
        row.applicant
    )));
    lines.push(Line::from(format!(
        "  documentation matching the {} above. I did not retain copies of it. I understand",
        row.required_claims.join(", "),
    )));
    lines.push(Line::from(format!(
        "  this statement is attributable to me within {}.\"",
        row.community
    )));
    lines.push(field(
        "I attest",
        format!("{}  sign this statement as me", tick(form.attested)),
        form.field == 4,
        false,
    ));
    lines.push(Line::from(""));
    lines.push(hint(
        "↑/↓: item  ←/→: choose  Space: tick  Enter: sign and send  Esc: cancel",
    ));
}

fn tickets(lines: &mut Vec<Line<'static>>, v: &VettingState) {
    if v.tickets.is_empty() {
        lines.push(hint("You have no tickets out."));
        lines.push(Line::from(""));
        lines.push(hint(
            "t: hand out a ticket — read the code to someone, or copy it to send them",
        ));
        return;
    }
    for (i, row) in v.tickets.iter().enumerate() {
        let selected = i == v.selected;
        let style = if selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            label()
        };
        lines.push(Line::from(vec![
            Span::styled(if selected { "▸ " } else { "  " }, style),
            Span::styled(
                row.code.clone(),
                if row.live {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else {
                    dim()
                },
            ),
            Span::styled(format!("  {}", row.community), style),
            Span::styled(
                if row.live {
                    format!("  {} left, until {}", row.uses_left, row.expires)
                } else {
                    "  spent or expired".to_string()
                },
                dim(),
            ),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(hint(
        "t: new ticket  y: copy code  d: delete  Tab: next tab",
    ));
}

fn issued(lines: &mut Vec<Line<'static>>, v: &VettingState) {
    if v.issued.is_empty() {
        lines.push(hint("You have not signed any vetting statements."));
        return;
    }
    for (i, row) in v.issued.iter().enumerate() {
        let selected = i == v.selected;
        let style = if selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            label()
        };
        lines.push(Line::from(vec![
            Span::styled(if selected { "▸ " } else { "  " }, style),
            Span::styled(row.applicant.clone(), style),
        ]));
        lines.push(Line::from(vec![
            Span::styled(
                format!(
                    "    {} · {} · {} → {}",
                    row.community, row.method, row.issued, row.valid_until
                ),
                dim(),
            ),
            match &row.withdrawal {
                Some(w) => Span::styled(format!("  {w}"), Style::new().fg(COLOR_ORANGE)),
                None => Span::styled("", dim()),
            },
        ]));
    }
    lines.push(Line::from(""));
    lines.push(hint("w: withdraw  Tab: next tab"));
}
