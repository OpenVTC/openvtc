//! The Vetting page (`docs/design/vetting-process.md` §12.3).
//!
//! Two tabs, for the two roles a person holds here: **Applications**, where
//! they are being vetted, and the **Vetting desk**, where they vet. The desk
//! has three views — the requests that have arrived, the tickets handed out
//! that let them arrive, and the statements signed — under a header saying
//! which communities made this persona a vetter and until when.
//!
//! That header is the only place a vetter's own `vetter` role credential is
//! visible. It gates every ticket and is presented to every applicant, and
//! before it existed the applicant could see it and its holder could not.
//!
//! Copy says "meets the published requirements", never "approved": only the
//! community decides (D12).

use super::panel::Panel;
use super::qr::{QrError, qr_lines};
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::{
    main_page::content::{
        AttestForm, CardPreview, ContentPanelState, DIRECTORY_FIELDS, DIRECTORY_LABELS,
        DIRECTORY_METHODS, DeskStage, DeskView, DirectoryView, EVENT_LABELS, EventForm, LineTone,
        PROFILE_FIELDS, PROFILE_LABELS, VETTING_METHODS, VETTING_RELATIONSHIPS,
        VETTING_TICKET_USES, VETTING_WITHDRAWAL_REASONS, VetterProfileForm, VettingMode,
        VettingState, VettingTab, method_label, reason_label, relationship_label,
    },
    state::ConnectionState,
};
use openvtc_core::config::community_context::ContextOption;
use openvtc_core::display::display_identifier;
use openvtc_core::vetting::registry::event_line;
use ratatui::{
    style::{Color, Style, Stylize},
    text::{Line, Span},
};
use vta_sdk::protocols::vetting::VettingMethod;

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
        // Each desk view scrolls on its own: they are different lists of
        // different lengths, and carrying one's offset into the next lands
        // somewhere arbitrary.
        (VettingMode::List, VettingTab::Desk) => match state.desk_view {
            DeskView::Requests => "desk",
            DeskView::Tickets => "tickets",
            DeskView::Issued => "issued",
        },
        (VettingMode::NewApplication { .. }, _) => "new-application",
        (VettingMode::ChooseFace { .. }, _) => "face",
        (VettingMode::RequestVetter { .. }, _) => "request",
        (VettingMode::Directory(_), _) => "directory",
        (VettingMode::Profile(form), _) if form.event.is_some() => "profile-event",
        (VettingMode::Profile(_), _) => "profile",
        (VettingMode::Resend { .. }, _) => "resend",
        (VettingMode::SendCard { .. }, _) => "card",
        (VettingMode::NewTicket { .. }, _) => "new-ticket",
        (VettingMode::ShowTicket { .. }, _) => "show-ticket",
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

fn tick(on: bool) -> String {
    if on { "[x]" } else { "[ ]" }.to_string()
}

fn tone(tone: LineTone) -> Style {
    match tone {
        LineTone::Good => Style::new().fg(COLOR_SUCCESS),
        LineTone::Caution => Style::new().fg(COLOR_ORANGE),
        LineTone::Bad => Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
    }
}

/// A community's accent as a swatch before its name, or nothing.
///
/// The colour is data about the community — the accent it publishes in its
/// branding — so it is drawn as that literal colour rather than mapped through
/// the theme. It identifies; it carries no meaning a person has to read, and the
/// name beside it is always shown.
pub(crate) fn accent_swatch(accent: Option<(u8, u8, u8)>) -> Span<'static> {
    match accent {
        Some((r, g, b)) => Span::styled("● ", Style::new().fg(Color::Rgb(r, g, b))),
        None => Span::raw(""),
    }
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
    // Two tabs, for the two roles: being vetted, and vetting. The desk's own
    // count is the one that wants attention — requests waiting on us.
    lines.push(Line::from(vec![
        Span::styled(
            format!(" Applications ({}) ", v.applications.len()),
            tab_style(VettingTab::Applications),
        ),
        sep(),
        Span::styled(
            format!(" Vetting desk ({}) ", v.desk.len()),
            tab_style(VettingTab::Desk),
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
            VettingTab::Desk => {
                standing(&mut lines, v);
                desk_views(&mut lines, v);
                match v.desk_view {
                    DeskView::Requests => desk(&mut lines, v),
                    DeskView::Tickets => tickets(&mut lines, v),
                    DeskView::Issued => issued(&mut lines, v),
                }
            }
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
                .map_or_else(|| "—".to_string(), ContextOption::summary);
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
            ticket,
            note,
            field: f,
            ..
        } => {
            lines.push(heading("Ask a vetter"));
            lines.push(Line::from(""));
            lines.push(hint(
                "A vetter only answers a request carrying their ticket: a code they read to you, or",
            ));
            lines.push(hint(
                "the link in their QR code. Pasting that link fills in both fields.",
            ));
            if let Some(note) = note {
                lines.push(Line::from(""));
                lines.push(Line::from(note.clone()).fg(COLOR_ORANGE));
            }
            lines.push(Line::from(""));
            lines.push(field("Vetter DID", vetter.clone(), *f == 0, true));
            let shown = if ticket.is_some() && code.is_empty() {
                "scanned ticket, from the link".to_string()
            } else {
                code.clone()
            };
            lines.push(field("Ticket code", shown, *f == 1, true));
            lines.push(Line::from(""));
            lines.push(hint("Enter: send  Tab: next field  Esc: cancel"));
        }
        VettingMode::Directory(view) => directory(&mut lines, v, view),
        VettingMode::Profile(form) => match &form.event {
            Some(event) => event_form(&mut lines, event),
            None => profile(&mut lines, v, form),
        },
        VettingMode::Resend { index } => {
            lines.push(heading("Ask for your vetter credential again"));
            lines.push(Line::from(""));
            lines.push(hint(
                "If a community named you a vetter but the credential never reached you, or you lost",
            ));
            lines.push(hint(
                "it, the community can send it again. It refuses if it has not named you a vetter.",
            ));
            lines.push(Line::from(""));
            let mut line = field(
                "Community",
                v.resend_candidates
                    .get(*index)
                    .map(|m| m.name.clone())
                    .unwrap_or_default(),
                true,
                false,
            );
            if let Some(m) = v.resend_candidates.get(*index) {
                line.spans.insert(2, accent_swatch(m.accent));
            }
            lines.push(line);
            lines.push(Line::from(""));
            lines.push(hint("Enter: ask  ←/→: choose  Esc: cancel"));
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
        VettingMode::ShowTicket { index } => show_ticket(&mut lines, v, *index),
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
        // You apply and vet *as* a persona, so with none there is nothing to
        // start yet. Guide to creating one in the panel rather than offering an
        // "n: new application" key that only refuses — the same guard the runtime
        // handler applies (`vetting_actions::StartApplication`).
        if v.personas.is_empty() {
            lines.push(hint("You have no persona yet."));
            lines.push(Line::from(""));
            lines.push(hint(
                "You apply and vet as a persona — the DID a community vets. Create one under",
            ));
            lines.push(hint(
                "My Identity, and vetting comes online automatically (no restart).",
            ));
            return;
        }
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
            accent_swatch(app.accent),
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
        // Shortened at the SCID, not the tail: the host and path are what
        // distinguish this persona from the next one on the same server.
        Span::styled(
            openvtc_core::display::shorten_webvh(&app.join_did, 4).into_owned(),
            value(),
        ),
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
    if let Some(next) = &app.next_step {
        lines.push(Line::from(vec![
            Span::styled("Next         ", label()),
            Span::styled(next.clone(), Style::new().fg(COLOR_SUCCESS).bold()),
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
        if let Some((line_tone, line)) = &request.grant {
            lines.push(Line::from(Span::styled(
                format!("    {line}"),
                tone(*line_tone),
            )));
        }
    }
    lines.push(Line::from(""));
    lines.push(hint(
        "n: new  f: face  r: ask a vetter  v: find vetters  c: send card  m: refresh requirements",
    ));
    lines.push(hint(
        "j: join this community — the join this application was made for",
    ));
    lines.push(hint("Tab: your vetting desk"));
}

fn directory(lines: &mut Vec<Line<'static>>, v: &VettingState, view: &DirectoryView) {
    lines.push(heading("Find a vetter"));
    lines.push(Line::from(""));
    lines.push(hint(
        "Vetters who chose to be listed, narrowed to what suits you. Finding one is not enough:",
    ));
    lines.push(hint(
        "ask them for a ticket (each says how), then send your request with it.",
    ));
    lines.push(Line::from(""));
    let f = view.field;
    let community = v.directory_communities.get(view.community_index);
    let row = |i: usize| DIRECTORY_LABELS[i];
    let mut line = field(
        row(0),
        community.map(|c| c.name.clone()).unwrap_or_default(),
        f == 0,
        false,
    );
    if let Some(c) = community {
        line.spans.insert(2, accent_swatch(c.accent));
    }
    lines.push(line);
    lines.push(field(row(1), view.filter.language.clone(), f == 1, true));
    lines.push(field(row(2), view.filter.country.clone(), f == 2, true));
    lines.push(field(row(3), view.filter.region.clone(), f == 3, true));
    lines.push(field(row(4), view.filter.city.clone(), f == 4, true));
    let method = DIRECTORY_METHODS[view.method_index.min(DIRECTORY_METHODS.len() - 1)];
    lines.push(field(
        row(5),
        method.map_or("any", method_label).to_string(),
        f == 5,
        false,
    ));
    lines.push(field(row(6), view.filter.event_from.clone(), f == 6, true));
    lines.push(field(row(7), view.filter.event_to.clone(), f == 7, true));
    lines.push(field(row(8), view.filter.event_name.clone(), f == 8, true));
    lines.push(hint(
        "  Language is a tag such as en or de, country a code such as CZ, dates YYYY-MM-DD.",
    ));
    lines.push(hint("  Leave a filter empty for any."));
    lines.push(Line::from(""));

    if view.pending.is_some() {
        lines.push(Line::from("Asking the community…").fg(COLOR_ORANGE));
    }
    if let Some(error) = &view.error {
        lines.push(Line::from(error.clone()).fg(COLOR_WARNING_ACCESSIBLE_RED));
    }
    if view.searched && view.pending.is_none() && view.error.is_none() && view.results.is_empty() {
        lines.push(hint("No listed vetter matches. Fewer filters find more."));
    }
    for (i, row) in view.results.iter().enumerate() {
        let selected = view.result_index() == Some(i);
        let style = if selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            label()
        };
        lines.push(Line::from(vec![
            Span::styled(if selected { "▸ " } else { "  " }, style),
            Span::styled(row.name.clone(), style),
            Span::styled(
                format!("  {}", display_identifier(None, &row.did, 48)),
                dim(),
            ),
        ]));
        let mut about = vec![format!("speaks {}", row.languages)];
        about.extend(row.location.clone());
        about.push(row.methods.clone());
        lines.push(Line::from(Span::styled(
            format!("    {}", about.join(" · ")),
            value(),
        )));
        lines.push(Line::from(Span::styled(
            format!("    accepts {}", row.documentation),
            value(),
        )));
        if let Some(availability) = &row.availability {
            lines.push(Line::from(Span::styled(
                format!("    available {availability}"),
                value(),
            )));
        }
        for event in &row.events {
            lines.push(Line::from(Span::styled(format!("    at {event}"), value())));
        }
        lines.push(Line::from(Span::styled(
            format!(
                "    getting a ticket: {}",
                row.contact_hint
                    .as_deref()
                    .unwrap_or("they have not said — ask them in person or through the community")
            ),
            Style::new().fg(COLOR_TEXT_DEFAULT),
        )));
        lines.push(Line::from(Span::styled(
            format!("    named a vetter until {}", row.grant_until),
            dim(),
        )));
    }
    lines.push(Line::from(""));
    if view.searched {
        let more = if view.next_cursor.is_some() {
            "  n: next page"
        } else {
            "  last page"
        };
        let back = if view.cursors.len() > 1 {
            "  p: previous page"
        } else {
            ""
        };
        lines.push(hint(format!(
            "Page {}{more}{back}",
            view.cursors.len().max(1)
        )));
    }
    lines.push(hint(if f >= DIRECTORY_FIELDS {
        "Enter or a: ask this vetter  ↑/↓: move  Esc: back"
    } else {
        "Enter: search  ↑/↓ or Tab: move  ←/→: choose  Esc: back"
    }));
}

fn profile(lines: &mut Vec<Line<'static>>, v: &VettingState, form: &VetterProfileForm) {
    lines.push(heading("Your vetter profile"));
    lines.push(Line::from(""));
    lines.push(hint(
        "What applicants see when they look for a vetter. Being listed is your choice: unlisted,",
    ));
    lines.push(hint(
        "the community keeps the profile, and only people you give a ticket can reach you.",
    ));
    if let Some((line_tone, line)) = &form.state_line {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(line.clone(), tone(*line_tone))));
    }
    lines.push(Line::from(""));
    let f = form.field;
    let d = &form.draft;
    let membership = v.memberships.get(form.membership_index);
    // Each row's label comes from `PROFILE_LABELS`, the same array a refused
    // draft names its row in and the cursor jump resolves against.
    let row = |i: usize| PROFILE_LABELS[i];
    let mut line = field(
        row(0),
        membership.map(|m| m.name.clone()).unwrap_or_default(),
        f == 0,
        false,
    );
    if let Some(m) = membership {
        line.spans.insert(2, accent_swatch(m.accent));
    }
    lines.push(line);
    lines.push(field(
        row(1),
        format!("{}  show me in the directory", tick(d.listed)),
        f == 1,
        false,
    ));
    lines.push(field(row(2), d.display_name.clone(), f == 2, true));
    lines.push(field(row(3), d.languages.clone(), f == 3, true));
    lines.push(field(row(4), d.country.clone(), f == 4, true));
    lines.push(field(row(5), d.region.clone(), f == 5, true));
    lines.push(field(row(6), d.city.clone(), f == 6, true));
    for (i, method) in [
        VettingMethod::InPerson,
        VettingMethod::Video,
        VettingMethod::PriorAcquaintance,
    ]
    .into_iter()
    .enumerate()
    {
        lines.push(field(
            row(7 + i),
            format!(
                "{}  {}",
                tick(d.methods.contains(&method)),
                method_label(method)
            ),
            f == 7 + i,
            false,
        ));
    }
    lines.push(field(
        row(10),
        d.accepts_documentation.clone(),
        f == 10,
        true,
    ));
    lines.push(field(row(11), d.availability.clone(), f == 11, true));
    lines.push(field(row(12), d.contact_hint.clone(), f == 12, true));
    lines.push(Line::from(""));
    lines.push(Line::from(" Events you will vet at").fg(COLOR_SUCCESS));
    for (i, event) in d.events.iter().enumerate() {
        let selected = f == PROFILE_FIELDS + i;
        let shown = match event.to_event() {
            Ok(e) => event_line(&e),
            Err(e) => format!("{} — {e}", event.name),
        };
        lines.push(Line::from(vec![
            Span::styled(
                if selected { "▸ " } else { "  " },
                Style::new().fg(COLOR_SUCCESS).bold(),
            ),
            Span::styled(
                shown,
                if selected {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else {
                    value()
                },
            ),
        ]));
    }
    let add = form.on_add_event();
    lines.push(Line::from(Span::styled(
        format!("{}+ add an event", if add { "▸ " } else { "  " }),
        if add {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            dim()
        },
    )));
    if let Some(error) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(error.clone()).fg(COLOR_WARNING_ACCESSIBLE_RED));
    }
    lines.push(Line::from(""));
    lines.push(hint(
        "↑/↓: move  type to edit  Space: tick  Enter on an event: edit  x: remove it",
    ));
    lines.push(hint(
        "Enter elsewhere: publish  ←/→: community  Esc: cancel",
    ));
}

fn event_form(lines: &mut Vec<Line<'static>>, event: &EventForm) {
    lines.push(heading(if event.index.is_some() {
        "Edit an event"
    } else {
        "Add an event you will vet at"
    }));
    lines.push(Line::from(""));
    lines.push(hint(
        "Applicants find vetters by event, so they can meet you there. At most 31 days long.",
    ));
    lines.push(Line::from(""));
    let d = &event.draft;
    let f = event.field;
    let row = |i: usize| EVENT_LABELS[i];
    lines.push(field(row(0), d.name.clone(), f == 0, true));
    lines.push(field(row(1), d.start_date.clone(), f == 1, true));
    lines.push(field(row(2), d.end_date.clone(), f == 2, true));
    lines.push(field(row(3), d.country.clone(), f == 3, true));
    lines.push(field(row(4), d.region.clone(), f == 4, true));
    lines.push(field(row(5), d.city.clone(), f == 5, true));
    lines.push(field(row(6), d.url.clone(), f == 6, true));
    lines.push(hint("  Days are YYYY-MM-DD; the page must be https."));
    if let Some(error) = &event.error {
        lines.push(Line::from(""));
        lines.push(Line::from(error.clone()).fg(COLOR_WARNING_ACCESSIBLE_RED));
    }
    lines.push(Line::from(""));
    lines.push(hint("Enter: keep it  ↑/↓: move  Esc: back to the profile"));
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

/// Draw `uri` as a QR code into `lines`, given the rows still unspent.
///
/// `above` is what has already been pushed and `tail` what is still to come;
/// the code gets what is left. A code that does not fit is not drawn at all —
/// a scanner needs the whole thing, so a clipped code is not a smaller code but
/// a picture of nothing — and the message names the direction that is short.
fn push_qr(lines: &mut Vec<Line<'static>>, uri: &str, above: usize, tail: usize) {
    let width = super::status::content_width();
    let height = super::status::content_height().saturating_sub(above + tail);
    match qr_lines(uri, width, height) {
        Ok(code) => lines.extend(code),
        Err(QrError::TooBig {
            needed_width,
            needed_height,
        }) => {
            // Name the direction that is actually short. "Make the window
            // bigger" on a window already wide enough is the kind of advice
            // that gets followed once and then ignored.
            let short_of_width = needed_width > width;
            let taller_by = needed_height.saturating_sub(height).max(1);
            let what = if short_of_width && needed_height > height {
                format!("{needed_width} columns wide and {taller_by} rows taller")
            } else if short_of_width {
                format!("{needed_width} columns wide")
            } else {
                // Rows the *window* needs, not rows the code needs: the code is
                // competing with everything else on the panel.
                format!("{taller_by} rows taller")
            };
            lines.push(
                Line::from(format!(
                    "The QR code needs a window {what} — or copy the link with u."
                ))
                .fg(COLOR_ORANGE),
            );
        }
        Err(QrError::TooLong) => lines.push(
            Line::from("This ticket's link is too long for a QR code — copy it with u instead.")
                .fg(COLOR_ORANGE),
        ),
    }
}

/// One ticket's code, with the whole panel to itself.
///
/// This is a screen someone else is pointing a phone at, so it holds the code,
/// the six characters to read aloud if the scan fails, and nothing else. The
/// panel's full height is what makes a real code fit at all: sharing it with
/// the desk header, the view tabs and two key lines leaves roughly half, and
/// half is not enough for the codes these links produce.
fn show_ticket(lines: &mut Vec<Line<'static>>, v: &VettingState, index: usize) {
    let Some(row) = v.tickets.get(index) else {
        lines.push(hint("That ticket is gone."));
        return;
    };
    lines.push(Line::from(vec![
        Span::styled("Ticket   ", label()),
        Span::styled(row.code.clone(), Style::new().fg(COLOR_SUCCESS).bold()),
        Span::styled(format!("   {}", row.community), dim()),
    ]));
    lines.push(Line::from(""));
    match &row.uri {
        // `lines` already holds the page's own heading rows, so ask it rather
        // than counting the two pushed here. Below: a blank and the key line.
        Some(uri) if row.live => {
            let above = lines.len();
            push_qr(lines, uri, above, 2);
        }
        Some(_) => lines.push(Line::from("This ticket is spent or expired.").fg(COLOR_ORANGE)),
        None => lines.push(hint("This ticket has no link to scan.")),
    }
    lines.push(Line::from(""));
    lines.push(hint("Esc or Enter: back  (y: copy code  u: copy link)"));
}

/// The desk's header: what each community has made us, and what it holds of our
/// profile.
///
/// This is the only place a vetter can see their own vetter credential. It is a
/// real VC (`vtc/vetting/vetters/grant`, design §10.3) — it gates every ticket
/// and is presented to every applicant we accept — and until this header it was
/// visible to applicants and to nobody else, least of all its holder.
fn standing(lines: &mut Vec<Line<'static>>, v: &VettingState) {
    if v.standing.is_empty() {
        lines.push(hint(
            "No community has named you a vetter yet. A community's admins grant the role;",
        ));
        lines.push(hint(
            "until one does, you can hold no tickets and requests to you are refused.",
        ));
        lines.push(Line::from(""));
        return;
    }
    for (i, row) in v.standing.iter().enumerate() {
        let mut spans = vec![
            Span::styled(
                if i == 0 {
                    "You vet for  "
                } else {
                    "             "
                },
                label(),
            ),
            accent_swatch(row.accent),
            Span::styled(format!("{:<30}", row.community), value()),
            Span::styled(
                row.grant.clone(),
                if row.grant_warns {
                    Style::new().fg(COLOR_ORANGE)
                } else {
                    dim()
                },
            ),
        ];
        // The profile only makes sense alongside a grant that works: an
        // applicant cannot find a vetter the community will not list.
        spans.push(Span::styled(format!("   {}", row.profile), dim()));
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
}

/// The desk's sub-view line: inbound, outbound, and what came of it.
fn desk_views(lines: &mut Vec<Line<'static>>, v: &VettingState) {
    let count = |view: DeskView| match view {
        DeskView::Requests => v.desk.len(),
        DeskView::Tickets => v.tickets.len(),
        DeskView::Issued => v.issued.len(),
    };
    let mut spans = vec![Span::styled("  ", dim())];
    for view in DeskView::ALL {
        spans.push(Span::styled(
            format!(" {} ({}) ", view.label(), count(view)),
            if v.desk_view == view {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else {
                dim()
            },
        ));
    }
    spans.push(Span::styled("   ←/→", dim()));
    lines.push(Line::from(spans));
    lines.push(Line::from(""));
}

fn desk(lines: &mut Vec<Line<'static>>, v: &VettingState) {
    if v.desk.is_empty() {
        lines.push(hint("No one has asked you to vet them."));
        lines.push(Line::from(""));
        lines.push(hint(
            "Requests arrive only with one of your tickets — hand them out under Tickets (→).",
        ));
        lines.push(hint("p: your vetter profile"));
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
        DeskStage::Accepted => "o: open session  x: decline",
        DeskStage::Session => "o: reopen session  x: decline",
        DeskStage::Card => "a: check and attest  x: decline",
        DeskStage::Closed => "",
    };
    lines.push(hint(
        format!("{keys}  {DESK_KEYS}").trim_start().to_string(),
    ));
}

/// The keys every desk view carries, on its last line. `p` and `g` are the
/// desk's, not any one view's — the profile and the vetter credential belong to
/// the whole desk — and `←/→` is how the views are reached at all.
const DESK_KEYS: &str = "p: your vetter profile  g: ask for your vetter credential again  \
                         ←/→: Requests · Tickets · Issued  Tab: Applications";

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
            "t: hand out a ticket — read the code to someone, or show them its QR code",
        ));
        lines.push(hint(DESK_KEYS));
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
    if let Some(row) = v.tickets.get(v.selected)
        && row.live
        && let Some(uri) = &row.uri
    {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Read aloud   ", label()),
            Span::styled(row.code.clone(), Style::new().fg(COLOR_SUCCESS).bold()),
        ]));
        lines.push(Line::from(""));
        lines.push(hint(
            "Or let them scan this — ⏎ shows it full-screen. It carries the ticket and your DID:",
        ));
        lines.push(Line::from(""));
        // The tail below the code: a blank, the link (which wraps on a narrow
        // panel), a blank, and two key lines.
        let width = super::status::content_width();
        let tail = 4 + uri.chars().count().div_ceil(width.max(1));
        let above = lines.len();
        push_qr(lines, uri, above, tail);
        lines.push(Line::from(""));
        lines.push(hint(uri.clone()));
    }
    lines.push(Line::from(""));
    lines.push(hint(
        "⏎: show the code full-screen  t: new ticket  y: copy code  u: copy link  d: delete",
    ));
    lines.push(hint(DESK_KEYS));
}

fn issued(lines: &mut Vec<Line<'static>>, v: &VettingState) {
    if v.issued.is_empty() {
        lines.push(hint("You have not signed any vetting statements."));
        lines.push(Line::from(""));
        lines.push(hint(DESK_KEYS));
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
    lines.push(hint("w: withdraw"));
    lines.push(hint(DESK_KEYS));
}

#[cfg(test)]
mod desk_tests {
    use super::*;
    use crate::state_handler::main_page::content::VetterStandingRow;

    fn drawn(v: &VettingState) -> String {
        render(v)
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn standing_row(community: &str, grant: &str, warns: bool, profile: &str) -> VetterStandingRow {
        VetterStandingRow {
            community: community.to_string(),
            accent: None,
            grant: grant.to_string(),
            grant_warns: warns,
            profile: profile.to_string(),
        }
    }

    /// The desk answers "am I a vetter, for whom, and until when" on the screen
    /// a vetter works from. Before this header the `vetter` role credential was
    /// shown to every applicant and to nobody else — least of all its holder.
    #[test]
    fn the_desk_header_shows_the_vetter_credential_and_the_profile() {
        let v = VettingState {
            tab: VettingTab::Desk,
            standing: vec![
                standing_row(
                    "Kernel Developers",
                    "until 2027-01-18",
                    false,
                    "listed in the directory",
                ),
                standing_row(
                    "first-vtc",
                    "expires in 12 days, 2026-09-27",
                    true,
                    "no profile sent",
                ),
            ]
            .into(),
            ..VettingState::default()
        };
        let text = drawn(&v);

        assert!(text.contains("You vet for"), "{text}");
        assert!(text.contains("Kernel Developers"), "{text}");
        assert!(text.contains("until 2027-01-18"), "{text}");
        assert!(text.contains("expires in 12 days"), "{text}");
        assert!(text.contains("listed in the directory"), "{text}");
        assert!(
            text.contains("p: your vetter profile"),
            "the profile is reachable from the desk itself: {text}"
        );
    }

    /// Someone no community has named. The page must say so rather than simply
    /// listing nothing — an empty desk looks identical to a quiet one.
    #[test]
    fn a_desk_with_no_grant_explains_itself() {
        let v = VettingState {
            tab: VettingTab::Desk,
            ..VettingState::default()
        };
        let text = drawn(&v);
        assert!(
            text.contains("No community has named you a vetter"),
            "{text}"
        );
        assert!(text.contains("requests to you are refused"), "{text}");
    }

    /// Two tabs, and the desk's three views on one screen under them.
    #[test]
    fn the_desk_carries_its_three_views() {
        let v = VettingState {
            tab: VettingTab::Desk,
            standing: vec![standing_row(
                "VTC",
                "until 2027-01-18",
                false,
                "listed in the directory",
            )]
            .into(),
            ..VettingState::default()
        };
        let text = drawn(&v);
        assert!(text.contains("Applications (0)"), "{text}");
        assert!(text.contains("Vetting desk (0)"), "{text}");
        for view in DeskView::ALL {
            assert!(text.contains(view.label()), "{view:?} missing from {text}");
        }
        assert!(
            !text.contains("Vetter desk"),
            "the tab is the whole desk now: {text}"
        );
    }

    /// A real ticket link on a real terminal: 132×41, which is what a maximised
    /// window gives. The list view has to share those rows with the desk header,
    /// the view tabs, the ticket row and two key lines; the full-screen view
    /// does not, and that difference is the whole point of it.
    ///
    /// This is the case that shipped broken — the code was sized by width
    /// alone, so a wide, short panel got the tallest code and it ran off the
    /// bottom, where no amount of scrolling would have made it scannable.
    #[test]
    fn a_ticket_code_that_does_not_fit_the_list_fits_the_full_screen_view() {
        use crate::state_handler::main_page::content::TicketRow;

        const LINK: &str = "vetting-ticket:?v=1&community=did%3Awebvh%3AQmCommunity%3Avtc.example.com\
                            &vetter=did%3Awebvh%3AQmVetter%3Aexample.com%3Acarol\
                            &ticket=vt-0123456789abcdef0123456789abcdef\
                            &secret=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

        super::super::status::set_wrap_width(130);
        super::super::status::set_content_height(41);

        let ticket = TicketRow {
            id: "t1".into(),
            code: "9ENN-8R76".into(),
            community: "webvh.storm.ws/@first-vtc".into(),
            uses_left: 1,
            expires: "2026-09-29".into(),
            live: true,
            uri: Some(LINK.to_string()),
        };
        let base = VettingState {
            tab: VettingTab::Desk,
            desk_view: DeskView::Tickets,
            tickets: vec![ticket].into(),
            standing: vec![standing_row(
                "webvh.storm.ws/@first-vtc",
                "until 2027-09-15",
                false,
                "listed in the directory",
            )]
            .into(),
            ..VettingState::default()
        };

        // In the list, the code cannot have the rows, so it is not drawn — and
        // the message says which way to grow the window.
        let listed = drawn(&base);
        assert!(
            listed.contains("rows taller"),
            "the list says what is short rather than drawing half a code: {listed}"
        );
        assert!(
            listed.contains("⏎ shows it full-screen"),
            "and points at the view that does fit: {listed}"
        );

        // Full-screen, the same code fits, and the panel holds it whole.
        let full = VettingState {
            mode: VettingMode::ShowTicket { index: 0 },
            ..base
        };
        let lines = render(&full);
        assert!(
            !lines
                .iter()
                .any(|l| l.spans.iter().any(|s| s.content.contains("rows taller"))),
            "the full-screen view has the rows for it"
        );
        assert!(
            lines.len() <= 41,
            "and the whole code is on the panel — a QR that needs scrolling \
             cannot be scanned at all ({} rows)",
            lines.len()
        );
        let text = drawn(&full);
        assert!(text.contains("9ENN-8R76"), "the code to read aloud: {text}");
        assert!(text.contains("Esc or Enter: back"), "{text}");
    }

    /// Each view keeps the header, including the one thing no other view shows:
    /// a grant that has lapsed.
    #[test]
    fn every_desk_view_keeps_the_header() {
        for view in DeskView::ALL {
            let v = VettingState {
                tab: VettingTab::Desk,
                desk_view: view,
                standing: vec![standing_row(
                    "VTC",
                    "expired 2026-09-01",
                    true,
                    "no profile sent",
                )]
                .into(),
                ..VettingState::default()
            };
            let text = drawn(&v);
            assert!(
                text.contains("expired 2026-09-01"),
                "a lapsed grant must show on {view:?}, which is the view that explains \
                 why nothing is arriving: {text}"
            );
        }
    }
}

#[cfg(test)]
mod persona_guidance_tests {
    use super::*;
    use crate::state_handler::main_page::content::{VettingPersona, VettingState};
    use openvtc_core::config::account::PersonaId;
    use std::sync::Arc;

    fn text(v: &VettingState) -> String {
        render(v)
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// With no persona there is nothing to apply as, so the empty Applications
    /// state guides the operator to create one in the panel — not the dead
    /// "n: new application" key that would only refuse.
    #[test]
    fn empty_applications_with_no_persona_guides_to_create_one() {
        let out = text(&VettingState::default());
        assert!(out.contains("no persona"), "{out}");
        assert!(out.contains("My Identity"), "{out}");
        assert!(
            !out.contains("n: new application"),
            "the call to action is create-a-persona, not new application:\n{out}"
        );
    }

    /// Once a persona exists, the normal empty state (with the new-application
    /// key) is shown.
    #[test]
    fn empty_applications_with_a_persona_offers_new_application() {
        let v = VettingState {
            personas: Arc::from(vec![VettingPersona {
                persona: PersonaId::new(),
                did: "did:webvh:example:p".to_string(),
                label: "me".to_string(),
            }]),
            ..VettingState::default()
        };
        let out = text(&v);
        assert!(out.contains("n: new application"), "{out}");
        assert!(!out.contains("no persona yet"), "{out}");
    }
}
