use super::panel::Panel;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
};
use crate::state_handler::{
    main_page::content::{
        CommunitiesState, ContentPanelState, ContextDeletePhase, ContextDeleteView,
        DeviceAccessView, GrantListing,
    },
    state::ConnectionState,
};
use openvtc_core::community_access::{DEVICE_ROLE, EXPIRY_CHOICES};
use openvtc_core::config::community_context::DELETE_CONFIRMATION;
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Width for identifier rows in the expanded detail block. Generous, because a
/// DID shown here is what you copy when diagnosing — truncating it would defeat
/// the purpose of the block.
const ID_WIDTH: usize = 256;

/// Communities overview content panel (R-C-1..R-C-8).
pub struct CommunitiesPanel;

impl Panel for CommunitiesPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        render(&state.communities, &state.identity.bindings)
    }
}

/// Render the communities panel content.
///
/// `bindings` is the persona pane's map, read here rather than copied: this
/// panel and the persona pane render the same thing — what a persona presents in a
/// community — and two copies of it would drift the moment one was refreshed
/// and the other was not.
pub fn render(
    state: &CommunitiesState,
    bindings: &std::collections::HashMap<
        (String, String),
        openvtc_core::persona::binding::BindingSummary,
    >,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    if let Some(msg) = &state.status_message {
        super::status::push_status(&mut lines, msg, "");
        lines.push(Line::from(""));
    }

    // A context deletion or device access, while open, is the whole panel.
    if let Some(view) = &state.context_delete {
        render_context_delete(&mut lines, view);
        return lines;
    }
    if let Some(view) = &state.device_access {
        render_device_access(&mut lines, view, state.device_grants.get(&view.context_id));
        return lines;
    }

    push_personhood_challenge(&mut lines, state);

    if state.items.is_empty() {
        return render_empty(lines);
    }

    // Header with actions-required count (R-C-3).
    if state.actions_required > 0 {
        lines.push(
            Line::from(format!(
                " ● {} communit{} need your attention",
                state.actions_required,
                if state.actions_required == 1 {
                    "y"
                } else {
                    "ies"
                }
            ))
            .fg(COLOR_ORANGE),
        );
    } else {
        lines.push(
            Line::from(format!(
                " {} communit{}",
                state.items.len(),
                if state.items.len() == 1 { "y" } else { "ies" }
            ))
            .fg(COLOR_TEXT_DEFAULT),
        );
    }
    lines.push(Line::from(""));

    for (i, c) in state.items.iter().enumerate() {
        let is_selected = i == state.selected_index;
        // A community may hold several memberships (one per persona). Rows are
        // grouped: the community name is shown once as a header, then each
        // membership is a selectable sub-row labelled by its presented persona.
        let new_group = i == 0 || state.items[i - 1].vtc_did != c.vtc_did;
        if new_group {
            lines.push(Line::from(vec![
                Span::raw("  "),
                super::vetting_panel::accent_swatch(c.accent),
                Span::styled(
                    c.display_name.clone(),
                    Style::new().fg(COLOR_TEXT_DEFAULT).bold(),
                ),
            ]));
        }

        let row_style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else if c.is_inactive {
            // Inactive memberships are read-only (D14) — dimmed in the list.
            Style::new().fg(COLOR_DARK_GRAY)
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        let prefix = if is_selected { "    ▸ " } else { "      " };
        let star = if c.favourite { "★ " } else { "" };
        let attention = if c.needs_attention { " ●" } else { "" };
        let persona = if c.persona_label.is_empty() {
            c.persona_did.clone()
        } else {
            c.persona_label.clone()
        };

        // Membership sub-row: the presented persona is the selectable label.
        lines.push(Line::from(vec![
            Span::styled(prefix, row_style),
            Span::styled(star, Style::new().fg(COLOR_ORANGE)),
            Span::styled(format!("as {persona}"), row_style),
            Span::styled(attention, Style::new().fg(COLOR_ORANGE)),
        ]));

        // Secondary line: status · member-since · what this persona presents.
        //
        // The row above says WHICH of the holder's personas this community sees;
        // this says WHAT that persona tells them. Both halves are needed to answer
        // "what does this community know about me", and until now only the
        // first was on screen.
        //
        // An absent entry reads "presents: unknown" rather than being omitted.
        // Omitting it would render identically to a persona bound to nothing,
        // and "we have not asked yet" is not "you are sharing nothing" — see
        // `BindingSummary::unknown`.
        let mut detail = format!("        {}", c.status_label);
        if !c.member_since.is_empty() {
            detail.push_str(&format!("  ·  since {}", c.member_since));
        }
        if !c.sub_context_id.is_empty() && !c.persona_did.is_empty() {
            let key = (c.sub_context_id.clone(), c.persona_did.clone());
            let summary = bindings
                .get(&key)
                .cloned()
                .unwrap_or_else(openvtc_core::persona::binding::BindingSummary::unknown);
            detail.push_str(&format!("  ·  {}", summary.describe()));
        }
        if c.archived {
            detail.push_str("  ·  archived");
        }
        let detail_style = if is_selected {
            Style::new().fg(COLOR_SOFT_PURPLE)
        } else {
            Style::new().fg(COLOR_DARK_GRAY)
        };
        lines.push(Line::from(Span::styled(detail, detail_style)));

        // A Pending join the VTC hasn't acknowledged within the grace window: the
        // submit may have been dropped (size limit / unhandled type) rather than
        // healthily awaiting a decision. Surface it so a stuck join is visible
        // long before the 7-day Expired (D16).
        if c.pending_unacknowledged {
            // Name the transport the submit went out over. "No response" alone
            // reads identically whether the community ignored the request, the
            // mediator dropped it, or the community could not decode the
            // transport its own document advertises — and only the last of
            // those is fixed somewhere other than here.
            let over = c
                .submit_transport
                .as_deref()
                .map_or(String::new(), |t| format!(" (sent over {t})"));
            lines.push(Line::from(Span::styled(
                format!(
                    "    ⚠ no response from the community yet{over} — the request may not have \
                     been received"
                ),
                Style::new().fg(COLOR_ORANGE),
            )));
        }

        // Expanded troubleshooting detail for the selected community: which
        // persona this community actually uses (full DID), the VTC, the
        // sub-context, the in-flight request id, and which credentials are held.
        if is_selected {
            let label = Style::new().fg(COLOR_DARK_GRAY);
            let value = Style::new().fg(COLOR_TEXT_DEFAULT);
            let kv = |k: &str, v: String| {
                Line::from(vec![
                    Span::styled(format!("      {k:<13}"), label),
                    Span::styled(v, value),
                ])
            };
            // The identifier row shows the verified agent name when there is
            // one, and the DID when there is not — so the label is "Persona",
            // not "Persona DID": it names the party, and the DID is simply what
            // it falls back to. Two rows per identity (name above DID) read as
            // two different things to someone scanning the block.
            lines.push(kv(
                "Persona:",
                openvtc_core::display::display_identifier(
                    c.persona_agent_name.as_deref(),
                    &c.persona_did,
                    ID_WIDTH,
                )
                .into_owned(),
            ));
            lines.push(kv(
                "VTC:",
                openvtc_core::display::display_identifier(
                    c.vtc_agent_name.as_deref(),
                    &c.vtc_did,
                    ID_WIDTH,
                )
                .into_owned(),
            ));
            if !c.sub_context_id.is_empty() {
                lines.push(kv(
                    "Context:",
                    format!("{}  ({})", c.sub_context_id, c.context_note),
                ));
            }
            if c.has_own_context {
                push_device_grants(&mut lines, state.device_grants.get(&c.sub_context_id));
            }
            if !c.request_id.is_empty() {
                lines.push(kv("Request ID:", c.request_id.clone()));
            }
            lines.push(kv(
                "Credentials:",
                format!(
                    "membership {}   role {}",
                    if c.has_membership_credential {
                        "✓"
                    } else {
                        "—"
                    },
                    if c.has_role_credential { "✓" } else { "—" },
                ),
            ));
        }
    }

    lines.push(Line::from(""));
    let confirm_name = |idx: usize| {
        state
            .items
            .get(idx)
            .map(|c| c.display_name.clone())
            .unwrap_or_else(|| "this community".to_string())
    };
    if let Some(idx) = state.confirm_delete {
        lines.push(
            Line::from(format!(
                "Delete “{}”?   y: confirm    n: cancel",
                confirm_name(idx)
            ))
            .fg(COLOR_ORANGE)
            .bold(),
        );
    } else if let Some(idx) = state.confirm_leave {
        lines.push(
            Line::from(format!(
                "Leave “{}”? This sends a self-removal to the community.   y: confirm    n: cancel",
                confirm_name(idx)
            ))
            .fg(COLOR_ORANGE)
            .bold(),
        );
    } else if let Some(idx) = state.confirm_withdraw {
        lines.push(
            Line::from(format!(
                "Cancel the pending join to “{}”? The request will be marked withdrawn.   \
                 y: confirm    n: cancel",
                confirm_name(idx)
            ))
            .fg(COLOR_ORANGE)
            .bold(),
        );
    } else {
        lines.push(Line::from(key_hints(state)).fg(COLOR_DARK_GRAY));
    }

    lines
}

/// The detail block's device-access rows for a membership's own context.
///
/// A context never read says so rather than reading as "no devices": not having
/// asked is not the same answer as nobody having access.
fn push_device_grants(lines: &mut Vec<Line<'static>>, listing: Option<&GrantListing>) {
    let label = Style::new().fg(COLOR_DARK_GRAY);
    let value = Style::new().fg(COLOR_TEXT_DEFAULT);
    let row = |k: &str, v: String, style: Style| {
        Line::from(vec![
            Span::styled(format!("      {k:<13}"), label),
            Span::styled(v, style),
        ])
    };
    let now = chrono::Utc::now();
    match listing {
        None => lines.push(row(
            "Devices:",
            "not read yet — g to see device access".to_string(),
            label,
        )),
        Some(GrantListing::Loading) => {
            lines.push(row("Devices:", "reading…".to_string(), label));
        }
        Some(GrantListing::Failed(e)) => lines.push(row(
            "Devices:",
            format!("could not read: {e}"),
            Style::new().fg(COLOR_ORANGE),
        )),
        Some(GrantListing::Loaded(grants)) if grants.is_empty() => lines.push(row(
            "Devices:",
            "none — g to give a device access".to_string(),
            value,
        )),
        Some(GrantListing::Loaded(grants)) => {
            for (i, grant) in grants.iter().enumerate() {
                lines.push(row(
                    if i == 0 { "Devices:" } else { "" },
                    format!("{}  ({})", grant.did, grant.describe(now)),
                    if grant.is_expired(now) { label } else { value },
                ));
            }
        }
    }
}

/// Deleting a membership's context: what the VTA will remove, and the typed
/// confirmation.
fn render_context_delete(lines: &mut Vec<Line<'static>>, view: &ContextDeleteView) {
    let dim = Style::new().fg(COLOR_DARK_GRAY);
    lines.push(
        Line::from(format!(" Delete the context for “{}”", view.community))
            .fg(COLOR_ORANGE)
            .bold(),
    );
    lines.push(Line::from(format!("   {}", view.context_id)).fg(COLOR_TEXT_DEFAULT));
    lines.push(Line::from(""));
    match &view.phase {
        ContextDeletePhase::Previewing => {
            lines.push(Line::from("   Asking your VTA what this would remove…").style(dim));
            lines.push(Line::from(""));
            lines.push(Line::from("esc: cancel").style(dim));
        }
        ContextDeletePhase::Ready(preview) => {
            lines.push(Line::from(" Your VTA will permanently remove:").fg(COLOR_TEXT_DEFAULT));
            for line in preview.lines() {
                lines.push(Line::from(format!("   {line}")).fg(COLOR_SOFT_PURPLE));
            }
            if preview.holds_nothing() {
                lines.push(
                    Line::from("   (no keys, DIDs or access entries — only the context itself)")
                        .style(dim),
                );
            }
            // What goes beyond the VTA's preview: a persona deleted with the
            // context, and the membership record with it — or the record kept.
            lines.push(Line::from(""));
            let takes_persona = view.takes_persona.is_some();
            for line in view.deletion().consequences(&view.community) {
                let line = Line::from(format!(" {line}"));
                lines.push(if takes_persona {
                    line.fg(COLOR_ORANGE)
                } else {
                    line.style(dim)
                });
            }
            lines.push(Line::from(""));
            lines.push(
                Line::from(format!(
                    " This cannot be undone. Type {DELETE_CONFIRMATION} and press ⏎ to delete."
                ))
                .fg(COLOR_ORANGE),
            );
            lines.push(Line::from(vec![
                Span::styled("   > ", dim),
                Span::styled(
                    format!("{}▎", view.typed),
                    Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                ),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from("⏎ delete   esc: cancel").style(dim));
        }
        ContextDeletePhase::Deleting => {
            lines.push(Line::from("   Deleting…").style(dim));
        }
    }
}

/// Device access for one membership's context: its grants, the new-grant form,
/// and what the role allows.
fn render_device_access(
    lines: &mut Vec<Line<'static>>,
    view: &DeviceAccessView,
    listing: Option<&GrantListing>,
) {
    let dim = Style::new().fg(COLOR_DARK_GRAY);
    let text = Style::new().fg(COLOR_TEXT_DEFAULT);
    lines.push(
        Line::from(format!(" Device access — {}", view.community))
            .style(text)
            .bold(),
    );
    lines.push(Line::from(format!("   Context {}", view.context_id)).style(dim));
    lines.push(
        Line::from(format!(
            "   A device added here holds the {DEVICE_ROLE} role in this context only: it can sign and"
        ))
        .style(dim),
    );
    lines.push(
        Line::from(
            "   present as you here, but cannot mint keys, manage access, or reach your other",
        )
        .style(dim),
    );
    lines.push(Line::from("   communities. Every grant expires.").style(dim));
    lines.push(Line::from(""));

    let now = chrono::Utc::now();
    let grants = listing.map_or(&[][..], GrantListing::grants);
    match listing {
        None | Some(GrantListing::Loading) => {
            lines.push(Line::from("   Reading device access…").style(dim));
        }
        Some(GrantListing::Failed(e)) => {
            lines.push(Line::from(format!("   Couldn't read device access: {e}")).fg(COLOR_ORANGE))
        }
        Some(GrantListing::Loaded(_)) if grants.is_empty() => {
            lines.push(Line::from("   No device has access to this context.").style(text));
        }
        Some(GrantListing::Loaded(_)) => {
            for (i, grant) in grants.iter().enumerate() {
                let selected = i == view.selected && view.form.is_none();
                let style = if selected {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else if grant.is_expired(now) {
                    dim
                } else {
                    text
                };
                lines.push(Line::from(Span::styled(
                    format!("{}{}", if selected { " ▸ " } else { "   " }, grant.did),
                    style,
                )));
                lines.push(Line::from(Span::styled(
                    format!("     {}", grant.describe(now)),
                    dim,
                )));
            }
        }
    }

    if let Some(form) = &view.form {
        lines.push(Line::from(""));
        lines.push(Line::from(" Add a device").fg(COLOR_SUCCESS).bold());
        let field = |index: usize, name: &str, value: String, typed: bool| {
            let focused = form.field == index;
            let mut spans = vec![
                Span::styled(
                    if focused { "   ▸ " } else { "     " },
                    if focused {
                        Style::new().fg(COLOR_SUCCESS).bold()
                    } else {
                        dim
                    },
                ),
                Span::styled(format!("{name:<10}"), text),
                Span::styled(value, Style::new().fg(COLOR_SOFT_PURPLE)),
            ];
            if focused {
                spans.push(Span::styled(if typed { "▎" } else { "  ←/→" }, dim));
            }
            Line::from(spans)
        };
        lines.push(field(0, "did:key", form.did.clone(), true));
        lines.push(field(1, "Name", form.name.clone(), true));
        lines.push(field(
            2,
            "Expires",
            EXPIRY_CHOICES
                .get(form.expiry)
                .map_or("—", |c| c.label)
                .to_string(),
            false,
        ));
    }

    if view.confirm_revoke
        && let Some(grant) = grants.get(view.selected)
    {
        lines.push(Line::from(""));
        lines.push(
            Line::from(format!(
                " Revoke {}'s access to this community?   y: confirm    n: cancel",
                grant.did
            ))
            .fg(COLOR_ORANGE)
            .bold(),
        );
    }
    if let Some(message) = &view.message {
        lines.push(Line::from(""));
        super::status::push_status(lines, message, "");
    }

    lines.push(Line::from(""));
    let hints = if view.busy {
        "working…   esc: close".to_string()
    } else if view.form.is_some() {
        "Tab: next field   ←/→: expiry   ⏎ grant   esc: cancel".to_string()
    } else {
        let mut hints = vec!["↑/↓ select"];
        if view.can_grant {
            hints.push("n: add a device");
        }
        if !grants.is_empty() {
            hints.push("x: revoke");
        }
        hints.extend(["r: refresh", "esc: close"]);
        hints.join("   ")
    };
    lines.push(Line::from(hints).style(dim));
    if !view.can_grant {
        lines.push(
            Line::from(
                "This membership is over: no device can be added, but existing access can be revoked.",
            )
            .style(dim),
        );
    }
}

/// Show the live personhood challenge, if there is one.
///
/// The match code is the point of this block. It is the thing a member reads
/// aloud to whoever is vetting them, so it is rendered on its own line, spaced,
/// and in the panel's emphasis colour rather than folded into the status text —
/// a code that has to be picked out of a sentence is a code that gets misread.
///
/// A lapsed challenge renders as lapsed rather than vanishing. Silently
/// removing it would leave a member who has just been read a code looking at a
/// panel that never mentioned one, with no way to tell that time ran out from
/// never having received it.
fn push_personhood_challenge(lines: &mut Vec<Line<'static>>, state: &CommunitiesState) {
    let Some(challenge) = &state.personhood_challenge else {
        return;
    };

    if challenge.is_live(chrono::Utc::now()) {
        lines.push(Line::from(" Personhood challenge").fg(COLOR_DARK_GRAY));
        lines.push(
            Line::from(format!("   {}", challenge.match_code))
                .style(Style::new().fg(COLOR_SOFT_PURPLE).bold()),
        );
        lines.push(
            Line::from("   Confirm this code with whoever is vetting you, then press P.")
                .fg(COLOR_DARK_GRAY),
        );
    } else {
        lines.push(
            Line::from(" Personhood challenge expired — press p for a fresh one.")
                .fg(COLOR_DARK_GRAY),
        );
    }
    lines.push(Line::from(""));
}

/// The key hints for the selected row, gated exactly as the key handler gates
/// the keys themselves (`ui::pages::main::handle_communities_key`).
///
/// This used to be one unconditional string listing every binding, which
/// advertised `c` twice — `c: capabilities` and `c: cancel` — and read as a
/// collision. It never was one: `c` is capabilities on an Active row and cancel
/// on a Pending one, and the two states are mutually exclusive. The footer was
/// simply describing a keymap that does not exist.
///
/// `c` was the visible symptom; every state-gated key had the same defect.
/// `l`/`m` do nothing on a Pending or Inactive row and `x`/`d` do nothing on an
/// Active one, yet all four were offered on all three. Showing what the current
/// row actually accepts fixes the duplicate and the four silent no-ops together,
/// which is why this is gated per row rather than by special-casing `c`.
///
/// The two ungated keys (`j: join`, `v: show/hide archived`) are always listed:
/// they act on the panel, not the selection, and stay available when nothing is
/// selected at all.
fn key_hints(state: &CommunitiesState) -> String {
    let selected = state.items.get(state.selected_index);
    let mut hints = vec!["↑/↓ navigate".to_string()];

    if let Some(community) = selected {
        hints.push("⏎ open".to_string());
        hints.push("f: ★".to_string());
        hints.push("a: acknowledge".to_string());
        if community.is_active {
            hints.push("m: issue VMC".to_string());
            hints.push("c: capabilities".to_string());
            hints.push("p: personhood".to_string());
            hints.push("l: leave".to_string());
        }
        if community.is_pending {
            hints.push("c: cancel".to_string());
        }
        if community.is_inactive {
            hints.push("x: archive".to_string());
            hints.push("d: delete".to_string());
        }
        if community.has_own_context {
            hints.push("g: devices".to_string());
            if community.is_inactive {
                hints.push("D: delete context".to_string());
            }
        }
    }

    // Gated on the challenge, not on the row — matching the key handler,
    // which offers `P` only while there is something to answer. A live
    // challenge belongs to the membership that asked for it, so this stays
    // offered while the member navigates the list.
    if state
        .personhood_challenge
        .as_ref()
        .is_some_and(|c| c.is_live(chrono::Utc::now()))
    {
        hints.push("P: assert personhood".to_string());
    }

    hints.push("j: join".to_string());
    hints.push(
        if state.show_archived {
            "v: hide archived"
        } else {
            "v: show archived"
        }
        .to_string(),
    );
    hints.join("   ")
}

/// Empty state (R-C-5): a welcoming nudge to go find a community, not a dry
/// "no items" message.
fn render_empty(mut lines: Vec<Line<'static>>) -> Vec<Line<'static>> {
    lines.push(
        Line::from("Your account is ready. 🎉")
            .fg(COLOR_SUCCESS)
            .bold(),
    );
    lines.push(Line::from(""));
    lines.push(
        Line::from("You haven't joined any communities yet — that's where the fun begins.")
            .fg(COLOR_TEXT_DEFAULT),
    );
    lines.push(
        Line::from("Find a Verifiable Trust Community and choose who it will know you as.")
            .fg(COLOR_TEXT_DEFAULT),
    );
    lines.push(Line::from(""));
    lines.push(Line::from("Press  j  to join your first community.").fg(COLOR_ORANGE));
    lines
}

#[cfg(test)]
mod key_hint_tests {
    use super::*;
    use crate::state_handler::main_page::content::CommunitySummary;
    use std::sync::Arc;

    fn row(is_active: bool, is_inactive: bool, is_pending: bool) -> CommunitySummary {
        CommunitySummary {
            display_name: "acme".to_string(),
            status_label: String::new(),
            persona_label: String::new(),
            member_since: String::new(),
            favourite: false,
            is_active,
            is_inactive,
            is_pending,
            pending_unacknowledged: false,
            submit_transport: None,
            archived: false,
            needs_attention: false,
            persona_did: String::new(),
            persona_agent_name: None,
            vtc_did: String::new(),
            vtc_agent_name: None,
            sub_context_id: String::new(),
            context_note: String::new(),
            has_own_context: false,
            request_id: String::new(),
            has_membership_credential: false,
            has_role_credential: false,
            accent: None,
        }
    }

    fn hints_for(community: CommunitySummary) -> String {
        key_hints(&CommunitiesState {
            items: Arc::from(vec![community]),
            selected_index: 0,
            ..CommunitiesState::default()
        })
    }

    /// The reported bug: the footer advertised `c` twice. It can never be
    /// ambiguous now, because the two meanings live on mutually exclusive row
    /// states and the footer follows the state.
    #[test]
    fn c_is_never_offered_twice() {
        for (active, inactive, pending) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let hints = hints_for(row(active, inactive, pending));
            assert_eq!(
                hints.matches("c: ").count(),
                usize::from(active || pending),
                "`c` must appear at most once, and only where it does something: {hints}"
            );
        }
    }

    /// An Active row: capabilities, not cancel — and the leave/VMC pair that
    /// only Active accepts.
    #[test]
    fn an_active_row_offers_capabilities_and_leave() {
        let hints = hints_for(row(true, false, false));
        assert!(hints.contains("c: capabilities"), "{hints}");
        assert!(hints.contains("l: leave"), "{hints}");
        assert!(hints.contains("m: issue VMC"), "{hints}");
        assert!(!hints.contains("c: cancel"), "{hints}");
        assert!(
            !hints.contains("x: archive") && !hints.contains("d: delete"),
            "archive/delete are inactive-only and would be silent no-ops here: {hints}"
        );
    }

    /// A Pending row: `c` is cancel, and capabilities is gone.
    #[test]
    fn a_pending_row_offers_cancel_not_capabilities() {
        let hints = hints_for(row(false, false, true));
        assert!(hints.contains("c: cancel"), "{hints}");
        assert!(!hints.contains("c: capabilities"), "{hints}");
        assert!(!hints.contains("l: leave"), "{hints}");
    }

    /// An Inactive row: archive/delete, and none of the Active-only keys.
    #[test]
    fn an_inactive_row_offers_archive_and_delete() {
        let hints = hints_for(row(false, true, false));
        assert!(
            hints.contains("x: archive") && hints.contains("d: delete"),
            "{hints}"
        );
        assert!(!hints.contains("c: "), "{hints}");
        assert!(!hints.contains("l: leave"), "{hints}");
    }

    /// `j` and `v` act on the panel rather than the selection, so they survive
    /// an empty list — where every selection-gated key must be absent.
    #[test]
    fn panel_level_keys_survive_an_empty_selection() {
        let hints = key_hints(&CommunitiesState::default());
        assert!(hints.contains("j: join"), "{hints}");
        assert!(hints.contains("v: show archived"), "{hints}");
        assert!(!hints.contains("⏎ open"), "nothing is selected: {hints}");
        assert!(!hints.contains("c: "), "nothing is selected: {hints}");
    }

    /// The archived toggle reflects the current state, as it did before.
    #[test]
    fn the_archived_hint_tracks_the_toggle() {
        let hints = key_hints(&CommunitiesState {
            show_archived: true,
            ..CommunitiesState::default()
        });
        assert!(hints.contains("v: hide archived"), "{hints}");
    }

    // ─── personhood ──────────────────────────────────────────────────────

    use crate::state_handler::main_page::content::PersonhoodChallengeView;
    use openvtc_core::config::account::PersonaId;

    fn challenge(expires_in_minutes: i64) -> PersonhoodChallengeView {
        PersonhoodChallengeView {
            vtc_did: "did:webvh:acme".to_string(),
            persona: PersonaId(uuid::Uuid::nil()),
            challenge_id: uuid::Uuid::nil(),
            match_code: "5CY1-GZEE".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(expires_in_minutes),
        }
    }

    /// Render with no binding answers in hand — every row reads
    /// "presents: unknown", which is the honest state before the agent has been
    /// asked and the one these tests are not about.
    fn render_for_test(state: &CommunitiesState) -> Vec<Line<'static>> {
        render(state, &std::collections::HashMap::new())
    }

    fn state_with(
        community: Option<CommunitySummary>,
        c: Option<PersonhoodChallengeView>,
    ) -> CommunitiesState {
        CommunitiesState {
            items: Arc::from(community.map(|x| vec![x]).unwrap_or_default()),
            selected_index: 0,
            personhood_challenge: c,
            ..CommunitiesState::default()
        }
    }

    /// `p` is Active-only, matching the key handler. Offering it on a Pending
    /// row would be a silent no-op — the defect this file's hint gating was
    /// written to remove.
    #[test]
    fn personhood_is_offered_only_on_an_active_row() {
        assert!(hints_for(row(true, false, false)).contains("p: personhood"));
        for (active, inactive, pending) in [(false, true, false), (false, false, true)] {
            let hints = hints_for(row(active, inactive, pending));
            assert!(
                !hints.contains("p: personhood"),
                "personhood needs an Active membership: {hints}"
            );
        }
    }

    /// `P` is gated on holding a live challenge, not on the row — exactly as
    /// the key handler gates it. Advertising it with nothing to answer would
    /// be the same class of dead key.
    #[test]
    fn assert_is_offered_only_while_a_live_challenge_is_held() {
        let active = row(true, false, false);

        assert!(
            !key_hints(&state_with(Some(active.clone()), None)).contains("P: assert"),
            "nothing to assert against"
        );
        assert!(
            key_hints(&state_with(Some(active.clone()), Some(challenge(5))))
                .contains("P: assert personhood"),
        );
        assert!(
            !key_hints(&state_with(Some(active), Some(challenge(-1)))).contains("P: assert"),
            "an expired challenge cannot be answered"
        );
    }

    /// The match code is what a member reads aloud, so it has to be on screen
    /// — and on its own line rather than buried in a sentence.
    #[test]
    fn a_live_challenge_shows_its_match_code() {
        let rendered: Vec<String> = render_for_test(&state_with(
            Some(row(true, false, false)),
            Some(challenge(5)),
        ))
        .iter()
        .map(|l| l.to_string())
        .collect();

        assert!(
            rendered.iter().any(|l| l.trim() == "5CY1-GZEE"),
            "the code must stand alone: {rendered:#?}"
        );
    }

    /// An expired challenge says so rather than disappearing. A member who has
    /// just been read a code, looking at a panel that never mentions one,
    /// cannot tell "it lapsed" from "it never arrived".
    #[test]
    fn an_expired_challenge_says_so_rather_than_vanishing() {
        let rendered: Vec<String> = render_for_test(&state_with(
            Some(row(true, false, false)),
            Some(challenge(-1)),
        ))
        .iter()
        .map(|l| l.to_string())
        .collect();

        assert!(
            rendered.iter().any(|l| l.contains("expired")),
            "the lapse must be visible: {rendered:#?}"
        );
        assert!(
            !rendered.iter().any(|l| l.contains("5CY1-GZEE")),
            "a dead code must not still read as answerable: {rendered:#?}"
        );
    }

    // ─── community contexts ─────────────────────────────────────────────

    use crate::state_handler::main_page::content::{
        ContextDeletePhase, ContextDeleteView, DeviceAccessView, GrantListing,
    };
    use openvtc_core::community_access::DeviceGrant;
    use openvtc_core::config::community_context::ContextDeletionPreview;
    use vta_sdk::protocols::context_management::delete::DeleteContextPreviewResultBody;

    const CTX: &str = "openvtc/acme";

    fn own(is_inactive: bool) -> CommunitySummary {
        CommunitySummary {
            has_own_context: true,
            sub_context_id: CTX.to_string(),
            ..row(!is_inactive, is_inactive, false)
        }
    }

    fn grant(did: &str) -> DeviceGrant {
        DeviceGrant {
            did: did.to_string(),
            role: "application".to_string(),
            label: Some("laptop".to_string()),
            contexts: vec![CTX.to_string()],
            elsewhere: vec![],
            expires_at: None,
        }
    }

    fn text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Device access needs a community's own context, and only a finished
    /// membership's context can be deleted — the hints follow the keys.
    #[test]
    fn context_keys_are_offered_only_where_they_act() {
        let active = hints_for(own(false));
        assert!(active.contains("g: devices"), "{active}");
        assert!(!active.contains("D: delete context"), "{active}");

        let finished = hints_for(own(true));
        assert!(
            finished.contains("g: devices") && finished.contains("D: delete context"),
            "{finished}"
        );

        let top = hints_for(row(false, true, false));
        assert!(
            !top.contains("g: devices") && !top.contains("D: delete context"),
            "{top}"
        );
    }

    /// An unread context says so; "none" is only said once the VTA has answered.
    #[test]
    fn the_detail_says_whether_device_access_has_been_read() {
        let mut state = state_with(Some(own(false)), None);
        let unread = text(&render_for_test(&state));
        assert!(unread.contains("not read yet"), "{unread}");

        state.device_grants.insert(
            CTX.to_string(),
            GrantListing::Loaded(vec![grant("did:key:zLaptop")]),
        );
        let read = text(&render_for_test(&state));
        assert!(
            read.contains("did:key:zLaptop") && read.contains("application"),
            "{read}"
        );
    }

    /// A persona deleted with the context is named with its DID, with what that
    /// means, beside the membership record it takes along.
    #[test]
    fn a_deletion_that_takes_the_persona_says_so_plainly() {
        let mut state = state_with(Some(own(true)), None);
        let persona = PersonaId::new();
        state.context_delete = Some(ContextDeleteView {
            vtc_did: "did:webvh:acme".to_string(),
            persona,
            community: "Acme".to_string(),
            context_id: CTX.to_string(),
            takes_persona: Some(openvtc_core::config::community_context::PersonaTakenAlong {
                persona,
                did: "did:webvh:scid:host:kernel-me".to_string(),
                name: "Kernel me".to_string(),
            }),
            phase: ContextDeletePhase::Ready(ContextDeletionPreview::default()),
            typed: String::new(),
        });
        let shown = text(&render_for_test(&state));
        for item in [
            "Persona Kernel me",
            "did:webvh:scid:host:kernel-me",
            "can no longer be used anywhere",
            "stays published there",
            "finished membership of Acme",
            "Type DELETE",
        ] {
            assert!(shown.contains(item), "missing {item:?}:\n{shown}");
        }
    }

    #[test]
    fn a_deletion_shows_everything_the_vta_will_remove_and_what_to_type() {
        let mut state = state_with(Some(own(true)), None);
        state.context_delete = Some(ContextDeleteView {
            vtc_did: "did:webvh:acme".to_string(),
            persona: PersonaId::new(),
            community: "Acme".to_string(),
            context_id: CTX.to_string(),
            takes_persona: None,
            phase: ContextDeletePhase::Ready(ContextDeletionPreview {
                context_id: CTX.to_string(),
                contexts: vec![
                    DeleteContextPreviewResultBody {
                        id: CTX.to_string(),
                        keys: vec!["key-1".to_string()],
                        webvh_dids: vec!["did:webvh:scid:host:persona".to_string()],
                        acl_entries_removed: vec!["did:key:zLaptop".to_string()],
                        ..Default::default()
                    },
                    DeleteContextPreviewResultBody {
                        id: format!("{CTX}/ci"),
                        ..Default::default()
                    },
                ],
            }),
            typed: "DEL".to_string(),
        });
        let shown = text(&render_for_test(&state));
        for item in [
            "Acme",
            "key-1",
            "did:webvh:scid:host:persona",
            "did:key:zLaptop",
            "Sub-context openvtc/acme/ci",
            "Type DELETE",
            "> DEL",
        ] {
            assert!(shown.contains(item), "missing {item:?}:\n{shown}");
        }
    }

    #[test]
    fn device_access_names_the_role_and_what_a_finished_membership_allows() {
        let view = DeviceAccessView {
            community: "Acme".to_string(),
            context_id: CTX.to_string(),
            can_grant: true,
            selected: 0,
            form: None,
            confirm_revoke: false,
            busy: false,
            message: None,
        };
        let mut state = state_with(Some(own(false)), None);
        state.device_grants.insert(
            CTX.to_string(),
            GrantListing::Loaded(vec![grant("did:key:zLaptop")]),
        );
        state.device_access = Some(view.clone());
        let live = text(&render_for_test(&state));
        assert!(live.contains("application role"), "{live}");
        assert!(live.contains("did:key:zLaptop"), "{live}");
        assert!(
            live.contains("n: add a device") && live.contains("x: revoke"),
            "{live}"
        );

        state.device_access = Some(DeviceAccessView {
            can_grant: false,
            ..view
        });
        let finished = text(&render_for_test(&state));
        assert!(!finished.contains("n: add a device"), "{finished}");
        assert!(finished.contains("membership is over"), "{finished}");
    }
}
