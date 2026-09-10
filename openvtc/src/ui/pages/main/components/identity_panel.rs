//! The identity pane — every surface for a person's own identity, in one place.
//!
//! Five tabs, in the order the concepts build on each other. On screen they are
//! **Personas**, **Your attributes**, **Faces**, **Communities** and **What has
//! left**; in the code and on the wire they are personas, attributes, profiles,
//! contexts and disclosures. The first comes from `Config`; the rest come from
//! the agent.
//!
//! # The screen speaks a different language, on purpose
//!
//! `design-docs/persona-vocabulary.md` fixes the words a person reads, so the
//! console, `pnm`, the mobile agent and this pane say the same thing. The
//! spec's words are exact and stay in the types, on the wire and in the audit
//! log; they are kept off the screen. `persona/attribute/put` stays
//! `persona/attribute/put` — the form says *Add an attribute*.
//!
//! The three that matter most here:
//!
//! - an **attribute** stays an **attribute** — *something you say about
//!   yourself, held once*. This row is the one the table does not translate:
//!   the friendlier word it used to carry, *fact*, claimed a truth a
//!   self-asserted value does not have, and `Facts` already means a verified
//!   policy input in `vtc-service`. Truth is carried by the provenance line
//!   beneath the value, never by the noun;
//! - a **profile** is a **face** — *the set of attributes you show together*. Not
//!   "profile", which already means three things in this product and "my
//!   LinkedIn page" to everyone else;
//! - a **binding** is **wearing**: a persona *wears* a face in a community.
//!   `Be known here as…`, `Change face`, `Take it off`.
//!
//! A **persona** keeps its own name in both languages. It is already a human
//! word, and it is what a community knows you as.
//!
//! # What this pane will not draw
//!
//! A value the holder never asked to see. The list of attributes is fetched without
//! values by default and `v` re-reads *with* them — an opt-in that costs a
//! round-trip rather than a display flag over data already in memory, because a
//! listing that holds values has already read someone's identity whether or not
//! the panel chose to paint it.
//!
//! A number it does not have. "We could not ask the agent" and "you hold
//! nothing" are one pixel apart and one of them is a confident wrong answer
//! about a person's own data, so every agent-served tab draws the failure
//! rather than an empty list.

use super::panel::Panel;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::{
    main_page::content::{
        AttributeField, AttributeForm, BindPicker, IdentityState, PersonaConfirm, PersonaMode,
        PersonaTab, ProfileForm, ProfileFormFocus, VALUE_TYPES,
    },
    state::ConnectionState,
};
use openvtc_core::display::display_identifier;
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Width for identifiers on a row. Long enough to be checkable, short enough
/// that the label beside it survives on an 80-column terminal.
const ID_WIDTH: usize = 46;

/// Width for the DID inside a destructive confirmation, where both ends of the
/// identifier have to stay readable.
const CONFIRM_DID_WIDTH: usize = 48;

/// The identity pane.
pub struct IdentityPanel;

impl Panel for IdentityPanel {
    fn render(
        &self,
        state: &crate::state_handler::main_page::content::ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        render(&state.identity)
    }
}

/// Render the pane. A form or picker owns the whole panel while it is open —
/// the lists behind it are not interactive then, and drawing them would invite
/// keys that go nowhere.
pub fn render(state: &IdentityState) -> Vec<Line<'static>> {
    match &state.mode {
        PersonaMode::Attribute(form) => render_attribute_form(form),
        PersonaMode::Profile(form) => render_profile_form(state, form),
        PersonaMode::Bind(picker) => render_bind_picker(state, picker),
        PersonaMode::View => render_tabs(state),
    }
}

// ---------------------------------------------------------------------------
// The tabbed view
// ---------------------------------------------------------------------------

fn render_tabs(state: &IdentityState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    if let Some(msg) = &state.status_message {
        super::status::push_status(&mut lines, msg, "");
        lines.push(Line::from(""));
    }

    // Tab strip.
    let mut spans = Vec::new();
    for (i, tab) in PersonaTab::all().into_iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" | ", Style::new().fg(COLOR_DARK_GRAY)));
        }
        let style = if state.tab == tab {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_DARK_GRAY)
        };
        spans.push(Span::styled(format!(" {} ", tab.label()), style));
    }
    lines.push(Line::from(spans));
    lines.push(Line::from(""));

    match state.tab {
        PersonaTab::Personas => render_personas(state, &mut lines),
        PersonaTab::Attributes => render_attributes(state, &mut lines),
        PersonaTab::Profiles => render_profiles(state, &mut lines),
        PersonaTab::Communities => render_communities(state, &mut lines),
        PersonaTab::Disclosures => render_disclosures(state, &mut lines),
    }

    // The confirmation prompt replaces the key hints while it is armed: a
    // destructive question and a menu of other things to press do not belong on
    // screen together.
    lines.push(Line::from(""));
    match confirm_prompt(state) {
        Some(prompt) => lines.push(Line::from(prompt).fg(COLOR_ORANGE).bold()),
        None => lines.push(Line::from(hints(state)).fg(COLOR_DARK_GRAY)),
    }
    lines
}

/// The question to put, worded so a `y` cannot be given to the wrong one.
fn confirm_prompt(state: &IdentityState) -> Option<String> {
    match &state.confirm {
        PersonaConfirm::None => None,
        PersonaConfirm::DeletePersona(i) => {
            let persona = state.personas.get(*i)?;
            // Keep *both* the name and the DID. The row the operator selected
            // shows the name, so a DID-only prompt names something they never
            // saw; but a destructive confirm must stay unambiguous, so the DID
            // is not dropped either — it is centre-truncated to keep the line
            // readable while both ends stay checkable.
            let did = openvtc_core::display::truncate_did_centered(&persona.did, CONFIRM_DID_WIDTH);
            let name = match persona
                .label
                .is_empty()
                .then_some(persona.agent_name.as_deref())
                .flatten()
                .or_else(|| (!persona.label.is_empty()).then_some(persona.label.as_str()))
            {
                Some(name) => format!("{name} ({did})"),
                None => did.into_owned(),
            };
            Some(format!("Remove {name}?   y: confirm    n: cancel"))
        }
        PersonaConfirm::DeleteAttribute { name, cascade, .. } => {
            if *cascade {
                // The cascading question names the consequence the plain one
                // does not have: profiles that show this value stop showing it.
                Some(format!(
                    "\"{name}\" is on one or more faces. Forget it AND remove it from those \
                     faces too?   Nothing already shared is affected — that has left.   \
                     y: confirm    n: cancel"
                ))
            } else {
                Some(format!("Forget \"{name}\"?   y: confirm    n: cancel"))
            }
        }
        PersonaConfirm::DeleteProfile { name, unbind, .. } => {
            if *unbind {
                Some(format!(
                    "A persona wears \"{name}\". Delete it and leave that persona showing \
                     nothing?   Nothing already shared is affected — that has left.   \
                     y: confirm    n: cancel"
                ))
            } else {
                Some(format!(
                    "Delete the face \"{name}\"?   y: confirm    n: cancel"
                ))
            }
        }
        PersonaConfirm::Unbind { community, .. } => Some(format!(
            "Take it off — show {community} nothing?   Nothing already shared is affected \
             — that has left.   y: confirm    n: cancel"
        )),
    }
}

fn hints(state: &IdentityState) -> &'static str {
    match state.tab {
        PersonaTab::Personas => {
            "↑/↓ select   n: new persona   g: agent names   d: remove unused   ⇥/⇧⇥: tab"
        }
        PersonaTab::Attributes => {
            "↑/↓ select   n: add an attribute   e: edit   d: delete   v: values   s: show one   \
             r: refresh   ⇥/⇧⇥: tab"
        }
        PersonaTab::Profiles => {
            "↑/↓ select   ⏎: what it shows   n: make a face   e: edit   d: delete   r: refresh   ⇥/⇧⇥: tab"
        }
        PersonaTab::Communities => {
            "↑/↓ select   b: change face   u: take it off   r: refresh   ⇥/⇧⇥: tab"
        }
        PersonaTab::Disclosures => "↑/↓ select   r: refresh   ⇥/⇧⇥: tab",
    }
}

// ---------------------------------------------------------------------------
// Personas
// ---------------------------------------------------------------------------

fn render_personas(state: &IdentityState, lines: &mut Vec<Line<'static>>) {
    if state.personas.is_empty() {
        lines.push(Line::from(" You have no personas yet.").fg(COLOR_DARK_GRAY));
        lines.push(Line::from(""));
        lines.push(
            Line::from(
                " A persona is who a community knows you as. Make one with `n`, hand its DID \
                 to a community, and they can issue you an invitation bound to it.",
            )
            .fg(COLOR_DARK_GRAY),
        );
        return;
    }

    lines.push(
        Line::from(format!(
            " {} persona{}",
            state.personas.len(),
            if state.personas.len() == 1 { "" } else { "s" }
        ))
        .fg(COLOR_TEXT_DEFAULT),
    );
    lines.push(Line::from(""));

    for (i, persona) in state.personas.iter().enumerate() {
        let is_selected = i == state.persona_selected;
        // An orphan is a persona no community sees. Usually the residue of a join
        // that failed, and worth spotting: it costs keys and a mediator
        // registration while presenting nothing to anybody.
        let orphan = persona.bound_communities == 0;
        let prefix = if is_selected { "▸ " } else { "  " };
        let marker_style = if orphan {
            Style::new().fg(COLOR_ORANGE)
        } else {
            Style::new().fg(COLOR_SUCCESS)
        };
        let row_style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };

        lines.push(Line::from(vec![
            Span::styled(prefix, marker_style),
            Span::styled(if orphan { "○ " } else { "● " }, marker_style),
            Span::styled(
                display_identifier(persona.agent_name.as_deref(), &persona.did, ID_WIDTH)
                    .into_owned(),
                row_style,
            ),
        ]));

        let name = if persona.label.is_empty() {
            "unnamed persona".to_string()
        } else {
            persona.label.clone()
        };
        let seen_by = if orphan {
            "not known anywhere yet".to_string()
        } else {
            format!(
                "known to {} communit{}",
                persona.bound_communities,
                if persona.bound_communities == 1 {
                    "y"
                } else {
                    "ies"
                }
            )
        };
        let active = if persona.is_active {
            "  ·  active"
        } else {
            ""
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("      {name}{active}  ·  "),
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Span::styled(
                seen_by,
                if orphan {
                    Style::new().fg(COLOR_ORANGE)
                } else {
                    Style::new().fg(COLOR_DARK_GRAY)
                },
            ),
        ]));
    }
}

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

/// What the holder needs to know about the table these rows were painted from.
///
/// Two different sentences, and they are not variants of one:
///
/// - **The table is this build's, not the agent's.** Every mask on the screen
///   below was decided by a compiled copy of spec 0.1 because the agent does
///   not serve `persona/claim-types/list`. It is very likely right, and it
///   cannot know about anything the deployment declared for itself — so the
///   line says where the answers came from rather than claiming a fault.
/// - **The agent refused part of its own configuration.** This one is a fault,
///   and it is invisible without saying so: a refused row resolves exactly as
///   it would with no configuration at all, so an operator's intended
///   tightening is quietly not in force and the screen looks entirely normal.
///
/// Both are drawn under the mask explanation and above the rows, because they
/// qualify the rows rather than the pane.
fn push_registry_notes(state: &IdentityState, lines: &mut Vec<Line<'static>>) {
    let registry = &state.claim_types;

    if registry.is_fallback {
        lines.push(
            Line::from(
                " Masking here follows this build's own copy of the claim-type table: your \
                 agent is older than this client and does not serve one. Anything your \
                 deployment added to it is not reflected below.",
            )
            .fg(COLOR_DARK_GRAY),
        );
        lines.push(Line::from(""));
    }

    if let Some(error) = &registry.unapplied.file_error {
        lines.push(
            Line::from(format!(
                " Your agent could not read its own claim-type file, so none of what this \
                 deployment declared is in force: {error}"
            ))
            .fg(COLOR_WARNING_ACCESSIBLE_RED),
        );
        lines.push(Line::from(""));
    }

    // Named one by one rather than counted. "3 claim types were rejected" sends
    // the reader to a file to work out which; the token and the agent's own
    // reason are the whole of what they need to fix it.
    for rejected in &registry.unapplied.rejected {
        lines.push(
            Line::from(format!(
                " Your agent would not apply `{}` from this deployment's claim types: {}",
                rejected.claim_type, rejected.reason
            ))
            .fg(COLOR_WARNING_ACCESSIBLE_RED),
        );
    }
    if !registry.unapplied.rejected.is_empty() {
        lines.push(Line::from(""));
    }
}

fn render_attributes(state: &IdentityState, lines: &mut Vec<Line<'static>>) {
    if push_agent_state(state, lines, "attributes") {
        return;
    }

    lines.push(Line::from(vec![
        Span::styled(
            format!(
                " {} attribute{} about you",
                state.attributes.len(),
                if state.attributes.len() == 1 { "" } else { "s" }
            ),
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ),
        Span::styled(
            if state.show_values {
                "        values shown — v to hide"
            } else {
                "        values hidden — v to show"
            },
            if state.show_values {
                Style::new().fg(COLOR_ORANGE)
            } else {
                Style::new().fg(COLOR_DARK_GRAY)
            },
        ),
    ]));
    lines.push(Line::from(""));

    if state.attributes.is_empty() {
        lines.push(
            Line::from(
                " No attributes yet. `n` adds one — a name, an email, a date of birth. An attribute \
                 about you, held once; faces select from these.",
            )
            .fg(COLOR_DARK_GRAY),
        );
        return;
    }

    // Said once, above the rows, rather than on each of them: it explains the
    // key, and it says what the mask is worth. Only when something on screen is
    // actually masked — an explanation of a mechanism the holder is not looking
    // at is noise.
    if state
        .attributes
        .iter()
        .any(|a| a.is_masked(&state.claim_types))
    {
        lines.push(
            Line::from(
                " Some attributes are masked by what they are — `s` shows the selected one. The \
                 mask is against someone reading over your shoulder; your agent has already \
                 sent the value here.",
            )
            .fg(COLOR_DARK_GRAY),
        );
        lines.push(Line::from(""));
    }

    push_registry_notes(state, lines);

    for (i, attr) in state.attributes.iter().enumerate() {
        let is_selected = i == state.attribute_selected;
        let row_style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(if is_selected { "▸ " } else { "  " }, row_style),
            Span::styled(
                format!("{:<28}", truncate(attr.display_name(), 27)),
                row_style,
            ),
            Span::styled(
                format!("{:<20}", truncate(&attr.claim_type, 19)),
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
            Span::styled(
                attr.provenance.label().to_string(),
                // A credential-backed value is the one a holder must not expect
                // to edit here, so its provenance is the part of the row that
                // stands out rather than a footnote after they have tried.
                if attr.provenance.is_editable_here() {
                    Style::new().fg(COLOR_DARK_GRAY)
                } else {
                    Style::new().fg(COLOR_ORANGE)
                },
            ),
        ]));
        // A reveal is granted to one attribute, and only while it is the selected
        // one. Checking the selection as well as the identifier means a list
        // that re-sorted under a stale grant cannot open a row nobody chose.
        let revealed =
            is_selected && state.revealed_attribute.as_deref() == Some(attr.attribute_id.as_str());
        let value = if revealed {
            attr.revealed_value(&state.claim_types, state.show_values)
        } else {
            attr.display_value(&state.claim_types, state.show_values)
        };
        let mut value_spans = vec![Span::styled(
            format!("      {}", truncate(&value, 70)),
            if attr.stale {
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED)
            } else {
                Style::new().fg(COLOR_DARK_GRAY)
            },
        )];
        // Without this the row is a wrong answer rather than a reduced one:
        // `••••••••` and "(no value)" are the same shape, and a holder reading
        // the first as the second believes they hold nothing.
        if attr.is_masked(&state.claim_types) {
            value_spans.push(Span::styled(
                if revealed {
                    "   showing — s to mask"
                } else {
                    "   masked — s to show"
                },
                if revealed {
                    Style::new().fg(COLOR_ORANGE)
                } else {
                    Style::new().fg(COLOR_SOFT_PURPLE)
                },
            ));
        }
        lines.push(Line::from(value_spans));
    }
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

fn render_profiles(state: &IdentityState, lines: &mut Vec<Line<'static>>) {
    if let Some(detail) = &state.open_profile {
        lines.push(
            Line::from(format!(" {}", detail.summary.display_name()))
                .fg(COLOR_SUCCESS)
                .bold(),
        );
        lines.push(Line::from(""));
        if !detail.is_editable_here() {
            super::status::push_status(lines, &detail.refusal(), " ");
            lines.push(Line::from(""));
        }
        if detail.resolved.is_empty() {
            lines.push(
                Line::from(" This face shows nothing — no attributes are on it.")
                    .fg(COLOR_DARK_GRAY),
            );
        } else {
            lines.push(
                Line::from(format!(
                    " Shows {} attribute{}:",
                    detail.resolved.len(),
                    if detail.resolved.len() == 1 { "" } else { "s" }
                ))
                .fg(COLOR_TEXT_DEFAULT),
            );
            lines.push(Line::from(""));
            for (i, claim) in detail.resolved.iter().enumerate() {
                let is_selected = i == state.face_claim_selected;
                // A reveal is granted to one claim, and only while it is the
                // selected one — the same pairing the attributes tab makes, so
                // a stale grant cannot open a row nobody chose.
                let revealed = is_selected && state.revealed_face_claim == Some(i);
                let value = if revealed {
                    claim.revealed_value(&state.claim_types)
                } else {
                    claim.display_value(&state.claim_types)
                };
                let mut spans = vec![
                    Span::styled(
                        if is_selected { " ▸ " } else { "   " },
                        if is_selected {
                            Style::new().fg(COLOR_SUCCESS).bold()
                        } else {
                            Style::new().fg(COLOR_TEXT_DEFAULT)
                        },
                    ),
                    Span::styled(
                        format!("{:<22}", truncate(&claim.claim_type, 21)),
                        Style::new().fg(COLOR_SOFT_PURPLE),
                    ),
                    Span::styled(truncate(&value, 44), Style::new().fg(COLOR_TEXT_DEFAULT)),
                ];
                // Without this the row is a wrong answer rather than a reduced
                // one: `••••••••` and "(no value)" are the same shape, and a
                // holder reading the first as the second believes the face
                // shows nothing.
                if claim.is_masked(&state.claim_types) && !revealed {
                    spans.push(Span::styled(
                        if is_selected {
                            "   masked — s to show"
                        } else {
                            "   masked"
                        },
                        Style::new().fg(COLOR_DARK_GRAY),
                    ));
                }
                lines.push(Line::from(spans));
                // A value that lives only in this face is not among the
                // holder's attributes, so correcting it there will not correct it
                // here. Saying so on the row is the only place they find out.
                let origin = match claim.attribute_id {
                    Some(_) => claim.provenance.label().to_string(),
                    None => format!("{} · only in this face", claim.provenance.label()),
                };
                lines.push(Line::from(Span::styled(
                    format!("   {origin}"),
                    Style::new().fg(COLOR_DARK_GRAY),
                )));
            }
        }
        lines.push(Line::from(""));
        // Said once, above the keys, rather than on every row — and only when
        // something on screen is actually masked, because explaining a
        // mechanism the holder is not looking at is noise.
        if detail
            .resolved
            .iter()
            .any(|c| c.is_masked(&state.claim_types))
        {
            lines.push(
                Line::from(
                    " Some values are masked by what they are — `s` shows the selected one. The \
                     mask is against someone reading over your shoulder; this face already \
                     shows the value to whoever wears it.",
                )
                .fg(COLOR_DARK_GRAY),
            );
            lines.push(Line::from(""));
        }
        lines.push(
            Line::from(if detail.resolved.is_empty() {
                " ⏎/Esc: back   e: edit".to_string()
            } else {
                " ↑/↓ select   s: show one   ⏎/Esc: back   e: edit".to_string()
            })
            .fg(COLOR_DARK_GRAY),
        );
        return;
    }

    if push_agent_state(state, lines, "faces") {
        return;
    }

    lines.push(
        Line::from(format!(
            " {} face{}",
            state.profiles.len(),
            if state.profiles.len() == 1 { "" } else { "s" }
        ))
        .fg(COLOR_TEXT_DEFAULT),
    );
    lines.push(Line::from(""));

    if state.profiles.is_empty() {
        lines.push(
            Line::from(
                " No faces yet. A face is the set of attributes you show together — \"Work\", \
                 \"Gaming\" — and it is what a persona wears in a community. What you leave \
                 unticked stays out, including attributes you add later.",
            )
            .fg(COLOR_DARK_GRAY),
        );
        return;
    }

    for (i, profile) in state.profiles.iter().enumerate() {
        let is_selected = i == state.profile_selected;
        let row_style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(if is_selected { "▸ " } else { "  " }, row_style),
            Span::styled(
                format!("{:<28}", truncate(profile.display_name(), 27)),
                row_style,
            ),
            Span::styled(
                format!(
                    "{} attribute{}",
                    profile.entry_count,
                    if profile.entry_count == 1 { "" } else { "s" }
                ),
                Style::new().fg(COLOR_DARK_GRAY),
            ),
        ]));
    }
}

// ---------------------------------------------------------------------------
// Communities
// ---------------------------------------------------------------------------

fn render_communities(state: &IdentityState, lines: &mut Vec<Line<'static>>) {
    if state.memberships.is_empty() {
        lines.push(Line::from(" You are not a member of any community yet.").fg(COLOR_DARK_GRAY));
        return;
    }

    lines.push(
        Line::from(format!(
            " {} membership{}",
            state.memberships.len(),
            if state.memberships.len() == 1 {
                ""
            } else {
                "s"
            }
        ))
        .fg(COLOR_TEXT_DEFAULT),
    );
    lines.push(Line::from(""));

    for (i, m) in state.memberships.iter().enumerate() {
        let is_selected = i == state.membership_selected;
        let row_style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(if is_selected { "▸ " } else { "  " }, row_style),
            Span::styled(truncate(&m.community_name, 30), row_style),
            Span::styled(
                format!("  as {}", truncate(&m.persona_label, 24)),
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
        ]));

        // What that persona tells them. `unknown` is drawn, never omitted: an
        // omitted row is indistinguishable from a persona bound to nothing, and
        // "we have not asked" is not "you are sharing nothing".
        let detail = format!(
            "      {}  ·  {}",
            m.status_label,
            state.binding_for(m).describe()
        );
        lines.push(Line::from(Span::styled(
            detail,
            if is_selected {
                Style::new().fg(COLOR_SOFT_PURPLE)
            } else {
                Style::new().fg(COLOR_DARK_GRAY)
            },
        )));

        // The linkage line. Two communities shown one persona can compare notes
        // and find the same person behind both, and that is the consequence a
        // holder cannot see by looking at either row on its own.
        if m.shared_with > 0 {
            lines.push(
                Line::from(format!(
                    "      ⚠ linked: the same persona is known to {} other communit{}",
                    m.shared_with,
                    if m.shared_with == 1 { "y" } else { "ies" }
                ))
                .fg(COLOR_ORANGE),
            );
        }
    }

    lines.push(Line::from(""));
    // The honest limit of this tab. A membership is held by a credential issued
    // to one persona DID, so which persona a community sees is fixed at the join —
    // `b` changes what that persona says, never who it is.
    lines.push(
        Line::from(
            " `b` changes the face this persona wears here. To be known to a community as a \
             *different* persona, join it again with that one — the membership credential names \
             the persona that joined.",
        )
        .fg(COLOR_DARK_GRAY),
    );
}

// ---------------------------------------------------------------------------
// Disclosures
// ---------------------------------------------------------------------------

fn render_disclosures(state: &IdentityState, lines: &mut Vec<Line<'static>>) {
    if push_agent_state(state, lines, "history") {
        return;
    }

    lines.push(
        Line::from(format!(
            " {} release{}, newest first — what has left, and to whom",
            state.disclosures.len(),
            if state.disclosures.len() == 1 {
                ""
            } else {
                "s"
            }
        ))
        .fg(COLOR_TEXT_DEFAULT),
    );
    lines.push(Line::from(""));

    if state.disclosures.is_empty() {
        lines.push(
            Line::from(
                " Nothing has left yet. Something leaves when a site asks and you approve \
                 it — this is the record of those, and it is read-only.",
            )
            .fg(COLOR_DARK_GRAY),
        );
        return;
    }

    for (i, row) in state.disclosures.iter().enumerate() {
        let is_selected = i == state.disclosure_selected;
        let row_style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(if is_selected { "▸ " } else { "  " }, row_style),
            Span::styled(
                format!("{:<22}", truncate(&row.disclosed_at, 21)),
                row_style,
            ),
            Span::styled(
                truncate(&row.verifier_did, 44),
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!("      {}", truncate(&row.describe_claims(), 70)),
            Style::new().fg(COLOR_DARK_GRAY),
        )));
        // A durable credential is the one kind of release that is still live —
        // and still revocable — rather than a thing that happened once.
        if let Some(id) = &row.durable_credential_id {
            lines.push(
                Line::from(format!(
                    "      ● still live as a credential ({}) — can be revoked",
                    truncate(id, 40)
                ))
                .fg(COLOR_ORANGE),
            );
        }
    }
}

/// Draw the "we are still asking" / "we could not ask" states shared by the
/// agent-served tabs. Returns true when it drew one and the caller should stop.
///
/// The failure case is why this exists: an empty list and an unreachable agent
/// render identically unless something says otherwise, and of the two, "you
/// hold no attributes" is the confident wrong answer (VTI R6.4).
fn push_agent_state(state: &IdentityState, lines: &mut Vec<Line<'static>>, noun: &str) -> bool {
    if let Some(error) = &state.load_error {
        lines.push(
            Line::from(format!(" Could not read your {noun} from the agent."))
                .fg(COLOR_WARNING_ACCESSIBLE_RED),
        );
        lines.push(Line::from(""));
        // The one failure we recognise is said in our own words, and they are
        // the agreed ones. The agent's sentence is accurate and abstract —
        // "the holder's attribute pool, which sits above every trust context" —
        // and echoing it would put three words on screen that the vocabulary
        // keeps off it, in the place a person is least able to absorb them.
        //
        // Every other failure is echoed verbatim. That text is *data*: it may
        // name a host, a port, a contract mismatch, and translating what we do
        // not recognise would be inventing a cause (VTI R6.4).
        if needs_holder_grant(error) {
            for line in holder_grant_hint(state.agent_credential_did.as_deref()) {
                lines.push(Line::from(line).fg(COLOR_ORANGE));
            }
        } else {
            super::status::push_status(lines, error, " ");
        }
        lines.push(Line::from(""));
        lines.push(Line::from(" r: try again").fg(COLOR_DARK_GRAY));
        return true;
    }
    if state.loading && !state.loaded {
        lines.push(Line::from(format!(" Reading your {noun}…")).fg(COLOR_DARK_GRAY));
        return true;
    }
    if !state.loaded {
        lines.push(
            Line::from(format!(
                " Your {noun} have not been read yet.   r: read them"
            ))
            .fg(COLOR_DARK_GRAY),
        );
        return true;
    }
    false
}

/// What to do about the one refusal that has a specific answer.
///
/// Kept as lines rather than a paragraph because the middle one is a command an
/// operator has to read character by character — and, when we know it, retype
/// or copy into another terminal.
///
/// We *do* know it: the DID this install authenticates as is in the config the
/// pane is already rendering from, so the command is emitted complete rather
/// than with a `<this install's DID>` placeholder the reader has to go and
/// resolve on another pane. The placeholder survives only for the case where
/// there is genuinely nothing to substitute — a BIP32 account, which has no
/// agent credential at all (and, having no agent, will not have produced this
/// refusal in the first place).
fn holder_grant_hint(credential_did: Option<&str>) -> Vec<String> {
    let subject = credential_did.unwrap_or("<this install's DID>");
    vec![
        " Your agent credential administers this context. Your attributes, and the faces"
            .to_string(),
        " over them, sit above every context — reaching them is a separate grant:".to_string(),
        String::new(),
        format!("   pnm acl update {subject} --capabilities persona-holder"),
        String::new(),
        " It adds authority over your own identity without giving this install any".to_string(),
        " authority over other contexts.".to_string(),
    ]
}

/// Whether a read failed because the caller lacks holder authority, as opposed
/// to the agent being unreachable or the request being malformed.
///
/// Matched on the phrase both the current and the pre-capability VTA use, since
/// an operator may be pointing at either: the older one refuses with "unscoped
/// holder credential" and names no capability, because there was none to name.
/// A false negative here costs a hint; a false positive would tell someone to
/// run a grant that is not their problem, so the match is on the specific
/// phrase rather than on "forbidden".
fn needs_holder_grant(error: &str) -> bool {
    let e = error.to_ascii_lowercase();
    e.contains("holder credential") || e.contains("persona-holder")
}

// ---------------------------------------------------------------------------
// The attribute editor
// ---------------------------------------------------------------------------

fn render_attribute_form(form: &AttributeForm) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from(if form.attribute_id.is_some() {
            " Edit an attribute"
        } else {
            " Add an attribute"
        })
        .fg(COLOR_SUCCESS)
        .bold(),
    );
    lines.push(Line::from(""));
    lines.push(
        Line::from(
            " Something you say about yourself, held once. Faces select it, so correcting it here corrects \
             it everywhere it is worn.",
        )
        .fg(COLOR_DARK_GRAY),
    );
    lines.push(Line::from(""));

    field(
        &mut lines,
        "Type",
        form.claim_type.value(),
        form.field == AttributeField::ClaimType,
    );
    lines.push(Line::from("      e.g. name.legal, email.work, phone.mobile").fg(COLOR_DARK_GRAY));
    field(
        &mut lines,
        "Label",
        form.label.value(),
        form.field == AttributeField::Label,
    );
    field(
        &mut lines,
        "Value type",
        &format!(
            "◂ {} ▸",
            VALUE_TYPES[form.value_type.min(VALUE_TYPES.len() - 1)]
        ),
        form.field == AttributeField::ValueType,
    );
    field(
        &mut lines,
        "Value",
        form.value.value(),
        form.field == AttributeField::Value,
    );

    lines.push(Line::from(""));
    if let Some(error) = &form.error {
        super::status::push_status(&mut lines, error, " ");
        lines.push(Line::from(""));
    }
    lines.push(
        Line::from(if form.working {
            " Saving…"
        } else {
            " ⇥: next field   ←/→: value type   ⏎: save   Esc: cancel"
        })
        .fg(COLOR_DARK_GRAY),
    );
    lines
}

// ---------------------------------------------------------------------------
// The profile editor
// ---------------------------------------------------------------------------

fn render_profile_form(state: &IdentityState, form: &ProfileForm) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from(if form.profile_id.is_some() {
            " Edit face"
        } else {
            " Make a face"
        })
        .fg(COLOR_SUCCESS)
        .bold(),
    );
    lines.push(Line::from(""));

    field(
        &mut lines,
        "Name",
        form.name.value(),
        form.focus == ProfileFormFocus::Name,
    );
    lines.push(Line::from(""));

    let list_style = if form.focus == ProfileFormFocus::Entries {
        Style::new().fg(COLOR_SUCCESS).bold()
    } else {
        Style::new().fg(COLOR_DARK_GRAY)
    };
    lines.push(Line::from(Span::styled(
        format!(" Shows these attributes ({} ticked)", form.ticked.len()),
        list_style,
    )));
    lines.push(Line::from(""));

    if state.attributes.is_empty() {
        lines.push(
            Line::from("   No attributes yet — add one first; a face selects over them.")
                .fg(COLOR_DARK_GRAY),
        );
    } else {
        for (i, attr) in state.attributes.iter().enumerate() {
            let ticked = form.ticked.contains(&attr.attribute_id);
            let is_cursor = form.focus == ProfileFormFocus::Entries && i == form.cursor;
            let row_style = if is_cursor {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else if ticked {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            } else {
                Style::new().fg(COLOR_DARK_GRAY)
            };
            lines.push(Line::from(vec![
                Span::styled(if is_cursor { " ▸ " } else { "   " }, row_style),
                Span::styled(if ticked { "[x] " } else { "[ ] " }, row_style),
                Span::styled(
                    format!("{:<28}", truncate(attr.display_name(), 27)),
                    row_style,
                ),
                Span::styled(
                    truncate(&attr.claim_type, 24),
                    Style::new().fg(COLOR_SOFT_PURPLE),
                ),
            ]));
        }
    }

    // The entries this editor does not own, counted so a holder can see that
    // saving will not lose them.
    if !form.preserved.is_empty() {
        lines.push(Line::from(""));
        lines.push(
            Line::from(format!(
                "   + {} pinned/overridden/inline entr{} kept as-is (edit with `pnm`)",
                form.preserved.len(),
                if form.preserved.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            ))
            .fg(COLOR_DARK_GRAY),
        );
    }

    lines.push(Line::from(""));
    if let Some(error) = &form.error {
        super::status::push_status(&mut lines, error, " ");
        lines.push(Line::from(""));
    }
    lines.push(
        Line::from(if form.working {
            " Saving…"
        } else {
            " ⇥: name/list   ↑/↓: move   Space: tick   ⏎: save   Esc: cancel"
        })
        .fg(COLOR_DARK_GRAY),
    );
    lines
}

// ---------------------------------------------------------------------------
// The bind picker
// ---------------------------------------------------------------------------

fn render_bind_picker(state: &IdentityState, picker: &BindPicker) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from(format!(
            " Be known to {} — which face should {} wear here?",
            picker.community, picker.persona_label
        ))
        .fg(COLOR_SUCCESS)
        .bold(),
    );
    lines.push(Line::from(""));
    lines.push(
        Line::from(
            " A context only ever gets a copy. It receives the values this face resolves \
             to — never a way back to your other attributes, and nothing about your other \
             personas. Copies go down; nothing reads up.",
        )
        .fg(COLOR_DARK_GRAY),
    );
    lines.push(Line::from(""));

    // Row 0 is always "take it off", because a persona that deliberately shows
    // nothing is a real choice and not the absence of one.
    for (i, label) in bind_options(state).into_iter().enumerate() {
        let is_cursor = i == picker.cursor;
        let style = if is_cursor {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(if is_cursor { " ▸ " } else { "   " }, style),
            Span::styled(label, style),
        ]));
    }

    lines.push(Line::from(""));
    if let Some(error) = &picker.error {
        super::status::push_status(&mut lines, error, " ");
        lines.push(Line::from(""));
    }
    lines.push(
        Line::from(if picker.working {
            " Applying…"
        } else {
            " ↑/↓: move   ⏎: apply   Esc: cancel"
        })
        .fg(COLOR_DARK_GRAY),
    );
    lines
}

/// The picker's rows: "take it off", then every face. Derived rather than stored
/// so a profile added or renamed between opening the picker and reading it
/// cannot show a stale name.
pub fn bind_options(state: &IdentityState) -> Vec<String> {
    let mut options = vec!["Take it off — show nothing here".to_string()];
    options.extend(state.profiles.iter().map(|p| {
        format!(
            "{}  ({} entr{})",
            p.display_name(),
            p.entry_count,
            if p.entry_count == 1 { "y" } else { "ies" }
        )
    }));
    options
}

// ---------------------------------------------------------------------------
// Shared bits
// ---------------------------------------------------------------------------

/// One labelled form field, with the focused one marked.
fn field(lines: &mut Vec<Line<'static>>, label: &str, value: &str, focused: bool) {
    let style = if focused {
        Style::new().fg(COLOR_SUCCESS).bold()
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if focused { " ▸ " } else { "   " }, style),
        Span::styled(format!("{label:<12}"), Style::new().fg(COLOR_DARK_GRAY)),
        Span::styled(value.to_string(), style),
        Span::styled(if focused { "▏" } else { "" }, style),
    ]));
}

/// Truncate for a fixed-width column, with an ellipsis so a cut is visible.
fn truncate(text: &str, max: usize) -> String {
    openvtc_core::display::truncate_chars(text, max).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::content::{ManagedDid, PersonaMembership};
    use openvtc_core::persona::binding::BindingSummary;
    use openvtc_core::persona::pool::PoolAttribute;

    fn text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn loaded(state: &mut IdentityState) {
        state.loaded = true;
        state.loading = false;
    }

    /// The words `design-docs/persona-vocabulary.md` keeps off the screen, held
    /// off it.
    ///
    /// Every one of them is a word this pane's own code and wire format use, so
    /// they are one careless `format!` away at all times — and the drift is
    /// invisible in review, because each looks correct to the person who wrote
    /// the line. The table's whole point is that a person meets the same
    /// sentence in the console, in `pnm` and here; a test is the only thing that
    /// notices when one surface wanders off.
    ///
    /// Two are absent from the list on purpose. **"credential"** is on-screen
    /// vocabulary (`credential · ‹issuer›`), and **"per verifier"** is the
    /// agreed phrase for a generated value — the table bans *"verifier" in
    /// prose*, not that phrase.
    ///
    /// **"attribute"** came *off* this list on 2026-09-08, and **"fact"** went
    /// on in its place. The screen used to translate an attribute to a *fact*,
    /// which asserted a truth the model cannot promise — everything in the pool
    /// is self-asserted until a credential backs it, and a face exists so a
    /// person may show an old, pinned, overridden or untrue value — while
    /// `Facts` already named a *verified* policy input in `vtc-service`. The
    /// spec word came to the screen instead; provenance carries the truth.
    #[test]
    fn the_pane_speaks_the_agreed_vocabulary() {
        const BANNED: &[&str] = &[
            "fact",
            "pool",
            "profile",
            "binding",
            "unbind",
            "materialise",
            "projection",
            "disclosure",
            "correlation",
            "self-asserted",
            "credential-backed",
            "provenance",
            "holder",
        ];

        // Every tab, in each of its three states — empty, populated, and having
        // failed to load — plus the three things that own the screen when they
        // are open.
        //
        // The failure state earns its place: the words there are the ones
        // written under pressure, they include a hint carrying a `pnm` command,
        // and nothing else on screen exercises them. This test did miss a
        // "pool" and a "profiles" that lived only in that hint.
        let mut screens: Vec<String> = Vec::new();
        for tab in PersonaTab::all() {
            let mut empty = IdentityState {
                tab,
                ..IdentityState::default()
            };
            loaded(&mut empty);
            screens.push(text(&render(&empty)));

            let mut full = populated(tab);
            loaded(&mut full);
            screens.push(text(&render(&full)));

            // The refusal we recognise, which this pane answers in its own
            // words. An *unrecognised* failure is echoed verbatim and is the
            // agent's text rather than ours, so it is not this test's to police.
            let mut refused = populated(tab);
            loaded(&mut refused);
            refused.load_error = Some(
                "this task reads or writes the holder's attribute pool, which sits above \
                 every trust context. It requires an unscoped holder credential"
                    .to_string(),
            );
            screens.push(text(&render(&refused)));
        }
        for mode in [
            PersonaMode::Attribute(AttributeForm::default()),
            PersonaMode::Profile(ProfileForm::default()),
            PersonaMode::Bind(BindPicker::default()),
        ] {
            let mut state = populated(PersonaTab::Personas);
            state.mode = mode;
            loaded(&mut state);
            screens.push(text(&render(&state)));
        }

        for screen in &screens {
            // `persona-holder` is a capability name an operator types verbatim,
            // like a task URI would be — wire vocabulary inside a command, not
            // prose. Removing it before the scan keeps "holder" banned as a
            // word while letting the one command that needs it stay correct;
            // exempting it any more loosely would let a sentence hide behind a
            // hyphen.
            let lower = screen
                .to_ascii_lowercase()
                .replace("persona-holder", "‹capability›");
            for word in BANNED {
                assert!(
                    !lower.contains(word),
                    "\"{word}\" is a word the vocabulary keeps off the screen \
                     (design-docs/persona-vocabulary.md):\n{screen}"
                );
            }
        }
    }

    /// One populated screen per tab, so the guard above reads real rows rather
    /// than five empty states.
    fn populated(tab: PersonaTab) -> IdentityState {
        use openvtc_core::persona::disclosure::{DisclosedClaim, DisclosureRow};
        use openvtc_core::persona::pool::ProvenanceKind;
        use openvtc_core::persona::profile::{ProfileDetail, ProfileSummary, ResolvedClaim};

        let mut attr = PoolAttribute {
            attribute_id: "01A".into(),
            claim_type: "email.work".into(),
            label: Some("Work email".into()),
            ..PoolAttribute::default()
        };
        attr.provenance = ProvenanceKind::CredentialBacked;
        attr.stale = true;
        attr.stale_reason = Some("revoked".into());

        // A masked row, so the vocabulary guard reads the masking copy too —
        // the header note, the row marker and the face-detail line only appear
        // when something on screen is actually masked.
        let card = PoolAttribute {
            attribute_id: "01B".into(),
            claim_type: "payment.card".into(),
            label: Some("Everyday card".into()),
            value: Some(serde_json::json!("4242424242424242")),
            ..PoolAttribute::default()
        };

        IdentityState {
            tab,
            show_values: true,
            personas: vec![ManagedDid {
                did: "did:webvh:example.com:alice".into(),
                label: "Work me".into(),
                ..ManagedDid::default()
            }]
            .into(),
            attributes: vec![attr, card].into(),
            profiles: vec![ProfileSummary {
                profile_id: "01P".into(),
                name: "Work".into(),
                entry_count: 3,
                ..ProfileSummary::default()
            }]
            .into(),
            memberships: vec![PersonaMembership {
                community_name: "Acme".into(),
                persona_label: "Work me".into(),
                status_label: "Member".into(),
                shared_with: 1,
                ..PersonaMembership::default()
            }]
            .into(),
            disclosures: vec![DisclosureRow {
                verifier_did: "did:webvh:example.com:acme".into(),
                disclosed_at: "2026-09-07T10:00:00Z".into(),
                claims: vec![DisclosedClaim {
                    claim_type: "email.work".into(),
                    rung: "selectiveDisclosure".into(),
                }],
                durable_credential_id: Some("urn:cred:1".into()),
                ..DisclosureRow::default()
            }]
            .into(),
            open_profile: (tab == PersonaTab::Profiles).then(|| ProfileDetail {
                summary: ProfileSummary {
                    profile_id: "01P".into(),
                    name: "Work".into(),
                    ..ProfileSummary::default()
                },
                resolved: vec![
                    ResolvedClaim {
                        claim_type: "nickname".into(),
                        value: Some(serde_json::json!("Ace")),
                        attribute_id: None,
                        ..ResolvedClaim::default()
                    },
                    ResolvedClaim {
                        claim_type: "phone.mobile".into(),
                        value: Some(serde_json::json!("+61400123456")),
                        attribute_id: Some("01C".into()),
                        ..ResolvedClaim::default()
                    },
                ],
                ..ProfileDetail::default()
            }),
            ..IdentityState::default()
        }
    }

    /// The distinction the whole pane is built around: an agent that could not
    /// be asked must never render as "you have no attributes". One of those is a
    /// confident claim about the holder's own data, and it would be wrong.
    #[test]
    fn an_unreachable_agent_never_reads_as_having_no_facts() {
        let mut state = IdentityState {
            tab: PersonaTab::Attributes,
            ..IdentityState::default()
        };
        loaded(&mut state);
        let empty = text(&render(&state));
        assert!(empty.contains("No attributes yet"), "{empty}");

        state.load_error = Some("connection refused".to_string());
        let failed = text(&render(&state));
        assert!(
            failed.contains("Could not read your attributes"),
            "{failed}"
        );
        assert!(
            failed.contains("connection refused"),
            "the reason has to reach the operator: {failed}"
        );
        assert!(
            !failed.contains("No attributes yet"),
            "a failed read must not claim there are no attributes: {failed}"
        );
    }

    /// The refusal a context-scoped credential earns says what to do about it.
    ///
    /// This is the failure every install hits before the grant exists, and the
    /// agent's own words — accurate, abstract, and in the spec's vocabulary —
    /// are not what a person needs at that moment. The pane answers it in its
    /// own words and gives them the command.
    #[test]
    fn the_holder_refusal_carries_the_grant_command() {
        let mut state = IdentityState {
            tab: PersonaTab::Attributes,
            load_error: Some(
                "this task reads or writes the holder's attribute pool … it requires an unscoped \
                 holder credential"
                    .to_string(),
            ),
            agent_credential_did: Some("did:key:z6MkThisInstall".to_string()),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert!(out.contains("persona-holder"), "{out}");
        // The whole command, ready to run. A hint that names a placeholder is a
        // hint that sends the reader somewhere else to finish reading it.
        assert!(
            out.contains("pnm acl update did:key:z6MkThisInstall --capabilities persona-holder"),
            "{out}"
        );
        assert!(
            !out.contains("<this install"),
            "the placeholder must not survive when we hold the DID: {out}"
        );
    }

    /// `did` is positional on `pnm acl update`; there is no `--did` flag, and a
    /// hint that grew one would be a command that fails on paste.
    #[test]
    fn the_grant_command_passes_the_did_positionally() {
        let hint = holder_grant_hint(Some("did:key:z6MkThisInstall")).join("\n");
        assert!(!hint.contains("--did"), "{hint}");
    }

    /// Nothing to substitute is the one case the placeholder is still right for
    /// — better an obvious blank than a command naming the wrong subject.
    #[test]
    fn the_grant_command_keeps_a_placeholder_when_there_is_no_credential() {
        let hint = holder_grant_hint(None).join("\n");
        assert!(
            hint.contains("pnm acl update <this install\'s DID>"),
            "{hint}"
        );
    }

    /// And an unrelated failure does not: telling someone to run a grant when
    /// their agent is simply unreachable sends them to fix the wrong thing.
    #[test]
    fn an_unrelated_failure_carries_no_grant_command() {
        let mut state = IdentityState {
            tab: PersonaTab::Attributes,
            load_error: Some("connection refused".to_string()),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert!(out.contains("connection refused"));
        assert!(!out.contains("pnm acl update"), "{out}");
    }

    /// Values are hidden until asked for, and the row says which state it is in
    /// — otherwise "(hidden)" and "no value" are the same pixels.
    #[test]
    fn values_are_hidden_until_asked_for() {
        let attr = PoolAttribute {
            attribute_id: "01A".into(),
            claim_type: "email.work".into(),
            label: Some("Work email".into()),
            ..PoolAttribute::default()
        };
        let mut state = IdentityState {
            tab: PersonaTab::Attributes,
            attributes: vec![attr].into(),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let hidden = text(&render(&state));
        assert!(hidden.contains("values hidden"), "{hidden}");
        assert!(hidden.contains("(hidden)"), "{hidden}");

        state.show_values = true;
        let shown = text(&render(&state));
        assert!(shown.contains("values shown"), "{shown}");
        assert!(
            shown.contains("(no value)"),
            "a listing that asked and got nothing says so: {shown}"
        );
    }

    /// A persona shown to more than one community carries the linkage warning.
    /// Nothing else on screen lets a holder work that out from a single row.
    #[test]
    fn a_reused_persona_is_flagged_as_linkable() {
        let mut state = IdentityState {
            tab: PersonaTab::Communities,
            memberships: vec![
                PersonaMembership {
                    community_name: "Acme".into(),
                    persona_label: "Work me".into(),
                    status_label: "Member".into(),
                    shared_with: 1,
                    ..PersonaMembership::default()
                },
                PersonaMembership {
                    community_name: "Chess Club".into(),
                    persona_label: "Gaming me".into(),
                    status_label: "Member".into(),
                    shared_with: 0,
                    ..PersonaMembership::default()
                },
            ]
            .into(),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert!(out.contains("known to 1 other community"), "{out}");
        assert_eq!(
            out.matches("⚠ linked").count(),
            1,
            "the persona used once must not be flagged: {out}"
        );
    }

    /// "We have not asked" and "wears nothing" are different sentences on a
    /// membership row, for the same reason they are different in
    /// `BindingSummary`.
    #[test]
    fn an_unasked_binding_reads_as_unknown_not_as_nothing() {
        let membership = PersonaMembership {
            community_name: "Acme".into(),
            sub_context_id: "ctx".into(),
            persona_did: "did:webvh:example.com:alice".into(),
            persona_label: "Work me".into(),
            status_label: "Member".into(),
            shared_with: 0,
        };
        let mut state = IdentityState {
            tab: PersonaTab::Communities,
            memberships: vec![membership.clone()].into(),
            ..IdentityState::default()
        };
        loaded(&mut state);
        assert!(text(&render(&state)).contains("wears: unknown"));

        state.bindings.insert(
            ("ctx".to_string(), membership.persona_did.clone()),
            BindingSummary::default(),
        );
        assert!(text(&render(&state)).contains("wears: nothing"));
    }

    /// The two delete questions are worded differently, and the cascading one
    /// names the consequence the plain one does not have. Which is asked is
    /// decided before the prompt appears — see `persona_actions`.
    #[test]
    fn a_cascading_delete_asks_a_visibly_different_question() {
        let attr = PoolAttribute {
            attribute_id: "01A".into(),
            label: Some("Work email".into()),
            ..PoolAttribute::default()
        };
        let mut state = IdentityState {
            tab: PersonaTab::Attributes,
            attributes: vec![attr].into(),
            ..IdentityState::default()
        };
        loaded(&mut state);

        state.confirm = PersonaConfirm::DeleteAttribute {
            attribute_id: "01A".into(),
            name: "Work email".into(),
            cascade: false,
        };
        let plain = text(&render(&state));
        assert!(plain.contains("Forget \"Work email\"?"), "{plain}");
        assert!(
            !plain.contains("faces"),
            "the plain question must not mention what it does not do: {plain}"
        );

        state.confirm = PersonaConfirm::DeleteAttribute {
            attribute_id: "01A".into(),
            name: "Work email".into(),
            cascade: true,
        };
        let escalated = text(&render(&state));
        assert!(escalated.contains("is on one or more faces"), "{escalated}");
    }

    /// An armed confirmation replaces the key hints: a destructive question and
    /// a menu of other keys do not belong on screen together.
    #[test]
    fn a_confirmation_replaces_the_key_hints() {
        let mut state = IdentityState {
            tab: PersonaTab::Personas,
            personas: vec![ManagedDid {
                did: "did:webvh:example.com:alice".into(),
                label: "Work me".into(),
                ..ManagedDid::default()
            }]
            .into(),
            ..IdentityState::default()
        };
        loaded(&mut state);
        assert!(text(&render(&state)).contains("n: new persona"));

        state.confirm = PersonaConfirm::DeletePersona(0);
        let armed = text(&render(&state));
        assert!(armed.contains("Remove Work me"), "{armed}");
        assert!(!armed.contains("n: new persona"), "{armed}");
    }

    /// The destructive confirm names what the operator selected *and* keeps the
    /// DID, so it is both recognisable and unambiguous. Moved here with the
    /// list it prompts over.
    #[test]
    fn the_persona_prompt_keeps_both_the_name_and_the_did() {
        const DID: &str = "did:webvh:QmScidAliceAAAAAAAAAAAAAAAAAAAAAA:example.com:alice";
        let mut state = IdentityState {
            tab: PersonaTab::Personas,
            personas: vec![ManagedDid {
                did: DID.into(),
                agent_name: Some("example.com/@alice".into()),
                label: String::new(),
                bound_communities: 0,
                is_active: false,
            }]
            .into(),
            confirm: PersonaConfirm::DeletePersona(0),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        let prompt = out
            .lines()
            .find(|l| l.starts_with("Remove "))
            .expect("confirm prompt rendered");
        assert!(prompt.contains("example.com/@alice"), "{prompt}");
        // The DID is centre-truncated, so both ends must still be checkable.
        assert!(prompt.contains("did:webvh:QmScidAlice"), "{prompt}");
        assert!(prompt.contains("example.com:alice"), "{prompt}");
        assert!(prompt.contains("y: confirm"), "{prompt}");
    }

    /// With no name at all the prompt falls back to the DID alone — never to an
    /// empty parenthetical or a nameless "this identity".
    #[test]
    fn the_persona_prompt_without_a_name_shows_the_did() {
        const DID: &str = "did:webvh:QmScidAliceAAAAAAAAAAAAAAAAAAAAAA:example.com:alice";
        let mut state = IdentityState {
            tab: PersonaTab::Personas,
            personas: vec![ManagedDid {
                did: DID.into(),
                ..ManagedDid::default()
            }]
            .into(),
            confirm: PersonaConfirm::DeletePersona(0),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        let prompt = out
            .lines()
            .find(|l| l.starts_with("Remove "))
            .expect("confirm prompt rendered");
        assert!(prompt.contains("did:webvh:QmScidAlice"), "{prompt}");
        assert!(prompt.contains("example.com:alice"), "{prompt}");
        assert!(
            !prompt.contains('('),
            "no empty name parenthetical: {prompt}"
        );
    }

    /// The picker always offers "nothing" first, and it is worded as a choice
    /// rather than as an empty row.
    #[test]
    fn the_bind_picker_offers_nothing_as_a_first_class_choice() {
        let state = IdentityState::default();
        let options = bind_options(&state);
        assert_eq!(options.len(), 1);
        assert!(options[0].starts_with("Take it off"));
    }

    /// The disclosure history is read-only and says so, and an empty one says
    /// what a release even is — the tab is where a holder goes to ask "what
    /// does anyone already know", and an unexplained blank answers nothing.
    #[test]
    fn an_empty_history_explains_itself_rather_than_going_blank() {
        let mut state = IdentityState {
            tab: PersonaTab::Disclosures,
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert!(out.contains("Nothing has left yet"), "{out}");
        assert!(out.contains("read-only"), "{out}");
        // No verbs beyond navigation and refresh: this pane cannot disclose.
        assert!(!out.contains("n: new"), "{out}");
    }

    /// Every attribute carries the rung it left at, and a release that is still
    /// live as a credential is marked as such — it is the one kind that can
    /// still be revoked rather than only regretted.
    #[test]
    fn a_disclosure_row_shows_its_rungs_and_flags_a_live_credential() {
        use openvtc_core::persona::disclosure::{DisclosedClaim, DisclosureRow};
        let mut state = IdentityState {
            tab: PersonaTab::Disclosures,
            disclosures: vec![
                DisclosureRow {
                    verifier_did: "did:webvh:example.com:acme".into(),
                    disclosed_at: "2026-09-06T10:00:00Z".into(),
                    claims: vec![
                        DisclosedClaim {
                            claim_type: "email.work".into(),
                            rung: "whole".into(),
                        },
                        DisclosedClaim {
                            claim_type: "age.over18".into(),
                            rung: "predicate".into(),
                        },
                    ],
                    durable_credential_id: Some("urn:cred:1".into()),
                    ..DisclosureRow::default()
                },
                DisclosureRow {
                    verifier_did: "did:webvh:example.com:chess".into(),
                    disclosed_at: "2026-09-05T10:00:00Z".into(),
                    ..DisclosureRow::default()
                },
            ]
            .into(),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert!(out.contains("email.work (whole)"), "{out}");
        assert!(out.contains("age.over18 (yes/no only)"), "{out}");
        assert_eq!(
            out.matches("still live as a credential").count(),
            1,
            "only the durable one is flagged: {out}"
        );
    }

    /// A value that lives only in a face is marked as such, because correcting
    /// the holder's attributes will not correct it.
    #[test]
    fn an_inline_claim_says_it_lives_only_in_the_profile() {
        use openvtc_core::persona::profile::{ProfileDetail, ProfileSummary, ResolvedClaim};
        let mut state = IdentityState {
            tab: PersonaTab::Profiles,
            open_profile: Some(ProfileDetail {
                summary: ProfileSummary {
                    profile_id: "01P".into(),
                    name: "Work".into(),
                    ..ProfileSummary::default()
                },
                resolved: vec![
                    ResolvedClaim {
                        claim_type: "email.work".into(),
                        value: Some(serde_json::json!("a@b.c")),
                        attribute_id: Some("01A".into()),
                        ..ResolvedClaim::default()
                    },
                    ResolvedClaim {
                        claim_type: "nickname".into(),
                        value: Some(serde_json::json!("Ace")),
                        attribute_id: None,
                        ..ResolvedClaim::default()
                    },
                ],
                ..ProfileDetail::default()
            }),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert_eq!(
            out.matches("only in this face").count(),
            1,
            "exactly the inline claim is marked: {out}"
        );
    }

    /// How many *rows* are marked masked, as distinct from the paragraph above
    /// them that explains the mask and contains the same word.
    fn masked_rows(out: &str) -> usize {
        out.lines()
            .filter(|l| l.contains("masked") && !l.contains("Some values are masked"))
            .count()
    }

    /// A face builds a detail with two masked claims, for the reveal tests below.
    fn face_with_two_masked_claims() -> IdentityState {
        use openvtc_core::persona::profile::{ProfileDetail, ProfileSummary, ResolvedClaim};
        let mut state = IdentityState {
            tab: PersonaTab::Profiles,
            open_profile: Some(ProfileDetail {
                summary: ProfileSummary {
                    profile_id: "01P".into(),
                    name: "OSS Developer".into(),
                    ..ProfileSummary::default()
                },
                resolved: vec![
                    ResolvedClaim {
                        claim_type: "name.legal".into(),
                        value: Some(serde_json::json!("Glenn Gore")),
                        ..ResolvedClaim::default()
                    },
                    ResolvedClaim {
                        claim_type: "email.work".into(),
                        value: Some(serde_json::json!("glenn@example.com")),
                        ..ResolvedClaim::default()
                    },
                    ResolvedClaim {
                        claim_type: "phone.mobile".into(),
                        value: Some(serde_json::json!("+6591234567")),
                        ..ResolvedClaim::default()
                    },
                ],
                ..ProfileDetail::default()
            }),
            ..IdentityState::default()
        };
        loaded(&mut state);
        state
    }

    /// A face's masked claims say they are masked, and say which key opens the
    /// selected one — rather than sending the holder to another tab.
    ///
    /// This is the half the view used to be missing. A face was read as a whole
    /// with no cursor, so it could offer no per-claim reveal and told the reader
    /// to go and find the value among their attributes instead. That is a real
    /// answer to a question nobody asked: the holder is looking at *this* face
    /// because they want to know what *this* face shows.
    #[test]
    fn a_face_says_which_key_opens_the_selected_masked_claim() {
        let state = face_with_two_masked_claims();
        let out = text(&render(&state));

        assert!(out.contains("s: show one"), "the key is offered: {out}");
        assert!(
            !out.contains("among your attributes"),
            "no longer sends the reader to another tab: {out}"
        );
        // Two of the three claim types carry a mask style; `name.legal` does
        // not. The selected row here is index 0 (`name.legal`), so neither
        // masked row carries the "s to show" tail — the key hint follows the
        // cursor rather than sitting on every masked row.
        assert_eq!(
            masked_rows(&out),
            2,
            "exactly the two masked claims are marked: {out}"
        );
        assert!(
            !out.contains("masked — s to show"),
            "the key hint follows the cursor, which is on an unmasked row: {out}"
        );
        assert!(
            out.contains("Glenn Gore"),
            "an unmasked type is still shown whole: {out}"
        );
    }

    /// The reveal opens one claim — the selected one — and nothing else on the
    /// face opens with it.
    #[test]
    fn a_face_reveal_opens_only_the_selected_claim() {
        let mut state = face_with_two_masked_claims();
        state.face_claim_selected = 1;
        state.revealed_face_claim = Some(1);

        let out = text(&render(&state));
        assert!(out.contains("glenn@example.com"), "the selected one: {out}");
        assert!(
            !out.contains("+6591234567"),
            "the other masked claim stays masked: {out}"
        );
        assert_eq!(
            masked_rows(&out),
            1,
            "the revealed row drops its marker: {out}"
        );
    }

    /// A grant that no longer names the selected row opens nothing.
    ///
    /// Belt and braces over the handler, which clears the grant when the
    /// selection moves: the render checks the pairing itself, so a grant that
    /// somehow outlived its row cannot unmask whatever moved under it.
    #[test]
    fn a_face_reveal_that_is_not_the_selected_row_opens_nothing() {
        let mut state = face_with_two_masked_claims();
        state.face_claim_selected = 2;
        state.revealed_face_claim = Some(1);

        let out = text(&render(&state));
        assert!(
            !out.contains("glenn@example.com"),
            "a stale grant does not open a row nobody chose: {out}"
        );
        assert!(!out.contains("+6591234567"), "{out}");
    }

    /// An attribute whose claim type carries a mask style is masked in the holder's
    /// own list, and the row says so rather than reading as empty.
    ///
    /// The failure this refuses is the quiet one: `••••••••` and "(no value)"
    /// occupy the same space, and a holder who reads the first as the second
    /// concludes they never stored the thing they are looking at.
    #[test]
    fn a_masked_fact_is_reduced_and_the_row_says_so() {
        let mut state = IdentityState {
            tab: PersonaTab::Attributes,
            show_values: true,
            attributes: vec![
                card(),
                PoolAttribute {
                    attribute_id: "01N".into(),
                    claim_type: "name.given".into(),
                    label: Some("First name".into()),
                    value: Some(serde_json::json!("Alice")),
                    ..PoolAttribute::default()
                },
            ]
            .into(),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert!(out.contains("••••••••••••4242"), "{out}");
        assert!(!out.contains("4242424242424242"), "{out}");
        assert_eq!(
            out.matches("masked — s to show").count(),
            1,
            "exactly the masked attribute is marked: {out}"
        );
        assert!(
            !out.contains("(no value)"),
            "a masked value is held, not absent: {out}"
        );
        // The name is shown as it is held: masking everything would make the
        // reveal a reflex.
        assert!(out.contains("Alice"), "{out}");
    }

    /// The reveal is granted to one attribute — the selected one — and nothing else
    /// on screen opens with it.
    #[test]
    fn a_reveal_opens_only_the_selected_fact() {
        let second = PoolAttribute {
            attribute_id: "01P".into(),
            claim_type: "phone.mobile".into(),
            label: Some("Mobile".into()),
            value: Some(serde_json::json!("+61400123456")),
            ..PoolAttribute::default()
        };
        let mut state = IdentityState {
            tab: PersonaTab::Attributes,
            show_values: true,
            attributes: vec![card(), second].into(),
            attribute_selected: 0,
            revealed_attribute: Some("01B".into()),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert!(out.contains("4242424242424242"), "{out}");
        assert!(out.contains("showing — s to mask"), "{out}");
        assert!(
            !out.contains("+61400123456"),
            "the other masked attribute stays masked: {out}"
        );

        // A grant that no longer names the selected row opens nothing: a list
        // that re-sorted under it must not reveal a row nobody chose.
        state.attribute_selected = 1;
        let moved = text(&render(&state));
        assert!(!moved.contains("4242424242424242"), "{moved}");
        assert!(!moved.contains("+61400123456"), "{moved}");
    }

    /// The pane says what the mask is worth, where a holder is deciding whether
    /// to trust it. It is protection from an onlooker, not from anything that
    /// has already been given the value.
    #[test]
    fn the_pane_does_not_overclaim_what_masking_buys() {
        let mut state = IdentityState {
            tab: PersonaTab::Attributes,
            show_values: true,
            attributes: vec![card()].into(),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert!(out.contains("reading over your shoulder"), "{out}");
        assert!(out.contains("already sent the value here"), "{out}");
    }

    /// The note appears only when something on screen is masked — an
    /// explanation of a mechanism the holder is not looking at is noise.
    #[test]
    fn the_masking_note_stays_off_a_screen_with_nothing_masked() {
        let mut state = IdentityState {
            tab: PersonaTab::Attributes,
            show_values: true,
            attributes: vec![PoolAttribute {
                attribute_id: "01N".into(),
                claim_type: "name.given".into(),
                value: Some(serde_json::json!("Alice")),
                ..PoolAttribute::default()
            }]
            .into(),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert!(!out.contains("reading over your shoulder"), "{out}");
        assert!(!out.contains("masked"), "{out}");
    }

    /// A face masks what it shows too, and a claim left unselected stays masked.
    ///
    /// This used to assert that the view sent the reader "among your
    /// attributes" to read a value, because the detail had no cursor of its own
    /// to reveal from. It has one now, so the pointer to another tab is gone
    /// and what is left to check is the masking itself.
    #[test]
    fn a_face_masks_its_values_and_says_where_to_read_one() {
        use openvtc_core::persona::profile::{ProfileDetail, ProfileSummary, ResolvedClaim};
        let mut state = IdentityState {
            tab: PersonaTab::Profiles,
            open_profile: Some(ProfileDetail {
                summary: ProfileSummary {
                    profile_id: "01P".into(),
                    name: "Work".into(),
                    ..ProfileSummary::default()
                },
                resolved: vec![ResolvedClaim {
                    claim_type: "payment.card".into(),
                    value: Some(serde_json::json!("4242424242424242")),
                    attribute_id: Some("01B".into()),
                    ..ResolvedClaim::default()
                }],
                ..ProfileDetail::default()
            }),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert!(out.contains("••••••••••••4242"), "{out}");
        assert!(!out.contains("4242424242424242"), "{out}");
        assert!(
            !out.contains("among your"),
            "no longer sends the reader to another tab: {out}"
        );
        // The one claim is also the selected one, so the row names the key.
        assert!(out.contains("masked — s to show"), "{out}");
    }

    /// The one masked attribute the tests above share.
    fn card() -> PoolAttribute {
        PoolAttribute {
            attribute_id: "01B".into(),
            claim_type: "payment.card".into(),
            label: Some("Everyday card".into()),
            value: Some(serde_json::json!("4242424242424242")),
            ..PoolAttribute::default()
        }
    }
}
