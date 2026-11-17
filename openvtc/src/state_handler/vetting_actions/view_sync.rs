//! Rebuilds the Vetting page's view model from the vetting book in `Config`.

use chrono::{DateTime, Utc};
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::applicant::RequestState;
use openvtc_core::vetting::book::RequestVetting;
use openvtc_core::vetting::queries::request_refusal_words;
use openvtc_core::vetting::vetter::DeskState;
use vta_sdk::protocols::vetting::documentation;
use vta_sdk::vetting::requirements::Evaluation;

use super::applicant::criterion_words;
use super::faces::required_claim_types;
use super::send::persona_did;
use super::words::{
    claim_text, community_display, eligibility_line, grant_line, grant_standing, hidden_row,
    mode_note, next_step_words, pcs_tokens_line, profile_standing, progress_line,
    requirements_line, standing_tokens,
};
use crate::state_handler::main_page::content::{
    ApplicationRow, DeskRow, DeskStage, DeskView, DirectoryCommunity, EventOffer, IssuedRow,
    JourneySteps, JourneyTarget, JourneyView, RequestRow, TicketRow, VetterStandingRow,
    VettingMembership, VettingPersona, VettingState, VettingTab, decline_reason_words,
    method_label,
};
use crate::state_handler::main_page::{sanitize_display, shorten_did};

/// Rebuild the page's rows from the book.
pub(crate) fn sync(vetting: &mut VettingState, config: &Config, now: DateTime<Utc>) {
    let book = &config.private.vetting;
    let name = |did: &str| config.agent_name_for(did).map(|n| sanitize_display(n, 256));
    // The membership's own name first; the name the community gives itself in
    // its branding only when there is none.
    let community_name = |did: &str| {
        config
            .account
            .memberships()
            .find(|m| m.vtc_did == did)
            .and_then(|m| m.display_name.as_deref())
            .or_else(|| book.branding(did).and_then(|b| b.display_name.as_deref()))
            .map(|n| sanitize_display(n, 128))
    };
    let accent = |did: &str| book.branding(did).and_then(|b| b.accent_rgb());

    vetting.personas = config
        .identities
        .iter()
        .map(|(persona, identity)| VettingPersona {
            persona: *persona,
            did: identity.persona_did().to_string(),
            label: sanitize_display(&config.persona_profile_label_for(*persona), 128),
        })
        .collect();

    vetting.memberships = config
        .account
        .memberships()
        .filter(|m| m.status.is_active())
        // Tickets are for communities that named us a vetter: a request made
        // with one to anyone else would be refused as not eligible.
        .filter(|m| book.vetter_grant(&m.vtc_did, m.persona_ref, now).is_some())
        .map(|m| VettingMembership {
            community: m.vtc_did.clone(),
            name: community_name(&m.vtc_did).unwrap_or_else(|| shorten_did(&m.vtc_did, 48)),
            persona: m.persona_ref,
            accent: accent(&m.vtc_did),
        })
        .collect();

    vetting.resend_candidates = book
        .resend_candidates(&config.account, now)
        .into_iter()
        .map(|m| VettingMembership {
            community: m.vtc_did.clone(),
            name: community_name(&m.vtc_did).unwrap_or_else(|| shorten_did(&m.vtc_did, 48)),
            persona: m.persona_ref,
            accent: accent(&m.vtc_did),
        })
        .collect();

    // The event menu, one row per (event, tier), with where our own request
    // stands beside it. Read from the parameters each community published —
    // what is on offer — never from anything that would say who else asked.
    let mut offers = Vec::new();
    for held in &book.hidden_vetter {
        let name =
            community_name(&held.community).unwrap_or_else(|| shorten_did(&held.community, 48));
        for event in &held.params.events {
            let ours = held.events.iter().find(|e| e.event_id == event.event_id);
            for tier in &event.tiers {
                offers.push(EventOffer {
                    community: held.community.clone(),
                    community_name: name.clone(),
                    persona: held.persona,
                    event_id: event.event_id.clone(),
                    tier: tier.name.clone(),
                    drip_per_tick: tier.drip_per_tick,
                    start_date: event.start_date,
                    end_date: event.end_date,
                    group_floor: event.group_floor,
                    state: ours.map(|e| e.state.clone()),
                    group_size: ours.map(|e| e.group_size),
                });
            }
        }
    }
    vetting.event_offers = offers.into();
    vetting.hidden = book
        .hidden_vetter
        .iter()
        .map(|held| {
            let name =
                community_name(&held.community).unwrap_or_else(|| shorten_did(&held.community, 48));
            hidden_row(held, name, accent(&held.community), now)
        })
        .collect();
    vetting.retired = book
        .retired
        .iter()
        .map(|note| sanitize_display(note, 320))
        .collect();

    // The desk's header. Built from `vetter_standing`, which — alone among the
    // vetter-side reads — keeps lapsed grants, so a vetter who has quietly
    // stopped being one can see that rather than infer it from an empty page.
    vetting.standing = book
        .vetter_standing(now)
        .into_iter()
        .map(|s| VetterStandingRow {
            community: community_name(&s.community)
                .unwrap_or_else(|| shorten_did(&s.community, 48)),
            accent: accent(&s.community),
            grant: grant_standing(&s, now),
            grant_warns: !s.live || s.expiring,
            profile: profile_standing(s.profile.as_ref()),
            tokens: standing_tokens(book, &s.community, s.persona, now).map(|(l, _)| l),
            tokens_warn: standing_tokens(book, &s.community, s.persona, now)
                .is_some_and(|(_, warn)| warn),
            mode_note: mode_note(book, &s.community, now),
        })
        .collect();

    // The directory is searched as a persona the community knows of: each
    // application's own persona, then each membership's for a community with
    // no application. One entry per application rather than per community, so
    // a search started from an application goes out as that application's
    // persona — not as whichever other application to the same community
    // happened to be listed first. A persona this account no longer holds
    // cannot sign the request, so it is never offered.
    let available = |persona: &PersonaId| config.identities.contains_key(persona);
    let mut directory: Vec<DirectoryCommunity> = Vec::new();
    let several = |community: &str| {
        book.applications
            .iter()
            .filter(|a| a.community == community && available(&a.persona))
            .count()
            > 1
    };
    for app in book.applications.iter().filter(|a| available(&a.persona)) {
        let community =
            community_name(&app.community).unwrap_or_else(|| shorten_did(&app.community, 48));
        directory.push(DirectoryCommunity {
            // Two applications to one community are told apart by who asks.
            name: if several(&app.community) {
                format!(
                    "{community} — as {}",
                    sanitize_display(&config.persona_profile_label_for(app.persona), 48)
                )
            } else {
                community
            },
            community: app.community.clone(),
            accent: accent(&app.community),
            persona: app.persona,
            application_id: Some(app.id.clone()),
        });
    }
    for m in config
        .account
        .memberships()
        .filter(|m| m.status.is_active() && available(&m.persona_ref))
    {
        if !directory.iter().any(|d| d.community == m.vtc_did) {
            directory.push(DirectoryCommunity {
                community: m.vtc_did.clone(),
                name: community_name(&m.vtc_did).unwrap_or_else(|| shorten_did(&m.vtc_did, 48)),
                accent: accent(&m.vtc_did),
                persona: m.persona_ref,
                application_id: None,
            });
        }
    }
    vetting.directory_communities = directory.into();

    vetting.documentation = book
        .policy
        .accepts_documentation
        .iter()
        .cloned()
        .chain(std::iter::once(documentation::NONE.to_string()))
        .collect();

    // A join that is done is not an application in progress: the list is the
    // joins still under way. A finished one stays in the book — leaving and
    // rejoining as that persona presents its statements again — and reappears
    // here if the membership ends.
    let joined = |app: &&openvtc_core::vetting::applicant::Application| {
        config.account.memberships().any(|m| {
            m.status.is_active() && m.vtc_did == app.community && m.persona_ref == app.persona
        })
    };
    vetting.applications = book
        .applications
        .iter()
        .filter(|app| !joined(app))
        .map(|app| {
            let required = required_claim_types(app);
            let identity = required
                .iter()
                .map(|claim_type| {
                    let value = app
                        .identity_claims
                        .iter()
                        .find(|c| c.type_.as_str() == claim_type.as_str())
                        .map(|c| claim_text(&c.value))
                        .unwrap_or_default();
                    (claim_type.clone(), value)
                })
                .collect();
            let evaluation = app.checklist(now);
            ApplicationRow {
                id: app.id.clone(),
                community: app.community.clone(),
                community_name: community_name(&app.community),
                accent: accent(&app.community),
                pcs_zkp: app.hidden.is_some(),
                next_step: Some(next_step_words(&app.next_step(now))),
                join_did: app.join_did.clone(),
                requirements: app.requirements.as_ref().map(|r| {
                    let mut line = requirements_line(r);
                    // The whole feature, in the one place the applicant reads what is being
                    // asked of them. Without it, a criterion that hides its vetters looks
                    // exactly like one that does not, and the difference is the point.
                    if app.hidden.is_some() {
                        line.push_str(" — their names never reach this community");
                    }
                    line
                }),
                criterion: criterion_words(book, app),
                progress: evaluation.as_ref().map(progress_line),
                satisfied: evaluation.as_ref().is_some_and(Evaluation::satisfied),
                face: app.face.as_ref().map(|f| f.name.clone()),
                identity,
                statements: app.statements.len(),
                requests: app
                    .requests
                    .iter()
                    .map(|r| {
                        let (state, match_code, card_session) = match &r.state {
                            RequestState::Sent => {
                                ("sent — waiting for the vetter".to_string(), None, None)
                            }
                            RequestState::Accepted { session_hint, .. } => (
                                match session_hint {
                                    Some(hint) => {
                                        format!("accepted — {}", sanitize_display(hint, 200))
                                    }
                                    None => "accepted — waiting for a session".to_string(),
                                },
                                None,
                                None,
                            ),
                            RequestState::Session {
                                session,
                                card: None,
                                ..
                            } => (
                                "session open — read the code together, then send your card"
                                    .to_string(),
                                Some(session.match_code.clone()),
                                Some(session.id.clone()),
                            ),
                            RequestState::Session { session, .. } => (
                                "card sent — waiting for their statement".to_string(),
                                Some(session.match_code.clone()),
                                None,
                            ),
                            RequestState::Attested { .. } => {
                                ("statement received".to_string(), None, None)
                            }
                            // The vetter's reason and note, when they gave
                            // them. A decline with neither says only that, and
                            // owes the applicant nothing more.
                            RequestState::Declined { code, message } => {
                                let mut said = "declined".to_string();
                                if let Some(code) = code {
                                    said.push_str(" — ");
                                    said.push_str(decline_reason_words(*code));
                                }
                                if let Some(note) = message {
                                    said.push_str(&format!(
                                        " · they wrote: \"{}\"",
                                        sanitize_display(note, 500)
                                    ));
                                }
                                (said, None, None)
                            }
                            RequestState::Refused { code, .. } => (
                                format!("refused ({})", sanitize_display(code, 80)),
                                None,
                                None,
                            ),
                        };
                        RequestRow {
                            vetter: r.vetter.clone(),
                            vetter_name: name(&r.vetter),
                            state,
                            match_code,
                            card_session,
                            eligibility: r.eligibility.as_ref().map(eligibility_line),
                            grant: r.grant_status.as_ref().map(grant_line),
                            // The code stays on the state line, because it is
                            // what to quote when asking anyone else about this;
                            // what it *means* gets a line of its own, because a
                            // wire code is not an instruction.
                            refusal: match &r.state {
                                RequestState::Refused { code, .. } => {
                                    Some(request_refusal_words(code).to_string())
                                }
                                _ => None,
                            },
                        }
                    })
                    .collect(),
            }
        })
        .collect();

    // Only requests still waiting on us. A finished one leaves at once — its
    // statement is under History, a decline is a line there too — rather than
    // sitting among the open ones with the person's card beside it.
    vetting.desk = book
        .desk
        .iter()
        .filter(|entry| entry.state.is_open())
        .map(|entry| {
            let (state, stage, session, card) = match &entry.state {
                DeskState::Accepted => (
                    "accepted — open a session when you are together",
                    DeskStage::Accepted,
                    None,
                    None,
                ),
                DeskState::Session { session } => (
                    "session open — waiting for their card",
                    DeskStage::Session,
                    Some(session),
                    None,
                ),
                DeskState::CardReceived { session, card } => (
                    "card verified — check the person, then attest or decline",
                    DeskStage::Card,
                    Some(session),
                    Some(card),
                ),
                DeskState::Attested { card, .. } => {
                    ("statement signed", DeskStage::Closed, None, Some(card))
                }
                DeskState::Declined { card, .. } => {
                    ("declined", DeskStage::Closed, None, card.as_ref())
                }
            };
            DeskRow {
                request_id: entry.request_id.clone(),
                applicant: entry.applicant.clone(),
                applicant_name: name(&entry.applicant),
                community: entry.community.clone(),
                pcs_zkp: book.pcs_zkp(&entry.community)
                    && book.request_vetting(&entry.request_id) == RequestVetting::Hidden,
                pcs_tokens: pcs_tokens_line(book, &entry.community, entry.persona, now)
                    .map(|(line, _)| line),
                pcs_events: book
                    .hidden_vetter(&entry.community, entry.persona)
                    .is_some_and(|h| !h.params.events.is_empty()),
                state: state.to_string(),
                stage,
                method: session.map(|s| method_label(s.method).to_string()),
                match_code: entry.match_code().map(str::to_string),
                claims: card
                    .map(|c| {
                        c.claims
                            .iter()
                            .map(|claim| {
                                (
                                    sanitize_display(claim.type_.as_str(), 64),
                                    sanitize_display(&claim_text(&claim.value), 256),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                required_claims: session
                    .map(|s| s.required_claims.clone())
                    .unwrap_or_default(),
                message: entry
                    .request
                    .message
                    .as_deref()
                    .map(|m| sanitize_display(m, 500)),
            }
        })
        .collect();

    vetting.tickets = book
        .tickets
        .iter()
        .map(|t| TicketRow {
            id: t.id.clone(),
            code: t.code.clone(),
            community: community_name(&t.community)
                .unwrap_or_else(|| shorten_did(&t.community, 48)),
            uses_left: t.uses_left,
            expires: t.expires_at.format("%Y-%m-%d").to_string(),
            live: t.is_live(now),
            // A ticket whose link the published URI cannot carry simply has no
            // link; its code still reads aloud.
            uri: persona_did(config, t.persona).and_then(|did| t.uri(&did).ok()),
            // Issued under a mode the community no longer runs: its requests are answered
            // under the one it runs now, which is worth knowing before handing it on.
            mode_note: t
                .mode
                .filter(|issued| {
                    book.vetter_mode(&t.community)
                        .mode()
                        .is_some_and(|current| current != *issued)
                })
                .map(|issued| format!("issued under {}", issued.words())),
        })
        .collect();

    vetting.issued = book
        .issued
        .iter()
        .map(|s| IssuedRow {
            id: s.id.clone(),
            applicant: s.applicant.clone(),
            community: community_name(&s.community)
                .unwrap_or_else(|| shorten_did(&s.community, 48)),
            method: method_label(s.method).to_string(),
            issued: s.issued_at.format("%Y-%m-%d").to_string(),
            valid_until: s.valid_until.format("%Y-%m-%d").to_string(),
            withdrawal: s.withdrawal.as_ref().map(|w| match w.recorded_at {
                Some(at) => format!("withdrawn — recorded {}", at.format("%Y-%m-%d")),
                None => "withdrawal sent — not yet recorded".to_string(),
            }),
            withdrawal_recorded: s
                .withdrawal
                .as_ref()
                .is_some_and(|w| w.recorded_at.is_some()),
        })
        .collect();

    // Declines, newest first: the ones still on the desk in their grace, then
    // the archived. Community and date only — a decline keeps no identifier.
    let mut declined: Vec<(chrono::DateTime<Utc>, String)> = book
        .desk
        .iter()
        .filter_map(|e| match &e.state {
            openvtc_core::vetting::vetter::DeskState::Declined { at, .. } => {
                Some((*at, e.community.clone()))
            }
            _ => None,
        })
        .chain(book.vetted.iter().filter_map(|r| match r.outcome {
            openvtc_core::vetting::book::VettedOutcome::Declined => {
                Some((r.closed_at, r.community.clone()))
            }
            openvtc_core::vetting::book::VettedOutcome::Signed { .. } => None,
        }))
        .collect();
    declined.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
    vetting.declined = declined
        .into_iter()
        .map(|(at, community)| {
            (
                community_name(&community).unwrap_or_else(|| shorten_did(&community, 48)),
                at.format("%Y-%m-%d").to_string(),
            )
        })
        .collect();

    // Hidden-vetting attestations, newest first, the same way: recorded as signed, but with no
    // statement in `issued` to list them by.
    use openvtc_core::vetting::book::is_hidden_attestation;
    let mut attested_hidden: Vec<(chrono::DateTime<Utc>, String)> = book
        .desk
        .iter()
        .filter_map(|e| match &e.state {
            openvtc_core::vetting::vetter::DeskState::Attested {
                statement_id,
                issued_at,
                ..
            } if is_hidden_attestation(statement_id) => Some((*issued_at, e.community.clone())),
            _ => None,
        })
        .chain(book.vetted.iter().filter_map(|r| match &r.outcome {
            openvtc_core::vetting::book::VettedOutcome::Signed { statement_id }
                if is_hidden_attestation(statement_id) =>
            {
                Some((r.closed_at, r.community.clone()))
            }
            _ => None,
        }))
        .collect();
    attested_hidden.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
    vetting.attested_hidden = attested_hidden
        .into_iter()
        .map(|(at, community)| {
            (
                community_name(&community).unwrap_or_else(|| shorten_did(&community, 48)),
                at.format("%Y-%m-%d").to_string(),
            )
        })
        .collect();

    vetting.selected = vetting.selected.min(vetting.tab_len().saturating_sub(1));
    sync_journey(vetting, config, now);
}

/// Work the open journey out from the book again, so it follows every change
/// — a statement arriving, a session opening — without being asked.
///
/// Keeps the list's highlight on the journey's own row: every action the
/// journey offers is one the list already had, and those act on the
/// highlighted row. A journey whose application or request has gone closes,
/// rather than drawing steps for something that no longer exists.
pub(crate) fn sync_journey(vetting: &mut VettingState, config: &Config, now: DateTime<Utc>) {
    use openvtc_core::vetting::journey::{applicant_journey, vetter_journey};
    let book = &config.private.vetting;
    let view = match &vetting.journey_target {
        None => None,
        Some(JourneyTarget::Application(id)) => {
            book.applications.iter().find(|a| &a.id == id).map(|app| {
                if let Some(i) = vetting.applications.iter().position(|r| &r.id == id) {
                    vetting.tab = VettingTab::Applications;
                    vetting.selected = i;
                }
                JourneyView {
                    title: format!(
                        "Applying to {} as {}",
                        community_display(config, &app.community),
                        sanitize_display(&config.persona_profile_label_for(app.persona), 64)
                    ),
                    pcs_zkp: app.hidden.is_some(),
                    steps: JourneySteps::Applicant(applicant_journey(app, now)),
                }
            })
        }
        Some(JourneyTarget::Desk(id)) => book.desk_entry(id).map(|entry| {
            if let Some(i) = vetting.desk.iter().position(|r| &r.request_id == id) {
                vetting.tab = VettingTab::Desk;
                vetting.desk_view = DeskView::Requests;
                vetting.selected = i;
            }
            let (steps, ending) = vetter_journey(entry);
            JourneyView {
                title: format!(
                    "Vetting {} for {}",
                    openvtc_core::display::display_identifier(
                        config.agent_name_for(&entry.applicant),
                        &entry.applicant,
                        48
                    ),
                    community_display(config, &entry.community)
                ),
                pcs_zkp: book.pcs_zkp(&entry.community)
                    && book.request_vetting(&entry.request_id) == RequestVetting::Hidden,
                steps: JourneySteps::Vetter(steps, ending),
            }
        }),
    };
    if view.is_none() {
        vetting.journey_target = None;
    }
    vetting.journey = view;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::content::VettingState;
    use crate::state_handler::vetting_actions::test_support::read_as;
    use chrono::Utc;
    use openvtc_core::config::account::PersonaId;
    use openvtc_core::vetting::applicant::{Application, NextStep};
    use openvtc_core::vetting::mode::VetterMode;
    use openvtc_core::vetting::tickets::{DEFAULT_VALIDITY, Ticket};

    /// A hidden-vetting attestation is in History once archived, and is not taken for a
    /// signed statement or a decline.
    #[test]
    fn an_archived_hidden_attestation_is_in_history() {
        use openvtc_core::vetting::book::{HIDDEN_ATTESTATION_PREFIX, VettedOutcome, VettedRecord};
        let community = "did:web:first-vtc.example";
        let now = Utc::now();
        let mut config = test_config();
        config.private.vetting.vetted.push(VettedRecord {
            community: community.to_string(),
            closed_at: now,
            outcome: VettedOutcome::Signed {
                statement_id: format!("{HIDDEN_ATTESTATION_PREFIX}req-1"),
            },
        });
        let mut v = VettingState::default();
        sync(&mut v, &config, Utc::now());
        assert_eq!(v.attested_hidden.len(), 1);
        assert_eq!(v.attested_hidden[0].1, now.format("%Y-%m-%d").to_string());
        assert!(v.issued.is_empty());
        assert!(v.declined.is_empty());
    }

    /// A ticket issued under one mode is marked once the community runs the other.
    #[test]
    fn a_ticket_from_another_mode_is_marked() {
        let community = "did:web:first-vtc.example";
        let now = Utc::now();
        let mut config = test_config();
        let mut ticket = Ticket::issue(
            community,
            PersonaId::new(),
            vec![],
            1,
            DEFAULT_VALIDITY,
            now,
        );
        ticket.mode = Some(VetterMode::PcsZkp);
        config.private.vetting.tickets.push(ticket);
        read_as(
            &mut config.private.vetting,
            community,
            VetterMode::Named,
            now,
        );
        let mut v = VettingState::default();
        sync(&mut v, &config, Utc::now());
        assert_eq!(
            v.tickets[0].mode_note.as_deref(),
            Some("issued under PCS ZKP")
        );
        read_as(
            &mut config.private.vetting,
            community,
            VetterMode::PcsZkp,
            now,
        );
        sync(&mut v, &config, Utc::now());
        assert_eq!(v.tickets[0].mode_note, None);
    }

    #[test]
    fn the_directory_never_searches_as_a_persona_that_is_gone() {
        let mut config = test_config();
        let app = Application::new(
            "did:web:vtc.example",
            PersonaId::new(),
            "did:key:zGone",
            Utc::now(),
        )
        .unwrap();
        config.private.vetting.applications.push(app);
        let mut v = VettingState::default();
        sync(&mut v, &config, Utc::now());
        assert!(
            v.directory_communities.is_empty(),
            "a deleted persona's application is not a searcher: {:?}",
            v.directory_communities
        );
    }

    /// The page lists what the book holds.
    #[test]
    fn sync_lists_applications_and_tickets() {
        use affinidi_tdk::messaging::profiles::{ATMProfile, ATMProfileInner};
        let mut config = test_config();
        let persona = PersonaId::new();
        // A persona this account holds: only one of those can sign a search.
        config.identities.insert(
            persona,
            openvtc_core::identity::IdentityContext {
                persona_id: persona,
                did: "did:key:zA".to_string(),
                document: serde_json::from_value(serde_json::json!({ "id": "did:key:zA" }))
                    .expect("minimal DID document"),
                profile: std::sync::Arc::new(ATMProfile {
                    inner: std::sync::Arc::new(ATMProfileInner {
                        did: "did:key:zA".to_string(),
                        alias: "did:key:zA".to_string(),
                        mediator: std::sync::Arc::new(None),
                    }),
                }),
                mediator_did: None,
            },
        );
        config
            .private
            .vetting
            .start_application("did:web:vtc.example", persona, "did:key:zA", Utc::now())
            .unwrap();
        config.private.vetting.tickets.push(Ticket::issue(
            "did:web:vtc.example",
            persona,
            vec![],
            1,
            DEFAULT_VALIDITY,
            Utc::now(),
        ));
        let mut v = VettingState::default();
        sync(&mut v, &config, Utc::now());
        assert_eq!(v.applications.len(), 1);
        assert_eq!(
            v.applications[0].next_step.as_deref(),
            Some(next_step_words(&NextStep::LearnRequirements).as_str())
        );
        assert_eq!(
            v.directory_communities.len(),
            1,
            "an application can search"
        );
        assert_eq!(
            v.applications[0].identity,
            vec![("name.legal".to_string(), String::new())],
            "without requirements the page asks for a legal name"
        );
        assert_eq!(v.tickets.len(), 1);
        assert!(v.tickets[0].live);
        assert!(v.documentation.iter().any(|d| d == "none"));
    }
}
