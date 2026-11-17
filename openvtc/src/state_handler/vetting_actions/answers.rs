//! Answers from communities, revocation checks, and the join flow's hand-off
//! into the Vetting page.

use crate::state_handler::main_page::status::Status;
use chrono::Utc;
use openvtc_core::config::Config;
use openvtc_core::vetting::applicant::GrantStatus;
use openvtc_core::vetting::mode::ModeFailure;
use openvtc_core::vetting::queries::{CommunityAnswer, QUERY_TIMEOUT, QueryKind, refusal_words};
use openvtc_core::vetting::registry::{listed_event_line, listed_location_line};
use openvtc_core::vetting::status::GrantCheck;
use vta_sdk::protocols::vetting::vetters;
use vta_sdk::vetting::status::StatusCheck;

use super::view_sync::sync_journey;
use super::words::{community_display, when_words};
use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome};
use crate::state_handler::dispatch_util::{self, Persist, SyncLog};
use crate::state_handler::main_page::content::{
    DIRECTORY_FIELDS, DeskView, JourneyTarget, ListedVetterRow, VettingMode, VettingState,
    VettingTab,
};
use crate::state_handler::main_page::menu::MainMenu;
use crate::state_handler::main_page::sync_clock;
use crate::state_handler::main_page::{sanitize_display, shorten_did};
use crate::state_handler::save_coalesce::SaveScheduler;
use crate::state_handler::state::State;

// ============================================================================
// Answers from communities, revocation checks, and the join flow's hand-off
// ============================================================================

/// Fold communities' answers into the page: a directory page into the view
/// that asked for it, everything else into the status line and the log.
pub(crate) fn apply_answers(state: &mut State, config: &Config, answers: Vec<CommunityAnswer>) {
    for answer in answers {
        let name = community_display(config, answer.community());
        let v = &mut state.main_page.content_panel.vetting;
        let message = match answer {
            // The challenge's notice already says it arrived; a join waiting on
            // one has taken its answer before this runs.
            // Likewise a wallet session's: the join that opened it takes them.
            CommunityAnswer::Manifest { .. }
            | CommunityAnswer::Challenge { .. }
            | CommunityAnswer::WalletSessionStarted { .. }
            | CommunityAnswer::WalletSessionStatus { .. } => None,
            CommunityAnswer::Vetters { query, page, .. } => match &mut v.mode {
                VettingMode::Directory(view) if view.pending.as_deref() == Some(query.as_str()) => {
                    view.pending = None;
                    if let Some(cursors) = view.pending_cursors.take() {
                        view.cursors = cursors;
                    }
                    view.results = page.vetters.iter().map(|l| listed_row(config, l)).collect();
                    view.next_cursor = page.next_cursor.map(|c| c.as_str().to_string());
                    view.searched = true;
                    view.error = None;
                    view.field = if view.results.is_empty() {
                        view.field.min(DIRECTORY_FIELDS - 1)
                    } else {
                        DIRECTORY_FIELDS
                    };
                    Some(match view.results.len() {
                        0 => format!("No vetter listed in {name} matches."),
                        1 => format!("1 vetter listed in {name} matches."),
                        n => format!("{n} vetters listed in {name} match, on this page."),
                    })
                }
                _ => None,
            },
            CommunityAnswer::ProfileStored { listed, .. } => Some(if listed {
                format!("{name} published your vetter profile and lists you in its directory.")
            } else {
                format!(
                    "{name} stored your vetter profile. You are not listed, so only people you \
                     give a ticket can reach you."
                )
            }),
            CommunityAnswer::Resent { valid_until, .. } => Some(format!(
                "{name} is sending your vetter credential again, valid until {}. It shows under \
                 Tickets when it arrives.",
                valid_until.format("%Y-%m-%d")
            )),
            CommunityAnswer::Refused { kind, code, .. } if !kind.refusal_is_news(&code) => None,
            CommunityAnswer::Refused {
                query,
                kind,
                code,
                message,
                ..
            } => {
                let mut words = refusal_words(kind, &name, &sanitize_display(&code, 120));
                if let Some(note) = message {
                    words.push_str(&format!(" They said: {}", sanitize_display(&note, 300)));
                }
                directory_failed(v, &query, &words);
                Some(words)
            }
            CommunityAnswer::Unreadable {
                query,
                kind,
                detail,
                ..
            } => {
                let words = format!(
                    "{name} answered about {} in a form this client cannot read — the two \
                     disagree about the task; it is not a refusal ({}).",
                    kind.describe(),
                    sanitize_display(&detail, 200)
                );
                directory_failed(v, &query, &words);
                Some(words)
            }
        };
        if let Some(message) = message {
            state.main_page.content_panel.vetting.status_message =
                Some(Status::error(message.clone()));
            state.main_page.log(message);
        }
    }
}

/// The directory view waiting on `query` stops waiting, and says why.
fn directory_failed(v: &mut VettingState, query: &str, why: &str) {
    if let VettingMode::Directory(view) = &mut v.mode
        && view.pending.as_deref() == Some(query)
    {
        view.pending = None;
        view.pending_cursors = None;
        view.error = Some(why.to_string());
    }
}

/// One listed vetter, ready to show. The name is the one they published — it
/// is shown beside their DID, never instead of it.
fn listed_row(config: &Config, listed: &vetters::list::v0_1::ListedVetter) -> ListedVetterRow {
    let join = |items: Vec<String>, none: &str| {
        if items.is_empty() {
            none.to_string()
        } else {
            sanitize_display(&items.join(", "), 300)
        }
    };
    let did = listed.vetter_did.as_str();
    ListedVetterRow {
        did: did.to_string(),
        name: listed
            .display_name
            .as_ref()
            .map(|n| n.as_str())
            .or_else(|| config.agent_name_for(did))
            .map(|n| sanitize_display(n, 128))
            .unwrap_or_else(|| shorten_did(did, 48)),
        languages: join(
            listed
                .languages
                .iter()
                .map(|l| l.as_str().to_string())
                .collect(),
            "no language listed",
        ),
        location: listed
            .location
            .as_ref()
            .map(|l| sanitize_display(&listed_location_line(l), 300)),
        // The listing carries its own copy of the method vocabulary, so each is
        // labelled by the token it spells.
        methods: listed
            .methods
            .0
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        documentation: join(
            listed
                .accepts_documentation
                .0
                .iter()
                .map(|d| d.as_str().to_string())
                .collect(),
            "no documentation listed — ask them",
        ),
        availability: listed
            .availability
            .as_ref()
            .map(|a| sanitize_display(a.as_str(), 500)),
        contact_hint: listed
            .contact_hint
            .as_ref()
            .map(|h| sanitize_display(h.as_str(), 300)),
        events: listed
            .events
            .iter()
            .map(|e| sanitize_display(&listed_event_line(e), 300))
            .collect(),
        grant_until: listed.grant_valid_until.format("%Y-%m-%d").to_string(),
    }
}

/// Tell whoever is waiting that a question went unanswered, and forget it. A
/// manifest question is the join flow's, which keeps its own, shorter clock.
pub(crate) fn expire_queries(state: &mut State, config: &mut Config, now: chrono::DateTime<Utc>) {
    let expired = config.private.vetting.expire_queries(now, QUERY_TIMEOUT);
    for query in expired {
        if query.kind == QueryKind::Manifest {
            // Nothing is said here — a waiting ticket or the desk header says it, where it
            // matters — but how the community vets now is unknown, not what it last was. A
            // failure already recorded since the question went (it could not be sent) is the
            // truer story, and stays.
            let book = &mut config.private.vetting;
            if book
                .vetter_mode(&query.community)
                .failed_since(query.sent_at)
                .is_none()
            {
                book.mode_failed(&query.community, ModeFailure::Unanswered, now);
            }
            continue;
        }
        let name = community_display(config, &query.community);
        // Enrolment and the drip are asked again on their own, backed off (R1.4), so the line
        // says when rather than sending the vetter to try something they never started. An
        // answer that arrives late is still taken.
        let retry = matches!(
            query.kind,
            QueryKind::PcsRoot | QueryKind::PcsTokens | QueryKind::PcsBinding
        )
        .then(|| {
            config
                .private
                .vetting
                .hidden_vetter_mut(&query.community, query.persona)
                .map(|held| held.unanswered_at(now))
        })
        .flatten();
        let words = match retry {
            Some(at) => format!(
                "No answer from {name} about {} within {} seconds — its service may be offline \
                 or slow. Asking again at {}; an answer that arrives before then is still taken.",
                query.kind.describe(),
                QUERY_TIMEOUT.num_seconds(),
                when_words(at, now)
            ),
            None => format!(
                "No answer from {name} about {} within {} seconds — its service may be offline. \
                 Try again later.",
                query.kind.describe(),
                QUERY_TIMEOUT.num_seconds()
            ),
        };
        let v = &mut state.main_page.content_panel.vetting;
        directory_failed(v, &query.document_id, &words);
        v.status_message = Some(Status::error(words.clone()));
        state.main_page.log(words);
    }
}

/// Check, off the loop, whether the community revoked a vetter's grant.
///
/// Not claimed through the busy-guard: a check starts from an inbound
/// acceptance rather than a person, each is independent, and none may hold up
/// a vetting send the person is making.
pub(crate) fn spawn_grant_check(
    dispatch_tx: &tokio::sync::mpsc::UnboundedSender<DispatchOutcome>,
    tdk: &affinidi_tdk::TDK,
    check: GrantCheck,
) {
    let job = GrantCheckJob {
        resolver: tdk.did_resolver().clone(),
        check,
    };
    background_dispatch::spawn_unclaimed(job, dispatch_tx);
}

/// One revocation check, with the resolver it reads the status list through.
struct GrantCheckJob {
    resolver: affinidi_tdk::did_resolver::DIDCacheClient,
    check: GrantCheck,
}

impl background_dispatch::Job for GrantCheckJob {
    fn domain(&self) -> DispatchDomain {
        DispatchDomain::VettingStatus
    }

    async fn execute(self) -> DispatchOutcome {
        let result = self.check.run(&self.resolver).await;
        DispatchOutcome::VettingStatus(GrantChecked {
            check: self.check,
            result,
        })
    }
}

/// A finished revocation check.
pub(crate) struct GrantChecked {
    pub(crate) check: GrantCheck,
    pub(crate) result: StatusCheck,
}

impl GrantChecked {
    /// Record the result on the request. A revocation is said on the page;
    /// the other results only change the request's line and the log.
    pub(crate) fn apply(self, state: &mut State, config: &mut Config, save: &mut SaveScheduler) {
        let GrantChecked { check, result } = self;
        let vetter = config
            .agent_name_for(&check.vetter)
            .map(|n| sanitize_display(n, 128))
            .unwrap_or_else(|| shorten_did(&check.vetter, 48));
        let community = community_display(config, &check.issuer);
        let message = match &result {
            StatusCheck::Active => format!("{community} has not revoked {vetter}'s vetter grant."),
            StatusCheck::Revoked => format!(
                "{community} has revoked {vetter}'s vetter grant — a statement from them will not \
                 count."
            ),
            StatusCheck::Unknown(reason) => format!(
                "Could not check whether {community} revoked {vetter}'s vetter grant: {}",
                sanitize_display(reason, 200)
            ),
        };
        let revoked = result == StatusCheck::Revoked;
        let recorded = config
            .private
            .vetting
            .application_by_id_mut(&check.application_id)
            .is_some_and(|app| {
                app.record_grant_status(
                    &check.request_document_id,
                    &check.vetter,
                    GrantStatus::from_check(result, Utc::now()),
                )
                .is_ok()
            });
        if !recorded {
            // The application or request went away while the check ran.
            state.main_page.log(message);
            return;
        }
        if revoked {
            dispatch_util::save_and_sync(
                &mut state.main_page,
                config,
                save,
                Persist::SaveAndSync(crate::state_handler::main_page::Panels::FROM_VETTING_BOOK),
                |mp| &mut mp.content_panel.vetting.status_message,
                message.clone(),
                SyncLog::Plain(message),
            );
        } else {
            save.mark_dirty();
            state.main_page.sync_panels(
                config,
                crate::state_handler::main_page::Panels::FROM_VETTING_BOOK,
            );
            state.main_page.log(message);
        }
    }
}

/// Show application `application_id` on the Vetting page, with `message`. Used
/// by the join flow when a person starts or continues an application there.
/// Go to where a vetting task is acted on: the card page for an applicant's
/// open session, or the request on the vetter's desk.
pub(crate) fn focus_vetting_target(
    state: &mut State,
    config: &Config,
    target: &crate::state_handler::main_page::content::VettingTarget,
) {
    use crate::state_handler::main_page::content::VettingTarget;
    match target {
        VettingTarget::Card {
            application_id,
            session_id,
        } => {
            focus_application(
                state,
                config,
                application_id,
                "A vetter opened a session. Read the match code to each other, then Enter \
                 previews your card."
                    .to_string(),
            );
            state.main_page.content_panel.vetting.mode = VettingMode::SendCard {
                application_id: application_id.clone(),
                session_id: session_id.clone(),
                preview: None,
            };
        }
        VettingTarget::Desk { request_id } => {
            state.main_page.sync_from_config(config);
            state.main_page.menu_panel.selected_menu = MainMenu::Vetting;
            state.main_page.menu_panel.selected = false;
            state.main_page.content_panel.selected = true;
            let v = &mut state.main_page.content_panel.vetting;
            v.tab = VettingTab::Desk;
            v.desk_view = DeskView::Requests;
            v.mode = VettingMode::List;
            match v.desk.iter().position(|r| &r.request_id == request_id) {
                Some(i) => {
                    v.selected = i;
                    v.status_message = None;
                    v.journey_target = Some(JourneyTarget::Desk(request_id.clone()));
                    sync_journey(v, config, sync_clock());
                }
                None => {
                    v.status_message = Some(Status::warning(
                        "That request is no longer on your desk.".to_string(),
                    ));
                }
            }
        }
    }
}

pub(crate) fn focus_application(
    state: &mut State,
    config: &Config,
    application_id: &str,
    message: String,
) {
    state.main_page.sync_from_config(config);
    state.main_page.menu_panel.selected_menu = MainMenu::Vetting;
    state.main_page.menu_panel.selected = false;
    state.main_page.content_panel.selected = true;
    let v = &mut state.main_page.content_panel.vetting;
    v.tab = VettingTab::Applications;
    v.mode = VettingMode::List;
    if let Some(i) = v.applications.iter().position(|a| a.id == application_id) {
        v.selected = i;
    }
    v.status_message = Some(Status::info(message));
    // Every way here — starting from the join page, an Inbox entry — lands on
    // the application's journey, so the holder always arrives at the same
    // picture of where they are.
    v.journey_target = Some(JourneyTarget::Application(application_id.to_string()));
    sync_journey(v, config, sync_clock());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::content::{
        DirectoryView, LineTone, VettingMode, VettingTab,
    };
    use crate::state_handler::main_page::menu::MainMenu;
    use crate::state_handler::save_coalesce::SaveScheduler;
    use crate::state_handler::state::State;
    use chrono::Utc;
    use openvtc_core::config::Config;
    use openvtc_core::config::account::PersonaId;
    use openvtc_core::vetting::applicant::{Application, GrantStatus, RequestDraft};
    use openvtc_core::vetting::queries::{
        CommunityAnswer, CommunityQuery, QUERY_TIMEOUT, QueryKind,
    };
    use openvtc_core::vetting::status::GrantCheck;
    use vta_sdk::protocols::vetting::VETTING_VETTER_RESEND_ERR_NOT_GRANTED;
    use vta_sdk::protocols::vetting::{request, vetters};
    use vta_sdk::vetting::status::StatusCheck;

    fn listed(did: &str) -> vetters::list::v0_1::ListedVetter {
        serde_json::from_value(serde_json::json!({
            "vetterDid": did,
            "displayName": "Carol",
            "languages": ["en"],
            "methods": ["inPerson"],
            "acceptsDocumentation": [],
            "contactHint": "ask at the LPC desk",
            "events": [],
            "grantValidUntil": "2027-09-01T00:00:00Z",
            "updatedAt": "2026-09-01T00:00:00Z"
        }))
        .unwrap()
    }

    fn directory_waiting_on(query: &str) -> State {
        let mut state = State::default();
        state.main_page.content_panel.vetting.mode =
            VettingMode::Directory(Box::new(DirectoryView {
                pending: Some(query.into()),
                pending_cursors: Some(vec![None, Some("page-2".into())]),
                cursors: vec![None],
                ..DirectoryView::default()
            }));
        state
    }

    /// A directory page lands only in the view that asked for it, and moves the
    /// focus onto the first result.
    #[test]
    fn a_directory_page_lands_only_where_it_was_asked_for() {
        let config = test_config();
        let mut state = directory_waiting_on("q1");
        let page = vetters::list::v0_1::Response::try_from(
            vetters::list::v0_1::Response::builder().vetters(vec![listed("did:key:zCarol")]),
        )
        .unwrap();
        apply_answers(
            &mut state,
            &config,
            vec![CommunityAnswer::Vetters {
                query: "someone-else".into(),
                community: "did:web:vtc".into(),
                page: page.clone(),
            }],
        );
        let VettingMode::Directory(view) = &state.main_page.content_panel.vetting.mode else {
            panic!("still the directory");
        };
        assert!(view.results.is_empty() && view.pending.is_some());

        apply_answers(
            &mut state,
            &config,
            vec![CommunityAnswer::Vetters {
                query: "q1".into(),
                community: "did:web:vtc".into(),
                page,
            }],
        );
        let VettingMode::Directory(view) = &state.main_page.content_panel.vetting.mode else {
            panic!("still the directory");
        };
        assert_eq!(view.results.len(), 1);
        assert_eq!(view.results[0].name, "Carol");
        assert_eq!(
            view.results[0].documentation,
            "no documentation listed — ask them"
        );
        assert_eq!(view.cursors.len(), 2, "this is page two");
        assert_eq!(view.result_index(), Some(0));
        assert!(view.pending.is_none());
    }

    /// A refusal reads as what to do next, on the page and in the view.
    #[test]
    fn refusals_are_said_plainly() {
        let config = test_config();
        let mut state = directory_waiting_on("q1");
        apply_answers(
            &mut state,
            &config,
            vec![CommunityAnswer::Refused {
                query: "q1".into(),
                community: "did:web:vtc".into(),
                kind: QueryKind::VetterList,
                code: "permissionDenied".into(),
                message: None,
            }],
        );
        let v = &state.main_page.content_panel.vetting;
        let VettingMode::Directory(view) = &v.mode else {
            panic!("still the directory");
        };
        assert!(view.pending.is_none());
        assert!(
            view.error
                .as_deref()
                .is_some_and(|e| e.contains("would not answer"))
        );

        apply_answers(
            &mut state,
            &config,
            vec![CommunityAnswer::Refused {
                query: "r1".into(),
                community: "did:web:vtc".into(),
                kind: QueryKind::VetterResend,
                code: VETTING_VETTER_RESEND_ERR_NOT_GRANTED.into(),
                message: None,
            }],
        );
        assert!(
            state
                .main_page
                .content_panel
                .vetting
                .status_message
                .as_ref()
                .map(|s| s.text.as_str())
                .is_some_and(|m| m.contains("has not named you a vetter"))
        );
    }

    /// A question nobody answered is said to be unanswered, not left spinning.
    #[test]
    fn an_unanswered_search_stops_waiting() {
        let mut config = test_config();
        let mut state = directory_waiting_on("q1");
        config.private.vetting.ask(CommunityQuery {
            document_id: "q1".into(),
            community: "did:web:vtc".into(),
            persona: PersonaId::new(),
            kind: QueryKind::VetterList,
            sent_at: Utc::now() - QUERY_TIMEOUT,
        });
        expire_queries(&mut state, &mut config, Utc::now());
        let VettingMode::Directory(view) = &state.main_page.content_panel.vetting.mode else {
            panic!("still the directory");
        };
        assert!(view.pending.is_none());
        assert!(
            view.error
                .as_deref()
                .is_some_and(|e| e.contains("No answer"))
        );
    }

    fn application_with_request(config: &mut Config) -> (String, String) {
        let mut app = Application::new(
            "did:web:vtc.example",
            PersonaId::new(),
            "did:key:zApplicant",
            Utc::now(),
        )
        .unwrap();
        app.prepare_request(
            "urn:uuid:r1",
            "did:key:zVetter",
            request::v0_1::Ticket::ShortCodeTicket(
                request::v0_1::ShortCodeTicket::try_from(
                    request::v0_1::ShortCodeTicket::builder().code("K7QF-2M9X"),
                )
                .unwrap(),
            ),
            RequestDraft::default(),
            Utc::now(),
        )
        .unwrap();
        let id = app.id.clone();
        config.private.vetting.applications.push(app);
        (id, "urn:uuid:r1".into())
    }

    /// A revoked grant is recorded on the request and said on the page.
    #[test]
    fn a_revoked_grant_is_recorded_and_said() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        let (application_id, request_document_id) = application_with_request(&mut config);
        GrantChecked {
            check: GrantCheck {
                application_id,
                request_document_id,
                vetter: "did:key:zVetter".into(),
                issuer: "did:web:vtc.example".into(),
                credential_status: serde_json::json!({}),
            },
            result: StatusCheck::Revoked,
        }
        .apply(&mut state, &mut config, &mut save);
        assert!(matches!(
            config.private.vetting.applications[0].requests[0].grant_status,
            Some(GrantStatus::Revoked { .. })
        ));
        let v = &state.main_page.content_panel.vetting;
        assert!(
            v.status_message
                .as_ref()
                .map(|s| s.text.as_str())
                .is_some_and(|m| m.contains("has revoked"))
        );
        assert_eq!(
            v.applications[0].requests[0]
                .grant
                .as_ref()
                .map(|(t, _)| *t),
            Some(LineTone::Bad)
        );
    }

    /// An inbox vetting task opens where its step is taken: the card page for
    /// an applicant's session, the desk for a vetter's request — and says so
    /// when the request has gone, rather than landing on an unrelated row.
    #[test]
    fn a_vetting_task_opens_where_its_step_is_taken() {
        use crate::state_handler::main_page::content::VettingTarget;
        let config = test_config();
        let mut state = State::default();
        focus_vetting_target(
            &mut state,
            &config,
            &VettingTarget::Card {
                application_id: "a".into(),
                session_id: "s".into(),
            },
        );
        assert_eq!(state.main_page.menu_panel.selected_menu, MainMenu::Vetting);
        assert!(matches!(
            &state.main_page.content_panel.vetting.mode,
            VettingMode::SendCard { application_id, session_id, .. }
                if application_id == "a" && session_id == "s"
        ));

        let mut state = State::default();
        focus_vetting_target(
            &mut state,
            &config,
            &VettingTarget::Desk {
                request_id: "gone".into(),
            },
        );
        let v = &state.main_page.content_panel.vetting;
        assert_eq!(v.tab, VettingTab::Desk);
        assert!(
            v.status_message
                .as_ref()
                .map(|s| s.text.as_str())
                .is_some_and(|m| m.contains("no longer on your desk"))
        );
    }
}
