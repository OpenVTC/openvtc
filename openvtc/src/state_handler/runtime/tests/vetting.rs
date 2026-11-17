//! Runtime-harness tests pinning the vetting handlers: the busy, send-failure
//! and success paths (#612).
//!
//! Each person-started send is pinned three ways: refused while another
//! vetting job holds the domain (nothing prepared, nothing saved), failing
//! before it is sent because the persona's keys do not resolve (the book put
//! back, the failure said), and sent — which claims the domain, and, with no
//! messaging listener in the harness, fails off the loop, whose outcome is
//! then applied.

use std::time::Duration;

use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::queries::QueryKind;
use vta_sdk::protocols::vetting::request;

use super::fixtures;
use super::*;
use crate::state_handler::actions::VettingAction;
use crate::state_handler::main_page::content::{
    DirectoryView, EventOffer, VettingMembership, VettingMode, VettingTab,
};
use crate::state_handler::main_page::status::{Severity, Status};
use background_dispatch::{DispatchDomain, InFlight};

const VTC: &str = "did:web:vtc.example";
const VETTER: &str = "did:key:zVetterOfTheApplicant";

fn page(rt: &Runtime) -> &crate::state_handler::main_page::content::VettingState {
    &rt.state.main_page.content_panel.vetting
}

fn status(rt: &Runtime) -> &Status {
    page(rt)
        .status_message
        .as_ref()
        .expect("the page says something")
}

fn busy(rt: &Runtime) -> bool {
    rt.in_flight.is_busy(DispatchDomain::Vetting)
}

fn asked(rt: &Runtime, kind: QueryKind) -> bool {
    rt.config.private.vetting.waiting_on(VTC, kind).is_some()
}

async fn act(rt: &mut Runtime, action: VettingAction) {
    rt.on_action(Action::Vetting(action)).await;
}

/// A persona whose identity is held but whose keys do not resolve: the
/// handlers get past every check and fail at the key lookup.
async fn persona_without_keys(rt: &mut Runtime, did: &str) -> PersonaId {
    let persona = fixtures::persona_with_keys(rt, did).await;
    rt.config.key_info.clear();
    persona
}

/// An application to [`VTC`] as `persona`, shown on the page and selected.
fn application(rt: &mut Runtime, persona: PersonaId) -> String {
    let did = rt.config.identities[&persona].did.clone();
    let id = rt
        .config
        .private
        .vetting
        .start_application(VTC, persona, &did, chrono::Utc::now())
        .expect("an application")
        .id
        .clone();
    rt.state.main_page.sync_from_config(&rt.config);
    rt.state.main_page.content_panel.vetting.selected = 0;
    id
}

/// The send the last action handed to the background fails (the harness has
/// no listener); apply its outcome as the loop would.
async fn settle(rt: &mut Runtime) {
    let outcome = tokio::time::timeout(Duration::from_secs(30), rt.dispatch_rx.recv())
        .await
        .expect("the send reports back")
        .expect("the channel is open");
    assert!(outcome.claimed(), "a person's send holds the domain");
    rt.on_dispatch_outcome(outcome).await;
}

fn assert_busy_refusal(rt: &Runtime) {
    assert_eq!(
        status(rt),
        &Status::warning(InFlight::busy_message(DispatchDomain::Vetting))
    );
}

/// Where the first activity-log line containing `needle` is.
fn log_line(rt: &Runtime, needle: &str) -> usize {
    rt.state
        .main_page
        .activity_log
        .iter()
        .position(|e| e.summary.contains(needle))
        .unwrap_or_else(|| panic!("{needle:?} is logged"))
}

/// The error status and log line a send gives up with before it was sent.
fn assert_abandoned(rt: &Runtime, what: &str) {
    let s = status(rt);
    assert_eq!(s.severity, Severity::Error);
    assert!(s.text.starts_with(&format!("{what}: ")), "{}", s.text);
    assert!(logged(&rt.state, what));
    assert!(!busy(rt), "nothing was dispatched");
}

// ============================================================================
// Applicant
// ============================================================================

// ---- refresh requirements ----

#[tokio::test]
async fn refreshing_requirements_while_busy_asks_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    application(&mut rt, persona);
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::RefreshRequirements).await;

    assert_busy_refusal(&rt);
    assert!(!asked(&rt, QueryKind::Manifest));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn refreshing_requirements_without_keys_gives_up_unsent() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zApplicant").await;
    application(&mut rt, persona);

    act(&mut rt, VettingAction::RefreshRequirements).await;

    assert_abandoned(&rt, "Could not ask the community");
    assert!(!asked(&rt, QueryKind::Manifest));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn refreshing_requirements_files_the_question_and_claims_the_domain() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    application(&mut rt, persona);

    act(&mut rt, VettingAction::RefreshRequirements).await;

    assert!(busy(&rt));
    assert_eq!(
        status(&rt),
        &Status::progress("Asking the community what it requires…")
    );
    assert!(asked(&rt, QueryKind::Manifest));
    assert!(!rt.save.is_pending());

    settle(&mut rt).await;
    assert!(!busy(&rt));
    let s = status(&rt);
    assert_eq!(s.severity, Severity::Success);
    assert!(
        s.text
            .starts_with(&format!("Could not yet ask {VTC} what it requires (")),
        "{}",
        s.text
    );
}

// ---- start an application ----

fn new_application_form(rt: &mut Runtime, community: &str) {
    rt.state.main_page.content_panel.vetting.mode = VettingMode::NewApplication {
        community: community.into(),
        persona_index: 0,
        context_options: Vec::new(),
        context_index: 0,
        field: 0,
    };
}

#[tokio::test]
async fn an_application_to_something_not_a_did_is_refused() {
    let (mut rt, _h) = runtime().await;
    fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    rt.state.main_page.sync_from_config(&rt.config);
    new_application_form(&mut rt, "vtc.example");

    act(&mut rt, VettingAction::Submit).await;

    assert_eq!(
        status(&rt),
        &Status::warning("Enter the community's DID (it starts with did:).")
    );
    assert!(rt.config.private.vetting.applications.is_empty());
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn starting_an_application_while_busy_saves_it_and_asks_nothing() {
    let (mut rt, _h) = runtime().await;
    fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    rt.state.main_page.sync_from_config(&rt.config);
    new_application_form(&mut rt, VTC);
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert_eq!(rt.config.private.vetting.applications.len(), 1);
    assert!(rt.save.is_pending(), "the application is saved");
    assert!(logged(&rt.state, "Application started."));
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(page(&rt).tab, VettingTab::Applications);
    // The refresh that follows is what is refused.
    assert_busy_refusal(&rt);
    assert!(!asked(&rt, QueryKind::Manifest));
}

#[tokio::test]
async fn starting_an_application_saves_it_then_asks_for_its_requirements() {
    let (mut rt, _h) = runtime().await;
    fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    rt.state.main_page.sync_from_config(&rt.config);
    new_application_form(&mut rt, VTC);

    act(&mut rt, VettingAction::Submit).await;

    let book = &rt.config.private.vetting;
    assert_eq!(book.applications.len(), 1);
    assert_eq!(book.applications[0].context_id, None);
    assert!(rt.save.is_pending());
    assert!(logged(&rt.state, "Application started."));
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(page(&rt).tab, VettingTab::Applications);
    assert_eq!(
        page(&rt).applications[page(&rt).selected].id,
        book.applications[0].id
    );
    assert!(busy(&rt));
    assert!(asked(&rt, QueryKind::Manifest));
    assert_eq!(
        status(&rt),
        &Status::progress("Asking the community what it requires…")
    );
}

// ---- request a vetter ----

fn code_ticket() -> request::v0_1::Ticket {
    request::v0_1::Ticket::ShortCodeTicket(
        request::v0_1::ShortCodeTicket::try_from(
            request::v0_1::ShortCodeTicket::builder().code("0000-0000"),
        )
        .expect("a Crockford code"),
    )
}

fn request_form(rt: &mut Runtime, application_id: &str) {
    rt.state.main_page.content_panel.vetting.mode = VettingMode::RequestVetter {
        application_id: application_id.into(),
        entry: String::new(),
        vetter: VETTER.into(),
        ticket: Some(code_ticket()),
        note: None,
    };
}

fn requests(rt: &Runtime, application_id: &str) -> usize {
    rt.config
        .private
        .vetting
        .application_by_id(application_id)
        .map_or(0, |a| a.requests.len())
}

#[tokio::test]
async fn a_request_with_no_link_says_to_paste_one() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    let id = application(&mut rt, persona);
    request_form(&mut rt, &id);
    if let VettingMode::RequestVetter { vetter, ticket, .. } =
        &mut rt.state.main_page.content_panel.vetting.mode
    {
        vetter.clear();
        *ticket = None;
    }

    act(&mut rt, VettingAction::Submit).await;

    let s = status(&rt);
    assert_eq!(s.severity, Severity::Warning);
    assert!(
        s.text
            .starts_with("Paste the link from the vetter's QR code")
    );
    assert_eq!(requests(&rt, &id), 0);
}

#[tokio::test]
async fn a_request_while_busy_prepares_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    let id = application(&mut rt, persona);
    request_form(&mut rt, &id);
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert_busy_refusal(&rt);
    assert_eq!(requests(&rt, &id), 0);
    assert!(matches!(page(&rt).mode, VettingMode::RequestVetter { .. }));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn a_request_without_keys_is_saved_then_forgotten() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zApplicant").await;
    let id = application(&mut rt, persona);
    request_form(&mut rt, &id);

    act(&mut rt, VettingAction::Submit).await;

    assert_abandoned(&rt, "Could not send the request");
    assert_eq!(requests(&rt, &id), 0, "the unsent request is forgotten");
    assert!(matches!(page(&rt).mode, VettingMode::List));
    // Saved holding the request before the signing failed.
    assert!(rt.save.is_pending());
    assert!(
        log_line(&rt, "Sending your request…") < log_line(&rt, "Could not send the request"),
        "saved and said, then given up"
    );
}

#[tokio::test]
async fn a_request_is_saved_and_sent_and_a_failed_send_forgets_it() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    let id = application(&mut rt, persona);
    request_form(&mut rt, &id);

    act(&mut rt, VettingAction::Submit).await;

    assert!(busy(&rt));
    assert_eq!(requests(&rt, &id), 1);
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(status(&rt), &Status::success("Sending your request…"));
    assert!(rt.save.is_pending());

    settle(&mut rt).await;
    assert!(!busy(&rt));
    assert_eq!(requests(&rt, &id), 0);
    assert!(
        status(&rt).text.starts_with("Could not send the request: "),
        "{}",
        status(&rt).text
    );
}

// ---- the vetter directory ----

fn directory(rt: &mut Runtime) {
    rt.state.main_page.content_panel.vetting.mode = VettingMode::Directory(Box::default());
}

fn directory_view(rt: &Runtime) -> &DirectoryView {
    match &page(rt).mode {
        VettingMode::Directory(view) => view,
        other => panic!("the directory is open, not {other:?}"),
    }
}

#[tokio::test]
async fn the_directory_with_no_community_says_how_to_get_one() {
    let (mut rt, _h) = runtime().await;

    act(&mut rt, VettingAction::FindVetters).await;

    let s = status(&rt);
    assert_eq!(s.severity, Severity::Warning);
    assert!(
        s.text
            .starts_with("The vetter directory is searched per community")
    );
    assert!(matches!(page(&rt).mode, VettingMode::List));
}

#[tokio::test]
async fn a_directory_search_while_busy_asks_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    application(&mut rt, persona);
    act(&mut rt, VettingAction::FindVetters).await;
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert_busy_refusal(&rt);
    assert!(!asked(&rt, QueryKind::VetterList));
    assert_eq!(directory_view(&rt).pending, None);
}

#[tokio::test]
async fn a_directory_search_without_keys_forgets_its_question() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zApplicant").await;
    application(&mut rt, persona);
    directory(&mut rt);

    act(&mut rt, VettingAction::Submit).await;

    assert_abandoned(&rt, "Could not search the directory");
    assert!(!asked(&rt, QueryKind::VetterList));
    let view = directory_view(&rt);
    assert_eq!(view.pending, None);
    assert_eq!(view.pending_cursors, None);
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn a_directory_search_waits_on_its_answer_and_a_failed_send_says_so() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    application(&mut rt, persona);
    directory(&mut rt);
    let name = page(&rt).directory_communities[0].name.clone();

    act(&mut rt, VettingAction::Submit).await;

    assert!(busy(&rt));
    assert!(asked(&rt, QueryKind::VetterList));
    let view = directory_view(&rt);
    assert!(view.pending.is_some());
    assert_eq!(view.pending_cursors, Some(vec![None]));
    assert_eq!(view.error, None);
    assert_eq!(
        status(&rt),
        &Status::progress(format!("Asking {name} for its vetter directory…"))
    );
    assert!(!rt.save.is_pending());

    settle(&mut rt).await;
    assert!(!busy(&rt));
    assert!(!asked(&rt, QueryKind::VetterList));
    let view = directory_view(&rt);
    assert_eq!(view.pending, None);
    assert!(
        view.error
            .as_deref()
            .is_some_and(|e| e.starts_with("Could not ask the community: ")),
        "{:?}",
        view.error
    );
}

#[tokio::test]
async fn paging_past_the_last_directory_page_says_so() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    application(&mut rt, persona);
    directory(&mut rt);

    act(&mut rt, VettingAction::DirectoryPage(true)).await;
    assert_eq!(status(&rt), &Status::warning("That is the last page."));
    act(&mut rt, VettingAction::DirectoryPage(false)).await;
    assert_eq!(status(&rt), &Status::warning("This is the first page."));
    assert!(!busy(&rt));
}

// ---- switch path, abandon ----

#[tokio::test]
async fn switching_path_before_the_requirements_are_known_is_refused() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    application(&mut rt, persona);

    act(&mut rt, VettingAction::SwitchVettingPath).await;

    let s = status(&rt);
    assert_eq!(s.severity, Severity::Error);
    assert!(s.text.contains("refresh them (m) first"), "{}", s.text);
    assert!(!rt.save.is_pending());
}

/// first-vtc's live manifest, learnt: its `vetted-member` criterion offers
/// PCS ZKP and named vetting.
fn learn_first_vtc(rt: &mut Runtime) -> String {
    let document: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../openvtc-core/tests/fixtures/first-vtc-manifest-0.3.json"
    ))
    .unwrap();
    let payload = document["payload"].clone();
    let community = payload["communityDid"].as_str().unwrap().to_string();
    let protocol = openvtc_core::vetting::protocol::JoinProtocol::V0_4;
    let (parsed, meta) =
        openvtc_core::vetting::protocol::read_manifest(protocol, &payload).unwrap();
    let book = &mut rt.config.private.vetting;
    let now = chrono::Utc::now();
    book.learn_manifest_in(&community, &parsed, Some(protocol), &meta, now);
    book.learn_mode(&community, &payload, None, now);
    community
}

#[tokio::test]
async fn switching_path_saves_the_application_and_says_what_it_uses() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    let community = learn_first_vtc(&mut rt);
    let id = rt
        .config
        .private
        .vetting
        .start_application(
            &community,
            persona,
            "did:key:zApplicant",
            chrono::Utc::now(),
        )
        .unwrap()
        .id
        .clone();
    rt.config
        .private
        .vetting
        .adopt_known_requirements(&id)
        .unwrap();
    rt.state.main_page.sync_from_config(&rt.config);

    act(&mut rt, VettingAction::SwitchVettingPath).await;

    assert_eq!(
        status(&rt),
        &Status::success("This application now uses criterion vetted-member with named vetting.")
    );
    assert!(rt.save.is_pending());
    assert!(logged(
        &rt.state,
        "This application now uses criterion vetted-member"
    ));
}

fn confirm_abandon(rt: &mut Runtime, application_id: &str) {
    rt.state.main_page.content_panel.vetting.mode = VettingMode::ConfirmAbandon {
        application_id: application_id.into(),
    };
}

#[tokio::test]
async fn abandoning_an_application_removes_and_saves_it() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    let id = application(&mut rt, persona);
    rt.state.main_page.content_panel.vetting.selected = 3;
    confirm_abandon(&mut rt, &id);

    act(&mut rt, VettingAction::Submit).await;

    assert!(rt.config.private.vetting.applications.is_empty());
    assert!(page(&rt).applications.is_empty(), "the page shows it gone");
    assert_eq!(page(&rt).selected, 0);
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert!(rt.save.is_pending());
    assert_eq!(
        status(&rt),
        &Status::success(format!("Abandoned your application to {VTC}."))
    );
}

#[tokio::test]
async fn abandoning_an_application_already_gone_says_so() {
    let (mut rt, _h) = runtime().await;
    confirm_abandon(&mut rt, "gone");

    act(&mut rt, VettingAction::Submit).await;

    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert!(!rt.save.is_pending());
    assert_eq!(
        status(&rt),
        &Status::warning("That application is already gone.")
    );
}

// ============================================================================
// Vetter profile
// ============================================================================

fn membership(persona: PersonaId) -> VettingMembership {
    VettingMembership {
        community: VTC.into(),
        name: "VTC".into(),
        persona,
        accent: None,
    }
}

/// The profile form open on [`VTC`], with a name to publish.
async fn profile_form(rt: &mut Runtime, persona: PersonaId) {
    rt.state.main_page.content_panel.vetting.memberships = vec![membership(persona)].into();
    act(rt, VettingAction::EditProfile).await;
    let VettingMode::Profile(form) = &mut rt.state.main_page.content_panel.vetting.mode else {
        panic!("the profile form is open");
    };
    form.draft.display_name = "Carol".into();
}

fn profile_held(rt: &Runtime, persona: PersonaId) -> bool {
    rt.config
        .private
        .vetting
        .vetter_profile(VTC, persona)
        .is_some()
}

#[tokio::test]
async fn editing_a_profile_with_no_membership_says_why() {
    let (mut rt, _h) = runtime().await;

    act(&mut rt, VettingAction::EditProfile).await;

    assert_eq!(
        status(&rt),
        &Status::warning(
            "A profile is published to a community that named you a vetter, and none has."
        )
    );
}

#[tokio::test]
async fn publishing_a_profile_while_busy_records_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    profile_form(&mut rt, persona).await;
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert_busy_refusal(&rt);
    assert!(!profile_held(&rt, persona));
    assert!(!asked(&rt, QueryKind::VetterProfile));
    assert!(matches!(page(&rt).mode, VettingMode::Profile(_)));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn publishing_a_profile_without_keys_puts_the_record_back() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
    profile_form(&mut rt, persona).await;

    act(&mut rt, VettingAction::Submit).await;

    assert_abandoned(&rt, "Could not publish your profile");
    assert!(!profile_held(&rt, persona));
    assert!(!asked(&rt, QueryKind::VetterProfile));
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(page(&rt).tab, VettingTab::Desk);
    assert!(rt.save.is_pending(), "saved holding the profile first");
    assert!(
        log_line(&rt, "Sending your profile to VTC…")
            < log_line(&rt, "Could not publish your profile"),
        "saved and said, then given up"
    );
}

#[tokio::test]
async fn publishing_a_profile_records_and_sends_it_and_a_failed_send_undoes_it() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    profile_form(&mut rt, persona).await;

    act(&mut rt, VettingAction::Submit).await;

    assert!(busy(&rt));
    assert!(profile_held(&rt, persona));
    assert!(asked(&rt, QueryKind::VetterProfile));
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(page(&rt).tab, VettingTab::Desk);
    assert_eq!(
        status(&rt),
        &Status::success("Sending your profile to VTC…")
    );
    assert!(rt.save.is_pending());

    settle(&mut rt).await;
    assert!(!busy(&rt));
    assert!(!profile_held(&rt, persona));
    assert!(!asked(&rt, QueryKind::VetterProfile));
    assert!(
        status(&rt)
            .text
            .starts_with("Could not send your profile: "),
        "{}",
        status(&rt).text
    );
}

#[tokio::test]
async fn a_profile_vetting_by_no_method_is_refused_on_its_form() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    profile_form(&mut rt, persona).await;
    if let VettingMode::Profile(form) = &mut rt.state.main_page.content_panel.vetting.mode {
        form.draft.methods.clear();
    }

    act(&mut rt, VettingAction::Submit).await;

    let VettingMode::Profile(form) = &page(&rt).mode else {
        panic!("the form stays open");
    };
    assert!(form.error.is_some());
    assert!(!busy(&rt));
    assert!(!profile_held(&rt, persona));
}

// ---- event mode, resend ----

fn event_offer(rt: &mut Runtime, persona: PersonaId) {
    let today = chrono::Utc::now().date_naive();
    rt.state.main_page.content_panel.vetting.event_offers = vec![EventOffer {
        community: VTC.into(),
        community_name: "VTC".into(),
        persona,
        event_id: "ev1".into(),
        tier: "gold".into(),
        drip_per_tick: 10,
        start_date: today,
        end_date: today,
        group_floor: 1,
        state: None,
        group_size: None,
    }]
    .into();
    rt.state.main_page.content_panel.vetting.mode = VettingMode::EventMode { index: 0 };
}

#[tokio::test]
async fn asking_for_event_mode_while_busy_asks_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    event_offer(&mut rt, persona);
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert_busy_refusal(&rt);
    assert!(!asked(&rt, QueryKind::PcsEventMode));
    assert!(matches!(page(&rt).mode, VettingMode::EventMode { .. }));
}

#[tokio::test]
async fn asking_for_event_mode_without_keys_forgets_the_question() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
    event_offer(&mut rt, persona);

    act(&mut rt, VettingAction::Submit).await;

    assert_abandoned(&rt, "Could not ask to vet at the event");
    assert!(!asked(&rt, QueryKind::PcsEventMode));
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn asking_for_event_mode_files_the_question_and_a_failed_send_forgets_it() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    event_offer(&mut rt, persona);

    act(&mut rt, VettingAction::Submit).await;

    assert!(busy(&rt));
    assert!(asked(&rt, QueryKind::PcsEventMode));
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(
        status(&rt),
        &Status::progress("Asking VTC to vet at ev1 (gold)…")
    );
    assert!(!rt.save.is_pending());

    settle(&mut rt).await;
    assert!(!busy(&rt));
    assert!(!asked(&rt, QueryKind::PcsEventMode));
    assert!(
        status(&rt)
            .text
            .starts_with(&format!("Could not ask {VTC} for ")),
        "{}",
        status(&rt).text
    );
}

fn resend(rt: &mut Runtime, persona: PersonaId) {
    rt.state.main_page.content_panel.vetting.resend_candidates = vec![membership(persona)].into();
    rt.state.main_page.content_panel.vetting.mode = VettingMode::Resend { index: 0 };
}

#[tokio::test]
async fn asking_for_a_resend_while_busy_asks_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    resend(&mut rt, persona);
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert_busy_refusal(&rt);
    assert!(!asked(&rt, QueryKind::VetterResend));
    assert!(matches!(page(&rt).mode, VettingMode::Resend { .. }));
}

#[tokio::test]
async fn asking_for_a_resend_without_keys_forgets_the_question() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
    resend(&mut rt, persona);

    act(&mut rt, VettingAction::Submit).await;

    assert_abandoned(&rt, "Could not ask for your vetter credential");
    assert!(!asked(&rt, QueryKind::VetterResend));
    assert!(matches!(page(&rt).mode, VettingMode::List));
}

#[tokio::test]
async fn asking_for_a_resend_files_the_question_and_a_failed_send_forgets_it() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    resend(&mut rt, persona);

    act(&mut rt, VettingAction::Submit).await;

    assert!(busy(&rt));
    assert!(asked(&rt, QueryKind::VetterResend));
    assert_eq!(
        status(&rt),
        &Status::progress("Asking VTC to send your vetter credential again…")
    );

    settle(&mut rt).await;
    assert!(!busy(&rt));
    assert!(!asked(&rt, QueryKind::VetterResend));
    assert!(
        status(&rt)
            .text
            .starts_with(&format!("Could not ask {VTC} for ")),
        "{}",
        status(&rt).text
    );
}

// ============================================================================
// Desk
// ============================================================================

use openvtc_core::vetting::tickets::{DEFAULT_VALIDITY, Ticket};
use openvtc_core::vetting::vetter::{DeskEntry, DeskSession, DeskState, ReceivedCard};

const APPLICANT: &str = "did:key:zApplicantAtTheDesk";

/// A request from [`APPLICANT`] to `persona`, accepted onto the desk for
/// [`VTC`]. Returns its id.
fn desk_request(rt: &mut Runtime, persona: PersonaId) -> String {
    let body = request::v0_1::Payload::try_from(
        request::v0_1::Payload::builder()
            .community(VTC)
            .join_did(APPLICANT)
            .ticket(Some(code_ticket())),
    )
    .expect("a request");
    let request_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    rt.config.private.vetting.desk.push(DeskEntry {
        request_id: request_id.clone(),
        request_document_id: uuid::Uuid::new_v4().to_string(),
        applicant: APPLICANT.into(),
        community: VTC.into(),
        persona,
        ticket_id: None,
        request: body,
        state: DeskState::Accepted,
        received_at: now,
        updated_at: now,
    });
    rt.state.main_page.sync_from_config(&rt.config);
    request_id
}

fn desk_state<'a>(rt: &'a Runtime, request_id: &str) -> &'a DeskState {
    &rt.config
        .private
        .vetting
        .desk_entry(request_id)
        .expect("the request is on the desk")
        .state
}

/// The page has already asked [`VTC`] what it requires, so a session opens
/// without asking first.
fn requirements_asked(rt: &mut Runtime) {
    rt.state
        .main_page
        .content_panel
        .vetting
        .requirements_requested
        .push(VTC.into());
}

fn open_session_form(rt: &mut Runtime, request_id: &str) {
    rt.state.main_page.content_panel.vetting.mode = VettingMode::OpenSession {
        request_id: request_id.into(),
        method_index: 0,
    };
}

/// A send the client makes on its own (`Claim::Unheld`) reports back; apply
/// its outcome as the loop would.
async fn settle_unclaimed(rt: &mut Runtime) {
    let outcome = tokio::time::timeout(Duration::from_secs(30), rt.dispatch_rx.recv())
        .await
        .expect("the send reports back")
        .expect("the channel is open");
    assert!(
        !outcome.claimed(),
        "a send of the client's own holds nothing"
    );
    rt.on_dispatch_outcome(outcome).await;
}

// ---- open a session: the community's requirements asked first ----

#[tokio::test]
async fn opening_a_session_before_the_requirements_while_busy_asks_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    open_session_form(&mut rt, &id);
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert_busy_refusal(&rt);
    assert!(page(&rt).requirements_requested.is_empty());
    assert!(!asked(&rt, QueryKind::Manifest));
    assert!(matches!(desk_state(&rt, &id), DeskState::Accepted));
    assert!(matches!(page(&rt).mode, VettingMode::OpenSession { .. }));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn opening_a_session_before_the_requirements_without_keys_gives_up_unsent() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    open_session_form(&mut rt, &id);

    act(&mut rt, VettingAction::Submit).await;

    assert_abandoned(&rt, "Could not ask the community");
    assert!(!asked(&rt, QueryKind::Manifest));
    // Marked as asked although nothing went: the next Enter opens the session
    // without the requirements.
    assert_eq!(page(&rt).requirements_requested, vec![VTC.to_string()]);
    assert!(matches!(desk_state(&rt, &id), DeskState::Accepted));
    assert!(matches!(page(&rt).mode, VettingMode::OpenSession { .. }));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn opening_a_session_before_the_requirements_asks_the_community_first() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    open_session_form(&mut rt, &id);

    act(&mut rt, VettingAction::Submit).await;

    assert!(busy(&rt));
    assert!(asked(&rt, QueryKind::Manifest));
    assert_eq!(page(&rt).requirements_requested, vec![VTC.to_string()]);
    assert_eq!(
        status(&rt),
        &Status::progress(
            "Asking the community which claims it requires — open the session again in a moment."
        )
    );
    assert!(matches!(desk_state(&rt, &id), DeskState::Accepted));
    assert!(matches!(page(&rt).mode, VettingMode::OpenSession { .. }));
    assert!(!rt.save.is_pending());

    settle(&mut rt).await;
    assert!(!busy(&rt));
    assert!(
        status(&rt)
            .text
            .starts_with(&format!("Could not yet ask {VTC} what it requires (")),
        "{}",
        status(&rt).text
    );
}

#[tokio::test]
async fn opening_a_session_as_a_persona_not_held_says_so() {
    let (mut rt, _h) = runtime().await;
    let id = desk_request(&mut rt, PersonaId::new());
    open_session_form(&mut rt, &id);
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert_eq!(
        status(&rt),
        &Status::error("The persona this request was made to is not available.")
    );
    assert!(page(&rt).requirements_requested.is_empty());
}

#[tokio::test]
async fn opening_a_session_for_a_request_not_on_the_desk_does_nothing() {
    let (mut rt, _h) = runtime().await;
    open_session_form(&mut rt, "gone");

    act(&mut rt, VettingAction::Submit).await;

    assert!(page(&rt).status_message.is_none());
    assert!(matches!(page(&rt).mode, VettingMode::OpenSession { .. }));
    assert!(!busy(&rt));
}

// ---- open a session ----

#[tokio::test]
async fn opening_a_session_while_busy_opens_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    requirements_asked(&mut rt);
    open_session_form(&mut rt, &id);
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert_busy_refusal(&rt);
    assert!(matches!(desk_state(&rt, &id), DeskState::Accepted));
    assert!(matches!(page(&rt).mode, VettingMode::OpenSession { .. }));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn opening_a_session_without_keys_leaves_it_open_and_unsaved() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    requirements_asked(&mut rt);
    open_session_form(&mut rt, &id);

    act(&mut rt, VettingAction::Submit).await;

    assert_abandoned(&rt, "Could not send the session");
    // The session the book opened before the signing stays open, its document
    // never kept, and nothing is saved.
    let DeskState::Session { session } = desk_state(&rt, &id) else {
        panic!("the session stays open");
    };
    assert!(session.document.is_none());
    assert!(matches!(page(&rt).mode, VettingMode::OpenSession { .. }));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn opening_a_session_keeps_its_document_saves_and_sends_it() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    requirements_asked(&mut rt);
    open_session_form(&mut rt, &id);

    act(&mut rt, VettingAction::Submit).await;

    assert!(busy(&rt));
    let DeskState::Session { session } = desk_state(&rt, &id) else {
        panic!("the session is open");
    };
    let signed = session
        .document
        .as_ref()
        .expect("the signed document is kept");
    assert!(signed.get("proof").is_some(), "kept as signed");
    let code = session.match_code.clone();
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(
        status(&rt),
        &Status::success(format!(
            "Session open. Read the match code {code} to each other — the community's \
             requirements are still unknown, so this asks for a legal name only."
        ))
    );
    assert!(logged(&rt.state, "Session open."));
    assert!(rt.save.is_pending());

    settle(&mut rt).await;
    assert!(!busy(&rt));
    assert!(
        status(&rt).text.starts_with("Could not send — try again: "),
        "{}",
        status(&rt).text
    );
}

// ---- attest ----

/// The request's card has arrived, on a session whose document `vetter`
/// signed and kept.
fn card_received(rt: &mut Runtime, request_id: &str, vetter: &str) {
    let session_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let document = openvtc_core::vetting::wire::document(
        vta_sdk::protocols::vetting::VETTING_SESSION_TYPE,
        vetter,
        APPLICANT,
        session_id.clone(),
        &serde_json::json!({}),
    )
    .expect("a session document");
    let now = chrono::Utc::now();
    let entry = rt
        .config
        .private
        .vetting
        .desk_entry_mut(request_id)
        .expect("on the desk");
    entry.state = DeskState::CardReceived {
        session: DeskSession {
            id: session_id.clone(),
            challenge: "challenge".into(),
            method: vta_sdk::protocols::vetting::VettingMethod::PriorAcquaintance,
            required_claims: Vec::new(),
            optional_claims: Vec::new(),
            expires_at: now + chrono::Duration::hours(1),
            match_code: "1234".into(),
            document: Some(Box::new(serde_json::to_value(&document).unwrap())),
        },
        card: ReceivedCard {
            digest_multibase: "zQmCardDigest".into(),
            identity_commitment: "zCommitment".into(),
            claims: Vec::new(),
            card: None,
            received_at: now,
        },
    };
    rt.state.main_page.sync_from_config(&rt.config);
}

/// The attest form, ticked, attesting by prior acquaintance (which needs no
/// document).
fn attest_form(rt: &mut Runtime, request_id: &str, attested: bool) {
    rt.state.main_page.content_panel.vetting.mode = VettingMode::Attest {
        request_id: request_id.into(),
        form: crate::state_handler::main_page::content::AttestForm {
            method_index: 2,
            attested,
            ..Default::default()
        },
    };
}

fn issued(rt: &Runtime) -> usize {
    rt.config.private.vetting.issued.len()
}

#[tokio::test]
async fn attesting_unticked_says_to_tick_it() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    card_received(&mut rt, &id, "did:key:zVetter");
    attest_form(&mut rt, &id, false);

    act(&mut rt, VettingAction::Submit).await;

    assert_eq!(
        status(&rt),
        &Status::warning(
            "Tick the attestation (the last line) — signing is attributable to you in this community."
        )
    );
    assert_eq!(issued(&rt), 0);
}

#[tokio::test]
async fn attesting_before_the_card_says_to_wait_for_it() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    attest_form(&mut rt, &id, true);

    act(&mut rt, VettingAction::Submit).await;

    assert_eq!(
        status(&rt),
        &Status::warning("You can attest once their card has arrived.")
    );
}

#[tokio::test]
async fn attesting_while_busy_signs_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    card_received(&mut rt, &id, "did:key:zVetter");
    attest_form(&mut rt, &id, true);
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert_busy_refusal(&rt);
    assert_eq!(issued(&rt), 0);
    assert!(matches!(
        desk_state(&rt, &id),
        DeskState::CardReceived { .. }
    ));
    assert!(matches!(page(&rt).mode, VettingMode::Attest { .. }));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn attesting_without_keys_signs_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    card_received(&mut rt, &id, "did:key:zVetter");
    attest_form(&mut rt, &id, true);

    act(&mut rt, VettingAction::Submit).await;

    assert_abandoned(&rt, "Could not sign the statement");
    assert_eq!(issued(&rt), 0);
    assert!(matches!(
        desk_state(&rt, &id),
        DeskState::CardReceived { .. }
    ));
    assert!(matches!(page(&rt).mode, VettingMode::Attest { .. }));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn a_statement_that_does_not_verify_is_not_recorded() {
    let (mut rt, _h) = runtime().await;
    // Signed with a key, but under a DID that resolves to no document.
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    card_received(&mut rt, &id, "did:key:zVetter");
    attest_form(&mut rt, &id, true);

    act(&mut rt, VettingAction::Submit).await;

    assert_abandoned(&rt, "The statement did not verify");
    assert_eq!(issued(&rt), 0);
    assert!(matches!(
        desk_state(&rt, &id),
        DeskState::CardReceived { .. }
    ));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn attesting_records_saves_and_sends_the_statement_and_a_failed_send_unissues_it() {
    let (mut rt, _h) = runtime().await;
    let (persona, did) = fixtures::persona_with_did_key(&mut rt).await;
    let id = desk_request(&mut rt, persona);
    card_received(&mut rt, &id, &did);
    attest_form(&mut rt, &id, true);

    act(&mut rt, VettingAction::Submit).await;

    assert!(busy(&rt));
    assert_eq!(issued(&rt), 1);
    assert!(matches!(desk_state(&rt, &id), DeskState::Attested { .. }));
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(status(&rt), &Status::success("Sending your statement…"));
    assert!(rt.save.is_pending());

    settle(&mut rt).await;
    assert!(!busy(&rt));
    assert_eq!(issued(&rt), 0);
    assert!(matches!(
        desk_state(&rt, &id),
        DeskState::CardReceived { .. }
    ));
    assert!(
        status(&rt)
            .text
            .starts_with("Could not send the statement, so it was not issued: "),
        "{}",
        status(&rt).text
    );
}

// ---- decline ----

fn decline_form(rt: &mut Runtime, request_id: &str, message: &str) {
    rt.state.main_page.content_panel.vetting.mode = VettingMode::ConfirmDecline {
        request_id: request_id.into(),
        reason_index: 1,
        message: message.into(),
        field: 0,
    };
}

#[tokio::test]
async fn a_decline_note_too_long_is_refused() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    let max = crate::state_handler::main_page::content::DECLINE_MESSAGE_MAX;
    decline_form(&mut rt, &id, &"x".repeat(max + 1));

    act(&mut rt, VettingAction::Submit).await;

    assert_eq!(
        status(&rt),
        &Status::warning(format!(
            "The note is {} characters; a decline carries at most {max}.",
            max + 1
        ))
    );
    assert!(matches!(desk_state(&rt, &id), DeskState::Accepted));
}

#[tokio::test]
async fn declining_while_busy_declines_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    decline_form(&mut rt, &id, "  not today ");
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert_busy_refusal(&rt);
    assert!(matches!(desk_state(&rt, &id), DeskState::Accepted));
    assert!(matches!(page(&rt).mode, VettingMode::ConfirmDecline { .. }));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn declining_without_keys_is_saved_then_put_back() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    decline_form(&mut rt, &id, "");

    act(&mut rt, VettingAction::Submit).await;

    assert_abandoned(&rt, "Could not send the decline");
    assert!(matches!(desk_state(&rt, &id), DeskState::Accepted));
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert!(rt.save.is_pending(), "saved declined before the signing");
    assert!(
        log_line(&rt, "Declining…") < log_line(&rt, "Could not send the decline"),
        "saved and said, then given up"
    );
}

#[tokio::test]
async fn declining_saves_and_sends_and_a_failed_send_reopens_the_request() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    decline_form(&mut rt, &id, "not today");

    act(&mut rt, VettingAction::Submit).await;

    assert!(busy(&rt));
    assert!(matches!(desk_state(&rt, &id), DeskState::Declined { .. }));
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(status(&rt), &Status::success("Declining…"));
    assert!(rt.save.is_pending());

    settle(&mut rt).await;
    assert!(!busy(&rt));
    assert!(matches!(desk_state(&rt, &id), DeskState::Accepted));
    assert!(
        status(&rt).text.starts_with("Could not send the decline: "),
        "{}",
        status(&rt).text
    );
}

// ---- withdraw ----

/// A statement `persona` signed about [`APPLICANT`], on record. Returns its id.
fn issued_statement(rt: &mut Runtime, persona: PersonaId) -> String {
    let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    rt.config
        .private
        .vetting
        .issued
        .push(openvtc_core::vetting::vetter::IssuedStatement {
            id: id.clone(),
            digest_multibase: "zQmStatementDigest".into(),
            applicant: APPLICANT.into(),
            community: VTC.into(),
            persona,
            method: vta_sdk::protocols::vetting::VettingMethod::InPerson,
            issued_at: now,
            valid_until: now + chrono::Duration::days(365),
            withdrawal: None,
        });
    rt.state.main_page.sync_from_config(&rt.config);
    rt.state.main_page.content_panel.vetting.mode = VettingMode::Withdraw {
        statement_id: id.clone(),
        reason_index: 0,
    };
    id
}

fn withdrawn(rt: &Runtime, statement_id: &str) -> bool {
    rt.config
        .private
        .vetting
        .issued
        .iter()
        .find(|s| s.id == statement_id)
        .expect("on record")
        .withdrawal
        .is_some()
}

#[tokio::test]
async fn withdrawing_as_a_persona_not_held_says_so() {
    let (mut rt, _h) = runtime().await;
    let id = issued_statement(&mut rt, PersonaId::new());

    act(&mut rt, VettingAction::Submit).await;

    assert_eq!(
        status(&rt),
        &Status::error("The persona that signed this statement is not available.")
    );
    assert!(!withdrawn(&rt, &id));
}

#[tokio::test]
async fn withdrawing_while_busy_withdraws_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let id = issued_statement(&mut rt, persona);
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert_busy_refusal(&rt);
    assert!(!withdrawn(&rt, &id));
    assert!(matches!(page(&rt).mode, VettingMode::Withdraw { .. }));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn withdrawing_without_keys_is_saved_then_put_back() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
    let id = issued_statement(&mut rt, persona);

    act(&mut rt, VettingAction::Submit).await;

    assert_abandoned(&rt, "Could not send the withdrawal");
    assert!(!withdrawn(&rt, &id));
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert!(rt.save.is_pending());
    assert!(
        log_line(&rt, "Telling the community…") < log_line(&rt, "Could not send the withdrawal"),
        "saved and said, then given up"
    );
}

#[tokio::test]
async fn withdrawing_saves_and_sends_and_a_failed_send_puts_it_back() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let id = issued_statement(&mut rt, persona);

    act(&mut rt, VettingAction::Submit).await;

    assert!(busy(&rt));
    assert!(withdrawn(&rt, &id));
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(status(&rt), &Status::success("Telling the community…"));
    assert!(rt.save.is_pending());

    settle(&mut rt).await;
    assert!(!busy(&rt));
    assert!(!withdrawn(&rt, &id));
    assert!(
        status(&rt)
            .text
            .starts_with("Could not send the withdrawal: "),
        "{}",
        status(&rt).text
    );
}

// ---- the vetter side: how each community vets, and the key it bound ----

/// A live vetter grant from [`VTC`] for `persona`.
fn vetter_grant(rt: &mut Runtime, persona: PersonaId) {
    let now = chrono::Utc::now();
    rt.config
        .private
        .vetting
        .vetter_grants
        .push(openvtc_core::vetting::book::VetterGrant {
            community: VTC.into(),
            persona,
            credential_id: None,
            valid_until: Some(now + chrono::Duration::days(90)),
            received_at: now,
            credential: serde_json::json!({}),
        });
    rt.state.main_page.sync_from_config(&rt.config);
}

fn manifests_asked(rt: &Runtime) -> usize {
    rt.config
        .private
        .vetting
        .queries
        .iter()
        .filter(|q| q.kind == QueryKind::Manifest)
        .count()
}

#[tokio::test]
async fn opening_the_desk_asks_each_stale_community_how_it_vets() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    vetter_grant(&mut rt, persona);
    rt.config.private.vetting.vetter_refresh_failures = 2;

    act(&mut rt, VettingAction::SwitchTab).await;

    assert_eq!(page(&rt).tab, VettingTab::Desk);
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(manifests_asked(&rt), 1);
    let book = &rt.config.private.vetting;
    assert!(book.manifest_recently_asked(VTC, chrono::Utc::now()));
    assert_eq!(
        book.vetter_refresh_failures, 0,
        "a send that went resets the count"
    );
    assert!(!book.vetter_refresh_due);
    assert!(!busy(&rt), "asked on the client's own: nothing held");
    assert!(page(&rt).status_message.is_none());
    assert!(!rt.save.is_pending());

    settle_unclaimed(&mut rt).await;
    assert_eq!(manifests_asked(&rt), 1);
    assert!(
        status(&rt)
            .text
            .starts_with(&format!("Could not yet ask {VTC} what it requires (")),
        "{}",
        status(&rt).text
    );
}

#[tokio::test]
async fn opening_the_desk_without_keys_counts_the_failed_ask_and_asks_again_soon() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
    vetter_grant(&mut rt, persona);

    act(&mut rt, VettingAction::SwitchTab).await;

    assert_eq!(page(&rt).tab, VettingTab::Desk);
    assert_eq!(manifests_asked(&rt), 0);
    let book = &rt.config.private.vetting;
    assert!(
        !book.manifest_recently_asked(VTC, chrono::Utc::now()),
        "an unsent question holds nothing back"
    );
    assert_eq!(book.vetter_refresh_failures, 1);
    assert!(book.vetter_refresh_due);
    assert!(page(&rt).status_message.is_none());
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn a_community_vetted_for_as_two_personas_is_asked_once() {
    let (mut rt, _h) = runtime().await;
    let first = fixtures::persona_with_keys(&mut rt, "did:key:zVetterOne").await;
    let second = fixtures::persona_with_keys(&mut rt, "did:key:zVetterTwo").await;
    vetter_grant(&mut rt, first);
    vetter_grant(&mut rt, second);

    act(&mut rt, VettingAction::SwitchTab).await;

    assert_eq!(
        manifests_asked(&rt),
        1,
        "the second sees the first's question"
    );
}

#[tokio::test]
async fn a_community_vetted_for_as_two_personas_without_keys_is_tried_as_each() {
    let (mut rt, _h) = runtime().await;
    let first = fixtures::persona_with_keys(&mut rt, "did:key:zVetterOne").await;
    let second = fixtures::persona_with_keys(&mut rt, "did:key:zVetterTwo").await;
    rt.config.key_info.clear();
    vetter_grant(&mut rt, first);
    vetter_grant(&mut rt, second);

    act(&mut rt, VettingAction::SwitchTab).await;

    // The first failing to send releases the second: each attempt counts.
    assert_eq!(manifests_asked(&rt), 0);
    assert_eq!(rt.config.private.vetting.vetter_refresh_failures, 2);
}

#[tokio::test]
async fn leaving_the_desk_asks_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    vetter_grant(&mut rt, persona);
    rt.state.main_page.content_panel.vetting.tab = VettingTab::Desk;
    rt.state.main_page.content_panel.vetting.selected = 2;

    act(&mut rt, VettingAction::SwitchTab).await;

    assert_ne!(page(&rt).tab, VettingTab::Desk);
    assert_eq!(page(&rt).selected, 0);
    assert_eq!(manifests_asked(&rt), 0);
}

/// An engine for [`VTC`] whose last word from the community was
/// `identifierRebound`, with no key check yet.
fn rebound_engine(rt: &mut Runtime, persona: PersonaId) {
    use openvtc_core::vetting::book::{HiddenRefusal, HiddenVetterState};
    let params = openvtc_core::vetting::hidden::HiddenParams {
        suite: openvtc_core::vetting::hidden::SUITE.into(),
        helper_key: "zHelper".into(),
        token_key: "zToken".into(),
        vetter_labels: vec!["vetter/2026-10".into()],
        token_labels: vec!["token/2026-10".into()],
        drip_per_tick: 10,
        events: Vec::new(),
        tick_length: None,
    };
    let mut held = HiddenVetterState::new(VTC, persona, params);
    held.last_refusal = Some(HiddenRefusal {
        what: "your hidden-vetting credential".into(),
        code: "vtc/vetting/vetters/pcs-root:identifierRebound".into(),
        at: chrono::Utc::now(),
    });
    rt.config.private.vetting.hidden_vetter.push(held);
}

fn key_check_started(rt: &Runtime) -> bool {
    rt.config.private.vetting.hidden_vetter[0].key.is_some()
}

#[tokio::test]
async fn refreshing_the_vetter_side_asks_which_key_a_rebound_community_holds() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    rebound_engine(&mut rt, persona);

    act(&mut rt, VettingAction::RefreshVetterSide).await;

    assert!(key_check_started(&rt));
    assert!(asked(&rt, QueryKind::PcsBinding));
    assert!(
        !rt.config.private.vetting.hidden_vetter[0].binding_read_due(chrono::Utc::now()),
        "asked: not again until the re-ask interval"
    );
    assert!(rt.save.is_pending());
    assert!(!busy(&rt));
}

#[tokio::test]
async fn a_binding_question_without_keys_says_so_and_stays_asked() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
    rebound_engine(&mut rt, persona);

    act(&mut rt, VettingAction::RefreshVetterSide).await;

    assert!(key_check_started(&rt));
    // Filed and marked asked before the signing failed, and left so.
    assert!(asked(&rt, QueryKind::PcsBinding));
    assert!(rt.save.is_pending());
    let s = status(&rt);
    assert_eq!(s.severity, Severity::Error);
    assert!(
        s.text.starts_with("Could not ask ")
            && s.text
                .contains(" which hidden-vetting key it holds for you: "),
        "{}",
        s.text
    );
    assert!(!logged(
        &rt.state,
        "which hidden-vetting key it holds for you"
    ));
}

// ============================================================================
// Tickets
// ============================================================================

fn ticket(rt: &mut Runtime, persona: PersonaId) -> Ticket {
    let ticket = Ticket::issue(
        VTC,
        persona,
        vec![],
        1,
        DEFAULT_VALIDITY,
        chrono::Utc::now(),
    );
    rt.config.private.vetting.tickets.push(ticket.clone());
    rt.state.main_page.sync_from_config(&rt.config);
    ticket
}

#[tokio::test]
async fn deleting_a_ticket_already_gone_says_so() {
    let (mut rt, _h) = runtime().await;
    rt.state.main_page.content_panel.vetting.mode = VettingMode::ConfirmDeleteTicket {
        ticket_id: "gone".into(),
    };

    act(&mut rt, VettingAction::Submit).await;

    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(
        status(&rt),
        &Status::warning("That ticket is already gone.")
    );
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn deleting_a_ticket_removes_and_saves_it() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    let t = ticket(&mut rt, persona);
    rt.state.main_page.content_panel.vetting.selected = 3;
    rt.state.main_page.content_panel.vetting.mode = VettingMode::ConfirmDeleteTicket {
        ticket_id: t.id.clone(),
    };
    // Deleting needs no free domain.
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert!(rt.config.private.vetting.tickets.is_empty());
    assert!(page(&rt).tickets.is_empty(), "the page shows it gone");
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(page(&rt).selected, 0);
    assert!(rt.save.is_pending());
    assert_eq!(
        status(&rt),
        &Status::success(format!(
            "Ticket {} deleted — anyone already holding it is now refused, and they are not \
             told why.",
            t.code
        ))
    );
}

/// The new-ticket form open on [`VTC`], as `persona`.
fn new_ticket_form(rt: &mut Runtime, persona: PersonaId) {
    let v = &mut rt.state.main_page.content_panel.vetting;
    v.memberships = vec![membership(persona)].into();
    v.mode = VettingMode::NewTicket {
        membership_index: 0,
        uses_index: 0,
        field: 0,
    };
}

fn mode_failed(rt: &Runtime) -> bool {
    rt.config
        .private
        .vetting
        .vetter_mode(VTC)
        .failed_since(chrono::Utc::now() - chrono::Duration::minutes(1))
        .is_some()
}

#[tokio::test]
async fn a_ticket_while_another_waits_on_its_answer_says_so() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    new_ticket_form(&mut rt, persona);
    rt.state.main_page.content_panel.vetting.pending_ticket =
        Some(crate::state_handler::main_page::content::PendingTicket {
            membership: membership(persona),
            uses: 1,
            asked_at: chrono::Utc::now(),
        });

    act(&mut rt, VettingAction::Submit).await;

    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(
        status(&rt),
        &Status::progress("Still asking VTC how it vets, for the last ticket — a moment.")
    );
    assert_eq!(manifests_asked(&rt), 0);
}

#[tokio::test]
async fn a_ticket_as_a_persona_not_held_is_refused() {
    let (mut rt, _h) = runtime().await;
    new_ticket_form(&mut rt, PersonaId::new());

    act(&mut rt, VettingAction::Submit).await;

    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(
        status(&rt),
        &Status::error(
            "No ticket issued: the persona you vet for that community as is not available."
        )
    );
}

#[tokio::test]
async fn a_ticket_while_busy_asks_nothing() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    new_ticket_form(&mut rt, persona);
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::Submit).await;

    assert_busy_refusal(&rt);
    // The form is closed before the busy check.
    assert!(matches!(page(&rt).mode, VettingMode::List));
    assert_eq!(manifests_asked(&rt), 0);
    assert!(
        !rt.config
            .private
            .vetting
            .manifest_recently_asked(VTC, chrono::Utc::now())
    );
    assert!(page(&rt).pending_ticket.is_none());
}

#[tokio::test]
async fn a_ticket_without_keys_says_its_community_could_not_be_read() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
    new_ticket_form(&mut rt, persona);

    act(&mut rt, VettingAction::Submit).await;

    let s = status(&rt);
    assert_eq!(s.severity, Severity::Error);
    assert!(
        s.text
            .starts_with("No ticket issued: could not confirm how VTC vets now — "),
        "{}",
        s.text
    );
    assert!(logged(&rt.state, "No ticket issued: could not confirm"));
    assert!(mode_failed(&rt));
    assert!(page(&rt).pending_ticket.is_none());
    assert_eq!(manifests_asked(&rt), 0);
    assert!(!busy(&rt));
    assert!(!rt.save.is_pending());
}

#[tokio::test]
async fn a_ticket_asks_its_community_how_it_vets_and_waits() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    new_ticket_form(&mut rt, persona);

    act(&mut rt, VettingAction::Submit).await;

    assert!(busy(&rt));
    assert_eq!(manifests_asked(&rt), 1);
    let pending = page(&rt).pending_ticket.as_ref().expect("the ticket waits");
    assert_eq!(pending.membership.community, VTC);
    assert_eq!(pending.uses, 1);
    assert_eq!(
        status(&rt),
        &Status::progress(
            "Asking VTC how it vets now — named vetting or PCS ZKP — before issuing the ticket…"
        )
    );
    assert!(rt.config.private.vetting.tickets.is_empty());
    assert!(!rt.save.is_pending());

    settle(&mut rt).await;
    assert!(!busy(&rt));
    assert!(mode_failed(&rt));
}
