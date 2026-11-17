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

// The challenge and the vetter pass follow a refresh whatever became of it:
// refused while busy, given up at the key lookup, or with no application
// selected at all.

#[tokio::test]
async fn refreshing_requirements_while_busy_still_runs_the_vetter_pass() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
    application(&mut rt, persona);
    rebound_engine(&mut rt, persona);
    assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

    act(&mut rt, VettingAction::RefreshRequirements).await;

    assert!(!asked(&rt, QueryKind::Manifest), "the refresh was refused");
    assert!(key_check_started(&rt), "the vetter pass ran after it");
    assert!(asked(&rt, QueryKind::PcsBinding));
    assert!(busy(&rt), "the other job still holds the domain");
}

#[tokio::test]
async fn refreshing_requirements_without_keys_still_runs_the_vetter_pass() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zApplicant").await;
    application(&mut rt, persona);
    rebound_engine(&mut rt, persona);

    act(&mut rt, VettingAction::RefreshRequirements).await;

    assert!(!asked(&rt, QueryKind::Manifest));
    assert!(
        key_check_started(&rt),
        "the vetter pass ran after the give-up"
    );
    assert!(
        log_line(&rt, "Could not ask the community")
            < log_line(&rt, "which hidden-vetting key it holds for you"),
        "the refresh gives up before the pass runs"
    );
    assert!(!asked(&rt, QueryKind::PcsBinding));
}

#[tokio::test]
async fn refreshing_requirements_with_no_application_runs_the_vetter_pass() {
    let (mut rt, _h) = runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
    rebound_engine(&mut rt, persona);

    act(&mut rt, VettingAction::RefreshRequirements).await;

    assert!(!asked(&rt, QueryKind::Manifest));
    assert!(key_check_started(&rt));
    assert!(asked(&rt, QueryKind::PcsBinding));
    assert!(!busy(&rt), "the pass asks on the client's own");
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
async fn starting_an_application_while_busy_saves_it_and_says_its_requirements_wait() {
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
    // The refresh that follows waits on the busy domain, and the status says
    // both: the application started, and why its requirements wait.
    let s = status(&rt);
    assert_eq!(s.severity, Severity::Warning);
    assert!(s.text.starts_with("Application started."), "{}", s.text);
    assert!(
        s.text
            .contains(&InFlight::busy_message(DispatchDomain::Vetting)),
        "{}",
        s.text
    );
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
// Faces and the card
// ============================================================================
//
// The face and card jobs run against the VTA session. The harness gives it
// one at a closed local port, so a job fails off the loop at once — the
// failure path whose outcome is then applied.

mod faces {
    use chrono::Utc;
    use openvtc_core::vetting::applicant::{OpenSession, OutboundRequest, RequestState};
    use vta_sdk::protocols::vetting::VettingMethod;

    use super::*;
    use crate::state_handler::main_page::content::{CardPreview, FaceChoice, NewFaceForm, PoolRow};

    const NO_VTA: &str = "Faces live in your VTA, and it is not connected — try again once it is.";
    const SESSION: &str = "session-1";

    fn connect(rt: &mut Runtime) {
        rt.admin_vta = Some(vta_sdk::client::VtaClient::new("http://127.0.0.1:1"));
    }

    fn context_of(rt: &Runtime, id: &str) -> Option<String> {
        rt.config
            .private
            .vetting
            .application_by_id(id)
            .and_then(|a| a.context_id.clone())
    }

    fn face(name: &str, worn: bool) -> FaceChoice {
        FaceChoice {
            profile_id: format!("p-{name}"),
            name: name.into(),
            entries: 1,
            worn,
            claim_types: vec!["name.legal".into()],
        }
    }

    fn picker(rt: &mut Runtime, id: &str, faces: Vec<FaceChoice>, index: usize) {
        rt.state.main_page.content_panel.vetting.mode = VettingMode::ChooseFace {
            application_id: id.into(),
            faces,
            index,
            required: vec!["name.legal".into()],
        };
    }

    /// The make-a-face form over `pool`, asking for a legal name.
    fn new_face(rt: &mut Runtime, id: &str, pool: Vec<PoolRow>) {
        rt.state.main_page.content_panel.vetting.mode =
            VettingMode::NewFace(Box::new(NewFaceForm::open(
                id.into(),
                vec!["name.legal".into()],
                Vec::new(),
                pool,
                "Vetting".into(),
            )));
    }

    fn legal_name() -> PoolRow {
        PoolRow {
            attribute_id: "attr-name".into(),
            claim_type: "name.legal".into(),
            label: "Legal name".into(),
            value: Some("Alice Example".into()),
        }
    }

    fn form(rt: &Runtime) -> &NewFaceForm {
        match &page(rt).mode {
            VettingMode::NewFace(form) => form,
            _ => panic!("the form stays open"),
        }
    }

    /// An application with an open session from [`VETTER`], expiring at
    /// `expires_at`.
    fn with_session(
        rt: &mut Runtime,
        persona: PersonaId,
        expires_at: chrono::DateTime<Utc>,
    ) -> String {
        let id = application(rt, persona);
        let app = rt
            .config
            .private
            .vetting
            .application_by_id_mut(&id)
            .expect("the application");
        app.requests.push(OutboundRequest {
            document_id: "req-1".into(),
            vetter: VETTER.into(),
            state: RequestState::Session {
                request_id: "r-1".into(),
                session: Box::new(OpenSession {
                    id: SESSION.into(),
                    challenge: "challenge".into(),
                    domain: VTC.into(),
                    method: VettingMethod::Video,
                    required_claims: vec!["name.legal".into()],
                    optional_claims: Vec::new(),
                    expires_at,
                    match_code: "0000".into(),
                    document: None,
                }),
                card: None,
            },
            eligibility: None,
            grant_status: None,
            sent_at: Utc::now(),
            updated_at: Utc::now(),
        });
        id
    }

    fn card(rt: &mut Runtime, id: &str, preview: Option<CardPreview>) {
        rt.state.main_page.content_panel.vetting.mode = VettingMode::SendCard {
            application_id: id.into(),
            session_id: SESSION.into(),
            preview,
        };
    }

    fn previewed(problem: Option<&str>) -> CardPreview {
        CardPreview {
            preview_id: "01PREVIEW".into(),
            claims: vec![("name.legal".into(), "Alice Example".into())],
            problem: problem.map(ToString::to_string),
        }
    }

    fn later() -> chrono::DateTime<Utc> {
        Utc::now() + chrono::Duration::hours(1)
    }

    // ---- choose a face (list the faces) ----

    #[tokio::test]
    async fn choosing_a_face_with_no_vta_says_so_and_derives_nothing() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        rt.state.main_page.content_panel.vetting.card_after_face = Some(("x".into(), "y".into()));

        act(&mut rt, VettingAction::ChooseFace).await;

        assert_eq!(status(&rt), &Status::error(NO_VTA));
        assert_eq!(context_of(&rt, &id), None);
        assert!(
            page(&rt).card_after_face.is_none(),
            "from the list, no card"
        );
        assert!(!busy(&rt));
        assert!(!rt.save.is_pending());
    }

    #[tokio::test]
    async fn choosing_a_face_from_a_card_remembers_the_card_even_when_refused() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = with_session(&mut rt, persona, later());
        card(&mut rt, &id, None);

        act(&mut rt, VettingAction::ChooseFace).await;

        assert_eq!(status(&rt), &Status::error(NO_VTA));
        assert_eq!(page(&rt).card_after_face, Some((id, SESSION.into())));
        assert!(matches!(page(&rt).mode, VettingMode::SendCard { .. }));
    }

    #[tokio::test]
    async fn choosing_a_face_while_busy_keeps_no_context_and_reads_nothing() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

        act(&mut rt, VettingAction::ChooseFace).await;

        assert_busy_refusal(&rt);
        // Nothing is kept for a read that never started.
        assert!(context_of(&rt, &id).is_none());
        assert!(!rt.save.is_pending());
    }

    #[tokio::test]
    async fn choosing_a_face_reads_the_faces_and_a_failed_read_says_why() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);

        act(&mut rt, VettingAction::ChooseFace).await;

        assert!(busy(&rt));
        assert_eq!(status(&rt), &Status::progress("Reading your faces…"));
        assert!(context_of(&rt, &id).is_some());
        assert!(matches!(page(&rt).mode, VettingMode::List));
        assert!(rt.save.is_pending(), "the context kept is saved");

        settle(&mut rt).await;
        assert!(!busy(&rt));
        assert!(
            status(&rt).text.starts_with("Could not read your faces"),
            "{}",
            status(&rt).text
        );
        assert!(rt.save.is_pending(), "the derived context is saved");
    }

    // ---- make a new face (read the pool) ----

    #[tokio::test]
    async fn opening_a_new_face_with_no_vta_says_so() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        picker(&mut rt, &id, Vec::new(), 0);

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(status(&rt), &Status::error(NO_VTA));
        assert!(matches!(page(&rt).mode, VettingMode::ChooseFace { .. }));
        assert!(!busy(&rt));
    }

    #[tokio::test]
    async fn opening_a_new_face_while_busy_reads_nothing() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        picker(&mut rt, &id, Vec::new(), 0);
        assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

        act(&mut rt, VettingAction::Submit).await;

        assert_busy_refusal(&rt);
        assert!(matches!(page(&rt).mode, VettingMode::ChooseFace { .. }));
        assert_eq!(
            context_of(&rt, &id),
            None,
            "the pool read derives no context"
        );
    }

    #[tokio::test]
    async fn opening_a_new_face_reads_the_pool_and_a_failed_read_says_why() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        picker(&mut rt, &id, vec![face("Work", false)], 1);

        act(&mut rt, VettingAction::Submit).await;

        assert!(busy(&rt));
        assert_eq!(status(&rt), &Status::progress("Reading your attributes…"));
        assert!(matches!(page(&rt).mode, VettingMode::ChooseFace { .. }));
        assert!(!rt.save.is_pending());

        settle(&mut rt).await;
        assert!(!busy(&rt));
        assert!(
            status(&rt)
                .text
                .starts_with("Could not read your attributes"),
            "{}",
            status(&rt).text
        );
    }

    // ---- wear a face ----

    #[tokio::test]
    async fn wearing_no_face_says_to_make_one() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        // Past the "make one" row: there is no face at the index.
        picker(&mut rt, &id, Vec::new(), 3);

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(
            status(&rt),
            &Status::warning("Make a face under My Identity first.")
        );
        assert!(!busy(&rt));
    }

    #[tokio::test]
    async fn wearing_the_worn_face_goes_back_to_the_card() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        picker(&mut rt, &id, vec![face("Work", true)], 0);
        rt.state.main_page.content_panel.vetting.card_after_face =
            Some((id.clone(), SESSION.into()));

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(
            status(&rt),
            &Status::warning("Work is already the face you show vetters.")
        );
        assert!(matches!(
            &page(&rt).mode,
            VettingMode::SendCard { session_id, preview: None, .. } if session_id == SESSION
        ));
        assert!(page(&rt).card_after_face.is_none());
        assert_eq!(context_of(&rt, &id), None);
    }

    #[tokio::test]
    async fn wearing_a_face_with_no_vta_says_so() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        picker(&mut rt, &id, vec![face("Work", false)], 0);

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(status(&rt), &Status::error(NO_VTA));
        assert!(matches!(page(&rt).mode, VettingMode::ChooseFace { .. }));
        assert_eq!(context_of(&rt, &id), None);
    }

    #[tokio::test]
    async fn wearing_a_face_for_a_gone_application_cannot() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        picker(&mut rt, "gone", vec![face("Work", false)], 0);

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(
            status(&rt),
            &Status::error("Cannot wear that face: the application is gone")
        );
        assert!(matches!(page(&rt).mode, VettingMode::ChooseFace { .. }));
        assert!(!busy(&rt));
    }

    #[tokio::test]
    async fn wearing_a_face_while_busy_keeps_the_picker() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        picker(&mut rt, &id, vec![face("Work", false)], 0);
        assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

        act(&mut rt, VettingAction::Submit).await;

        assert_busy_refusal(&rt);
        assert!(matches!(page(&rt).mode, VettingMode::ChooseFace { .. }));
        // Nothing is kept for a job that never started.
        assert!(context_of(&rt, &id).is_none());
        assert!(!rt.save.is_pending());
    }

    #[tokio::test]
    async fn wearing_a_face_goes_to_the_list_and_a_failed_wear_says_why() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        picker(&mut rt, &id, vec![face("Work", false)], 0);

        act(&mut rt, VettingAction::Submit).await;

        assert!(busy(&rt));
        assert_eq!(status(&rt), &Status::progress("Wearing Work…"));
        assert!(matches!(page(&rt).mode, VettingMode::List));
        assert!(context_of(&rt, &id).is_some());
        assert!(rt.save.is_pending(), "the context kept is saved");

        settle(&mut rt).await;
        assert!(!busy(&rt));
        assert!(
            status(&rt).text.starts_with("Could not wear Work: "),
            "{}",
            status(&rt).text
        );
        assert!(rt.save.is_pending());
    }

    // ---- the make-a-face form ----

    #[tokio::test]
    async fn enter_on_an_empty_form_waits() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        new_face(&mut rt, &id, Vec::new());

        act(&mut rt, VettingAction::Submit).await;

        assert!(form(&rt).saving.is_none());
        assert!(page(&rt).status_message.is_none());
        assert!(!busy(&rt));
    }

    #[tokio::test]
    async fn saving_a_typed_value_with_no_vta_keeps_the_form_not_saving() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        new_face(&mut rt, &id, Vec::new());
        act(&mut rt, VettingAction::Input("Alice Example".into())).await;

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(status(&rt), &Status::error(NO_VTA));
        assert!(form(&rt).saving.is_none());
        assert_eq!(form(&rt).draft("name.legal"), "Alice Example");
        assert!(!busy(&rt));
    }

    #[tokio::test]
    async fn saving_a_typed_value_while_busy_keeps_the_form_not_saving() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        new_face(&mut rt, &id, Vec::new());
        act(&mut rt, VettingAction::Input("Alice Example".into())).await;
        assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

        act(&mut rt, VettingAction::Submit).await;

        assert_busy_refusal(&rt);
        assert!(form(&rt).saving.is_none());
        assert_eq!(form(&rt).draft("name.legal"), "Alice Example");
    }

    #[tokio::test]
    async fn saving_a_typed_value_waits_on_the_write_and_a_failed_write_says_why() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        new_face(&mut rt, &id, Vec::new());
        act(&mut rt, VettingAction::Input("Alice Example".into())).await;

        act(&mut rt, VettingAction::Submit).await;

        assert!(busy(&rt));
        assert_eq!(form(&rt).saving.as_deref(), Some("name.legal"));
        assert!(page(&rt).status_message.is_none(), "the form says it");
        assert_eq!(context_of(&rt, &id), None);

        settle(&mut rt).await;
        assert!(!busy(&rt));
        assert!(form(&rt).saving.is_none());
        assert!(
            form(&rt)
                .error
                .as_deref()
                .is_some_and(|e| e.starts_with("Could not save it: ")),
            "{:?}",
            form(&rt).error
        );
        assert!(status(&rt).text.starts_with("Could not save your "));
    }

    #[tokio::test]
    async fn making_a_face_with_no_vta_says_so_and_keeps_the_form() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        new_face(&mut rt, &id, vec![legal_name()]);

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(status(&rt), &Status::error(NO_VTA));
        assert!(matches!(page(&rt).mode, VettingMode::NewFace(_)));
        assert_eq!(context_of(&rt, &id), None);
    }

    #[tokio::test]
    async fn making_a_face_while_busy_keeps_the_form() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        new_face(&mut rt, &id, vec![legal_name()]);
        assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

        act(&mut rt, VettingAction::Submit).await;

        assert_busy_refusal(&rt);
        assert!(matches!(page(&rt).mode, VettingMode::NewFace(_)));
        // Nothing is kept for a job that never started.
        assert!(context_of(&rt, &id).is_none());
        assert!(!rt.save.is_pending());
    }

    #[tokio::test]
    async fn making_a_face_goes_to_the_list_and_a_failed_make_says_why() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        new_face(&mut rt, &id, vec![legal_name()]);

        act(&mut rt, VettingAction::Submit).await;

        assert!(busy(&rt));
        assert_eq!(status(&rt), &Status::progress("Making Vetting…"));
        assert!(matches!(page(&rt).mode, VettingMode::List));
        assert!(context_of(&rt, &id).is_some());

        settle(&mut rt).await;
        assert!(!busy(&rt));
        assert!(
            status(&rt).text.starts_with("Could not wear Vetting: "),
            "{}",
            status(&rt).text
        );
    }

    // ---- send the card ----

    #[tokio::test]
    async fn a_card_for_a_gone_application_does_nothing() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        card(&mut rt, "gone", None);

        act(&mut rt, VettingAction::Submit).await;

        assert!(page(&rt).status_message.is_none());
        assert!(!busy(&rt));
    }

    #[tokio::test]
    async fn a_card_for_a_closed_session_says_so() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        card(&mut rt, &id, None);

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(status(&rt), &Status::warning("That session has closed."));
        assert_eq!(context_of(&rt, &id), None);
    }

    #[tokio::test]
    async fn a_card_for_an_expired_session_says_so() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = with_session(&mut rt, persona, Utc::now() - chrono::Duration::minutes(1));
        card(&mut rt, &id, None);

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(
            status(&rt),
            &Status::warning("The session has expired — ask the vetter to open another.")
        );
    }

    #[tokio::test]
    async fn a_card_the_face_cannot_make_says_why() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = with_session(&mut rt, persona, later());
        card(&mut rt, &id, Some(previewed(Some("no legal name"))));

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(status(&rt), &Status::warning("no legal name"));
        assert!(!busy(&rt));
    }

    #[tokio::test]
    async fn a_card_with_no_vta_says_so() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = with_session(&mut rt, persona, later());
        card(&mut rt, &id, None);

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(status(&rt), &Status::error(NO_VTA));
        assert_eq!(context_of(&rt, &id), None);
    }

    #[tokio::test]
    async fn a_card_while_busy_keeps_no_context_and_sends_nothing() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = with_session(&mut rt, persona, later());
        card(&mut rt, &id, Some(previewed(None)));
        assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

        act(&mut rt, VettingAction::Submit).await;

        assert_busy_refusal(&rt);
        // Nothing is kept for a job that never started.
        assert!(context_of(&rt, &id).is_none());
        assert!(matches!(
            page(&rt).mode,
            VettingMode::SendCard {
                preview: Some(_),
                ..
            }
        ));
        assert!(!rt.save.is_pending());
    }

    #[tokio::test]
    async fn previewing_a_card_asks_the_vta_and_a_failed_preview_says_why() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = with_session(&mut rt, persona, later());
        card(&mut rt, &id, None);

        act(&mut rt, VettingAction::Submit).await;

        assert!(busy(&rt));
        assert_eq!(
            status(&rt),
            &Status::progress("Asking your VTA what your face shows this vetter…")
        );
        assert!(context_of(&rt, &id).is_some());
        assert!(rt.save.is_pending(), "the context kept is saved");

        settle(&mut rt).await;
        assert!(!busy(&rt));
        assert!(
            status(&rt).text.starts_with("Could not preview the card: "),
            "{}",
            status(&rt).text
        );
    }

    #[tokio::test]
    async fn sending_a_card_without_keys_gives_up_unsent() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = persona_without_keys(&mut rt, "did:key:zApplicant").await;
        let id = with_session(&mut rt, persona, later());
        card(&mut rt, &id, Some(previewed(None)));

        act(&mut rt, VettingAction::Submit).await;

        assert_abandoned(&rt, "Could not sign the card");
        // The context derived for the card is taken back with it.
        assert!(context_of(&rt, &id).is_none());
        assert!(!rt.save.is_pending());
    }

    #[tokio::test]
    async fn sending_a_card_releases_it_and_a_failed_send_previews_again() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = with_session(&mut rt, persona, later());
        card(&mut rt, &id, Some(previewed(None)));

        act(&mut rt, VettingAction::Submit).await;

        assert!(busy(&rt));
        assert_eq!(
            status(&rt),
            &Status::progress("Releasing and signing your card…")
        );
        assert!(context_of(&rt, &id).is_some());
        assert!(rt.save.is_pending(), "the context kept is saved");

        settle(&mut rt).await;
        assert!(!busy(&rt));
        assert!(
            status(&rt).text.starts_with("Could not send the card: "),
            "{}",
            status(&rt).text
        );
        assert!(matches!(
            page(&rt).mode,
            VettingMode::SendCard { preview: None, .. }
        ));
    }
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
    // Not marked as asked, since nothing went: the next Enter asks again
    // rather than opening the session without the requirements.
    assert!(page(&rt).requirements_requested.is_empty());
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
async fn opening_a_session_without_keys_puts_the_request_back() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
    let id = desk_request(&mut rt, persona);
    requirements_asked(&mut rt);
    open_session_form(&mut rt, &id);

    act(&mut rt, VettingAction::Submit).await;

    assert_abandoned(&rt, "Could not send the session");
    // The session the book opened before the signing is undone: the request
    // stands where it stood, as on disk, and nothing is saved.
    assert!(matches!(desk_state(&rt, &id), DeskState::Accepted));
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
async fn a_binding_question_without_keys_says_so_and_is_unfiled() {
    let (mut rt, _h) = runtime().await;
    let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
    rebound_engine(&mut rt, persona);

    act(&mut rt, VettingAction::RefreshVetterSide).await;

    assert!(key_check_started(&rt));
    // Filed before the signing and un-filed when it fails; the check keeps
    // the time it was asked, so it is not asked again before the re-ask
    // interval.
    assert!(!asked(&rt, QueryKind::PcsBinding));
    assert!(!rt.config.private.vetting.hidden_vetter[0].binding_read_due(chrono::Utc::now()));
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
    // Logged as well as said, so it outlives the status line (R6.5).
    assert!(logged(
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

// ============================================================================
// Hidden vetting
// ============================================================================
//
// What the client does on its own for PCS ZKP vetting: the challenge an
// applicant asks for, the vetter schedule's pass, the key check and the draw
// asked for by hand, and what the VTA's answers lead to. The sends here are
// the client's (`Claim::Unheld`): none is refused while a person's send holds
// the vetting domain, and none claims it.
//
// Not reached offline: a job at the VTA (the harness holds no admin VTA
// session, so no PCS job ever starts), and attesting the hidden way from the
// desk, which needs a received card carrying the applicant's PCS identifier.
// The plan's own unit tests pin those.

mod hidden {
    use super::*;
    use crate::state_handler::hidden_vetting_vta::{PcsDone, PcsOutcome, PcsWork};
    use openvtc_core::vetting::book::{HiddenRefusal, HiddenVetterState, PcsInbound, VetterGrant};
    use openvtc_core::vetting::hidden::{Due, HiddenParams, SUITE};
    use openvtc_core::vetting::pcs_vta::PcsError;
    use openvtc_core::vetting::wire::pcs::{RootRequest, TokensRequest};

    fn params() -> HiddenParams {
        HiddenParams {
            suite: SUITE.into(),
            helper_key: "zHelper".into(),
            token_key: "zToken".into(),
            vetter_labels: vec!["vetter/2026-10".into()],
            token_labels: vec!["token/2026-10".into()],
            drip_per_tick: 10,
            events: Vec::new(),
            tick_length: None,
        }
    }

    /// A hidden-vetting application to [`VTC`] as `persona`, selected.
    fn hidden_application(rt: &mut Runtime, persona: PersonaId) -> String {
        let id = application(rt, persona);
        rt.config
            .private
            .vetting
            .application_by_id_mut(&id)
            .unwrap()
            .hidden = Some(params());
        id
    }

    /// An engine held for [`VTC`] as `persona`, shown on the page.
    fn engine(rt: &mut Runtime, persona: PersonaId) {
        rt.config
            .private
            .vetting
            .hidden_vetter
            .push(HiddenVetterState::new(VTC, persona, params()));
        rt.state.main_page.sync_from_config(&rt.config);
    }

    /// A live vetter grant from [`VTC`] for `persona`.
    fn grant(rt: &mut Runtime, persona: PersonaId) {
        let now = chrono::Utc::now();
        rt.config.private.vetting.vetter_grants.push(VetterGrant {
            community: VTC.into(),
            persona,
            credential_id: None,
            valid_until: Some(now + chrono::Duration::days(90)),
            received_at: now,
            credential: serde_json::Value::Null,
        });
    }

    /// The next background job's outcome, which must be one the client
    /// started on its own (it holds no domain), applied as the loop would.
    async fn settle_unheld(rt: &mut Runtime) {
        let outcome = tokio::time::timeout(Duration::from_secs(30), rt.dispatch_rx.recv())
            .await
            .expect("the send reports back")
            .expect("the channel is open");
        assert!(!outcome.claimed(), "the client's own send holds nothing");
        rt.on_dispatch_outcome(outcome).await;
    }

    /// A PCS job's answers arrive at the loop.
    async fn answered(
        rt: &mut Runtime,
        inbox_taken: usize,
        results: Vec<(PcsWork, Result<PcsDone, PcsError>)>,
    ) {
        rt.on_dispatch_outcome(background_dispatch::DispatchOutcome::HiddenVetting(
            Box::new(PcsOutcome {
                inbox_taken,
                results,
            }),
        ))
        .await;
    }

    fn owed(persona: PersonaId, due: Due) -> PcsWork {
        PcsWork::Owed {
            community: VTC.into(),
            persona,
            context_id: "openvtc/ctx".into(),
            did: "did:key:zVetter".into(),
            params: params(),
            owed: due,
        }
    }

    fn enrol() -> Due {
        Due::Enrol {
            period: "2026-10".into(),
        }
    }

    fn draw() -> Due {
        Due::Draw {
            label: "token/2026-10".into(),
            tick: 3,
            rate: 10,
        }
    }

    fn root() -> PcsDone {
        PcsDone::Root(RootRequest {
            label: "vetter/2026-10".into(),
            id: "z3Vetter".into(),
            request: serde_json::json!({}),
        })
    }

    fn tokens() -> PcsDone {
        PcsDone::Tokens(TokensRequest {
            label: "token/2026-10".into(),
            tick: 3,
            requests: Vec::new(),
        })
    }

    fn refused() -> PcsError {
        PcsError::Refused {
            code: "vta/pcs:nope".into(),
            message: "no".into(),
        }
    }

    fn held(rt: &Runtime) -> &HiddenVetterState {
        &rt.config.private.vetting.hidden_vetter[0]
    }

    /// [`VTC`]'s manifest, read just now, said it hides its vetters.
    fn reads_as_hidden(rt: &mut Runtime) {
        use openvtc_core::vetting::book::KnownCommunity;
        use openvtc_core::vetting::mode::{ModeRead, VetterMode};
        let now = chrono::Utc::now();
        rt.config.private.vetting.communities.push(KnownCommunity {
            community: VTC.into(),
            branding: Default::default(),
            requested: Vec::new(),
            fetched_at: now,
            protocol: None,
            routes: Vec::new(),
            post_quantum_key: None,
            vetter_mode: Some(ModeRead {
                mode: VetterMode::PcsZkp,
                read_at: now,
            }),
            directory: None,
        });
    }

    fn rebound(rt: &mut Runtime) {
        rt.config.private.vetting.hidden_vetter[0].last_refusal = Some(HiddenRefusal {
            what: "enrol".into(),
            code: "vtc/pcs:identifierRebound".into(),
            at: chrono::Utc::now(),
        });
    }

    // ---- the submission challenge ----

    #[tokio::test]
    async fn a_challenge_without_keys_gives_up_and_unfiles_its_question() {
        let (mut rt, _h) = runtime().await;
        let persona = persona_without_keys(&mut rt, "did:key:zApplicant").await;
        hidden_application(&mut rt, persona);

        act(&mut rt, VettingAction::RefreshRequirements).await;

        assert_abandoned(&rt, "Could not ask for a submission challenge");
        assert!(
            log_line(&rt, "Could not ask the community")
                < log_line(&rt, "Could not ask for a submission challenge"),
            "the requirements are asked for first"
        );
        assert!(!asked(&rt, QueryKind::Manifest));
        // Filed before the signing and un-filed when it fails: nothing waits
        // on a question that never went.
        assert!(!asked(&rt, QueryKind::PcsChallenge));
        assert!(!rt.save.is_pending());
    }

    #[tokio::test]
    async fn a_challenge_asked_while_busy_leaves_the_busy_refusal_said() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        hidden_application(&mut rt, persona);
        assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

        act(&mut rt, VettingAction::RefreshRequirements).await;

        // The requirements are refused; the challenge is not, and asks
        // quietly so the refusal stays on the status line.
        assert!(!asked(&rt, QueryKind::Manifest));
        assert!(asked(&rt, QueryKind::PcsChallenge));
        assert_busy_refusal(&rt);
        assert!(!rt.save.is_pending());
        settle_unheld(&mut rt).await;
        assert!(busy(&rt), "the person's send still holds the domain");
    }

    #[tokio::test]
    async fn a_hidden_application_asks_for_its_requirements_then_a_challenge() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        hidden_application(&mut rt, persona);

        act(&mut rt, VettingAction::RefreshRequirements).await;

        assert!(busy(&rt), "the requirements claim the domain");
        assert!(asked(&rt, QueryKind::Manifest));
        assert!(asked(&rt, QueryKind::PcsChallenge));
        assert_eq!(
            status(&rt),
            &Status::progress("Asking the community for a submission challenge…")
        );
        assert!(!rt.save.is_pending());
        // Both sends fail off the loop: one held, one not.
        let mut claimed = Vec::new();
        for _ in 0..2 {
            let outcome = tokio::time::timeout(Duration::from_secs(30), rt.dispatch_rx.recv())
                .await
                .expect("the send reports back")
                .expect("the channel is open");
            claimed.push(outcome.claimed());
            rt.on_dispatch_outcome(outcome).await;
        }
        claimed.sort_unstable();
        assert_eq!(claimed, vec![false, true]);
        assert!(!busy(&rt));
        assert!(!asked(&rt, QueryKind::PcsChallenge));
    }

    // ---- the key check, drawing by hand, Enter on the view ----

    #[tokio::test]
    async fn checking_a_key_not_in_question_says_there_is_nothing_to_check() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);
        rt.state.main_page.content_panel.vetting.mode = VettingMode::HiddenVetting { index: 0 };

        act(&mut rt, VettingAction::CheckHiddenKey).await;

        assert_eq!(
            status(&rt),
            &Status::warning(format!(
                "Nothing to check at {VTC}: your hidden-vetting key is not in question, or a \
                 check is already running."
            ))
        );
        assert!(held(&rt).key.is_none());
        assert!(!rt.save.is_pending());
    }

    #[tokio::test]
    async fn checking_a_key_with_no_engine_does_nothing() {
        let (mut rt, _h) = runtime().await;
        rt.state.main_page.content_panel.vetting.mode = VettingMode::HiddenVetting { index: 2 };

        act(&mut rt, VettingAction::CheckHiddenKey).await;

        assert!(page(&rt).status_message.is_none());
        assert!(!rt.save.is_pending());
    }

    #[tokio::test]
    async fn checking_a_rebound_key_starts_the_check_and_runs_the_vetter_pass() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);
        rebound(&mut rt);
        rt.state.main_page.content_panel.vetting.mode = VettingMode::HiddenVetting { index: 0 };

        act(&mut rt, VettingAction::CheckHiddenKey).await;

        assert!(held(&rt).key.is_some(), "the check started");
        assert!(rt.save.is_pending());
        // The pass asks the community which key it bound us to.
        assert!(asked(&rt, QueryKind::PcsBinding));
        assert_eq!(
            status(&rt),
            &Status::progress(format!(
                "Asking {VTC} which hidden-vetting key it holds for you, to restore it at your \
                 VTA…"
            ))
        );
        assert!(!busy(&rt), "the pass claims nothing");
    }

    #[tokio::test]
    async fn drawing_with_no_hidden_community_says_there_are_no_tokens() {
        let (mut rt, _h) = runtime().await;

        act(&mut rt, VettingAction::DrawNow).await;

        assert_eq!(
            status(&rt),
            &Status::info(
                "None of the communities you vet for proves vetting with PCS ZKP, so there are \
                 no tokens to get — hand out tickets with t."
            )
        );
        assert!(!rt.save.is_pending());
    }

    #[tokio::test]
    async fn drawing_by_hand_reasks_a_lost_enrolment_and_says_what_each_community_does() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);
        grant(&mut rt, persona);
        rt.config
            .private
            .vetting
            .hidden_published
            .insert(VTC.into(), params());
        rt.config.private.vetting.hidden_vetter[0].lost_reasked = true;
        reads_as_hidden(&mut rt);

        act(&mut rt, VettingAction::DrawNow).await;

        assert!(!held(&rt).lost_reasked);
        let s = status(&rt);
        assert_eq!(s.severity, Severity::Info);
        assert!(
            s.text.starts_with(&format!("Getting tokens — {VTC}: ")),
            "{}",
            s.text
        );
        // The pass planned the schedule; with no VTA connected no job
        // started, so it is owed again.
        assert!(rt.config.private.vetting.vetter_refresh_due);
        assert!(!busy(&rt));
    }

    /// A pass that fails to ask something says why, and the summary of what
    /// each community does does not cover it.
    #[tokio::test]
    async fn drawing_by_hand_leaves_a_failure_of_the_pass_said() {
        let (mut rt, _h) = runtime().await;
        let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);
        grant(&mut rt, persona);
        rt.config
            .private
            .vetting
            .hidden_published
            .insert(VTC.into(), params());
        reads_as_hidden(&mut rt);
        rebound(&mut rt);

        act(&mut rt, VettingAction::DrawNow).await;

        let s = status(&rt);
        assert_eq!(s.severity, Severity::Error);
        assert!(
            s.text
                .contains(" which hidden-vetting key it holds for you: "),
            "{}",
            s.text
        );
    }

    #[tokio::test]
    async fn enter_on_the_hidden_view_runs_the_vetter_pass() {
        let (mut rt, _h) = runtime().await;
        rt.state.main_page.content_panel.vetting.mode = VettingMode::HiddenVetting { index: 0 };

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(
            status(&rt),
            &Status::progress(
                "Reading each community's requirements again and drawing what the schedule owes…"
            )
        );
        assert!(matches!(page(&rt).mode, VettingMode::HiddenVetting { .. }));
        assert!(!rt.save.is_pending());
    }

    // ---- the schedule's pass ----

    #[tokio::test]
    async fn the_first_pass_mints_an_engine_and_owes_the_vta_an_enrolment() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        grant(&mut rt, persona);
        rt.config
            .private
            .vetting
            .hidden_published
            .insert(VTC.into(), params());

        act(&mut rt, VettingAction::RefreshVetterSide).await;

        assert_eq!(rt.config.private.vetting.hidden_vetter.len(), 1);
        assert_eq!(held(&rt).persona, persona);
        assert!(rt.save.is_pending());
        assert_eq!(
            status(&rt),
            &Status::progress(format!(
                "{VTC} hides its vetters. Enrolling you — your attestations there will name \
                 nobody."
            ))
        );
        // No VTA: nothing started, and the pass is owed again.
        assert!(rt.config.private.vetting.vetter_refresh_due);
        assert!(!rt.in_flight.is_busy(DispatchDomain::HiddenVetting));
    }

    #[tokio::test]
    async fn a_pass_without_a_live_grant_mints_nothing() {
        let (mut rt, _h) = runtime().await;
        fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        rt.config
            .private
            .vetting
            .hidden_published
            .insert(VTC.into(), params());

        act(&mut rt, VettingAction::RefreshVetterSide).await;

        assert!(rt.config.private.vetting.hidden_vetter.is_empty());
        assert!(!rt.config.private.vetting.vetter_refresh_due);
    }

    // ---- what the VTA answered ----

    fn refused_draw(persona: PersonaId) -> PcsInbound {
        PcsInbound::DrawRefused {
            community: VTC.into(),
            persona,
            label: "token/2026-10".into(),
            tick: 1,
        }
    }

    fn inbound(item: PcsInbound) -> PcsWork {
        PcsWork::Inbound {
            item,
            context_id: None,
            params: None,
            vta_application: None,
        }
    }

    #[tokio::test]
    async fn an_unreachable_vta_keeps_the_inbox_and_backs_off() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);
        let item = refused_draw(persona);
        rt.config.private.vetting.pcs_inbox.push(item.clone());

        answered(
            &mut rt,
            1,
            vec![(inbound(item), Err(PcsError::Unreachable("down".into())))],
        )
        .await;

        let book = &rt.config.private.vetting;
        assert_eq!(book.pcs_inbox.len(), 1, "kept for the next job");
        assert_eq!(book.pcs_failures, 1);
        assert!(book.pcs_retry_at.is_some());
        assert!(book.pcs_due);
        assert!(rt.save.is_pending());
        assert!(page(&rt).status_message.is_none(), "nothing said");
    }

    #[tokio::test]
    async fn an_answered_inbox_item_is_taken_and_the_backoff_cleared() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);
        let item = refused_draw(persona);
        let book = &mut rt.config.private.vetting;
        book.pcs_inbox.push(item.clone());
        book.pcs_failures = 3;
        book.pcs_retry_at = Some(chrono::Utc::now());

        answered(
            &mut rt,
            1,
            vec![(inbound(item), Ok(PcsDone::Abandoned(None)))],
        )
        .await;

        let book = &rt.config.private.vetting;
        assert!(book.pcs_inbox.is_empty());
        assert_eq!(book.pcs_failures, 0);
        assert_eq!(book.pcs_retry_at, None);
        assert!(!book.pcs_due);
        assert!(rt.save.is_pending());
    }

    #[tokio::test]
    async fn a_vta_refusing_a_draw_says_so() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);

        answered(&mut rt, 0, vec![(owed(persona, draw()), Err(refused()))]).await;

        let s = status(&rt);
        assert_eq!(s.severity, Severity::Error);
        assert!(
            s.text
                .starts_with(&format!("Could not draw tokens for {VTC}: ")),
            "{}",
            s.text
        );
        assert!(rt.save.is_pending());
    }

    #[tokio::test]
    async fn an_enrolment_the_vta_built_is_filed_and_sent_unheld() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);

        answered(&mut rt, 0, vec![(owed(persona, enrol()), Ok(root()))]).await;

        assert!(held(&rt).enrol_asked_at.is_some());
        assert!(asked(&rt, QueryKind::PcsRoot));
        assert_eq!(
            status(&rt),
            &Status::progress("Asking to enrol as a vetter under vetter/2026-10…")
        );
        assert!(rt.save.is_pending());
        assert!(!busy(&rt));
        settle_unheld(&mut rt).await;
        assert!(
            !asked(&rt, QueryKind::PcsRoot),
            "the failed send forgets it"
        );
    }

    #[tokio::test]
    async fn an_enrolment_without_keys_is_said_and_unfiled() {
        let (mut rt, _h) = runtime().await;
        let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);

        answered(&mut rt, 0, vec![(owed(persona, enrol()), Ok(root()))]).await;

        let s = status(&rt);
        assert_eq!(s.severity, Severity::Error);
        assert!(s.text.starts_with("Could not ask to enrol: "), "{}", s.text);
        assert!(
            logged(&rt.state, "Could not ask to enrol"),
            "logged as well as said, so it outlives the status line"
        );
        // The question is un-filed, as a failed send's is; the time asked
        // stays, since the VTA holds the request it built either way.
        assert!(held(&rt).enrol_asked_at.is_some());
        assert!(!asked(&rt, QueryKind::PcsRoot));
        assert!(rt.save.is_pending());
    }

    #[tokio::test]
    async fn a_draw_the_vta_built_is_filed_in_flight_and_sent_unheld() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);

        answered(&mut rt, 0, vec![(owed(persona, draw()), Ok(tokens()))]).await;

        assert!(asked(&rt, QueryKind::PcsTokens));
        let in_flight: Vec<(String, u32)> = rt
            .config
            .private
            .vetting
            .draws_in_flight
            .values()
            .cloned()
            .collect();
        assert_eq!(in_flight, vec![("token/2026-10".to_string(), 3)]);
        assert!(
            page(&rt).status_message.is_none(),
            "a draw is not announced"
        );
        assert!(!busy(&rt));
        settle_unheld(&mut rt).await;
    }

    #[tokio::test]
    async fn a_draw_without_keys_is_said_and_not_left_in_flight() {
        let (mut rt, _h) = runtime().await;
        let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);

        answered(&mut rt, 0, vec![(owed(persona, draw()), Ok(tokens()))]).await;

        let s = status(&rt);
        assert_eq!(s.severity, Severity::Error);
        assert!(s.text.starts_with("Could not draw tokens: "), "{}", s.text);
        assert!(logged(&rt.state, "Could not draw tokens"));
        assert!(!asked(&rt, QueryKind::PcsTokens));
        assert!(rt.config.private.vetting.draws_in_flight.is_empty());
    }

    #[tokio::test]
    async fn the_answers_are_taken_in_order_and_a_failure_stops_none_after_it() {
        let (mut rt, _h) = runtime().await;
        let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);

        answered(
            &mut rt,
            0,
            vec![
                (owed(persona, enrol()), Ok(root())),
                (owed(persona, draw()), Ok(tokens())),
            ],
        )
        .await;

        // Each failure undoes its own question; the second still ran.
        assert!(!asked(&rt, QueryKind::PcsRoot));
        assert!(!asked(&rt, QueryKind::PcsTokens));
        assert!(held(&rt).enrol_asked_at.is_some(), "the enrolment ran");
        assert!(
            status(&rt).text.starts_with("Could not draw tokens: "),
            "the last word stands"
        );
    }

    /// A request on the desk, accepted, its card not in yet.
    fn desk_request(rt: &mut Runtime, persona: PersonaId) -> String {
        use openvtc_core::vetting::vetter::{DeskEntry, DeskState};
        let now = chrono::Utc::now();
        let request = request::v0_1::Payload::try_from(
            request::v0_1::Payload::builder()
                .community(VTC)
                .join_did("did:key:zJoiner")
                .ticket(Some(code_ticket())),
        )
        .unwrap();
        rt.config.private.vetting.desk.push(DeskEntry {
            request_id: "req-1".into(),
            request_document_id: "doc-1".into(),
            applicant: "did:key:zJoiner".into(),
            community: VTC.into(),
            persona,
            ticket_id: None,
            request,
            state: DeskState::Accepted,
            received_at: now,
            updated_at: now,
        });
        "req-1".into()
    }

    fn attest_work(request_id: &str, persona: PersonaId) -> PcsWork {
        PcsWork::Attest {
            job: openvtc_core::vetting::book::HiddenAttestJob {
                request_id: request_id.into(),
                community: VTC.into(),
                persona,
                applicant: "did:key:zJoiner".into(),
                applicant_id: "zApplicantId".into(),
                meta: serde_json::json!({}),
                params: params(),
            },
            context_id: "openvtc/ctx".into(),
            vetter_did: "did:key:zVetter".into(),
            session_id: "s-1".into(),
        }
    }

    #[tokio::test]
    async fn an_attestation_the_vta_refused_says_why_nothing_was_sent() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        let id = desk_request(&mut rt, persona);

        answered(
            &mut rt,
            0,
            vec![(attest_work(&id, persona), Err(refused()))],
        )
        .await;

        let s = status(&rt);
        assert_eq!(s.severity, Severity::Error);
        assert!(
            s.text.starts_with("Cannot attest: your VTA refused"),
            "{}",
            s.text
        );
    }

    #[tokio::test]
    async fn an_attestation_on_a_request_that_moved_on_is_not_recorded() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        let id = desk_request(&mut rt, persona);

        answered(
            &mut rt,
            0,
            vec![(
                attest_work(&id, persona),
                Ok(PcsDone::Attested(serde_json::json!({}))),
            )],
        )
        .await;

        let s = status(&rt);
        assert_eq!(s.severity, Severity::Error);
        assert!(
            s.text.starts_with("Could not record the attestation: "),
            "{}",
            s.text
        );
        assert!(!logged(&rt.state, "Sending your attestation"));
        assert!(!busy(&rt));
    }

    #[tokio::test]
    async fn a_recovery_the_vta_refused_is_said_and_saved() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);
        rebound(&mut rt);
        assert!(rt.config.private.vetting.hidden_vetter[0].recheck_key(chrono::Utc::now()));

        answered(
            &mut rt,
            0,
            vec![(
                PcsWork::Recover {
                    community: VTC.into(),
                    persona,
                    context_id: "openvtc/ctx".into(),
                    did: "did:key:zVetter".into(),
                    bound_id: "zBound".into(),
                },
                Err(refused()),
            )],
        )
        .await;

        let s = status(&rt);
        assert_eq!(s.severity, Severity::Success);
        assert!(
            s.text.starts_with(&format!("Hidden vetting at {VTC} — ")),
            "{}",
            s.text
        );
        assert!(logged(&rt.state, &format!("Hidden vetting at {VTC} — ")));
        assert!(rt.save.is_pending());
    }

    /// The challenge's progress note follows a refresh that went out: a
    /// warning on the status line from before the refresh is not news the
    /// refresh left, so it does not hold the note back.
    #[tokio::test]
    async fn a_challenge_after_a_refresh_that_went_out_says_it_is_asking() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        hidden_application(&mut rt, persona);
        rt.state.main_page.content_panel.vetting.status_message =
            Some(Status::warning("from an earlier action"));

        act(&mut rt, VettingAction::RefreshRequirements).await;

        assert!(asked(&rt, QueryKind::Manifest));
        assert!(asked(&rt, QueryKind::PcsChallenge));
        assert_eq!(
            status(&rt),
            &Status::progress("Asking the community for a submission challenge…")
        );
    }

    // ---- a refresh's follow-ups, in order ----

    #[tokio::test]
    async fn a_refresh_gives_up_then_the_challenge_then_the_vetter_pass() {
        let (mut rt, _h) = runtime().await;
        let persona = persona_without_keys(&mut rt, "did:key:zApplicant").await;
        hidden_application(&mut rt, persona);
        rebound_engine(&mut rt, persona);

        act(&mut rt, VettingAction::RefreshRequirements).await;

        let requirements = log_line(&rt, "Could not ask the community");
        let challenge = log_line(&rt, "Could not ask for a submission challenge");
        let pass = log_line(&rt, "which hidden-vetting key it holds for you");
        assert!(requirements < challenge && challenge < pass);
        assert!(key_check_started(&rt));
        assert!(!asked(&rt, QueryKind::PcsChallenge));
        assert!(!asked(&rt, QueryKind::PcsBinding));
    }

    // ---- attesting a request that asks for a proof ----

    /// A desk request from the applicant carrying its PCS identifier, its
    /// card in, and the attest form ticked.
    fn hidden_card(rt: &mut Runtime, persona: PersonaId) -> String {
        let id = super::desk_request(rt, persona);
        let entry = rt.config.private.vetting.desk_entry_mut(&id).unwrap();
        let mut raw = serde_json::to_value(&entry.request).unwrap();
        raw.as_object_mut().unwrap().insert(
            "ext".into(),
            openvtc_core::vetting::hidden::request_ext(SUITE, "zApplicantId"),
        );
        entry.request = serde_json::from_value(raw).unwrap();
        card_received(rt, &id, "did:key:zVetter");
        attest_form(rt, &id, true);
        id
    }

    #[tokio::test]
    async fn attesting_a_proof_unenrolled_enrols_through_the_vetter_pass() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        grant(&mut rt, persona);
        rt.config
            .private
            .vetting
            .hidden_published
            .insert(VTC.into(), params());
        reads_as_hidden(&mut rt);
        let id = hidden_card(&mut rt, persona);

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(issued(&rt), 0, "nothing was signed");
        assert!(matches!(page(&rt).mode, VettingMode::List));
        assert!(matches!(
            desk_state(&rt, &id),
            DeskState::CardReceived { .. }
        ));
        assert_eq!(
            rt.config.private.vetting.hidden_vetter.len(),
            1,
            "the vetter pass minted the engine"
        );
        assert_eq!(held(&rt).persona, persona);
        assert!(rt.save.is_pending());
    }

    #[tokio::test]
    async fn attesting_a_proof_unenrolled_while_busy_still_enrols() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        grant(&mut rt, persona);
        rt.config
            .private
            .vetting
            .hidden_published
            .insert(VTC.into(), params());
        reads_as_hidden(&mut rt);
        hidden_card(&mut rt, persona);
        assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

        act(&mut rt, VettingAction::Submit).await;

        assert_eq!(rt.config.private.vetting.hidden_vetter.len(), 1);
        assert!(matches!(page(&rt).mode, VettingMode::List));
    }

    #[tokio::test]
    async fn attesting_a_proof_with_no_vta_says_it_is_not_connected() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);
        reads_as_hidden(&mut rt);
        let id = hidden_card(&mut rt, persona);
        // A person's job holding the vetting domain does not stop it: the
        // attestation is the VTA's job, on its own domain.
        assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

        act(&mut rt, VettingAction::Submit).await;

        let s = status(&rt);
        assert_eq!(s.severity, Severity::Error);
        assert!(
            s.text
                .starts_with("A hidden attestation is made by your VTA, and it is not connected"),
            "{}",
            s.text
        );
        assert!(matches!(page(&rt).mode, VettingMode::Attest { .. }));
        assert!(matches!(
            desk_state(&rt, &id),
            DeskState::CardReceived { .. }
        ));
        assert_eq!(issued(&rt), 0);
        assert!(!rt.in_flight.is_busy(DispatchDomain::HiddenVetting));
    }

    #[tokio::test]
    async fn attesting_a_proof_with_no_token_says_to_wait() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);
        reads_as_hidden(&mut rt);
        hidden_card(&mut rt, persona);
        rt.admin_vta = Some(vta_sdk::client::VtaClient::new("http://127.0.0.1:1"));

        act(&mut rt, VettingAction::Submit).await;

        let s = status(&rt);
        assert_ne!(s.severity, Severity::Progress, "{}", s.text);
        assert!(!rt.in_flight.is_busy(DispatchDomain::HiddenVetting));
        assert_eq!(issued(&rt), 0);
    }
}
