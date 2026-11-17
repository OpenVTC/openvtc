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
    async fn a_challenge_without_keys_gives_up_and_leaves_its_question_filed() {
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
        // Filed before the signing and left filed when it fails: it expires
        // on its reply window.
        assert!(asked(&rt, QueryKind::PcsChallenge));
        assert!(!rt.save.is_pending());
    }

    #[tokio::test]
    async fn a_challenge_is_asked_even_while_a_persons_send_holds_the_domain() {
        let (mut rt, _h) = runtime().await;
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        hidden_application(&mut rt, persona);
        assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

        act(&mut rt, VettingAction::RefreshRequirements).await;

        // The requirements are refused; the challenge is not, and is said last.
        assert!(!asked(&rt, QueryKind::Manifest));
        assert!(asked(&rt, QueryKind::PcsChallenge));
        assert_eq!(
            status(&rt),
            &Status::progress("Asking the community for a submission challenge…")
        );
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
    async fn an_enrolment_without_keys_is_said_and_left_filed() {
        let (mut rt, _h) = runtime().await;
        let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);

        answered(&mut rt, 0, vec![(owed(persona, enrol()), Ok(root()))]).await;

        let s = status(&rt);
        assert_eq!(s.severity, Severity::Error);
        assert!(s.text.starts_with("Could not ask to enrol: "), "{}", s.text);
        assert!(
            !logged(&rt.state, "Could not ask to enrol"),
            "said, not logged"
        );
        // Recorded as asked, and left so: the question expires on its window.
        assert!(held(&rt).enrol_asked_at.is_some());
        assert!(asked(&rt, QueryKind::PcsRoot));
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
    async fn a_draw_without_keys_is_said_and_left_in_flight() {
        let (mut rt, _h) = runtime().await;
        let persona = persona_without_keys(&mut rt, "did:key:zVetter").await;
        engine(&mut rt, persona);

        answered(&mut rt, 0, vec![(owed(persona, draw()), Ok(tokens()))]).await;

        let s = status(&rt);
        assert_eq!(s.severity, Severity::Error);
        assert!(s.text.starts_with("Could not draw tokens: "), "{}", s.text);
        assert!(asked(&rt, QueryKind::PcsTokens));
        assert_eq!(rt.config.private.vetting.draws_in_flight.len(), 1);
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

        assert!(asked(&rt, QueryKind::PcsRoot));
        assert!(asked(&rt, QueryKind::PcsTokens));
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
}
