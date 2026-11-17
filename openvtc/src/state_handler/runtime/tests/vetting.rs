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
    async fn choosing_a_face_while_busy_derives_the_context_and_reads_nothing() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = application(&mut rt, persona);
        assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

        act(&mut rt, VettingAction::ChooseFace).await;

        assert_busy_refusal(&rt);
        // The context is derived before the busy check, in memory only.
        assert!(context_of(&rt, &id).is_some());
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
        assert!(!rt.save.is_pending());

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
        assert!(context_of(&rt, &id).is_some());
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
        assert!(!rt.save.is_pending());

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
        assert!(context_of(&rt, &id).is_some());
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
    async fn a_card_while_busy_derives_the_context_and_sends_nothing() {
        let (mut rt, _h) = runtime().await;
        connect(&mut rt);
        let persona = fixtures::persona_with_keys(&mut rt, "did:key:zApplicant").await;
        let id = with_session(&mut rt, persona, later());
        card(&mut rt, &id, Some(previewed(None)));
        assert!(rt.in_flight.try_begin(DispatchDomain::Vetting));

        act(&mut rt, VettingAction::Submit).await;

        assert_busy_refusal(&rt);
        assert!(context_of(&rt, &id).is_some());
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
        assert!(!rt.save.is_pending());

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
        // Derived before the key lookup, and kept.
        assert!(context_of(&rt, &id).is_some());
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
        assert!(!rt.save.is_pending());

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
