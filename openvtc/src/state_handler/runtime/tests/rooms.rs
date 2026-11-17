//! Runtime-harness tests pinning the rooms handlers: the busy, send-failure
//! and success paths (#612).
//!
//! A persona from [`fixtures::persona_with_keys`] gets past the key lookup and
//! reaches the claim; its send then fails off the loop (no listener, no
//! mediator), which is the send-failure path. A persona with a membership but
//! no messaging identity fails the key lookup before any claim.

use std::time::Duration;

use openvtc_core::community_rooms::{Renewal, RoomMembership};
use openvtc_core::config::account::PersonaId;

use super::super::Runtime;
use super::fixtures;
use crate::state_handler::actions::{Action, RoomsAction as Act};
use crate::state_handler::background_dispatch::{DispatchDomain, DispatchOutcome, InFlight};
use crate::state_handler::main_page::rooms::{
    AcceptStep, Next, Pending, Purpose, RoomsPhase, RoomsView, Severity,
};

const VTC: &str = "did:key:zRoomsVtc";
const PERSONA: &str = "did:key:zRoomsPersona";
const ROOM: &str = "did:key:zRoomOne";
const NO_IDENTITY: &str = "this persona has no messaging identity";

/// A runtime whose Active membership in [`VTC`] is held by a persona whose
/// keys resolve.
async fn with_keys() -> Runtime {
    let (mut rt, _h) = super::runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, PERSONA).await;
    fixtures::active_membership(&mut rt, VTC, persona);
    rt
}

/// A runtime whose Active membership in [`VTC`] is held by a persona with no
/// messaging identity: its key lookup fails before any claim.
async fn without_identity() -> Runtime {
    let (mut rt, _h) = super::runtime().await;
    fixtures::active_membership(&mut rt, VTC, PersonaId::new());
    rt
}

fn connect_vta(rt: &mut Runtime) {
    rt.admin_vta = Some(vta_sdk::client::VtaClient::new("https://vta.example"));
}

fn view(rt: &mut Runtime) -> &mut RoomsView {
    rt.state
        .main_page
        .content_panel
        .rooms
        .view
        .as_mut()
        .expect("the panel is open")
}

fn status(rt: &mut Runtime) -> Option<(Severity, String)> {
    view(rt)
        .status
        .as_ref()
        .map(|s| (s.severity, s.text.clone()))
}

/// Open the panel with both of its lanes held, so nothing is sent or asked,
/// then free them.
async fn open_quietly(rt: &mut Runtime) {
    assert!(rt.in_flight.try_begin(DispatchDomain::Rooms));
    assert!(rt.in_flight.try_begin(DispatchDomain::RoomsVta));
    rt.on_action(Action::Rooms(Act::Open(0))).await;
    rt.in_flight.finish(DispatchDomain::Rooms);
    rt.in_flight.finish(DispatchDomain::RoomsVta);
    let v = view(rt);
    assert!(v.pending.is_none());
    v.held_error = None;
    v.status = None;
}

fn offered_room() -> RoomMembership {
    serde_json::from_value(serde_json::json!({
        "roomId": ROOM, "host": VTC, "label": "Board pack",
        "visibility": "private", "actions": ["read"],
        "validUntil": "2027-10-01T00:00:00Z", "state": "offered",
        "offeredAt": "2026-10-14T10:00:00Z", "roomState": "active",
    }))
    .expect("a room membership")
}

fn renewal() -> Renewal {
    serde_json::from_value(serde_json::json!({
        "roomId": ROOM, "host": VTC, "label": "Board pack",
        "visibility": "private", "actions": ["read"],
        "validUntil": "2027-11-10T00:00:00Z", "renewsAt": "2027-10-01T00:00:00Z",
        "issuedAt": "2026-11-03T09:00:00Z",
        "credentials": { "membership": "{}", "authority": "{}" },
    }))
    .expect("a renewal")
}

/// The open view lists one offered room, highlighted, the VTA holding none.
fn with_offered_room(rt: &mut Runtime) {
    let v = view(rt);
    v.take_page(vec![offered_room()], true);
    v.held = Some(Vec::new());
}

/// The Rooms send's own outcome, applied through the loop's outcome arm.
async fn apply_send_outcome(rt: &mut Runtime) {
    loop {
        let outcome = tokio::time::timeout(Duration::from_secs(20), rt.dispatch_rx.recv())
            .await
            .expect("the send reports back")
            .expect("the channel is open");
        let ours = matches!(outcome, DispatchOutcome::Rooms(_));
        rt.on_dispatch_outcome(outcome).await;
        if ours {
            return;
        }
    }
}

fn armed_on(rt: &mut Runtime, purpose: &Purpose) {
    let pending = view(rt)
        .pending
        .clone()
        .expect("the view waits on the send");
    assert_eq!(&pending.purpose, purpose);
    assert_eq!(pending.to, VTC);
}

// ---- Open / Refresh ----

/// A refresh on a busy Rooms lane sends nothing and says why: the panel stays
/// loading with the busy note, and with no VTA the custody says why it is not
/// shown.
#[tokio::test]
async fn a_refresh_on_a_busy_lane_sends_nothing_and_says_the_lane_is_busy() {
    let mut rt = with_keys().await;
    assert!(rt.in_flight.try_begin(DispatchDomain::Rooms));
    rt.on_action(Action::Rooms(Act::Open(0))).await;
    let v = view(&mut rt);
    assert_eq!(v.phase, RoomsPhase::Loading);
    assert!(v.pending.is_none());
    assert!(v.held.is_none());
    let (severity, text) = status(&mut rt).expect("the busy lane is said");
    assert_eq!(severity, Severity::Warning);
    assert!(
        text.starts_with(&InFlight::busy_message(DispatchDomain::Rooms)),
        "{text}"
    );
    let v = view(&mut rt);
    assert_eq!(
        v.held_error.as_deref(),
        Some("no VTA is connected, so which rooms it holds keys for can't be shown")
    );
    assert!(!rt.in_flight.is_busy(DispatchDomain::RoomsVta));
}

/// A refresh whose key lookup fails fails an empty record with the reason,
/// and claims nothing.
#[tokio::test]
async fn a_refresh_whose_key_lookup_fails_fails_the_empty_record() {
    let mut rt = without_identity().await;
    rt.on_action(Action::Rooms(Act::Open(0))).await;
    let v = view(&mut rt);
    assert_eq!(v.phase, RoomsPhase::Failed(NO_IDENTITY.into()));
    assert!(v.pending.is_none());
    assert!(!rt.in_flight.is_busy(DispatchDomain::Rooms));
}

/// With a record already shown, a refresh whose key lookup fails says why on
/// the status line and keeps the record.
#[tokio::test]
async fn a_refresh_whose_key_lookup_fails_over_a_record_notes_it() {
    let mut rt = without_identity().await;
    open_quietly(&mut rt).await;
    with_offered_room(&mut rt);
    rt.on_action(Action::Rooms(Act::Refresh)).await;
    assert_eq!(view(&mut rt).phase, RoomsPhase::Loaded);
    assert_eq!(
        status(&mut rt),
        Some((Severity::Error, NO_IDENTITY.to_string()))
    );
}

/// A refresh arms the view on the request's thread and claims the lane; the
/// send then fails off the loop, which fails the empty record and frees the
/// lane.
#[tokio::test]
async fn a_refresh_arms_the_view_then_a_failed_send_fails_the_record() {
    let mut rt = with_keys().await;
    rt.on_action(Action::Rooms(Act::Open(0))).await;
    armed_on(&mut rt, &Purpose::Memberships);
    assert!(rt.in_flight.is_busy(DispatchDomain::Rooms));
    assert_eq!(view(&mut rt).phase, RoomsPhase::Loading);
    assert!(view(&mut rt).status.is_none());

    apply_send_outcome(&mut rt).await;
    assert!(!rt.in_flight.is_busy(DispatchDomain::Rooms));
    let v = view(&mut rt);
    assert!(v.pending.is_none());
    assert!(
        matches!(&v.phase, RoomsPhase::Failed(why) if why.starts_with("couldn't reach the community: ")),
        "{:?}",
        v.phase
    );
}

/// With a VTA connected whose lane is busy, the custody says so and the record
/// still refreshes.
#[tokio::test]
async fn a_refresh_on_a_busy_vta_lane_says_so_and_still_reads_the_record() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    assert!(rt.in_flight.try_begin(DispatchDomain::RoomsVta));
    rt.on_action(Action::Rooms(Act::Open(0))).await;
    let v = view(&mut rt);
    assert!(v.held.is_none());
    assert_eq!(v.held_error.as_deref(), Some("your VTA is busy"));
    armed_on(&mut rt, &Purpose::Memberships);
}

/// With a VTA connected and its lane free, a refresh asks it which rooms it
/// holds as well as reading the record.
#[tokio::test]
async fn a_refresh_with_a_vta_asks_it_and_reads_the_record() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    rt.on_action(Action::Rooms(Act::Open(0))).await;
    assert!(rt.in_flight.is_busy(DispatchDomain::RoomsVta));
    assert!(view(&mut rt).held_error.is_none());
    armed_on(&mut rt, &Purpose::Memberships);
}

// ---- Accept ----

/// Accepting needs a VTA: without one the press is refused and starts nothing.
#[tokio::test]
async fn an_accept_without_a_vta_is_refused() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    with_offered_room(&mut rt);
    rt.on_action(Action::Rooms(Act::Accept)).await;
    assert!(view(&mut rt).accept.is_none());
    assert_eq!(
        status(&mut rt),
        Some((
            Severity::Error,
            "Accepting a room needs your VTA: it holds the room's keys and credentials.".into()
        ))
    );
    assert!(!rt.in_flight.is_busy(DispatchDomain::Rooms));
}

/// An acceptance pressed while the view still waits on an earlier request is
/// refused: nothing is set, nothing sent, and the press can be made again once
/// the earlier request answers.
#[tokio::test]
async fn an_accept_while_waiting_is_refused_and_can_be_pressed_again() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    with_offered_room(&mut rt);
    let earlier = Pending {
        thid: "earlier".into(),
        sent_at: std::time::Instant::now(),
        purpose: Purpose::Memberships,
        to: VTC.into(),
    };
    view(&mut rt).pending = Some(earlier.clone());

    rt.on_action(Action::Rooms(Act::Accept)).await;

    let v = view(&mut rt);
    assert!(v.accept.is_none());
    assert_eq!(v.pending, Some(earlier));
    assert_eq!(
        status(&mut rt),
        Some((
            Severity::Warning,
            "A request to this community is still waiting — try again when it answers.".into()
        ))
    );
    assert!(!rt.in_flight.is_busy(DispatchDomain::Rooms));

    // The earlier request answers; the same press now starts the acceptance.
    view(&mut rt).pending = None;
    rt.on_action(Action::Rooms(Act::Accept)).await;
    assert!(rt.in_flight.is_busy(DispatchDomain::Rooms));
    armed_on(&mut rt, &Purpose::Offers { room: ROOM.into() });
    let flow = view(&mut rt).accept.clone().expect("the acceptance is set");
    assert_eq!(flow.step, AcceptStep::Collecting);
}

/// An acceptance whose key lookup fails says why, not that the lane is busy
/// (it is not), and leaves no acceptance set.
#[tokio::test]
async fn an_accept_whose_key_lookup_fails_shows_the_reason() {
    let mut rt = without_identity().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    with_offered_room(&mut rt);
    rt.on_action(Action::Rooms(Act::Accept)).await;
    let v = view(&mut rt);
    assert!(v.accept.is_none());
    assert!(v.pending.is_none());
    assert_eq!(
        status(&mut rt),
        Some((Severity::Error, NO_IDENTITY.to_string()))
    );
    assert!(!rt.in_flight.is_busy(DispatchDomain::Rooms));
}

/// An acceptance on a busy Rooms lane leaves no acceptance set and says the
/// lane is busy.
#[tokio::test]
async fn an_accept_on_a_busy_lane_is_refused_and_leaves_nothing_set() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    with_offered_room(&mut rt);
    assert!(rt.in_flight.try_begin(DispatchDomain::Rooms));
    rt.on_action(Action::Rooms(Act::Accept)).await;
    let v = view(&mut rt);
    assert!(v.accept.is_none());
    assert!(v.pending.is_none());
    assert_eq!(
        status(&mut rt),
        Some((
            Severity::Warning,
            InFlight::busy_message(DispatchDomain::Rooms)
        ))
    );
}

/// An acceptance that starts claims the lane, arms the view on the offers
/// read and sets the acceptance; its send failing off the loop ends it and
/// says why.
#[tokio::test]
async fn an_accept_that_starts_arms_the_view_then_a_failed_send_ends_it() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    with_offered_room(&mut rt);
    rt.on_action(Action::Rooms(Act::Accept)).await;

    assert!(rt.in_flight.is_busy(DispatchDomain::Rooms));
    armed_on(&mut rt, &Purpose::Offers { room: ROOM.into() });
    let v = view(&mut rt);
    let flow = v.accept.as_ref().expect("the acceptance is set");
    assert_eq!(flow.room, ROOM);
    assert_eq!(flow.step, AcceptStep::Collecting);
    assert_eq!(
        status(&mut rt),
        Some((
            Severity::Progress,
            "Accepting Board pack… collecting the offer".into()
        ))
    );

    apply_send_outcome(&mut rt).await;
    let v = view(&mut rt);
    assert!(v.accept.is_none());
    assert!(v.pending.is_none());
    let (severity, text) = status(&mut rt).expect("the failure is said");
    assert_eq!(severity, Severity::Error);
    assert!(text.starts_with("couldn't reach the community: "), "{text}");
}

// ---- Steps taken on the tick ----

/// A refresh step on a busy lane is kept for the next tick.
#[tokio::test]
async fn a_refresh_step_on_a_busy_lane_is_kept() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    view(&mut rt).next = Some(Next::Refresh);
    assert!(rt.in_flight.try_begin(DispatchDomain::Rooms));
    rt.on_capabilities_sweep().await;
    assert_eq!(view(&mut rt).next, Some(Next::Refresh));
}

/// A page step whose key lookup fails says why and is given up, not retried
/// on the next tick: the reason stays until the person acts again.
#[tokio::test]
async fn a_page_step_whose_key_lookup_fails_is_given_up() {
    let mut rt = without_identity().await;
    open_quietly(&mut rt).await;
    with_offered_room(&mut rt);
    let next = Next::MembershipsPage {
        cursor: "c1".into(),
    };
    view(&mut rt).next = Some(next);
    rt.on_capabilities_sweep().await;
    assert!(view(&mut rt).next.is_none());
    assert_eq!(
        status(&mut rt),
        Some((Severity::Error, NO_IDENTITY.to_string()))
    );
    assert!(!rt.in_flight.is_busy(DispatchDomain::Rooms));

    // The next tick neither retries it nor rewrites the reason.
    view(&mut rt).status.as_mut().unwrap().text = "seen".into();
    rt.on_capabilities_sweep().await;
    assert!(view(&mut rt).next.is_none());
    assert_eq!(status(&mut rt), Some((Severity::Error, "seen".into())));
}

/// A page step that is sent arms the view and is taken.
#[tokio::test]
async fn a_page_step_that_is_sent_is_taken() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    view(&mut rt).next = Some(Next::MembershipsPage {
        cursor: "c1".into(),
    });
    rt.on_capabilities_sweep().await;
    assert!(view(&mut rt).next.is_none());
    armed_on(&mut rt, &Purpose::Memberships);
    assert!(rt.in_flight.is_busy(DispatchDomain::Rooms));
}

/// The check for renewals is skipped (taken, nothing sent) without a VTA.
#[tokio::test]
async fn a_renewals_check_without_a_vta_is_taken_and_sends_nothing() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    view(&mut rt).next = Some(Next::CheckRenewals);
    rt.on_capabilities_sweep().await;
    assert!(view(&mut rt).next.is_none());
    assert!(view(&mut rt).pending.is_none());
    assert!(!rt.in_flight.is_busy(DispatchDomain::Rooms));
}

/// With a VTA, the check for renewals reads the offers listing.
#[tokio::test]
async fn a_renewals_check_with_a_vta_reads_the_offers() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    view(&mut rt).next = Some(Next::CheckRenewals);
    rt.on_capabilities_sweep().await;
    assert!(view(&mut rt).next.is_none());
    armed_on(&mut rt, &Purpose::Renewals);
}

/// Renewals the VTA's busy lane cannot take yet stay in the view, and so does
/// the step.
#[tokio::test]
async fn a_renew_step_on_a_busy_vta_lane_keeps_the_renewals_and_the_step() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    assert!(rt.in_flight.try_begin(DispatchDomain::RoomsVta));
    view(&mut rt).renewals = vec![renewal()];
    view(&mut rt).next = Some(Next::Renew);
    rt.on_capabilities_sweep().await;
    let v = view(&mut rt);
    assert_eq!(v.next, Some(Next::Renew));
    assert_eq!(v.renewals.len(), 1);
}

/// Without a VTA a renew step is dropped with its renewals rather than kept
/// for ever: nothing can store them, and the first read once a VTA is
/// connected collects them again.
#[tokio::test]
async fn a_renew_step_without_a_vta_is_dropped() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    view(&mut rt).renewals = vec![renewal()];
    view(&mut rt).next = Some(Next::Renew);
    rt.on_capabilities_sweep().await;
    let v = view(&mut rt);
    assert!(v.next.is_none());
    assert!(v.renewals.is_empty());
    assert!(!rt.in_flight.is_busy(DispatchDomain::RoomsVta));
}

/// A renew step the VTA's lane takes hands the renewals to the job.
#[tokio::test]
async fn a_renew_step_that_starts_hands_over_the_renewals() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    view(&mut rt).renewals = vec![renewal()];
    view(&mut rt).next = Some(Next::Renew);
    rt.on_capabilities_sweep().await;
    let v = view(&mut rt);
    assert!(v.next.is_none());
    assert!(v.renewals.is_empty());
    assert!(rt.in_flight.is_busy(DispatchDomain::RoomsVta));
}
