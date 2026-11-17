//! Runtime-harness tests pinning the elections handlers: the busy, send-failure
//! and success paths (#612).
//!
//! A persona from [`fixtures::persona_with_keys`] gets past the key lookup and
//! reaches the claim; its send then fails off the loop (no listener, no
//! mediator), which is the send-failure path. A persona with a membership but
//! no messaging identity fails the key lookup before any claim.

use std::time::Duration;

use openvtc_core::config::account::PersonaId;
use openvtc_core::elections::ShownElection;
use openvtc_core::pending_replies::ReplyKind;
use serde_json::json;

use super::super::Runtime;
use super::fixtures;
use crate::state_handler::actions::{Action, ElectionsAction as Act};
use crate::state_handler::background_dispatch::{DispatchDomain, DispatchOutcome, InFlight};
use crate::state_handler::main_page::elections::{
    ElectionsPhase, ElectionsView, Flow, Intent, Next, NotifiedPhase, Purpose, Screen, Severity,
    Step,
};

const VTC: &str = "did:key:zElectionsVtc";
const PERSONA: &str = "did:key:zElectionsPersona";
const NO_IDENTITY: &str = "this persona has no messaging identity";
const NO_VTA: &str =
    "Voting needs your VTA: it holds the voter keys and the ticket. None is connected.";

/// A runtime whose Active membership in [`VTC`] is held by a persona whose
/// keys resolve.
async fn with_keys() -> Runtime {
    let (mut rt, _h) = super::runtime().await;
    let persona = fixtures::persona_with_keys(&mut rt, PERSONA).await;
    fixtures::active_membership(&mut rt, VTC, persona);
    rt
}

/// A runtime whose Active membership in [`VTC`] is held by a persona with no
/// messaging identity (and no persona record): its key lookup fails before
/// any claim.
async fn without_identity() -> Runtime {
    let (mut rt, _h) = super::runtime().await;
    fixtures::active_membership(&mut rt, VTC, PersonaId::new());
    rt
}

fn connect_vta(rt: &mut Runtime) {
    rt.admin_vta = Some(vta_sdk::client::VtaClient::new("https://vta.example"));
}

fn view(rt: &mut Runtime) -> &mut ElectionsView {
    rt.state
        .main_page
        .content_panel
        .elections
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

fn busy() -> Option<(Severity, String)> {
    Some((
        Severity::Warning,
        InFlight::busy_message(DispatchDomain::Elections),
    ))
}

/// Open the panel with the Elections lane held, so nothing is sent, then free
/// it. The list holds one election, `agm`, highlighted.
async fn open_quietly(rt: &mut Runtime) {
    assert!(rt.in_flight.try_begin(DispatchDomain::Elections));
    rt.on_action(Action::Elections(Act::Open(0))).await;
    rt.in_flight.finish(DispatchDomain::Elections);
    let v = view(rt);
    assert!(v.pending.is_none());
    v.notified_due = false;
    v.status = None;
    v.take_page(
        vec![
            serde_json::from_value(json!({
                "electionId": "agm", "state": "registration", "binding": false,
                "ticketHeld": false,
                "votingOpensAt": "2026-10-02T00:00:00Z", "votingClosesAt": "2026-12-01T00:00:00Z"
            }))
            .expect("a listed election"),
        ],
        true,
    );
}

fn shown() -> Box<ShownElection> {
    Box::new(
        ShownElection::from_payload(json!({
            "manifest": {
                "electionId": "agm", "community": VTC, "title": "AGM",
                "questions": [
                    { "key": "chair", "type": "choice", "options": [{ "key": "a" }, { "key": "b" }],
                      "minSelections": 1, "maxSelections": 1, "optional": false }
                ],
                "secrecy": "open", "roll": { "rule": "members" },
                "registrationOpensAt": "2026-10-01T00:00:00Z", "votingOpensAt": "2026-10-02T00:00:00Z",
                "votingClosesAt": "2026-12-01T00:00:00Z", "revote": "replace",
                "board": { "visibility": "public", "auditors": [] }, "ballotBox": "did:key:z6MkBox",
                "binding": false, "allowEarlyClose": false, "resultsBeforeClose": false,
                "textReleaseThreshold": 10
            },
            "manifestDigest": "zQmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
            "state": "registration",
            "parameters": { "suite": "ps-ddh-bls12381", "votingKey": "zKey" },
            "disclosure": {
                "ballotBox": "did:key:z6MkBox", "ballotBoxOperator": "Ballots Ltd",
                "sameOperator": false, "boardVisibility": "public", "auditors": [],
                "revote": "replace", "coercionResistance": false
            },
            "checkpoints": []
        }))
        .expect("a shown election"),
    )
}

/// The open election's detail screen.
fn on_detail(rt: &mut Runtime) {
    let v = view(rt);
    v.screen = Screen::Detail;
    v.shown = Some(shown());
}

/// The Elections send's own outcome, applied through the loop's outcome arm.
async fn apply_send_outcome(rt: &mut Runtime) {
    loop {
        let outcome = tokio::time::timeout(Duration::from_secs(20), rt.dispatch_rx.recv())
            .await
            .expect("the send reports back")
            .expect("the channel is open");
        let ours = matches!(outcome, DispatchOutcome::Elections(_));
        rt.on_dispatch_outcome(outcome).await;
        if ours {
            return;
        }
    }
}

/// The view waits on `purpose` from [`VTC`], its thread admitted at the gate.
/// Returns the thread.
fn armed_on(rt: &mut Runtime, purpose: &Purpose) -> String {
    let pending = view(rt)
        .pending
        .clone()
        .expect("the view waits on the send");
    assert_eq!(&pending.purpose, purpose);
    assert_eq!(pending.to, VTC);
    assert!(
        rt.pending_replies
            .is_awaited(ReplyKind::ElectionAnswer, VTC, &pending.thid)
    );
    pending.thid
}

// ---- Open / Refresh ----

/// Opening on a busy lane sends nothing and says the lane is busy. The held
/// notifications are still due: they are the VTA's, read on its own lane.
#[tokio::test]
async fn an_open_on_a_busy_lane_sends_nothing_and_says_the_lane_is_busy() {
    let mut rt = with_keys().await;
    assert!(rt.in_flight.try_begin(DispatchDomain::Elections));
    rt.on_action(Action::Elections(Act::Open(0))).await;
    let v = view(&mut rt);
    assert_eq!(v.phase, ElectionsPhase::Loading);
    assert!(v.pending.is_none());
    assert!(v.notified_due);
    let (severity, text) = status(&mut rt).expect("the busy lane is said");
    assert_eq!(severity, Severity::Warning);
    assert!(
        text.starts_with(&InFlight::busy_message(DispatchDomain::Elections)),
        "{text}"
    );
}

/// Opening with a key lookup that fails fails the empty list with the reason.
#[tokio::test]
async fn an_open_whose_key_lookup_fails_fails_the_empty_list() {
    let mut rt = without_identity().await;
    rt.on_action(Action::Elections(Act::Open(0))).await;
    let v = view(&mut rt);
    assert_eq!(v.phase, ElectionsPhase::Failed(NO_IDENTITY.into()));
    assert!(v.pending.is_none());
    assert!(!rt.in_flight.is_busy(DispatchDomain::Elections));
}

/// Opening arms the view on the list read and admits its thread at the gate;
/// the send failing off the loop fails the list and stops admitting it.
#[tokio::test]
async fn an_open_arms_the_view_then_a_failed_send_fails_the_list() {
    let mut rt = with_keys().await;
    rt.on_action(Action::Elections(Act::Open(0))).await;
    let thid = armed_on(&mut rt, &Purpose::List);
    assert!(rt.in_flight.is_busy(DispatchDomain::Elections));

    apply_send_outcome(&mut rt).await;
    assert!(!rt.in_flight.is_busy(DispatchDomain::Elections));
    assert!(
        !rt.pending_replies
            .is_awaited(ReplyKind::ElectionAnswer, VTC, &thid)
    );
    let v = view(&mut rt);
    assert!(v.pending.is_none());
    assert!(
        matches!(&v.phase, ElectionsPhase::Failed(why) if why.starts_with("couldn't reach the community: ")),
        "{:?}",
        v.phase
    );
}

/// `r` while the view waits says so and sends nothing.
#[tokio::test]
async fn a_refresh_while_waiting_says_so() {
    let mut rt = with_keys().await;
    rt.on_action(Action::Elections(Act::Open(0))).await;
    armed_on(&mut rt, &Purpose::List);
    rt.on_action(Action::Elections(Act::Refresh)).await;
    assert_eq!(
        status(&mut rt),
        Some((
            Severity::Warning,
            "Still waiting for the community's answer.".into()
        ))
    );
}

/// `r` on the detail screen on a busy lane says the lane is busy.
#[tokio::test]
async fn a_refresh_of_the_detail_on_a_busy_lane_says_so() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    on_detail(&mut rt);
    assert!(rt.in_flight.try_begin(DispatchDomain::Elections));
    rt.on_action(Action::Elections(Act::Refresh)).await;
    assert_eq!(status(&mut rt), busy());
    assert!(view(&mut rt).pending.is_none());
}

/// `r` on the detail screen whose key lookup fails says why.
#[tokio::test]
async fn a_refresh_of_the_detail_whose_key_lookup_fails_says_why() {
    let mut rt = without_identity().await;
    open_quietly(&mut rt).await;
    on_detail(&mut rt);
    rt.on_action(Action::Elections(Act::Refresh)).await;
    assert_eq!(
        status(&mut rt),
        Some((Severity::Error, NO_IDENTITY.to_string()))
    );
    assert_eq!(view(&mut rt).screen, Screen::Detail);
}

// ---- Show ----

/// Opening an election on a busy lane stays on the list and says the lane is
/// busy, changing nothing else: the community the view last read from, and
/// the membership it presented, stay as they were.
#[tokio::test]
async fn a_show_on_a_busy_lane_stays_on_the_list_and_keeps_its_target() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    view(&mut rt).target = "did:key:zEarlierHolder".into();
    view(&mut rt).presenting = Some("did:key:zParty".into());
    assert!(rt.in_flight.try_begin(DispatchDomain::Elections));
    rt.on_action(Action::Elections(Act::Show)).await;
    let v = view(&mut rt);
    assert_eq!(v.screen, Screen::List);
    assert!(v.shown.is_none());
    assert!(v.pending.is_none());
    assert_eq!(v.target, "did:key:zEarlierHolder");
    assert_eq!(v.presenting.as_deref(), Some("did:key:zParty"));
    assert_eq!(status(&mut rt), busy());
}

/// Opening an election whose key lookup fails shows the detail screen with
/// the reason.
#[tokio::test]
async fn a_show_whose_key_lookup_fails_shows_the_detail_with_the_reason() {
    let mut rt = without_identity().await;
    open_quietly(&mut rt).await;
    rt.on_action(Action::Elections(Act::Show)).await;
    let v = view(&mut rt);
    assert_eq!(v.screen, Screen::Detail);
    assert!(v.shown.is_none());
    assert!(v.flow.is_none());
    assert!(v.pending.is_none());
    assert_eq!(
        status(&mut rt),
        Some((Severity::Error, NO_IDENTITY.to_string()))
    );
    assert!(!rt.in_flight.is_busy(DispatchDomain::Elections));
}

/// Opening an election arms the view on its read and says so; the send
/// failing off the loop says why on the detail screen.
#[tokio::test]
async fn a_show_arms_the_view_then_a_failed_send_says_why() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    rt.on_action(Action::Elections(Act::Show)).await;
    let thid = armed_on(
        &mut rt,
        &Purpose::Show {
            election: "agm".into(),
            intent: Intent::View,
        },
    );
    assert_eq!(view(&mut rt).screen, Screen::Detail);
    assert_eq!(
        status(&mut rt),
        Some((Severity::Progress, "Reading the election…".into()))
    );

    apply_send_outcome(&mut rt).await;
    assert!(
        !rt.pending_replies
            .is_awaited(ReplyKind::ElectionAnswer, VTC, &thid)
    );
    assert_eq!(view(&mut rt).screen, Screen::Detail);
    assert!(view(&mut rt).pending.is_none());
    let (severity, text) = status(&mut rt).expect("the failure is said");
    assert_eq!(severity, Severity::Error);
    assert!(text.starts_with("couldn't reach the community: "), "{text}");
}

// ---- Take a ticket ----

/// Taking a ticket needs a VTA.
#[tokio::test]
async fn a_ticket_without_a_vta_is_refused() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    on_detail(&mut rt);
    rt.on_action(Action::Elections(Act::TakeTicket)).await;
    assert!(view(&mut rt).flow.is_none());
    assert_eq!(status(&mut rt), Some((Severity::Error, NO_VTA.into())));
}

/// Taking a ticket on a busy lane starts no flow and says the lane is busy.
#[tokio::test]
async fn a_ticket_on_a_busy_lane_starts_no_flow() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    on_detail(&mut rt);
    assert!(rt.in_flight.try_begin(DispatchDomain::Elections));
    rt.on_action(Action::Elections(Act::TakeTicket)).await;
    let v = view(&mut rt);
    assert!(v.flow.is_none());
    assert!(v.pending.is_none());
    assert_eq!(status(&mut rt), busy());
}

/// Taking a ticket whose key lookup fails ends the flow and says why.
#[tokio::test]
async fn a_ticket_whose_key_lookup_fails_ends_the_flow_and_says_why() {
    let mut rt = without_identity().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    on_detail(&mut rt);
    rt.on_action(Action::Elections(Act::TakeTicket)).await;
    let v = view(&mut rt);
    assert!(v.flow.is_none());
    assert!(v.pending.is_none());
    assert_eq!(
        status(&mut rt),
        Some((Severity::Error, NO_IDENTITY.to_string()))
    );
    assert!(!rt.in_flight.is_busy(DispatchDomain::Elections));
}

/// Taking a ticket reads the election again, the flow started and said.
#[tokio::test]
async fn a_ticket_that_starts_reads_the_election_again() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    on_detail(&mut rt);
    rt.on_action(Action::Elections(Act::TakeTicket)).await;
    armed_on(
        &mut rt,
        &Purpose::Show {
            election: "agm".into(),
            intent: Intent::Ticket,
        },
    );
    assert_eq!(
        view(&mut rt).flow,
        Some(Flow {
            election: "agm".into(),
            intent: Intent::Ticket,
            step: Step::Reading,
        })
    );
    assert_eq!(
        status(&mut rt),
        Some((Severity::Progress, "Reading the election again…".into()))
    );
}

/// An election read presenting a membership goes through the VTA first: the
/// flow starts and the presenting read is the next step, nothing sent yet.
#[tokio::test]
async fn a_ticket_presenting_a_membership_leaves_the_read_to_the_vta() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    on_detail(&mut rt);
    view(&mut rt).presenting = Some("did:key:zParty".into());
    rt.on_action(Action::Elections(Act::TakeTicket)).await;
    let v = view(&mut rt);
    assert!(v.flow.is_some());
    assert!(v.pending.is_none());
    assert!(matches!(
        &v.next,
        Some(Next::ReadPresenting { election, member_of, intent: Intent::Ticket })
            if election == "agm" && member_of == "did:key:zParty"
    ));
    assert!(!rt.in_flight.is_busy(DispatchDomain::Elections));
}

// ---- Steps taken on the tick ----

/// A refresh step on a busy lane is kept for the next tick.
#[tokio::test]
async fn a_refresh_step_on_a_busy_lane_is_kept() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    view(&mut rt).next = Some(Next::Refresh);
    assert!(rt.in_flight.try_begin(DispatchDomain::Elections));
    rt.on_capabilities_sweep().await;
    assert!(matches!(view(&mut rt).next, Some(Next::Refresh)));
}

/// A page step whose key lookup fails is taken (not retried), saying why.
#[tokio::test]
async fn a_page_step_whose_key_lookup_fails_is_taken() {
    let mut rt = without_identity().await;
    open_quietly(&mut rt).await;
    view(&mut rt).next = Some(Next::ListPage {
        cursor: "c1".into(),
    });
    rt.on_capabilities_sweep().await;
    assert!(view(&mut rt).next.is_none());
    assert_eq!(
        status(&mut rt),
        Some((Severity::Error, NO_IDENTITY.to_string()))
    );
}

/// A page step that is sent arms the view and is taken.
#[tokio::test]
async fn a_page_step_that_is_sent_is_taken() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    view(&mut rt).next = Some(Next::ListPage {
        cursor: "c1".into(),
    });
    rt.on_capabilities_sweep().await;
    assert!(view(&mut rt).next.is_none());
    armed_on(&mut rt, &Purpose::List);
}

/// A VTA-signed issue document addressed to another community is not sent:
/// the step is taken and the flow ends, saying why.
#[tokio::test]
async fn a_signed_document_for_another_community_ends_the_flow() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    on_detail(&mut rt);
    let v = view(&mut rt);
    v.flow = Some(Flow {
        election: "agm".into(),
        intent: Intent::Ticket,
        step: Step::Issuing,
    });
    v.next = Some(Next::SendIssueDocument(json!({
        "id": "urn:uuid:issue", "recipient": "did:key:zSomeoneElse"
    })));
    rt.on_capabilities_sweep().await;
    let v = view(&mut rt);
    assert!(v.next.is_none());
    assert!(v.flow.is_none());
    assert!(v.pending.is_none());
    assert_eq!(
        status(&mut rt),
        Some((
            Severity::Error,
            "your VTA signed the request for another community than this one".into()
        ))
    );
    assert!(!rt.in_flight.is_busy(DispatchDomain::Elections));
}

/// A VTA step without a VTA ends the flow, and is taken.
#[tokio::test]
async fn a_vta_step_without_a_vta_ends_the_flow() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    on_detail(&mut rt);
    let v = view(&mut rt);
    v.flow = Some(Flow {
        election: "agm".into(),
        intent: Intent::Ticket,
        step: Step::Registering,
    });
    v.next = Some(Next::Register);
    rt.on_capabilities_sweep().await;
    let v = view(&mut rt);
    assert!(v.next.is_none());
    assert!(v.flow.is_none());
    assert_eq!(status(&mut rt), Some((Severity::Error, NO_VTA.into())));
}

/// A VTA step on a busy VTA lane is kept.
#[tokio::test]
async fn a_vta_step_on_a_busy_vta_lane_is_kept() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    on_detail(&mut rt);
    assert!(rt.in_flight.try_begin(DispatchDomain::ElectionsVta));
    view(&mut rt).next = Some(Next::Register);
    rt.on_capabilities_sweep().await;
    assert!(matches!(view(&mut rt).next, Some(Next::Register)));
}

/// A VTA step that starts claims the VTA's lane and is taken.
#[tokio::test]
async fn a_vta_step_that_starts_is_taken() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    on_detail(&mut rt);
    view(&mut rt).next = Some(Next::Register);
    rt.on_capabilities_sweep().await;
    assert!(view(&mut rt).next.is_none());
    assert!(rt.in_flight.is_busy(DispatchDomain::ElectionsVta));
}

// ---- The held notifications, read before a step ----

/// Without a VTA the held notifications are not due any more, and say why.
#[tokio::test]
async fn notifications_without_a_vta_are_unavailable() {
    let mut rt = with_keys().await;
    open_quietly(&mut rt).await;
    view(&mut rt).notified_due = true;
    rt.on_capabilities_sweep().await;
    let v = view(&mut rt);
    assert!(!v.notified_due);
    assert_eq!(
        v.notified_phase,
        NotifiedPhase::Unavailable("no VTA is connected, and it holds them".into())
    );
}

/// On a busy VTA lane they stay due.
#[tokio::test]
async fn notifications_on_a_busy_vta_lane_stay_due() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    view(&mut rt).notified_due = true;
    assert!(rt.in_flight.try_begin(DispatchDomain::ElectionsVta));
    rt.on_capabilities_sweep().await;
    assert!(view(&mut rt).notified_due);
}

/// Asked, they are no longer due.
#[tokio::test]
async fn notifications_asked_are_no_longer_due() {
    let mut rt = with_keys().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    view(&mut rt).notified_due = true;
    rt.on_capabilities_sweep().await;
    assert!(!view(&mut rt).notified_due);
    assert!(rt.in_flight.is_busy(DispatchDomain::ElectionsVta));
}

/// For a persona with no VTA context they are not due either, and the panel
/// says why — ending any next step with it.
#[tokio::test]
async fn notifications_for_a_persona_with_no_context_say_why() {
    let mut rt = without_identity().await;
    connect_vta(&mut rt);
    open_quietly(&mut rt).await;
    view(&mut rt).notified_due = true;
    rt.on_capabilities_sweep().await;
    let v = view(&mut rt);
    assert!(!v.notified_due);
    assert!(v.next.is_none());
    assert_eq!(
        status(&mut rt),
        Some((
            Severity::Error,
            "This persona has no VTA context to hold its voter keys.".into()
        ))
    );
    assert!(!rt.in_flight.is_busy(DispatchDomain::ElectionsVta));
}
