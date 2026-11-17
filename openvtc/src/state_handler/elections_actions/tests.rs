use super::*;
use crate::state_handler::community_request::send_failed;
use crate::state_handler::main_page::elections::Pending;
use openvtc_core::elections::{Refusal, TicketRequest};
use openvtc_core::pending_replies::ReplyKind;
use serde_json::{Value, json};

const VTC: &str = "did:key:zVtc";
const DIGEST: &str = "zQmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";

fn state_with_view() -> State {
    let mut state = State::default();
    state.main_page.content_panel.elections.view = Some(ElectionsView::new(
        VTC.into(),
        PersonaId::default(),
        "did:key:zAlice".into(),
        "Community".into(),
    ));
    state
}

fn view(state: &mut State) -> &mut ElectionsView {
    view_mut(state).unwrap()
}

fn arm(state: &mut State, purpose: Purpose) {
    arm_to(state, purpose, VTC);
}

fn arm_to(state: &mut State, purpose: Purpose, to: &str) {
    view(state).pending = Some(Pending {
        thid: "t1".into(),
        sent_at: Instant::now(),
        purpose,
        to: to.into(),
    });
}

fn inbound(reply: Reply) -> InboundReply {
    InboundReply {
        from: VTC.into(),
        issuer: Some(VTC.into()),
        thid: "t1".into(),
        reply,
    }
}

fn show_raw(state: &str) -> Value {
    json!({
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
        "manifestDigest": DIGEST,
        "state": state,
        "parameters": { "suite": "ps-ddh-bls12381", "votingKey": "zKey" },
        "disclosure": {
            "ballotBox": "did:key:z6MkBox", "ballotBoxOperator": "Ballots Ltd",
            "sameOperator": false, "boardVisibility": "public", "auditors": [],
            "revote": "replace", "coercionResistance": false
        },
        "checkpoints": []
    })
}

fn shown(state: &str) -> Box<ShownElection> {
    Box::new(ShownElection::from_payload(show_raw(state)).unwrap())
}

fn vta(state: &mut State, answer: VtaAnswer) {
    let persona = view(state).persona;
    ElectionsVtaOutcome {
        vtc_did: VTC.into(),
        persona,
        answer,
    }
    .apply(state);
}

fn list_page(items: Value, next: Option<&str>) -> Reply {
    let mut v = json!({ "elections": items });
    if let Some(n) = next {
        v["nextCursor"] = json!(n);
    }
    Reply::List(Box::new(serde_json::from_value(v).unwrap()))
}

fn item(id: &str, state: &str) -> Value {
    json!({
        "electionId": id, "state": state, "binding": false, "ticketHeld": state == "voting",
        "votingOpensAt": "2026-10-02T00:00:00Z", "votingClosesAt": "2026-12-01T00:00:00Z"
    })
}

#[test]
fn the_list_is_read_a_page_at_a_time_and_ordered_by_what_can_be_done() {
    let mut state = state_with_view();
    arm(&mut state, Purpose::List);
    assert!(apply_replies(
        &mut state,
        &mut PendingReplies::default(),
        vec![inbound(list_page(
            json!([item("old", "tallied")]),
            Some("c1")
        ))]
    ));
    assert!(
        view(&mut state).elections.is_empty(),
        "not shown until the last page"
    );
    assert!(matches!(view(&mut state).next, Some(Next::ListPage { ref cursor }) if cursor == "c1"));
    view(&mut state).next = None;
    arm(&mut state, Purpose::List);
    apply_replies(
        &mut state,
        &mut PendingReplies::default(),
        vec![inbound(list_page(json!([item("now", "voting")]), None))],
    );
    let v = view(&mut state);
    assert_eq!(v.phase, ElectionsPhase::Loaded);
    let order: Vec<&str> = v.elections.iter().map(|e| e.election_id.as_str()).collect();
    assert_eq!(order, ["now", "old"]);
}

#[test]
fn an_answer_from_anyone_else_is_dropped() {
    let mut state = state_with_view();
    arm(&mut state, Purpose::List);
    let mut forged = inbound(list_page(json!([]), None));
    forged.from = "did:key:zMallory".into();
    assert!(!apply_replies(
        &mut state,
        &mut PendingReplies::default(),
        vec![forged]
    ));
    let mut forged = inbound(list_page(json!([]), None));
    forged.issuer = Some("did:key:zMallory".into());
    assert!(!apply_replies(
        &mut state,
        &mut PendingReplies::default(),
        vec![forged]
    ));
    assert!(view(&mut state).pending.is_some());
}

/// Voting reads the election again, then asks the VTA for the ticket request.
#[test]
fn a_vote_reads_the_election_again_then_registers() {
    let mut state = state_with_view();
    view(&mut state).screen = Screen::Detail;
    view(&mut state).flow = Some(Flow {
        election: "agm".into(),
        intent: Intent::Vote,
        step: FlowStep::Reading,
    });
    arm(
        &mut state,
        Purpose::Show {
            election: "agm".into(),
            intent: Intent::Vote,
        },
    );
    apply_replies(
        &mut state,
        &mut PendingReplies::default(),
        vec![inbound(Reply::Show(shown("voting")))],
    );
    let v = view(&mut state);
    assert!(matches!(v.next, Some(Next::Register)));
    assert_eq!(v.flow.as_ref().unwrap().step, FlowStep::Registering);
}

#[test]
fn a_closed_election_takes_no_ticket() {
    let mut state = state_with_view();
    view(&mut state).flow = Some(Flow {
        election: "agm".into(),
        intent: Intent::Ticket,
        step: FlowStep::Reading,
    });
    arm(
        &mut state,
        Purpose::Show {
            election: "agm".into(),
            intent: Intent::Ticket,
        },
    );
    apply_replies(
        &mut state,
        &mut PendingReplies::default(),
        vec![inbound(Reply::Show(shown("closed")))],
    );
    let v = view(&mut state);
    assert!(v.flow.is_none() && v.next.is_none());
    assert!(v.status.as_ref().unwrap().text.contains("closed"));
}

/// With no ticket held, voting takes it and stops: the ticket request goes to the community,
/// its answer to the VTA, and the member is told to come back later.
#[test]
fn voting_without_a_ticket_takes_it_and_stops() {
    let mut state = state_with_view();
    view(&mut state).shown = Some(shown("voting"));
    view(&mut state).flow = Some(Flow {
        election: "agm".into(),
        intent: Intent::Vote,
        step: FlowStep::Registering,
    });
    let ticket = TicketRequest {
        election_id: "agm".into(),
        manifest_digest: DIGEST.into(),
        request: json!({ "label": "voter/agm", "id": "z6Mk", "request": { "proof": "z6Mk" } }),
    };
    vta(
        &mut state,
        VtaAnswer::Registered(Ok(Registered::Request(ticket.clone()))),
    );
    assert!(matches!(view(&mut state).next, Some(Next::SendIssue(ref t)) if *t == ticket));
    view(&mut state).next = None;

    arm(
        &mut state,
        Purpose::Issue {
            election: "agm".into(),
        },
    );
    let issued = json!({ "electionId": "agm", "label": "voter/agm", "preCredential": "zPre" });
    apply_replies(
        &mut state,
        &mut PendingReplies::default(),
        vec![inbound(Reply::TicketIssued {
            typed: Box::new(serde_json::from_value(issued.clone()).unwrap()),
            raw: issued.clone(),
        })],
    );
    assert!(matches!(view(&mut state).next, Some(Next::Accept { issued: ref i }) if *i == issued));
    view(&mut state).next = None;

    vta(&mut state, VtaAnswer::Accepted(Ok(())));
    let v = view(&mut state);
    assert!(v.flow.is_none());
    assert_eq!(v.screen, Screen::List, "no ballot after taking the ticket");
    assert!(v.form.is_none());
    assert!(v.status.as_ref().unwrap().text.contains("Come back later"));
    assert!(
        state
            .main_page
            .content_panel
            .elections
            .ticket_taken_recently(VTC, "agm", Instant::now())
    );
}

/// With the ticket held, voting opens the ballot.
#[test]
fn voting_with_a_ticket_held_opens_the_ballot() {
    let mut state = state_with_view();
    view(&mut state).screen = Screen::Detail;
    view(&mut state).shown = Some(shown("voting"));
    view(&mut state).flow = Some(Flow {
        election: "agm".into(),
        intent: Intent::Vote,
        step: FlowStep::Registering,
    });
    vta(
        &mut state,
        VtaAnswer::Registered(Ok(Registered::AlreadyHeld)),
    );
    let v = view(&mut state);
    assert_eq!(v.screen, Screen::Ballot);
    assert!(v.form.is_some() && v.flow.is_none());
}

#[test]
fn a_ballot_is_reviewed_before_it_is_cast() {
    let mut state = state_with_view();
    let s = shown("voting");
    view(&mut state).form = Some(BallotForm::new(s.manifest()));
    view(&mut state).shown = Some(s);
    view(&mut state).screen = Screen::Ballot;
    assert!(reduce(&mut state, &Act::Review));
    assert_eq!(view(&mut state).screen, Screen::Ballot, "unanswered");
    assert!(view(&mut state).form.as_ref().unwrap().error.is_some());
    reduce(&mut state, &Act::BallotToggle);
    reduce(&mut state, &Act::Review);
    assert_eq!(view(&mut state).screen, Screen::Confirm);
    // Back from the confirmation returns to the ballot, answers intact.
    reduce(&mut state, &Act::Back);
    assert_eq!(view(&mut state).screen, Screen::Ballot);
}

/// A built cast drops the ballot and goes to the ballot box; a lost answer keeps the same cast
/// for a resend, a refusal does not.
#[test]
fn a_cast_is_resent_unchanged_only_when_its_answer_was_lost() {
    let mut state = state_with_view();
    let s = shown("voting");
    view(&mut state).form = Some(BallotForm::new(s.manifest()));
    view(&mut state).shown = Some(s);
    view(&mut state).flow = Some(Flow {
        election: "agm".into(),
        intent: Intent::Vote,
        step: FlowStep::Building,
    });
    let cast = Cast {
        document: json!({ "id": "urn:uuid:cast-1", "issuer": "did:key:z6MkOnce" }),
    };
    vta(&mut state, VtaAnswer::Voted(Ok(cast.clone())));
    let v = view(&mut state);
    assert!(
        v.form.is_none(),
        "the ballot is not kept once it is in a cast"
    );
    assert!(matches!(v.next, Some(Next::Deliver(_))));
    v.next = None;

    let persona = v.persona;
    ElectionsCastOutcome {
        vtc_did: VTC.into(),
        persona,
        cast: cast.clone(),
        result: Err(CastError::Unreachable("timed out".into())),
    }
    .apply(&mut state);
    let v = view(&mut state);
    assert!(matches!(
        v.result,
        Some(VoteResult::Failed { resend: true, .. })
    ));
    assert_eq!(v.cast.as_ref().unwrap().id(), "urn:uuid:cast-1");

    ElectionsCastOutcome {
        vtc_did: VTC.into(),
        persona,
        cast,
        result: Err(CastError::Refused {
            status: 422,
            code: Some("voting/ballot/cast:alreadyVoted".into()),
            message: String::new(),
        }),
    }
    .apply(&mut state);
    let v = view(&mut state);
    assert!(v.cast.is_none(), "a refused cast is spent");
    let Some(VoteResult::Failed { why, resend }) = &v.result else {
        panic!("a failure")
    };
    assert!(!resend);
    assert!(why.contains("already voted"));
}

#[test]
fn a_community_refusal_ends_the_flow_in_words() {
    let mut state = state_with_view();
    view(&mut state).flow = Some(Flow {
        election: "agm".into(),
        intent: Intent::Ticket,
        step: FlowStep::Issuing,
    });
    arm(
        &mut state,
        Purpose::Issue {
            election: "agm".into(),
        },
    );
    apply_replies(
        &mut state,
        &mut PendingReplies::default(),
        vec![inbound(Reply::Refused(Refusal {
            code: "vtc/elections/tickets/issue:notEligible".into(),
            message: None,
        }))],
    );
    let v = view(&mut state);
    assert!(v.flow.is_none());
    assert!(v.status.as_ref().unwrap().text.contains("roll"));
}

#[test]
fn back_walks_the_screens_and_closes_from_the_list() {
    let mut state = state_with_view();
    view(&mut state).screen = Screen::Result;
    reduce(&mut state, &Act::Back);
    assert_eq!(view(&mut state).screen, Screen::Detail);
    reduce(&mut state, &Act::Back);
    assert_eq!(view(&mut state).screen, Screen::List);
    reduce(&mut state, &Act::Back);
    assert!(state.main_page.content_panel.elections.view.is_none());
}

/// Another community, holding an election put to the members of this one (VTC), which is
/// itself one of its members.
const HOLDER: &str = "did:key:zHolder";

fn notified(held_by: &str, audience: &str, id: &str) -> NotifiedElection {
    NotifiedElection {
        record_id: format!("hn-{id}-0000000000000"),
        held_by: held_by.into(),
        election_id: id.into(),
        audience: audience.into(),
        originator: held_by.into(),
        relayed_by: vec![audience.into()],
        valid_from: Some("2027-01-01T00:00:00+00:00".into()),
        valid_until: Some("2027-01-08T00:00:00+00:00".into()),
        open_with: "https://trusttasks.org/spec/vtc/elections/show/0.6".into(),
    }
}

/// VTI-NTF-063: the list is the community's own and the held notifications that concern it —
/// a notified election the list already shows is not shown twice, and one for another
/// community not at all.
#[test]
fn vti_ntf_063_the_list_carries_notified_elections_once() {
    let mut state = state_with_view();
    arm(&mut state, Purpose::List);
    apply_replies(
        &mut state,
        &mut PendingReplies::default(),
        vec![inbound(list_page(json!([item("agm", "voting")]), None))],
    );
    vta(
        &mut state,
        VtaAnswer::Notified(Ok(vec![
            notified(HOLDER, VTC, "partners-vote"),
            notified(VTC, VTC, "agm"),
            notified("did:key:zElsewhere", "did:key:zElsewhere", "other"),
        ])),
    );
    let v = view(&mut state);
    assert_eq!(v.notified_phase, NotifiedPhase::Loaded);
    let rows = v.rows();
    assert_eq!(rows.len(), 2);
    assert!(matches!(rows[0], Row::Listed(e) if e.election_id.as_str() == "agm"));
    assert!(matches!(rows[1], Row::Notified(n) if n.election_id == "partners-vote"));
}

/// A notified election put to a party's members is read first presenting nothing; when its
/// community answers `electionUnknown`, the member is asked before anything is presented
/// (VTI-VOT-015, VTI-VOT-016), and only `y` presents.
#[test]
fn vti_vot_016_a_membership_is_presented_only_once_the_member_chooses() {
    let mut state = state_with_view();
    {
        let v = view(&mut state);
        v.take_notified(vec![notified(HOLDER, VTC, "partners-vote")]);
        v.target = HOLDER.into();
        v.opening = Some(notified(HOLDER, VTC, "partners-vote"));
        v.screen = Screen::Detail;
    }
    arm_to(
        &mut state,
        Purpose::Show {
            election: "partners-vote".into(),
            intent: Intent::View,
        },
        HOLDER,
    );
    let mut refusal = inbound(Reply::Refused(Refusal {
        code: "vtc/elections/show:electionUnknown".into(),
        message: None,
    }));
    // From the community the read went to — not the panel's own.
    refusal.from = HOLDER.into();
    refusal.issuer = Some(HOLDER.into());
    assert!(apply_replies(
        &mut state,
        &mut PendingReplies::default(),
        vec![refusal]
    ));
    let v = view(&mut state);
    assert_eq!(v.screen, Screen::Disclose);
    assert!(v.presenting.is_none(), "nothing presented yet");
    let d = v.disclose.clone().unwrap();
    assert_eq!((d.held_by.as_str(), d.member_of.as_str()), (HOLDER, VTC));

    // Any key but `y` goes back, presenting nothing.
    reduce(&mut state, &Act::Back);
    let v = view(&mut state);
    assert_eq!(v.screen, Screen::List);
    assert!(v.presenting.is_none() && v.disclose.is_none());
    assert_eq!(v.target, VTC);

    // `y` reads presenting the membership of the party the election is put to.
    let v = view(&mut state);
    v.screen = Screen::Disclose;
    v.disclose = Some(d);
    present(&mut state, true);
    let v = view(&mut state);
    assert_eq!(v.screen, Screen::Detail);
    assert_eq!(v.target, HOLDER);
    assert_eq!(v.presenting.as_deref(), Some(VTC));
    assert!(matches!(
        v.next,
        Some(Next::ReadPresenting { ref election, ref member_of, .. })
            if election == "partners-vote" && member_of == VTC
    ));
}

/// The VTA's signed read and claim are carried to the community unchanged.
#[test]
fn signed_reads_and_claims_go_to_the_community_as_the_vta_signed_them() {
    let mut state = state_with_view();
    let read = json!({ "id": "urn:uuid:read-1", "type": "https://trusttasks.org/spec/vtc/elections/show/0.6" });
    vta(
        &mut state,
        VtaAnswer::ReadSigned {
            election: "agm".into(),
            intent: Intent::Ticket,
            result: Ok(read.clone()),
        },
    );
    assert!(matches!(
        view(&mut state).next,
        Some(Next::SendShowDocument { ref document, .. }) if *document == read
    ));
    view(&mut state).next = None;
    view(&mut state).flow = Some(Flow {
        election: "agm".into(),
        intent: Intent::Ticket,
        step: FlowStep::Registering,
    });
    let claim = json!({ "id": "urn:uuid:claim-1", "payload": { "presentation": {} } });
    vta(
        &mut state,
        VtaAnswer::Registered(Ok(Registered::Document(claim.clone()))),
    );
    let v = view(&mut state);
    assert!(matches!(v.next, Some(Next::SendIssueDocument(ref d)) if *d == claim));
    assert_eq!(v.flow.as_ref().unwrap().step, FlowStep::Issuing);
}

/// An answer from the community a notified election is held by is taken while the view asks
/// it; the panel's own community answering that thread is not.
#[test]
fn an_answer_is_taken_from_the_community_the_request_went_to() {
    let mut state = state_with_view();
    view(&mut state).target = HOLDER.into();
    arm_to(
        &mut state,
        Purpose::Show {
            election: "agm".into(),
            intent: Intent::View,
        },
        HOLDER,
    );
    // The panel's own community is not the one asked.
    assert!(!apply_replies(
        &mut state,
        &mut PendingReplies::default(),
        vec![inbound(Reply::Show(shown("voting")))]
    ));
    let mut from_holder = inbound(Reply::Show(shown("voting")));
    from_holder.from = HOLDER.into();
    from_holder.issuer = Some(HOLDER.into());
    assert!(apply_replies(
        &mut state,
        &mut PendingReplies::default(),
        vec![from_holder]
    ));
    assert!(view(&mut state).shown.is_some());
}

/// Once the view has taken its answer, or its send failed, the inbound gate no longer admits an
/// answer on that thread from a community this persona does not belong to.
#[test]
fn an_answer_taken_or_failed_is_no_longer_awaited_at_the_gate() {
    let election = openvtc_core::pending_replies::Purpose::ElectionAnswer;
    // Taken.
    let mut state = state_with_view();
    arm(&mut state, Purpose::List);
    let mut pending = PendingReplies::default();
    pending.record("t1", VTC, election.clone());
    assert!(apply_replies(
        &mut state,
        &mut pending,
        vec![inbound(list_page(json!([]), None))]
    ));
    assert!(!pending.is_awaited(ReplyKind::ElectionAnswer, VTC, "t1"));

    // Its send failed.
    let mut state = state_with_view();
    arm(&mut state, Purpose::List);
    pending.record("t1", VTC, election);
    let persona = view(&mut state).persona;
    send_failed::<Elections>(
        &mut state,
        &mut pending,
        SendOutcome {
            vtc_did: VTC.into(),
            persona,
            thid: "t1".into(),
            result: Err("unreachable".into()),
        },
    );
    assert!(!pending.is_awaited(ReplyKind::ElectionAnswer, VTC, "t1"));
    assert!(view(&mut state).pending.is_none());
}

// ---- plan / plan_next / plan_notified: pure, nothing changed before a claim ----

fn the_send(effect: &ElectionsEffect) -> &Send {
    match effect.steps.last() {
        Some(Step::Send(send)) => send,
        _ => panic!("the last step is a send"),
    }
}

fn with_listed() -> State {
    let mut state = state_with_view();
    view(&mut state).take_page(
        vec![serde_json::from_value(item("agm", "registration")).unwrap()],
        true,
    );
    state
}

/// Opening an election is planned as its read, the detail screen committed
/// only once the read is under way.
#[test]
fn a_show_is_planned_with_the_detail_screen_as_the_commit() {
    let mut state = with_listed();
    let config = crate::state_handler::dispatch_util::test_config();
    let effect = plan(&mut state, &config, false, Act::Show);
    let send = the_send(&effect);
    assert_eq!(send.to, VTC);
    assert_eq!(
        send.purpose,
        Purpose::Show {
            election: "agm".into(),
            intent: Intent::View
        }
    );
    assert_eq!(
        send.commit,
        Some(Commit::Showing {
            target: VTC.into(),
            opening: None,
        })
    );
    assert_eq!(send.refusal, Some(super::Refusal::Busy));
    let v = view(&mut state);
    assert_eq!(v.screen, Screen::List);
    assert!(v.status.is_none());
}

/// Planning a show changes no target: a read refused on a busy lane leaves
/// the one an earlier read set, and the commit sets it once under way.
#[test]
fn a_show_keeps_the_earlier_target_until_its_read_is_under_way() {
    let mut state = with_listed();
    view(&mut state).target = "did:key:zEarlierHolder".into();
    view(&mut state).presenting = Some("did:key:zParty".into());
    let config = crate::state_handler::dispatch_util::test_config();
    let effect = plan(&mut state, &config, false, Act::Show);
    let v = view(&mut state);
    assert_eq!(v.target, "did:key:zEarlierHolder");
    assert_eq!(v.presenting.as_deref(), Some("did:key:zParty"));

    let Some(Step::Send(send)) = effect.steps.into_iter().last() else {
        panic!("a send");
    };
    send.commit.unwrap().apply(view(&mut state));
    let v = view(&mut state);
    assert_eq!(v.target, VTC);
    assert!(v.presenting.is_none());
    assert_eq!(v.screen, Screen::Detail);
}

/// A ticket is planned as the election's read again, the flow committed only
/// once it is under way.
#[test]
fn a_ticket_is_planned_with_its_flow_as_the_commit() {
    let mut state = state_with_view();
    let v = view(&mut state);
    v.screen = Screen::Detail;
    v.shown = Some(shown("registration"));
    let config = crate::state_handler::dispatch_util::test_config();
    let effect = plan(&mut state, &config, true, Act::TakeTicket);
    let send = the_send(&effect);
    assert_eq!(
        send.commit,
        Some(Commit::Reading(Flow {
            election: "agm".into(),
            intent: Intent::Ticket,
            step: FlowStep::Reading,
        }))
    );
    assert!(view(&mut state).flow.is_none());
}

/// A read presenting a membership is the VTA's to sign: the flow starts now
/// and nothing is sent.
#[test]
fn a_ticket_presenting_a_membership_is_planned_with_nothing_to_send() {
    let mut state = state_with_view();
    let v = view(&mut state);
    v.screen = Screen::Detail;
    v.shown = Some(shown("registration"));
    v.presenting = Some("did:key:zParty".into());
    let config = crate::state_handler::dispatch_util::test_config();
    let effect = plan(&mut state, &config, true, Act::TakeTicket);
    assert!(effect.steps.is_empty());
    let v = view(&mut state);
    assert!(v.flow.is_some());
    assert!(matches!(v.next, Some(Next::ReadPresenting { .. })));
}

/// The list is read from the panel's own community; an election, and a
/// document the VTA signed, from the community holding it.
#[test]
fn the_list_goes_to_the_panels_community_and_an_election_to_its_holder() {
    let mut state = state_with_view();
    view(&mut state).target = "did:key:zHolder".into();
    let page = plan_next(
        &mut state,
        false,
        Next::ListPage {
            cursor: "c1".into(),
        },
    );
    assert_eq!(the_send(&page).to, VTC);
    view(&mut state).shown = Some(shown("registration"));
    let issue = plan_next(
        &mut state,
        false,
        Next::SendIssueDocument(json!({ "id": "urn:uuid:x" })),
    );
    let send = the_send(&issue);
    assert_eq!(send.to, "did:key:zHolder");
    assert_eq!(
        send.purpose,
        Purpose::Issue {
            election: "agm".into()
        }
    );
    assert_eq!(issue.taken, Taken::ByLastStep);
}

/// A refresh step on a busy lane, or while the view waits, is not taken.
#[test]
fn a_refresh_step_on_a_busy_lane_is_planned_as_not_taken() {
    let mut state = state_with_view();
    let effect = plan_next(&mut state, true, Next::Refresh);
    assert!(effect.steps.is_empty());
    assert_eq!(effect.taken, Taken::No);
    arm(&mut state, Purpose::List);
    assert_eq!(plan_next(&mut state, false, Next::Refresh).taken, Taken::No);
}

/// The held notifications are asked only when due, with a VTA whose lane is
/// free; no longer due only once asked — or at once with no VTA to ask.
#[test]
fn the_held_notifications_are_planned_only_when_due_and_free() {
    let mut state = state_with_view();
    assert!(plan_notified(&mut state, true, false).is_none(), "not due");

    view(&mut state).notified_due = true;
    assert!(plan_notified(&mut state, true, true).is_none(), "busy");
    assert!(view(&mut state).notified_due);

    assert!(matches!(
        plan_notified(&mut state, true, false),
        Some(Step::Ask {
            ask: VtaAsk::Notified,
            commit: Some(Commit::NotifiedAsked),
        })
    ));
    assert!(view(&mut state).notified_due, "due until asked");

    assert!(plan_notified(&mut state, false, false).is_none());
    let v = view(&mut state);
    assert!(!v.notified_due);
    assert!(matches!(v.notified_phase, NotifiedPhase::Unavailable(_)));
}
