use super::*;
use openvtc_core::elections::{Refusal, TicketRequest};
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
    view(state).pending = Some(Pending {
        thid: "t1".into(),
        sent_at: Instant::now(),
        purpose,
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
    assert!(!apply_replies(&mut state, vec![forged]));
    let mut forged = inbound(list_page(json!([]), None));
    forged.issuer = Some("did:key:zMallory".into());
    assert!(!apply_replies(&mut state, vec![forged]));
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
        step: Step::Reading,
    });
    arm(
        &mut state,
        Purpose::Show {
            election: "agm".into(),
            intent: Intent::Vote,
        },
    );
    apply_replies(&mut state, vec![inbound(Reply::Show(shown("voting")))]);
    let v = view(&mut state);
    assert!(matches!(v.next, Some(Next::Register)));
    assert_eq!(v.flow.as_ref().unwrap().step, Step::Registering);
}

#[test]
fn a_closed_election_takes_no_ticket() {
    let mut state = state_with_view();
    view(&mut state).flow = Some(Flow {
        election: "agm".into(),
        intent: Intent::Ticket,
        step: Step::Reading,
    });
    arm(
        &mut state,
        Purpose::Show {
            election: "agm".into(),
            intent: Intent::Ticket,
        },
    );
    apply_replies(&mut state, vec![inbound(Reply::Show(shown("closed")))]);
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
        step: Step::Registering,
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
        step: Step::Registering,
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
        step: Step::Building,
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
        step: Step::Issuing,
    });
    arm(
        &mut state,
        Purpose::Issue {
            election: "agm".into(),
        },
    );
    apply_replies(
        &mut state,
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
