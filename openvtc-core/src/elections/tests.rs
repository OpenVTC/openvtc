use super::*;
use serde_json::json;

const VTC: &str = "did:key:z6MkCommunity";
const BOX: &str = "did:key:z6MkBallotBox";
const DIGEST: &str = "zQmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
const CAST_KEY: &str = "did:key:z6MkOneTimeCastKey";

fn manifest(secrecy: &str) -> Value {
    json!({
        "electionId": "agm-2027",
        "community": VTC,
        "title": "Annual general meeting",
        "questions": [
            { "key": "chair", "type": "choice", "text": "Who chairs?",
              "options": [{ "key": "ann", "label": "Ann" }, { "key": "bo" }],
              "minSelections": 1, "maxSelections": 1, "optional": false },
            { "key": "board", "type": "choice",
              "options": [{ "key": "a" }, { "key": "b" }, { "key": "c" }],
              "minSelections": 1, "maxSelections": 2, "optional": true },
            { "key": "logo", "type": "ranking",
              "options": [{ "key": "x" }, { "key": "y" }, { "key": "z" }],
              "partial": false, "optional": false },
            { "key": "venue", "type": "ranking",
              "options": [{ "key": "p" }, { "key": "q" }],
              "partial": true, "optional": false },
            { "key": "budget", "type": "score",
              "options": [{ "key": "ops" }, { "key": "events" }],
              "min": 0, "max": 5, "optional": false },
            { "key": "notes", "type": "text", "maxLength": 5, "optional": true }
        ],
        "secrecy": secrecy,
        "roll": { "rule": "members" },
        "registrationOpensAt": "2026-10-01T00:00:00Z",
        "votingOpensAt": "2026-10-02T00:00:00Z",
        "votingClosesAt": "2026-12-01T00:00:00Z",
        "revote": "replace",
        "board": { "visibility": "public", "auditors": [] },
        "ballotBox": BOX,
        "binding": false,
        "allowEarlyClose": false,
        "resultsBeforeClose": false,
        "textReleaseThreshold": 10
    })
}

fn shown_raw(secrecy: &str, ceremony: bool) -> Value {
    let mut v = json!({
        "manifest": manifest(secrecy),
        "manifestDigest": DIGEST,
        "state": "voting",
        "parameters": { "suite": "ps-ddh-bls12381", "votingKey": "zVotingKey" },
        "disclosure": {
            "ballotBox": BOX, "ballotBoxOperator": "Example Ballots Ltd",
            "sameOperator": true, "boardVisibility": "public", "auditors": [],
            "revote": "replace", "coercionResistance": false
        },
        "checkpoints": []
    });
    if secrecy != "open" {
        v["manifest"]["trustees"] =
            json!({ "dids": ["did:key:z6MkT1", "did:key:z6MkT2"], "threshold": 2 });
        if ceremony {
            v["ceremony"] = json!([{ "id": "urn:uuid:step-1" }]);
        }
    }
    v
}

fn shown(secrecy: &str) -> ShownElection {
    ShownElection::from_payload(shown_raw(secrecy, true)).expect("a valid show answer")
}

/// A full, valid ballot for the fixture's six questions.
fn good() -> Value {
    json!({
        "electionId": "agm-2027",
        "manifestDigest": DIGEST,
        "answers": [
            { "question": "chair", "choice": ["ann"] },
            { "question": "board", "choice": ["a", "c"] },
            { "question": "logo", "ranking": ["z", "x", "y"] },
            { "question": "venue", "ranking": ["q"] },
            { "question": "budget", "scores": { "ops": 3, "events": 5 } },
            { "question": "notes", "text": "héllo" }
        ]
    })
}

fn with_answer(i: usize, answer: Value) -> Value {
    let mut b = good();
    b["answers"][i] = answer;
    b
}

fn check(b: &Value) -> Result<(), BallotError> {
    check_ballot(shown("open").manifest(), DIGEST, b)
}

#[test]
fn a_complete_ballot_passes() {
    check(&good()).unwrap();
}

#[test]
fn a_ballot_for_another_election_or_manifest_is_refused() {
    let mut b = good();
    b["electionId"] = json!("other");
    assert_eq!(check(&b), Err(BallotError::ManifestMismatch));
    let mut b = good();
    b["manifestDigest"] = json!("zQmAnotherDigestAnotherDigest2");
    assert_eq!(check(&b), Err(BallotError::ManifestMismatch));
}

#[test]
fn choice_counts_and_options_are_held() {
    let none = with_answer(0, json!({ "question": "chair", "choice": [] }));
    assert!(matches!(
        check(&none),
        Err(BallotError::SelectionCount {
            min: 1,
            max: 1,
            chosen: 0,
            ..
        })
    ));
    let too_many = with_answer(1, json!({ "question": "board", "choice": ["a", "b", "c"] }));
    assert!(matches!(
        check(&too_many),
        Err(BallotError::SelectionCount { chosen: 3, .. })
    ));
    let unknown = with_answer(0, json!({ "question": "chair", "choice": ["cy"] }));
    assert_eq!(
        check(&unknown),
        Err(BallotError::UnknownOption("chair".into()))
    );
    let twice = with_answer(1, json!({ "question": "board", "choice": ["a", "a"] }));
    assert_eq!(
        check(&twice),
        Err(BallotError::UnknownOption("board".into()))
    );
    let wrong = with_answer(0, json!({ "question": "chair", "ranking": ["ann"] }));
    assert_eq!(
        check(&wrong),
        Err(BallotError::WrongKind("chair".into(), "a choice"))
    );
}

#[test]
fn a_full_ranking_ranks_every_option_and_a_partial_one_at_least_one() {
    let short = with_answer(2, json!({ "question": "logo", "ranking": ["z", "x"] }));
    assert_eq!(check(&short), Err(BallotError::RankEvery("logo".into())));
    let empty = with_answer(3, json!({ "question": "venue", "ranking": [] }));
    assert_eq!(check(&empty), Err(BallotError::RankSome("venue".into())));
    let repeated = with_answer(2, json!({ "question": "logo", "ranking": ["z", "z", "x"] }));
    assert_eq!(
        check(&repeated),
        Err(BallotError::UnknownOption("logo".into()))
    );
}

#[test]
fn a_score_scores_every_option_within_bounds() {
    let partial = with_answer(4, json!({ "question": "budget", "scores": { "ops": 1 } }));
    assert_eq!(
        check(&partial),
        Err(BallotError::ScoreEvery("budget".into()))
    );
    let high = with_answer(
        4,
        json!({ "question": "budget", "scores": { "ops": 1, "events": 6 } }),
    );
    assert_eq!(
        check(&high),
        Err(BallotError::ScoreBounds {
            key: "budget".into(),
            min: 0,
            max: 5
        })
    );
    let stray = with_answer(
        4,
        json!({ "question": "budget", "scores": { "ops": 1, "events": 1, "x": 1 } }),
    );
    assert_eq!(check(&stray), Err(BallotError::ScoreEvery("budget".into())));
}

#[test]
fn text_is_bounded_in_unicode_scalar_values() {
    // Five scalar values, more than five bytes: within bounds.
    check(&with_answer(
        5,
        json!({ "question": "notes", "text": "ééééé" }),
    ))
    .unwrap();
    let long = with_answer(5, json!({ "question": "notes", "text": "abcdef" }));
    assert_eq!(
        check(&long),
        Err(BallotError::TextTooLong {
            key: "notes".into(),
            max: 5
        })
    );
}

#[test]
fn only_an_optional_question_may_be_abstained() {
    check(&with_answer(
        1,
        json!({ "question": "board", "abstain": true }),
    ))
    .unwrap();
    let required = with_answer(0, json!({ "question": "chair", "abstain": true }));
    assert_eq!(
        check(&required),
        Err(BallotError::NotOptional("chair".into()))
    );
    let both = with_answer(
        1,
        json!({ "question": "board", "abstain": true, "choice": ["a"] }),
    );
    assert_eq!(check(&both), Err(BallotError::OneAnswer("board".into())));
}

#[test]
fn every_question_is_answered_exactly_once() {
    let mut missing = good();
    missing["answers"].as_array_mut().unwrap().remove(5);
    assert_eq!(
        check(&missing),
        Err(BallotError::Unanswered("notes".into()))
    );
    let mut twice = good();
    twice["answers"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "question": "chair", "choice": ["bo"] }));
    assert_eq!(
        check(&twice),
        Err(BallotError::AnsweredTwice("chair".into()))
    );
    let unknown = with_answer(0, json!({ "question": "nope", "choice": ["ann"] }));
    assert_eq!(check(&unknown), Err(BallotError::NoQuestion("nope".into())));
}

#[test]
fn a_blank_draft_is_incomplete_and_a_filled_one_passes() {
    let s = shown("open");
    let mut draft = BallotDraft::new(s.manifest());
    assert_eq!(draft.answers.len(), 6);
    assert!(check(&draft.to_ballot("agm-2027", DIGEST)).is_err());
    draft.answers[0].1 = AnswerDraft::Choice(vec!["bo".into()]);
    draft.answers[1].2 = true; // abstain on the optional choice
    draft.answers[2].1 = AnswerDraft::Ranking(vec!["x".into(), "y".into(), "z".into()]);
    draft.answers[3].1 = AnswerDraft::Ranking(vec!["p".into()]);
    draft.answers[4].1 =
        AnswerDraft::Scores(vec![("ops".into(), Some(0)), ("events".into(), None)]);
    draft.answers[5].2 = true;
    assert_eq!(
        check(&draft.to_ballot("agm-2027", DIGEST)),
        Err(BallotError::ScoreEvery("budget".into())),
        "an unscored option is left out, and named"
    );
    draft.answers[4].1 =
        AnswerDraft::Scores(vec![("ops".into(), Some(0)), ("events".into(), Some(2))]);
    check(&draft.to_ballot("agm-2027", DIGEST)).unwrap();
}

#[test]
fn a_draft_never_shows_its_answers_in_debug() {
    let mut draft = BallotDraft::new(shown("open").manifest());
    draft.answers[0].1 = AnswerDraft::Choice(vec!["ann".into()]);
    let text = format!("{draft:?}");
    assert!(!text.contains("ann") && !text.contains("chair"), "{text}");
}

// ---------------------------------------------------------------------------
// What goes where
// ---------------------------------------------------------------------------

fn client() -> VtaClient {
    VtaClient::new("https://vta.example")
}

#[test]
fn register_carries_the_manifest_as_received_and_no_member() {
    let vta = client();
    let v = Voter {
        vta: &vta,
        context_id: "ctx-persona",
        community: VTC,
    };
    let mut raw = shown_raw("open", false);
    // A spelling the generated type would rewrite: the VTA must see this one.
    raw["manifest"]["votingOpensAt"] = json!("2026-10-02T00:00:00.000Z");
    let s = ShownElection::from_payload(raw).unwrap();
    let p = register_payload(&v, &s);
    assert_eq!(p["contextId"], "ctx-persona");
    assert_eq!(p["community"], VTC);
    assert!(
        p.get("member").is_none(),
        "the VTA does not sign the ticket request as the member"
    );
    assert_eq!(p["manifest"]["votingOpensAt"], "2026-10-02T00:00:00.000Z");
    serde_json::from_value::<pcs_register::Payload>(p).expect("a valid register payload");
}

#[test]
fn a_register_answer_under_another_digest_takes_no_ticket() {
    let answer = json!({
        "electionId": "agm-2027",
        "manifestDigest": "zQmAnotherDigestAnotherDigest2",
        "request": { "label": "voter/agm-2027", "id": "z6MkRequestXd", "request": { "proof": "z6MkProof" } }
    });
    let typed: pcs_register::Response = serde_json::from_value(answer.clone()).unwrap();
    assert!(registered_from(&typed, &answer, DIGEST).is_err());
    let mut ok = answer.clone();
    ok["manifestDigest"] = json!(DIGEST);
    let typed: pcs_register::Response = serde_json::from_value(ok.clone()).unwrap();
    let Registered::Request(t) = registered_from(&typed, &ok, DIGEST).unwrap() else {
        panic!("a request")
    };
    // It becomes vtc/elections/tickets/issue/0.1 as the persona.
    let doc = build(&Request::IssueTicket(t), "did:key:z6MkMember", VTC).unwrap();
    assert_eq!(
        doc.type_uri.to_string(),
        "https://trusttasks.org/spec/vtc/elections/tickets/issue/0.1"
    );
    assert_eq!(doc.payload["request"]["label"], "voter/agm-2027");
    assert_eq!(doc.issuer.as_deref(), Some("did:key:z6MkMember"));
}

#[test]
fn accept_hands_over_the_communitys_answer_without_ext() {
    let vta = client();
    let v = Voter {
        vta: &vta,
        context_id: "ctx",
        community: VTC,
    };
    let issued = json!({
        "electionId": "agm-2027", "label": "voter/agm-2027", "preCredential": "zPre",
        "ext": { "org.example": {} }
    });
    let p = accept_payload(&v, &shown("open"), &issued);
    assert_eq!(
        p["response"],
        json!({ "electionId": "agm-2027", "label": "voter/agm-2027", "preCredential": "zPre" })
    );
    assert_eq!(p["electionId"], "agm-2027");
    serde_json::from_value::<pcs_accept::Payload>(p).expect("a valid accept payload");
}

#[test]
fn vote_takes_the_ceremony_only_where_the_election_is_encrypted() {
    let vta = client();
    let v = Voter {
        vta: &vta,
        context_id: "ctx",
        community: VTC,
    };
    let (p, encrypted) = vote_payload(&v, &shown("open"), &good()).unwrap();
    assert!(!encrypted && p.get("ceremony").is_none());
    serde_json::from_value::<pcs_vote::Payload>(p).expect("a valid vote payload");

    let mut sealed_ballot = good();
    sealed_ballot["answers"] = json!([
        { "question": "chair", "choice": ["ann"] },
        { "question": "board", "abstain": true },
        { "question": "logo", "ranking": ["x", "y", "z"] },
        { "question": "venue", "ranking": ["p"] },
        { "question": "budget", "scores": { "ops": 0, "events": 0 } },
        { "question": "notes", "abstain": true }
    ]);
    let (p, encrypted) = vote_payload(&v, &shown("sealed"), &sealed_ballot).unwrap();
    assert!(encrypted);
    assert_eq!(p["ceremony"][0]["id"], "urn:uuid:step-1");
    serde_json::from_value::<pcs_vote_encrypted::Payload>(p).expect("a valid encrypted vote");

    let no_key = ShownElection::from_payload(shown_raw("sealed", false)).unwrap();
    assert_eq!(
        vote_payload(&v, &no_key, &sealed_ballot).unwrap_err(),
        VoteError::NoCeremony
    );
    // A ballot breaking a rule is refused before the VTA is asked.
    let bad = with_answer(0, json!({ "question": "chair", "choice": [] }));
    assert!(matches!(
        vote_payload(&v, &shown("open"), &bad),
        Err(VoteError::Ballot(_))
    ));
}

/// Nothing a member sends its community carries a ballot, a cast or a receipt — whichever
/// request it is.
#[test]
fn nothing_sent_to_the_community_carries_a_ballot_or_a_cast() {
    let requests = [
        Request::List { cursor: None },
        Request::List {
            cursor: Some("c1".into()),
        },
        Request::Show {
            election_id: "agm-2027".into(),
        },
        Request::IssueTicket(TicketRequest {
            election_id: "agm-2027".into(),
            manifest_digest: DIGEST.into(),
            request: json!({ "label": "voter/agm-2027", "id": "z6MkRequestXd", "request": { "proof": "z6MkProof" } }),
        }),
    ];
    for r in &requests {
        let doc = build(r, "did:key:z6MkMember", VTC).unwrap();
        let text = serde_json::to_string(&doc).unwrap();
        for word in [
            "ballot",
            "answers",
            "cast",
            "receipt",
            "choice",
            "castDocument",
        ] {
            assert!(!text.contains(&format!("\"{word}\"")), "{word} in {text}");
        }
        assert!(doc.type_uri.to_string().starts_with(TYPE_PREFIX));
    }
}

#[test]
fn receipt_payload_carries_the_whole_receipt() {
    let vta = client();
    let v = Voter {
        vta: &vta,
        context_id: "ctx",
        community: VTC,
    };
    let (cast, answer) = cast_and_receipt();
    let receipt = read_receipt(answer.clone(), BOX, &cast, BOX).unwrap();
    let p = receipt_payload(&v, "agm-2027", &receipt);
    assert_eq!(p["receipt"], answer);
    serde_json::from_value::<pcs_receipt::Payload>(p).expect("a valid receipt payload");
}

// ---------------------------------------------------------------------------
// The receipt
// ---------------------------------------------------------------------------

fn cast_and_receipt() -> (Cast, Value) {
    let cast = Cast {
        document: json!({
            "id": "urn:uuid:cast-1",
            "type": "https://trusttasks.org/spec/voting/ballot/cast/0.1#request",
            "issuer": CAST_KEY,
            "recipient": BOX,
            "issuedAt": "2026-11-01T10:00:00Z",
            "payload": {},
            "proof": {}
        }),
    };
    let answer = json!({
        "id": "urn:uuid:receipt-1",
        "type": "https://trusttasks.org/spec/voting/ballot/cast/0.1#response",
        "issuer": BOX,
        "recipient": CAST_KEY,
        "threadId": "urn:uuid:cast-1",
        "payload": {
            "electionId": "agm-2027", "outcome": "replaced", "leafIndex": 7,
            "entryHash": DIGEST, "receiptToken": "zToken",
            "head": { "electionId": "agm-2027", "treeSize": 8, "rootHash": DIGEST,
                      "issuedAt": "2026-11-01T10:00:01Z" }
        }
    });
    (cast, answer)
}

#[test]
fn a_receipt_from_the_ballot_box_for_this_cast_is_read() {
    let (cast, answer) = cast_and_receipt();
    let r = read_receipt(answer, BOX, &cast, BOX).unwrap();
    assert_eq!(r.outcome, ReceiptOutcome::Replaced);
    assert_eq!(r.leaf_index, 7);
}

#[test]
fn a_receipt_signed_by_anyone_else_is_refused() {
    let (cast, answer) = cast_and_receipt();
    assert!(matches!(
        read_receipt(answer, "did:key:z6MkMallory", &cast, BOX),
        Err(CastError::WrongSigner { .. })
    ));
}

#[test]
fn a_receipt_for_another_cast_is_refused() {
    let (cast, mut answer) = cast_and_receipt();
    answer["threadId"] = json!("urn:uuid:another-cast");
    assert_eq!(
        read_receipt(answer, BOX, &cast, BOX).unwrap_err(),
        CastError::WrongThread
    );
}

#[test]
fn a_receipt_addressed_to_someone_else_is_refused() {
    let (cast, mut answer) = cast_and_receipt();
    answer["recipient"] = json!("did:key:z6MkTheMember");
    assert_eq!(
        read_receipt(answer, BOX, &cast, BOX).unwrap_err(),
        CastError::WrongRecipient
    );
}

#[test]
fn a_receipt_of_another_type_or_shape_is_unreadable() {
    let (cast, mut answer) = cast_and_receipt();
    answer["type"] = json!("https://trusttasks.org/spec/voting/board/head/0.1#response");
    assert!(matches!(
        read_receipt(answer, BOX, &cast, BOX),
        Err(CastError::Unreadable(_))
    ));
    let (cast, mut answer) = cast_and_receipt();
    answer["payload"]["outcome"] = json!("lost");
    assert!(matches!(
        read_receipt(answer, BOX, &cast, BOX),
        Err(CastError::Unreadable(_))
    ));
}

#[tokio::test]
async fn an_unsigned_receipt_proves_nothing() {
    let (cast, answer) = cast_and_receipt();
    let resolver = vta_sdk::trust_task_proof::TrustTaskVmResolver::default();
    assert!(matches!(
        check_receipt(answer, &cast, BOX, &resolver).await,
        Err(CastError::Unproven(_))
    ));
}

#[test]
fn a_refusal_is_read_whatever_its_status() {
    let refusal = json!({
        "type": "https://trusttasks.org/spec/trust-task-error/0.1",
        "payload": { "code": "voting/ballot/cast:alreadyVoted", "message": "once" }
    })
    .to_string();
    let e = read_cast_answer(200, &refusal).unwrap_err();
    assert!(matches!(&e, CastError::Refused { code: Some(c), .. } if c.ends_with("alreadyVoted")));
    assert!(e.to_string().contains("already voted"));
    assert!(!e.resendable());
    assert!(matches!(
        read_cast_answer(502, "Bad gateway"),
        Err(CastError::Refused {
            status: 502,
            code: None,
            ..
        })
    ));
    assert!(CastError::Unreachable("timed out".into()).resendable());
}

#[test]
fn every_cast_refusal_code_has_its_own_words() {
    let codes = [
        "electionUnknown",
        "notOpen",
        "manifestMismatch",
        "ballotInvalid",
        "classMismatch",
        "alreadyVoted",
        "castInvalid",
        "wrongLevel",
    ];
    let words: HashSet<String> = codes
        .iter()
        .map(|c| cast_refusal_words(Some(&format!("voting/ballot/cast:{c}")), ""))
        .collect();
    assert_eq!(
        words.len(),
        codes.len(),
        "each code says something different"
    );
    assert!(
        words.iter().all(|w| !w.contains("refused the cast (")),
        "none falls to the default"
    );
}

#[test]
fn community_and_vta_refusals_are_in_words() {
    let r = Refusal {
        code: "vtc/elections/tickets/issue:notEligible".into(),
        message: None,
    };
    assert!(r.explain().contains("roll"));
    let r = Refusal {
        code: "unsupportedType".into(),
        message: None,
    };
    assert!(r.explain().contains("vtc/elections/list/0.3"));
    let e = VtaCallError::Refused {
        code: "vta/pcs/voter/register:ticketHeld".into(),
        message: String::new(),
    };
    assert!(e.is("ticketHeld"));
    assert!(!e.is("notFound"));
    let e = VtaCallError::Refused {
        code: "vta/pcs/vote:notOpen".into(),
        message: String::new(),
    };
    assert!(e.to_string().contains("not open"));
}

#[test]
fn the_ballot_box_endpoint_is_the_https_trust_task_door() {
    let doc = json!({ "service": [
        { "id": "#didcomm", "type": "DIDCommMessaging", "serviceEndpoint": "did:web:mediator" },
        { "id": "#rest", "type": "TrustTaskHTTPS", "serviceEndpoint": "https://box.example/v1" }
    ]});
    assert_eq!(
        ballot_box_endpoint(&doc, BOX).unwrap(),
        "https://box.example/v1"
    );
    assert_eq!(
        cast_url("https://box.example/v1/"),
        "https://box.example/v1/trust-tasks"
    );
    let plain = json!({ "service": [
        { "id": "#rest", "type": "TrustTaskHTTPS", "serviceEndpoint": "http://box.example" }
    ]});
    assert_eq!(
        ballot_box_endpoint(&plain, BOX),
        Err(CastError::NoEndpoint(BOX.into()))
    );
}

#[test]
fn the_pause_before_a_cast_is_bounded() {
    for _ in 0..50 {
        assert!(cast_delay() < MAX_CAST_DELAY);
    }
}

#[test]
fn replies_are_classified_by_thread() {
    let doc: TrustTask<Value> = serde_json::from_value(json!({
        "id": "urn:uuid:00000000-0000-4000-8000-000000000002",
        "type": "https://trusttasks.org/spec/vtc/elections/show/0.3#response",
        "issuer": VTC,
        "recipient": "did:key:z6MkMember",
        "threadId": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "payload": shown_raw("open", false)
    }))
    .unwrap();
    let (thid, reply) = parse_reply(&doc).unwrap();
    assert_eq!(thid, "urn:uuid:00000000-0000-4000-8000-000000000001");
    let Reply::Show(s) = reply else {
        panic!("a show")
    };
    assert!(s.voting_open());
    assert_eq!(s.title(), "Annual general meeting");
    assert!(is_reply_type(
        "https://trusttasks.org/spec/vtc/elections/list/0.3#response"
    ));
    assert!(!is_reply_type(
        "https://trusttasks.org/spec/vtc/rooms/offers/list/0.4#response"
    ));
}

#[test]
fn the_list_puts_what_can_be_done_first() {
    let item = |id: &str, state: &str, closes: &str| -> ElectionListItem {
        serde_json::from_value(json!({
            "electionId": id, "state": state, "binding": false, "ticketHeld": false,
            "votingOpensAt": "2026-10-01T00:00:00Z", "votingClosesAt": closes
        }))
        .unwrap()
    };
    let mut items = vec![
        item("done", "tallied", "2026-01-01T00:00:00Z"),
        item("soon", "registered", "2027-01-01T00:00:00Z"),
        item("reg", "registration", "2027-01-01T00:00:00Z"),
        item("late", "voting", "2027-02-01T00:00:00Z"),
        item("now", "voting", "2026-12-01T00:00:00Z"),
    ];
    sort_for_display(&mut items);
    let order: Vec<&str> = items.iter().map(|i| i.election_id.as_str()).collect();
    assert_eq!(order, ["now", "late", "reg", "soon", "done"]);
}

/// VTI-VOT-065: voting/_shared/0.3 lets `textReleaseThreshold` be as low as 1, and a show
/// answer carrying one below 10 is read, not refused; 0 is still no manifest.
#[test]
fn vti_vot_065_a_threshold_below_ten_is_read_and_zero_is_refused() {
    for threshold in [1, 9] {
        let mut raw = shown_raw("open", false);
        raw["manifest"]["textReleaseThreshold"] = json!(threshold);
        let shown = ShownElection::from_payload(raw).expect("a threshold of 1 - 9 is valid");
        assert_eq!(shown.text_release_threshold(), threshold);
    }
    let mut raw = shown_raw("open", false);
    raw["manifest"]["textReleaseThreshold"] = json!(0);
    assert!(ShownElection::from_payload(raw).is_err());
}

/// VTI-VOT-090: below 10 the member is told, before a ticket and when voting, how soon written
/// answers come out and that one may identify its author; at 10 or above, nothing.
#[test]
fn vti_vot_090_a_threshold_below_ten_carries_its_warning() {
    assert_eq!(shown("open").text_release_warning(), None);
    assert_eq!(text_release_warning(10), None);
    assert_eq!(text_release_warning(25), None);
    assert_eq!(
        text_release_warning(3).as_deref(),
        Some(
            "Written answers are released once 3 ballots are counted. Below 10, a written \
             answer may identify who wrote it."
        )
    );
    assert_eq!(
        text_release_warning(1).as_deref(),
        Some(
            "Written answers are released once 1 ballot is counted. Below 10, a written \
             answer may identify who wrote it."
        )
    );
    let mut raw = shown_raw("open", false);
    raw["manifest"]["textReleaseThreshold"] = json!(4);
    let shown = ShownElection::from_payload(raw).expect("valid");
    assert_eq!(shown.text_release_warning(), text_release_warning(4));
}
