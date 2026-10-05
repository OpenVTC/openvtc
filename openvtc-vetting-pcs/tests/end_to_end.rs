//! End to end, one test per claim of the design (`design-docs/vetting-hidden-vetters-pcs.md`),
//! adversarial cases included. Counting is VTI's own `requirements::evaluate`, unchanged.

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use openvtc_vetting_pcs::{
    ProtoError,
    applicant::ApplicantEngine,
    meta::StatementMeta,
    scheme::point_text,
    token::TokenWallet,
    vetter::{HiddenAttestation, VetterEngine},
    vtc::{Decision, Vtc},
};
use predicate_credential_system::Error as PcsError;
use rand::{SeedableRng, rngs::StdRng};
use serde_json::json;
use vta_sdk::{
    protocols::vetting::{VETTED_PREDICATE, VettingMethod, VettingRelationship},
    vetting::requirements::Need,
};

const COMMUNITY: &str = "did:example:kernel-vtc";
const R: usize = 3; // tokens per tick in these tests

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 22, 12, 0, 0).unwrap()
}

fn requirements() -> serde_json::Value {
    json!({
        "version": "0.1",
        "statementType": VETTED_PREDICATE,
        "minStatements": 2,
        "minByMethod": { "inPerson": 1 },
        "acceptedMethods": ["inPerson", "video", "priorAcquaintance"],
        "requiredClaims": ["name.legal"],
        "maxStatementAge": "P120D",
        "eligibleVetters": { "role": "vetter" },
        "independence": {
            "maxByDeclaredRelationship": { "family": 0 },
            "requireConsistentIdentityCommitment": true
        }
    })
}

struct World {
    rng: StdRng,
    vtc: Vtc,
    vetters: Vec<VetterEngine>,
}

/// A community in period 2026-09 with `n` enrolled vetters, each with one drip.
fn world(seed: u64, n: usize) -> World {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut vtc = Vtc::new(COMMUNITY, "2026-09", requirements(), &mut rng).unwrap();
    let mut vetters = Vec::new();
    for i in 0..n {
        let member = format!("member-{i}");
        vtc.grant(&member);
        let mut v = VetterEngine::new(&member, &vtc, &mut rng).unwrap();
        v.enroll(&mut vtc, &mut rng).unwrap();
        let label = vtc.current_token_label().to_string();
        v.drip(&mut vtc, 1, &label, R, &mut rng).unwrap();
        vetters.push(v);
    }
    World { rng, vtc, vetters }
}

fn meta(app: &ApplicantEngine, vtc: &Vtc, method: VettingMethod) -> StatementMeta {
    app.statement_meta(
        &vtc.params().unwrap(),
        vtc.requirements_digest(),
        StatementMeta {
            community: String::new(),
            requirements_digest: String::new(),
            method,
            claims_verified: vec!["name.legal".into()],
            liveness_confirmed: true,
            declared_relationship: VettingRelationship::None,
            identity_commitment: "zCommitmentOfThisApplication".into(),
            card_digest_multibase: "zCardDigest".into(),
            valid_from: NaiveDate::from_ymd_opt(2026, 9, 20).unwrap(),
            valid_until: NaiveDate::from_ymd_opt(2027, 1, 18).unwrap(),
            token_label: String::new(),
            token_serial: String::new(),
        },
    )
}

/// One vetting session: accept (reserves a token), human check, attest.
fn vet(w: &mut World, j: usize, app: &ApplicantEngine, method: VettingMethod) -> HiddenAttestation {
    let m = meta(app, &w.vtc, method);
    let r = w.vetters[j].accept(None, 2).unwrap();
    w.vetters[j]
        .attest(&w.vtc.params().unwrap(), &r, app.id(), m, &mut w.rng)
        .unwrap()
}

fn submit(w: &mut World, app: &ApplicantEngine) -> Result<Decision, ProtoError> {
    let c = w.vtc.challenge(&mut w.rng);
    let sub = app.submit(
        &w.vtc.params().unwrap(),
        w.vtc.requirements_digest(),
        &c,
        &mut w.rng,
    )?;
    w.vtc.submit(&sub, now())
}

// -------------------------------------------------------------------------------------------

#[test]
fn admits_on_two_hidden_vetters_and_names_none() {
    let mut w = world(1, 3);
    let mut bob = ApplicantEngine::new(
        &w.vtc.params().unwrap(),
        "did:example:bob-kernel",
        &mut w.rng,
    )
    .unwrap();
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();
    let b = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), b).unwrap();

    let d = submit(&mut w, &bob).unwrap();
    assert!(d.evaluation.satisfied(), "{:?}", d.evaluation);
    assert_eq!(d.evaluation.distinct_vetters(), 2);

    // The facts the policy sees name no vetter: no member id, no vetter PCS id.
    let facts = serde_json::to_string(&d.statements).unwrap();
    for v in &w.vetters {
        assert!(!facts.contains(&v.member), "facts leak {}", v.member);
        assert!(!facts.contains(&point_text(v.id()).unwrap()));
    }
    assert!(
        d.statements
            .iter()
            .all(|s| s.issuer.starts_with('z') && s.counted)
    );
}

#[test]
fn request_more_then_admit_on_resubmission() {
    let mut w = world(2, 3);
    let mut bob =
        ApplicantEngine::new(&w.vtc.params().unwrap(), "did:example:bob", &mut w.rng).unwrap();
    let v = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), v).unwrap();

    let d = submit(&mut w, &bob).unwrap();
    assert!(!d.evaluation.satisfied());
    assert_eq!(
        d.evaluation.needs,
        vec![
            Need::Statements(1),
            Need::Method(VettingMethod::InPerson, 1)
        ]
    );

    let p = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), p).unwrap();
    let d = submit(&mut w, &bob).unwrap();
    assert!(d.evaluation.satisfied(), "{:?}", d.evaluation);
    // The first vetter's token came back with the same (id, tag): already counted, no anomaly.
    assert!(
        w.vtc.token_verifier().anomalies.is_empty(),
        "{:?}",
        w.vtc.token_verifier().anomalies
    );
}

#[test]
fn one_vetter_counts_once_across_submissions() {
    let mut w = world(3, 3);
    let mut bob =
        ApplicantEngine::new(&w.vtc.params().unwrap(), "did:example:bob", &mut w.rng).unwrap();
    let first = vet(&mut w, 0, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), first).unwrap();
    submit(&mut w, &bob).unwrap();

    // The same vetter vets again, e.g. in person, and the client swaps it in.
    let second = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.replace(&w.vtc.params().unwrap(), second).unwrap();
    let d = submit(&mut w, &bob).unwrap();
    // Two statements on record, one tag: counted once.
    assert_eq!(d.statements.len(), 2);
    assert_eq!(d.evaluation.distinct_vetters(), 1);
    assert!(
        d.statements
            .iter()
            .any(|s| s.failures.contains(&"same-vetter".to_string()))
    );
}

#[test]
fn a_double_spent_token_does_not_count() {
    let mut w = world(4, 3);
    let mut alice =
        ApplicantEngine::new(&w.vtc.params().unwrap(), "did:example:alice", &mut w.rng).unwrap();
    let mut bob =
        ApplicantEngine::new(&w.vtc.params().unwrap(), "did:example:bob", &mut w.rng).unwrap();

    let for_alice = vet(&mut w, 0, &alice, VettingMethod::InPerson);
    let reused = for_alice.token.clone();
    alice.receive(&w.vtc.params().unwrap(), for_alice).unwrap();
    submit(&mut w, &alice).unwrap();

    // A cheating vetter reuses Alice's spent token for Bob.
    let m = meta(&bob, &w.vtc, VettingMethod::InPerson);
    let cheat = w.vetters[0]
        .attest_with_token(
            &w.vtc.params().unwrap(),
            "2026-09",
            reused,
            bob.id(),
            m,
            &mut w.rng,
        )
        .unwrap();
    bob.receive(&w.vtc.params().unwrap(), cheat).unwrap(); // the signature itself is valid
    let honest = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), honest).unwrap();

    let d = submit(&mut w, &bob).unwrap();
    assert!(!d.evaluation.satisfied());
    assert_eq!(d.evaluation.distinct_vetters(), 1);
    assert!(
        d.statements
            .iter()
            .any(|s| s.failures.contains(&"token-double-spend".to_string()))
    );
    assert_eq!(
        w.vtc.token_verifier().anomalies.len(),
        1,
        "the VTC notices, without naming anyone"
    );
}

#[test]
fn tokens_and_metadata_cannot_move_between_attestations() {
    let mut w = world(5, 3);
    let mut bob =
        ApplicantEngine::new(&w.vtc.params().unwrap(), "did:example:bob", &mut w.rng).unwrap();
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();
    let b = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), b).unwrap();

    // Swap the tokens only: the metadata names the other serial.
    let c = w.vtc.challenge(&mut w.rng);
    let mut sub = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &mut w.rng,
        )
        .unwrap();
    let (t0, t1) = (sub.statements[0].1.clone(), sub.statements[1].1.clone());
    sub.statements[0].1 = t1;
    sub.statements[1].1 = t0;
    let d = w.vtc.submit(&sub, now()).unwrap();
    assert_eq!(d.evaluation.distinct_vetters(), 0);
    assert!(
        d.statements
            .iter()
            .all(|s| s.failures.contains(&"token-mismatch".to_string()))
    );

    // Swap the metadata too (claim "inPerson" for the video vetter): the proof breaks.
    let c = w.vtc.challenge(&mut w.rng);
    let mut sub = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &mut w.rng,
        )
        .unwrap();
    sub.statements.swap(0, 1);
    assert_eq!(
        w.vtc.submit(&sub, now()).err(),
        Some(ProtoError::ProofRejected(PcsError::InvalidAttestation))
    );
}

#[test]
fn a_challenge_is_single_use_and_bound_to_the_proof() {
    let mut w = world(6, 2);
    let mut bob =
        ApplicantEngine::new(&w.vtc.params().unwrap(), "did:example:bob", &mut w.rng).unwrap();
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();
    let c = w.vtc.challenge(&mut w.rng);
    let sub = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &mut w.rng,
        )
        .unwrap();
    w.vtc.submit(&sub, now()).unwrap();
    assert_eq!(
        w.vtc.submit(&sub, now()).err(),
        Some(ProtoError::BadChallenge)
    );

    // A proof made for one challenge does not verify under another.
    let c2 = w.vtc.challenge(&mut w.rng);
    let mut replay = sub.clone();
    replay.challenge = c2;
    assert_eq!(
        w.vtc.submit(&replay, now()).err(),
        Some(ProtoError::ProofRejected(PcsError::InvalidProof))
    );
    // ... nor for another join DID: the binding of `id` to the persona is checked before the
    // proof, so swapping the DID is refused as a binding mismatch rather than a bad proof.
    let c3 = w.vtc.challenge(&mut w.rng);
    let mut other = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c3,
            &mut w.rng,
        )
        .unwrap();
    other.join_did = "did:example:mallory".into();
    assert!(matches!(
        w.vtc.submit(&other, now()),
        Err(ProtoError::AttestationRejected(_))
    ));
    // And with a binding recomputed for the new DID, the proof itself fails: `app_0` carries it.
    let c4 = w.vtc.challenge(&mut w.rng);
    let mut forged = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c4,
            &mut w.rng,
        )
        .unwrap();
    forged.join_did = "did:example:mallory".into();
    forged.id_binding = openvtc_vetting_pcs::meta::id_binding(
        &point_text(bob.id()).unwrap(),
        COMMUNITY,
        w.vtc.requirements_digest(),
        "did:example:mallory",
    );
    assert_eq!(
        w.vtc.submit(&forged, now()).err(),
        Some(ProtoError::ProofRejected(PcsError::InvalidProof))
    );
}

#[test]
fn a_closed_token_label_means_no_token() {
    let mut w = world(7, 3);
    let mut bob =
        ApplicantEngine::new(&w.vtc.params().unwrap(), "did:example:bob", &mut w.rng).unwrap();
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();
    let b = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), b).unwrap();
    let c = w.vtc.challenge(&mut w.rng);
    let sub = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &mut w.rng,
        )
        .unwrap();

    let label = w.vtc.current_token_label().to_string();
    w.vtc.verifier.tokens.close_label(&label);
    let d = w.vtc.submit(&sub, now()).unwrap();
    assert_eq!(d.evaluation.distinct_vetters(), 0);
    assert!(
        d.statements
            .iter()
            .all(|s| s.failures.contains(&"no-token".to_string()))
    );
}

#[test]
fn rotation_mixes_epochs_in_one_proof_and_refresh_keeps_the_tag() {
    let mut w = world(8, 3);
    let mut bob =
        ApplicantEngine::new(&w.vtc.params().unwrap(), "did:example:bob", &mut w.rng).unwrap();
    let old = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    let old_tag = old.attestation.tag;
    bob.receive(&w.vtc.params().unwrap(), old).unwrap();

    // Rotate: 2026-10 is current, 2026-09 still live. Vetter 1 re-enrols and gets new tokens.
    w.vtc.rotate("2026-10").unwrap();
    w.vetters[1].enroll(&mut w.vtc, &mut w.rng).unwrap();
    let label = w.vtc.current_token_label().to_string();
    w.vetters[1]
        .drip(&mut w.vtc, 31, &label, R, &mut w.rng)
        .unwrap();
    let new = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), new).unwrap();

    // One proof over a 2026-09 and a 2026-10 attestation (§13 C1).
    let d = submit(&mut w, &bob).unwrap();
    assert!(d.evaluation.satisfied(), "{:?}", d.evaluation);

    // Vetter 0 re-enrols under 2026-10 and refreshes; 2026-09 then leaves the AllowList.
    w.vetters[0].enroll(&mut w.vtc, &mut w.rng).unwrap();
    w.vetters[0]
        .drip(&mut w.vtc, 31, &label, R, &mut w.rng)
        .unwrap();
    w.vtc.drop_period("2026-09").unwrap();
    let refreshed = w.vetters[0]
        .refresh(&w.vtc.params().unwrap(), bob.id(), &mut w.rng)
        .unwrap();
    assert_eq!(
        refreshed.attestation.tag, old_tag,
        "same usk, same tag (§13 C2)"
    );
    bob.replace(&w.vtc.params().unwrap(), refreshed).unwrap();
    let d = submit(&mut w, &bob).unwrap();
    assert!(d.evaluation.satisfied(), "{:?}", d.evaluation);
    assert_eq!(d.evaluation.distinct_vetters(), 2);
}

#[test]
fn a_dropped_period_fails_the_whole_proof() {
    let mut w = world(9, 3);
    let mut bob =
        ApplicantEngine::new(&w.vtc.params().unwrap(), "did:example:bob", &mut w.rng).unwrap();
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();
    let c = w.vtc.challenge(&mut w.rng);
    let sub = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &mut w.rng,
        )
        .unwrap();

    w.vtc.rotate("2026-10").unwrap();
    w.vtc.drop_period("2026-09").unwrap();
    assert_eq!(
        w.vtc.submit(&sub, now()).err(),
        Some(ProtoError::ProofRejected(PcsError::PolicyRejected))
    );
}

#[test]
fn a_member_is_bound_to_one_identifier() {
    let mut w = world(10, 1);
    // Enrolling again under the same period is refused.
    assert!(matches!(
        w.vetters[0].enroll(&mut w.vtc, &mut w.rng),
        Err(ProtoError::AlreadyIssued { .. })
    ));
    // A second key pair for the same member is refused, now and after rotation (C2).
    let mut twin = VetterEngine::new("member-0", &w.vtc, &mut w.rng).unwrap();
    w.vtc.rotate("2026-10").unwrap();
    assert_eq!(
        twin.enroll(&mut w.vtc, &mut w.rng).err(),
        Some(ProtoError::IdentifierRebound("member-0".into()))
    );
    // Without a grant there is no credential.
    let mut stranger = VetterEngine::new("member-9", &w.vtc, &mut w.rng).unwrap();
    assert_eq!(
        stranger.enroll(&mut w.vtc, &mut w.rng).err(),
        Some(ProtoError::NotAVetter("member-9".into()))
    );
    // A removed vetter gets nothing under the next period.
    w.vtc.revoke("member-0");
    w.vtc.rotate("2026-11").unwrap();
    assert_eq!(
        w.vetters[0].enroll(&mut w.vtc, &mut w.rng).err(),
        Some(ProtoError::NotAVetter("member-0".into()))
    );
}

#[test]
fn withdrawal_by_tag_stops_counting_and_cannot_be_forged() {
    let mut w = world(11, 3);
    let mut bob =
        ApplicantEngine::new(&w.vtc.params().unwrap(), "did:example:bob", &mut w.rng).unwrap();
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();
    let b = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), b).unwrap();
    assert!(submit(&mut w, &bob).unwrap().evaluation.satisfied());

    // Vetter 2 cannot withdraw vetter 1's statement: its proof is for its own tag.
    let (tag2, proof2) = w.vetters[2]
        .withdraw(&w.vtc.params().unwrap(), bob.id(), &mut w.rng)
        .unwrap();
    let (tag1, proof1) = w.vetters[1]
        .withdraw(&w.vtc.params().unwrap(), bob.id(), &mut w.rng)
        .unwrap();
    assert!(!w.vtc.withdraw(bob.id(), &tag1, &proof2).unwrap());
    assert!(!w.vtc.withdraw(bob.id(), &tag2, &proof1).unwrap() || tag1 == tag2);

    // Vetter 1 withdraws its own: no identity in the notice, only the tag and the proof.
    assert!(w.vtc.withdraw(bob.id(), &tag1, &proof1).unwrap());
    let d = w.vtc.evaluate(&point_text(bob.id()).unwrap(), now());
    assert!(!d.evaluation.satisfied());
    assert!(
        d.statements
            .iter()
            .any(|s| s.revoked && s.failures.contains(&"revoked".to_string()))
    );
}

#[test]
fn drip_is_once_per_tick_and_reservations_bound_capacity() {
    let mut w = world(12, 1);
    let label = w.vtc.current_token_label().to_string();
    // A second fetch in the same tick is refused.
    assert!(matches!(
        w.vetters[0].drip(&mut w.vtc, 1, &label, R, &mut w.rng),
        Err(ProtoError::AlreadyServedThisTick { .. })
    ));
    // R tokens: R reservations, then atCapacity until the next tick.
    let rs: Vec<_> = (0..R)
        .map(|_| w.vetters[0].accept(None, 2).unwrap())
        .collect();
    assert_eq!(
        w.vetters[0].accept(None, 2).err(),
        Some(ProtoError::AtCapacity { available_from: 2 })
    );
    // A decline releases the token.
    w.vetters[0].decline(&rs[0]);
    assert!(w.vetters[0].accept(None, 2).is_ok());
    w.vetters[0]
        .drip(&mut w.vtc, 2, &label, R, &mut w.rng)
        .unwrap();
    assert_eq!(w.vetters[0].tokens_held(), 2 * R);

    // A personal limit below the drip: local, never sent, still refuses.
    let mut w = world(13, 1);
    w.vetters[0].personal_limit = Some(1);
    let bob =
        ApplicantEngine::new(&w.vtc.params().unwrap(), "did:example:bob", &mut w.rng).unwrap();
    vet(&mut w, 0, &bob, VettingMethod::InPerson);
    assert!(w.vetters[0].tokens_free() > 0);
    assert!(matches!(
        w.vetters[0].accept(None, 2),
        Err(ProtoError::AtCapacity { .. })
    ));
}

#[test]
fn opening_proofs_are_bound_to_their_request() {
    let mut w = world(14, 1);
    let label = w.vtc.current_token_label().to_string();
    let tvk = w.vtc.tvk().clone();
    let mut wallet = TokenWallet::new(COMMUNITY).unwrap();
    // Proofs made for tick 5, presented for tick 6.
    let reqs = wallet
        .prepare(&tvk, &label, "member-0", 5, 2, &mut w.rng)
        .unwrap();
    assert_eq!(
        w.vtc.drip("member-0", 6, &label, &reqs, &mut w.rng).err(),
        Some(ProtoError::BadOpeningProof(0))
    );
    // ... or by another member.
    w.vtc.grant("member-7");
    assert_eq!(
        w.vtc.drip("member-7", 5, &label, &reqs, &mut w.rng).err(),
        Some(ProtoError::BadOpeningProof(0))
    );
}

#[test]
fn event_mode_needs_a_group_an_outside_approver_and_dies_after_the_event() {
    let mut w = world(15, 4);
    let members = ["member-0", "member-1", "member-2"];
    assert!(matches!(
        w.vtc.approve_event("summit", &members[..2], "admin", 3),
        Err(ProtoError::EventRefused(_))
    ));
    assert!(matches!(
        w.vtc.approve_event("summit", &members, "member-0", 3),
        Err(ProtoError::EventRefused(_))
    ));
    let event = w.vtc.approve_event("summit", &members, "admin", 3).unwrap();

    // Outside the group: refused. Inside: served.
    assert!(matches!(
        w.vetters[3].drip(&mut w.vtc, 2, &event, 20, &mut w.rng),
        Err(ProtoError::EventRefused(_))
    ));
    w.vetters[0]
        .drip(&mut w.vtc, 2, &event, 20, &mut w.rng)
        .unwrap();
    w.vetters[1]
        .drip(&mut w.vtc, 2, &event, 20, &mut w.rng)
        .unwrap();

    // Event tokens are preferred during the event and verify like any other.
    let mut bob =
        ApplicantEngine::new(&w.vtc.params().unwrap(), "did:example:bob", &mut w.rng).unwrap();
    for (j, method) in [(0, VettingMethod::InPerson), (1, VettingMethod::Video)] {
        let m = meta(&bob, &w.vtc, method);
        let r = w.vetters[j].accept(Some(&event), 3).unwrap();
        assert_eq!(r.label, event);
        let att = w.vetters[j]
            .attest(&w.vtc.params().unwrap(), &r, bob.id(), m, &mut w.rng)
            .unwrap();
        bob.receive(&w.vtc.params().unwrap(), att).unwrap();
    }
    let c = w.vtc.challenge(&mut w.rng);
    let late = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &mut w.rng,
        )
        .unwrap();
    assert!(submit(&mut w, &bob).unwrap().evaluation.satisfied());

    // After the grace period the event label closes: 19 leftover event tokens are gone, the
    // monthly drip (R, untouched) remains.
    assert_eq!(w.vetters[0].tokens_held(), R + 19);
    w.vtc.close_event("summit");
    w.vetters[0].expire(&w.vtc);
    assert_eq!(w.vetters[0].tokens_held(), R);
    // A submission prepared under the event (its challenge `c` still unused) now fails on the
    // closed label: every statement is `no-token`, nothing counts.
    let d = w.vtc.submit(&late, now()).unwrap();
    assert_eq!(d.evaluation.distinct_vetters(), 0);
    assert!(
        d.statements
            .iter()
            .all(|s| s.failures.contains(&"no-token".to_string()))
    );
}

#[test]
fn engine_state_survives_a_restart() {
    let mut w = world(16, 2);
    let mut bob =
        ApplicantEngine::new(&w.vtc.params().unwrap(), "did:example:bob", &mut w.rng).unwrap();
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();

    // Both engines round-trip through their storable forms, as openvtc's config would.
    let bob_json = serde_json::to_string(&bob.snapshot().unwrap()).unwrap();
    let vetter_json = serde_json::to_string(&w.vetters[1].snapshot().unwrap()).unwrap();
    let mut bob = ApplicantEngine::restore(&serde_json::from_str(&bob_json).unwrap()).unwrap();
    let restored_vetter =
        VetterEngine::restore(&serde_json::from_str(&vetter_json).unwrap(), COMMUNITY).unwrap();
    w.vetters[1] = restored_vetter;

    // The restored vetter attests with the same key: a stable tag is what stops one vetter
    // counting twice (§13 C2).
    let before = point_text(w.vetters[1].id()).unwrap();
    let b = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), b).unwrap();
    assert_eq!(point_text(w.vetters[1].id()).unwrap(), before);

    // And the restored applicant proves over the attestation it gathered before the restart.
    let d = submit(&mut w, &bob).unwrap();
    assert!(d.evaluation.satisfied(), "{:?}", d.evaluation);
    assert_eq!(d.evaluation.distinct_vetters(), 2);
}

/// A catch-up asks for several ticks in one pass, and openvtc stores the engine between every
/// request and its answer. Each answer has to find its own serials after that, whatever order
/// the answers arrive in — before draws in flight were stored, every answer met an empty wallet
/// and was dropped as a count mismatch.
#[test]
fn several_draws_in_flight_survive_a_snapshot_and_answer_in_any_order() {
    use openvtc_vetting_pcs::{issuer::TokenBatchWire, scheme::enc};

    let mut w = world(31, 1);
    let label = w.vtc.current_token_label().to_string();
    let params = w.vtc.params().unwrap();
    let held_before = w.vetters[0].tokens_held();

    let mut asked = Vec::new();
    for tick in [2u32, 3, 4] {
        asked.push(
            w.vetters[0]
                .drip_request(&params, tick, &label, R, &mut w.rng)
                .unwrap(),
        );
    }
    // Stored and restored, as openvtc does between the send and the answer.
    let snapshot = w.vetters[0].snapshot().unwrap();
    assert_eq!(snapshot.pending.len(), 3 * R);
    let mut restored = VetterEngine::restore(&snapshot, COMMUNITY).unwrap();
    assert_eq!(restored.draws_in_flight().len(), 3);

    // The community answers ticks 4 and 2; tick 3 it refuses, and its serials are dropped.
    for batch in [&asked[2], &asked[0]] {
        let reqs: Vec<_> = batch
            .requests
            .iter()
            .map(|r| r.to_request().unwrap())
            .collect();
        let pres = w
            .vtc
            .drip("member-0", batch.tick, &label, &reqs, &mut w.rng)
            .unwrap();
        let served = TokenBatchWire {
            label: label.clone(),
            tick: batch.tick,
            pre_credentials: pres.iter().map(|p| enc(p).unwrap()).collect(),
        };
        assert_eq!(restored.accept_drip(&params, &served).unwrap(), R);
    }
    restored.forget_draw(&label, 3);
    assert!(restored.draws_in_flight().is_empty());
    assert_eq!(restored.tokens_held(), held_before + 2 * R);
    assert!(restored.snapshot().unwrap().pending.is_empty());
}
