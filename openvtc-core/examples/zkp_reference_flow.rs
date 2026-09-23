//! A reference run of hidden-vetter admission, through the real vetting ceremony.
//!
//! Ten members hold a real community-issued vetter role credential. Three of them run real
//! vetting sessions with one applicant — ticket, session, a Vetting Card the applicant signs
//! with its own key and the vetter verifies against the resolver — and attest. The applicant
//! proves, and the community admits.
//!
//! Nothing here is a stand-in: every identity is a `did:key` with a real Ed25519 key, the role
//! credentials and the Vetting Cards carry real Data Integrity proofs, and the identity
//! commitment and card digest bound into each attestation are the ones the ceremony computed.
//! Admission mints the same credentials `vtc-service` mints — the community's VMC against a
//! revocation slot, the role VEC, and the member's own reciprocal VMC that closes the edge.
//!
//! Every credential is emitted in full, so the output doubles as a test-vector set: each VC is
//! self-contained and verifies against the `did:key` in its `issuer` with no network.
//!
//! ```sh
//! cargo run -p openvtc-core --example zkp_reference_flow > /tmp/zkp-reference.json
//! ```
//!
//! # Replicating it
//!
//! Every key is derived from a fixed seed byte repeated 32 times ([`identity`]), and the PCS
//! engine runs on a seeded `StdRng`, so the DIDs, the class labels and the requirements digest
//! are the same on every machine. See `step00_seeds` in the output for the table, and for what
//! is *not* stable: document ids (`urn:uuid:`), wall-clock timestamps, the card salt the
//! identity commitment is computed over, the match codes, and therefore every signature and
//! proof taken over them.

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, VerifyOptions};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::{DateTime, Duration, Utc};
use dtg_credentials::{DTGCredential, digest_multibase_json};
use openvtc_core::config::account::PersonaId;
use openvtc_core::members::build_member_vmc;
use openvtc_core::vetting::{
    VettingBook,
    applicant::{RequestDraft, VetterEligibility},
    hidden::{self, HiddenParams},
    tickets::Ticket,
    vetter::{Attestation, IncomingRequest, Intake},
};
use openvtc_vetting_pcs::{
    issuer::{RootCredentialWire, TokenBatchWire},
    meta::StatementMeta,
    scheme::key_text,
    snapshot::VetterSnapshot,
    vetter::VetterEngine,
    vtc::Vtc,
    wire::SubmissionWire,
};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use vta_sdk::protocols::vetting::{
    COMMUNITY_ROLE_ENDORSEMENT_TYPE, IDENTITY_VETTING_ENDORSEMENT_TYPE, VETTER_ROLE, VettingMethod,
    VettingRelationship, request, session,
};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::vetting::card::sign_card;

const PERIOD: &str = "2026-09";
const VETTERS: usize = 10;
/// Which of the ten vet. The other seven never hear of the application.
const VETTING: [usize; 3] = [2, 5, 7];

/// A `did:key` Ed25519 identity from a fixed seed, so the run is reproducible.
fn identity(seed: u8) -> (Secret, String) {
    let mut secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let public = secret.get_public_keymultibase().unwrap();
    secret.id = format!("did:key:{public}#{public}");
    let did = secret.id.split('#').next().unwrap().to_string();
    (secret, did)
}

fn requirements() -> Value {
    json!({
        "version": "0.1",
        "statementType": IDENTITY_VETTING_ENDORSEMENT_TYPE,
        "minStatements": 3,
        "minByMethod": { "inPerson": 1 },
        "acceptedMethods": ["inPerson", "video", "priorAcquaintance"],
        "requiredClaims": ["name.legal"],
        "maxStatementAge": "P120D",
        "eligibleVetters": { "role": "vetter" },
        "independence": {
            "maxByDeclaredRelationship": { "family": 0, "sameEmployer": 1 },
            "requireConsistentIdentityCommitment": true
        }
    })
}

/// A real community role credential: a DTG endorsement credential, signed by the community.
/// The shape `vtc-service` mints in `credentials::dtg::issue_role` — `{ type: CommunityRole,
/// role, communityDid }` at `credentialSubject.endorsement`.
async fn role_credential(issuer: &Secret, community: &str, subject: &str, role: &str) -> Value {
    let now = Utc::now();
    let mut credential = DTGCredential::new_vec(
        community.to_string(),
        subject.to_string(),
        now - Duration::minutes(1),
        Some(now + Duration::days(365)),
        json!({
            "type": COMMUNITY_ROLE_ENDORSEMENT_TYPE,
            "role": role,
            "communityDid": community,
        }),
    )
    .with_id(format!("urn:uuid:{}", uuid::Uuid::new_v4()));
    credential.sign(issuer, None).await.unwrap();
    serde_json::to_value(&credential).unwrap()
}

/// Sign a credential **document** — the body plus the members the catalog type does not model.
///
/// A VMC issued against a status list carries `credentialStatus`, and `DTGCredential` has no
/// field for it, so signing the parsed credential would leave the status reference outside the
/// proof: a revoked credential could have it stripped without breaking the signature. This is
/// `vtc-service`'s `LocalSigner::sign_doc`, which splices `id` + `credentialStatus` onto the
/// serialised body and signs the whole document.
async fn sign_doc(doc: &mut Value, signer: &Secret) {
    doc.as_object_mut().expect("a JSON object").remove("proof");
    let proof = DataIntegrityProof::sign(&*doc, signer, SignOptions::new())
        .await
        .expect("sign");
    doc.as_object_mut()
        .unwrap()
        .insert("proof".into(), serde_json::to_value(&proof).unwrap());
}

/// Verify a signed credential document against the signer's own public key — no resolver, which
/// is the point of a `did:key` test vector: the key is in the DID.
fn proof_verifies(doc: &Value, signer: &Secret) -> bool {
    let mut body = doc.clone();
    let Some(proof) = body.as_object_mut().and_then(|o| o.remove("proof")) else {
        return false;
    };
    let Ok(proof) = serde_json::from_value::<DataIntegrityProof>(proof) else {
        return false;
    };
    proof
        .verify_with_public_key(&body, signer.get_public_bytes(), VerifyOptions::new())
        .is_ok()
}

/// The community's VMC for a new member: the catalog body, an `id`, and the
/// `BitstringStatusListEntry` that makes it revocable — all three covered by one proof.
/// `vtc-service` builds this under the status-list lock, in `issue_member_credentials`.
async fn membership_grant(
    issuer: &Secret,
    community: &str,
    member: &str,
    status_list: &str,
    slot: u32,
    now: DateTime<Utc>,
) -> Value {
    let dtg = DTGCredential::new_vmc(
        community.to_string(),
        member.to_string(),
        now,
        Some(now + Duration::days(30)),
        false,
    );
    let mut doc = serde_json::to_value(dtg.credential()).unwrap();
    let obj = doc.as_object_mut().unwrap();
    obj.insert(
        "id".into(),
        json!(format!("urn:uuid:{}", uuid::Uuid::new_v4())),
    );
    obj.insert(
        "credentialStatus".into(),
        json!({
            "id": format!("{status_list}#{slot}"),
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": slot.to_string(),
            "statusListCredential": status_list,
        }),
    );
    sign_doc(&mut doc, issuer).await;
    doc
}

fn size_of(v: &Value) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0)
}

#[tokio::main]
async fn main() {
    let mut rng = StdRng::seed_from_u64(0x2026_0923);
    let resolver = TrustTaskVmResolver::did_key_only();
    let mut report = serde_json::Map::new();

    // --- 1. Real identities -----------------------------------------------------------------
    let (community_secret, community) = identity(0xC0);
    let (applicant_secret, applicant_did) = identity(0xB0);
    let vetter_ids: Vec<(Secret, String)> = (0..VETTERS).map(|i| identity(i as u8 + 1)).collect();

    // Everything anyone needs to reproduce the identities in this run.
    report.insert(
        "step00_seeds".into(),
        json!({
            "command": "cargo run -p openvtc-core --example zkp_reference_flow",
            "keyDerivation":
                "Ed25519 from a 32-byte seed of one repeated byte: Secret::generate_ed25519(None, Some(&[seed; 32])), \
                 then did:key over the multibase public key",
            "seeds": {
                "communityDid": { "seedByte": "0xC0", "did": community },
                "applicantDid": { "seedByte": "0xB0", "did": applicant_did },
                "vetterDids": vetter_ids
                    .iter()
                    .enumerate()
                    .map(|(i, (_, d))| json!({ "seedByte": format!("0x{:02X}", i + 1), "did": d }))
                    .collect::<Vec<_>>(),
            },
            "pcsRngSeed": "StdRng::seed_from_u64(0x2026_0923)",
            "period": PERIOD,
            "whichVettersVet": VETTING,
            "stableAcrossRuns": [
                "every DID and public key",
                "the PCS class labels and the requirements digest",
                "the structure and byte sizes of the attestations, proof and submission",
            ],
            "variesPerRun": [
                "urn:uuid document ids",
                "wall-clock validFrom / validUntil / proof.created",
                "the Vetting Card salt, and so the identityCommitment and card digest",
                "the session match codes",
                "every signature and PCS value taken over the above",
            ],
        }),
    );

    // --- 2. The community stands up its hidden-vetting deployment ---------------------------
    let mut vtc = Vtc::new(&community, PERIOD, requirements(), &mut rng).expect("vtc");
    let token_label = vtc.current_token_label().to_string();
    let digest = vtc.requirements_digest().to_string();
    report.insert(
        "step01_identities_and_deployment".into(),
        json!({
            "communityDid": community,
            "applicantJoinDid": applicant_did,
            "vetterDids": vetter_ids.iter().map(|(_, d)| d).collect::<Vec<_>>(),
            "helperKeyHvk": key_text(vtc.hvk()).unwrap(),
            "tokenKeyTvk": key_text(vtc.tvk()).unwrap(),
            "vetterLabel": format!("vetter/{PERIOD}"),
            "tokenLabel": token_label,
            "requirements": requirements(),
            "requirementsDigest": digest,
        }),
    );

    // --- 3. Ten real role credentials, then ten PCS enrolments ------------------------------
    //
    // Both exchanges are driven through their wire halves, so what the report shows is what a
    // transport would carry: the vetter asks blinded, the community checks its own records and
    // signs, the vetter unblinds something the community has never seen.
    let params = vtc.params().expect("published parameters");
    let mut engines: Vec<VetterSnapshot> = Vec::new();
    let mut role_credentials: Vec<Value> = Vec::new();
    let mut enrolment_exchange = Value::Null;
    let mut drip_exchange = Value::Null;
    for (n, (_, did)) in vetter_ids.iter().enumerate() {
        let credential = role_credential(&community_secret, &community, did, VETTER_ROLE).await;
        assert!(
            proof_verifies(&credential, &community_secret),
            "the role credential must verify as issued"
        );
        role_credentials.push(credential);
        // The community's record of who holds the vetter role. On the VTI side this is the ACL
        // and the role endorsement the credential above was written from — `pcs_issue::enrol`
        // reads those, never a list of its own.
        vtc.grant(did);

        let mut engine = VetterEngine::new(did, &vtc, &mut rng).expect("engine");

        // Enrolment, in two halves.
        let (request, blinding) = engine
            .enrolment_request(&params, PERIOD, &mut rng)
            .expect("a blinded request for the current label");
        let pre = vtc
            .issue_vetter_root(
                did,
                &openvtc_vetting_pcs::scheme::point_from_text(&request.id).unwrap(),
                &serde_json::from_value(request.request.clone()).unwrap(),
                &mut rng,
            )
            .expect("a granted vetter, enrolling once under this label");
        let answer = RootCredentialWire {
            label: request.label.clone(),
            pre_credential: openvtc_vetting_pcs::scheme::enc(&pre).unwrap(),
        };
        engine
            .accept_enrolment(&params, &answer, &blinding)
            .expect("what came back unblinds under the published key");

        // One tick of the drip, in two halves.
        let batch = engine
            .drip_request(&params, 1, &token_label, params.drip_per_tick(), &mut rng)
            .expect("a blinded batch");
        let served = vtc
            .drip(
                did,
                1,
                &token_label,
                &batch
                    .requests
                    .iter()
                    .map(|r| r.to_request().unwrap())
                    .collect::<Vec<_>>(),
                &mut rng,
            )
            .expect("within the published rate, and the first tick");
        let served = TokenBatchWire {
            label: batch.label.clone(),
            tick: batch.tick,
            pre_credentials: served
                .iter()
                .map(|p| openvtc_vetting_pcs::scheme::enc(p).unwrap())
                .collect(),
        };
        let taken = engine
            .accept_drip(&params, &served)
            .expect("the tokens verify under the published token key");

        if n == VETTING[0] {
            enrolment_exchange = json!({
                "request": request,
                "answer": answer,
                "note":
                    "The request carries a commitment and a proof, never the vetter's key. What comes back is a \
                    pre-credential only this vetter can unblind — which is why the community cannot recognise \
                    the credential it just made.",
            });
            drip_exchange = json!({
                "request": batch,
                "answer": served,
                "tokensTaken": taken,
                "note":
                    "Asked for on a schedule, not on demand: a fetch that happened only when a vetter was busy \
                    would announce that they were busy.",
            });
        }
        engines.push(engine.snapshot().expect("snapshot"));
    }

    // The two refusals that make the drip a cap rather than a suggestion. Neither depends on
    // the vetter's restraint: the community enforces both, and on the VTI side both are rows in
    // a keyspace rather than memory.
    let mut greedy = VetterEngine::new(&vetter_ids[0].1, &vtc, &mut rng).unwrap();
    let over = greedy
        .drip_request(
            &params,
            2,
            &token_label,
            params.drip_per_tick() + 5,
            &mut rng,
        )
        .unwrap();
    let over_quota = vtc
        .drip(
            &vetter_ids[0].1,
            2,
            &token_label,
            &over
                .requests
                .iter()
                .map(|r| r.to_request().unwrap())
                .collect::<Vec<_>>(),
            &mut rng,
        )
        .expect_err("more than the published rate");
    let again = greedy
        .drip_request(&params, 1, &token_label, params.drip_per_tick(), &mut rng)
        .unwrap();
    let twice_a_tick = vtc
        .drip(
            &vetter_ids[0].1,
            1,
            &token_label,
            &again
                .requests
                .iter()
                .map(|r| r.to_request().unwrap())
                .collect::<Vec<_>>(),
            &mut rng,
        )
        .expect_err("the first tick was already served");
    report.insert(
        "step02_vetter_role_credentials".into(),
        json!({
            "issuedBy": community,
            "count": role_credentials.len(),
            "allProofsVerify": true,
            "credentials": role_credentials,
        }),
    );
    report.insert(
        "step03_pcs_enrolment".into(),
        json!({
            "enrolled": VETTERS,
            "label": format!("vetter/{PERIOD}"),
            "tokenLabel": token_label,
            "dripPerTick": params.drip_per_tick(),
            "tokensMintedThisTick": VETTERS * params.drip_per_tick(),
            "enrolmentExchange": enrolment_exchange,
            "dripExchange": drip_exchange,
            "refusals": {
                "overTheDripRate": over_quota.to_string(),
                "twiceInOneTick": twice_a_tick.to_string(),
                "note":
                    "Both are the community's, not the vetter's: a vetter that asks for more is \
                     refused the batch, and one that asks twice for the same tick is refused \
                     outright.",
            },
            "note":
                "The root credential is the vetter's blind PCS credential for the label; the \
                 tokens are PS blind signatures on secret serials. Both are secrets held by the \
                 vetter — they are printed here because this is a reference vector, not because \
                 they travel.",
            "vetters": engines
                .iter()
                .enumerate()
                .map(|(i, e)| json!({
                    "vetterDid": vetter_ids[i].1,
                    "pcsIdentifier": e.id,
                    "rootCredential": e.credentials.get(PERIOD),
                    "tokens": e.tokens.iter().map(|t| json!({
                        "label": t.label,
                        "serial": t.serial,
                        "signature": t.credential,
                    })).collect::<Vec<_>>(),
                }))
                .collect::<Vec<_>>(),
        }),
    );

    // --- 4. The published criterion ----------------------------------------------------------
    let mut vetting = requirements();
    vetting["ext"] = json!({
        hidden::HIDDEN_VETTING_NS: {
            "suite": hidden::SUITE,
            "helperKey": key_text(vtc.hvk()).unwrap(),
            "tokenKey": key_text(vtc.tvk()).unwrap(),
            "vetterLabels": [format!("vetter/{PERIOD}")],
            "tokenLabels": [token_label],
        }
    });
    vetting["extCritical"] = json!([hidden::HIDDEN_VETTING_NS]);
    let criterion = json!({
        "id": "kernel-developer-private",
        "description": "Three kernel vetters must confirm who you are. At least one must meet you in person.",
        "presentationDefinition": { "credentials": [] },
        "vetting": vetting,
        "requirementsDigest": digest,
    });
    let manifest_payload = json!({ "communityDid": community, "criteria": [criterion.clone()] });
    report.insert("step04_manifest_criterion".into(), criterion);

    // --- 5. The applicant adopts it ----------------------------------------------------------
    let mut book = VettingBook::default();
    let persona = PersonaId::new();
    book.start_application(&community, persona, &applicant_did, Utc::now())
        .expect("application");
    let parsed = serde_json::from_value(manifest_payload.clone()).expect("manifest parses");
    let application = book.application_mut(&community, persona).unwrap();
    application
        .adopt_manifest(&parsed, &manifest_payload)
        .expect("a criterion this build implements");
    let params: HiddenParams = application
        .hidden
        .clone()
        .expect("hidden-vetting criterion");
    let applicant_pcs_id = application
        .hidden_id()
        .expect("a key of its own")
        .to_string();
    report.insert(
        "step05_application".into(),
        json!({
            "joinDid": applicant_did,
            "pcsIdentifier": applicant_pcs_id,
            "note": "The commitment salt stays local; the identity commitment below is computed over it.",
        }),
    );

    // --- 6. Three real vetting sessions -------------------------------------------------------
    let methods = [
        (VettingMethod::InPerson, vec!["passport".to_string()]),
        (VettingMethod::Video, vec!["nationalId".to_string()]),
        (VettingMethod::InPerson, vec!["passport".to_string()]),
    ];
    let mut sessions = Vec::new();
    for (n, &index) in VETTING.iter().enumerate() {
        let (vetter_secret, vetter_did) = &vetter_ids[index];
        let _ = vetter_secret;
        let (method, documents) = &methods[n];

        let mut desk = VettingBook::default();
        let ticket = Ticket::issue(
            community.clone(),
            persona,
            vec![VettingMethod::InPerson, VettingMethod::Video],
            3,
            Duration::days(7),
            Utc::now(),
        );
        let code = ticket.code.clone();
        desk.tickets.push(ticket);

        let request_document_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
        let request = book
            .application_mut(&community, persona)
            .unwrap()
            .prepare_request(
                &request_document_id,
                vetter_did,
                request::v0_1::Ticket::ShortCodeTicket(
                    request::v0_1::ShortCodeTicket::try_from(
                        request::v0_1::ShortCodeTicket::builder().code(code),
                    )
                    .expect("a Crockford code"),
                ),
                RequestDraft {
                    preferred_method: Some(*method),
                    languages: vec!["en".into()],
                    message: Some("Kernel maintainer application".into()),
                    availability: None,
                },
                Utc::now(),
            )
            .expect("a well-formed request");

        let accepted = desk.take_request(
            IncomingRequest {
                document_id: &request_document_id,
                sender: &applicant_did,
                persona,
                body: request,
                eligible: true,
            },
            Utc::now(),
        );
        let Intake::Accepted(response) = accepted else {
            panic!("the desk accepts the request");
        };
        // The acceptance reaches the applicant, carrying the vetter's own handle for it and
        // the eligibility the vetter showed — the role credential issued in step 2.
        book.application_mut(&community, persona)
            .unwrap()
            .on_accepted(
                &request_document_id,
                vetter_did,
                *response,
                VetterEligibility::Shown {
                    credential_id: None,
                    valid_until: Utc::now() + Duration::days(365),
                },
                Utc::now(),
            )
            .expect("the applicant records the acceptance");
        // The desk's own handle for this request, which it sent back to the applicant.
        let request_id = desk
            .desk
            .iter()
            .find(|e| e.request_document_id == request_document_id)
            .map(|e| e.request_id.clone())
            .expect("the desk took it");

        let session_document_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
        let session_payload = desk
            .open_session(
                &request_id,
                *method,
                vec!["name.legal".into()],
                vec![],
                &session_document_id,
                Utc::now(),
            )
            .expect("a session opens");
        let open = book
            .application_mut(&community, persona)
            .unwrap()
            .on_session(
                &session_document_id,
                vetter_did,
                session_payload,
                Utc::now(),
            )
            .expect("the applicant accepts the session");

        // A real Vetting Card, signed by the applicant's own key.
        let draft = book
            .application_mut(&community, persona)
            .unwrap()
            .card_draft(
                &open.id,
                vec![
                    session::v0_1::VettingCardClaim::try_from(
                        session::v0_1::VettingCardClaim::builder()
                            .type_("name.legal")
                            .value(json!("Bob Example"))
                            .provenance("selfAsserted"),
                    )
                    .unwrap(),
                ],
                Utc::now(),
            )
            .expect("a card draft");
        let card = sign_card(draft, &applicant_secret)
            .await
            .expect("a signed card");
        book.application_mut(&community, persona)
            .unwrap()
            .record_card(&open.id, &card, &resolver, Utc::now())
            .await
            .expect("the applicant re-verifies what it signed");

        // The vetter verifies the card against the resolver, then checks the human.
        desk.receive_card(
            vetter_did,
            &applicant_did,
            &open.id,
            &card,
            &resolver,
            Utc::now(),
        )
        .await
        .expect("the card verifies");

        // The statement the vetter would sign on the named path. Here it is the source of the
        // facts the attestation carries: the commitment and card digest are the ceremony's.
        let statement_draft = desk
            .statement_draft(
                &request_id,
                vetter_did,
                Attestation {
                    method: *method,
                    document_classes: documents.clone(),
                    claims_verified: vec!["name.legal".into()],
                    liveness_confirmed: true,
                    declared_relationship: VettingRelationship::None,
                    attestation_text_digest: None,
                },
                Utc::now(),
            )
            .expect("a statement draft");
        let endorsement = serde_json::to_value(&statement_draft.endorsement).unwrap();

        let meta = StatementMeta {
            community: community.clone(),
            requirements_digest: digest.clone(),
            method: *method,
            claims_verified: statement_draft
                .endorsement
                .claims_verified
                .iter()
                .map(|c| c.to_string())
                .collect(),
            liveness_confirmed: statement_draft.endorsement.liveness_confirmed,
            declared_relationship: statement_draft.endorsement.declared_relationship,
            identity_commitment: statement_draft.endorsement.identity_commitment.clone(),
            card_digest_multibase: statement_draft.endorsement.card_digest_multibase.clone(),
            valid_from: statement_draft.valid_from.date_naive(),
            valid_until: statement_draft.valid_until.date_naive(),
            token_label: String::new(),
            token_serial: String::new(),
        };
        let attestation = hidden::attest(
            &community,
            &params,
            &mut engines[index],
            &applicant_pcs_id,
            meta,
            &mut rng,
        )
        .expect("the vetter holds a live credential and a free token");
        book.application_mut(&community, persona)
            .unwrap()
            .receive_hidden_attestation(&attestation)
            .expect("the applicant verifies it at the session");

        sessions.push(json!({
            "vetterDid": vetter_did,
            "matchCode": open.match_code,
            "vettingCard": card,
            "namedPathStatementEndorsement": endorsement,
            "namedPathStatementNote":
                "On the named path the vetter signs this endorsement into a statement credential \
                 addressed to the applicant. On the hidden path it is never signed and never \
                 issued — a signed statement carries the vetter's DID, which is the thing being \
                 withheld. Its facts go into the attestation instead.",
            "hiddenAttestation": attestation.clone(),
            "hiddenAttestationBytes": size_of(&attestation),
        }));
    }
    report.insert(
        "step06_sessions".into(),
        json!({ "vetted": VETTING.len(), "ofEligible": VETTERS, "sessions": sessions }),
    );

    // --- 7. The applicant proves and submits ---------------------------------------------------
    //
    // The challenge is the COMMUNITY's: it mints one for this applicant, records it, and spends
    // it when the proof is counted. A proof bound to a challenge nobody issued is refused, and
    // so is the same proof submitted twice — both are demonstrated below. On the VTI side this
    // is `pcs_challenge`, a row in the join keyspace with a TTL.
    let challenge = vtc.challenge(&mut rng);
    let application = book.application_mut(&community, persona).unwrap();
    application
        .prepare_hidden_submission(&challenge)
        .expect("a proof over what it holds");
    let extensions = application.join_extensions();
    report.insert(
        "step07_submission".into(),
        json!({
            "challenge": challenge,
            "challengeIssuedBy": community,
            "extensions": extensions.clone(),
            "extensionsBytes": size_of(&extensions),
            "capBytes": 16 * 1024,
            "namedStatementsPresented": application.presentable_statements(Utc::now()).len(),
        }),
    );

    // --- 8. The community decides ---------------------------------------------------------------
    let carried = extensions[hidden::EXTENSIONS_MEMBER].clone();
    let wire: SubmissionWire = serde_json::from_value(carried).expect("wire");
    let submission = wire.to_submission().expect("decode");
    let decision = vtc
        .submit(&submission, Utc::now())
        .expect("the proof verifies");

    // The same submission again: the proof still verifies, and it is refused anyway, because the
    // challenge it is bound to was spent by the first one. Replay is a freshness question, not a
    // cryptographic one.
    let replayed = vtc
        .submit(&submission, Utc::now())
        .expect_err("the challenge is gone");
    // And a proof bound to a challenge the applicant minted for itself never had one.
    let mut forged = submission.clone();
    forged.challenge = "00000000000000000000000000000000".into();
    let unissued = vtc
        .submit(&forged, Utc::now())
        .expect_err("this community never issued that challenge");
    let tags: Vec<String> = decision
        .statements
        .iter()
        .map(|s| s.issuer.clone())
        .collect();
    let pcs_ids: Vec<String> = engines.iter().map(|e| e.id.clone()).collect();
    let submitted = serde_json::to_string(&extensions).unwrap();
    report.insert(
        "step08_decision".into(),
        json!({
            "facts": serde_json::to_value(&decision.statements).unwrap(),
            "distinctVetters": decision.evaluation.distinct_vetters(),
            "satisfied": decision.evaluation.satisfied(),
            "byMethod": decision
                .evaluation
                .by_method
                .iter()
                .map(|(m, n)| (m.to_string(), json!(n)))
                .collect::<serde_json::Map<String, Value>>(),
            "commitmentsConsistent": decision.evaluation.commitments_consistent,
            "replayRefused": replayed.to_string(),
            "unissuedChallengeRefused": unissued.to_string(),
        }),
    );
    // --- 9. Admission: the membership credentials ---------------------------------------------
    // The decision satisfied the criterion, so the community admits. This is what
    // `vtc-service`'s `Admit` effect mints (`ceremony::execute::issue_member_credentials`): a
    // VMC against the next free revocation slot and a role VEC at the granted role, both signed
    // by the community. The member then issues the other half of the edge with `openvtc-core`'s
    // own `build_member_vmc` — the same call the TUI makes — which digests the grant **as it
    // arrived**, `credentialStatus` and all.
    assert!(decision.evaluation.satisfied(), "admission follows a pass");
    let admitted_at = Utc::now();
    let status_list = "https://kernel-vtc.example/v1/status-lists/revocation";
    let status_slot = 0u32; // the first admission against a fresh list
    let grant = membership_grant(
        &community_secret,
        &community,
        &applicant_did,
        status_list,
        status_slot,
        admitted_at,
    )
    .await;
    let member_role_vec =
        role_credential(&community_secret, &community, &applicant_did, "member").await;
    // The member's half. Signed by the applicant's own key, subject = the community.
    let reciprocal = build_member_vmc(&applicant_secret, &grant)
        .await
        .expect("the grant is a membership grant this member can acknowledge");

    let grant_digest = digest_multibase_json(&grant).expect("digest the grant as it arrived");
    report.insert(
        "step09_admission_credentials".into(),
        json!({
            "membershipGrantVmc": grant,
            "memberRoleVec": member_role_vec,
            "reciprocalMemberVmc": reciprocal,
            "checks": {
                "grantProofVerifies": proof_verifies(&grant, &community_secret),
                "roleVecProofVerifies": proof_verifies(&member_role_vec, &community_secret),
                "reciprocalProofVerifies": proof_verifies(&reciprocal, &applicant_secret),
                "reciprocalSubjectIsTheCommunity":
                    reciprocal["credentialSubject"]["id"] == json!(community),
                "reciprocalIssuerIsTheMember": reciprocal["issuer"] == json!(applicant_did),
                "reciprocalDigestsTheGrantAsItArrived":
                    reciprocal["credentialSubject"]["digestMultibase"] == json!(grant_digest),
                "grantDigestMultibase": grant_digest,
            },
            "note":
                "The pair is the membership edge: the community's grant and the member's \
                 acknowledgement, bound by a digest over the grant's wire form. Neither half \
                 names a vetter — admission carries no trace of who vetted.",
        }),
    );

    let admission_json =
        serde_json::to_string(&json!([grant, member_role_vec, reciprocal])).unwrap();
    report.insert(
        "step10_what_the_community_learns".into(),
        json!({
            "tags": tags,
            "enrolledPcsIdentifiers": pcs_ids,
            "enrolledVetterDids": vetter_ids.iter().map(|(_, d)| d).collect::<Vec<_>>(),
            "anyTagEqualsAnEnrolledIdentifier": tags.iter().any(|t| pcs_ids.contains(t)),
            "anyVetterDidAppearsInTheSubmission": vetter_ids
                .iter()
                .any(|(_, d)| submitted.contains(d)),
            "whoActuallyVetted": VETTING
                .iter()
                .map(|i| vetter_ids[*i].1.clone())
                .collect::<Vec<_>>(),
            "anyVetterDidAppearsInTheAdmissionCredentials": vetter_ids
                .iter()
                .any(|(_, d)| admission_json.contains(d)),
        }),
    );

    // --- 11. What a real admission issues, and what this run does with each -------------------
    // Measured against `vtc-service`'s issuance paths and the DTG credentials catalog, so the
    // gaps are stated rather than implied.
    report.insert(
        "step11_credential_inventory".into(),
        json!({
            "issuedHere": [
                { "credential": "Vetting Card (VDS)", "issuer": "applicant", "count": VETTING.len(),
                  "note": "one per session, signed by the applicant's key and verified by the vetter" },
                { "credential": "Vetter role VEC (CommunityRole)", "issuer": "community", "count": VETTERS,
                  "note": "the eligibility the criterion's `eligibleVetters.role` names" },
                { "credential": "PCS root credential", "issuer": "community (as PCS helper)", "count": VETTERS,
                  "note": "not a W3C VC — a blind PS credential on the class label `vetter/<period>`" },
                { "credential": "PCS attestation token", "issuer": "community (as PCS helper)", "count": VETTERS * 3,
                  "note": "not a W3C VC — a PS blind signature on a secret serial; the velocity cap" },
                { "credential": "PCS attestation", "issuer": "vetter", "count": VETTING.len(),
                  "note": "stands in for the named path's signed vetting statement" },
                { "credential": "Membership grant (VMC)", "issuer": "community", "count": 1,
                  "note": "against revocation slot 0, the shape `issue_member_credentials` mints" },
                { "credential": "Member role VEC (CommunityRole, role=member)", "issuer": "community", "count": 1 },
                { "credential": "Reciprocal member VMC", "issuer": "the new member", "count": 1,
                  "note": "closes the membership edge; digests the grant's wire form" },
            ],
            "deliberatelyNotIssued": [
                { "credential": "Vetting statement credential (IdentityVettingEndorsement VEC)",
                  "why": "this is the point of the hidden path — a signed statement names its vetter. \
                          The endorsement is still built (it is where the attested facts come from) \
                          but never signed and never sent. `presentable_statements()` is 0." },
                { "credential": "Relationship credential pair (VRC)",
                  "why": "not part of admission in any path — VRCs are the peer relationship layer, and \
                          design D8 records that a VRC pair is not required for V0 membership. A \
                          community that required one *of its vetters* could not run hidden vetting: a \
                          VRC names both ends." },
                { "credential": "Invitation credential (VIC)",
                  "why": "invitation-gated admission only; this community is vetting-gated" },
                { "credential": "Personhood credential (VPC / personhood VMC)",
                  "why": "a separate evaluation (`personhood.rego`); this VMC carries personhood = false, \
                          as `admit` mints it" },
                { "credential": "Withdrawal credential (VWC)",
                  "why": "withdraws a named statement, which the hidden path does not produce. Hidden \
                          withdrawal is by token spend-set and class-label rotation instead" },
            ],
            "referencedButNotMintedHere": [
                { "artifact": "BitstringStatusList credential",
                  "detail": format!("the VMC's credentialStatus points at {status_list}#{status_slot}; the \
                                     list credential itself is served by a running vtc-service, which this \
                                     in-process run has no HTTP host for") },
            ],
            "notRunHere": [
                "delivery: a live flow carries all of this over DIDComm (`members/vmc/1.0`, the vetting \
                 Trust Tasks) between agents with mediators. This run drives the same library calls \
                 in-process, so the documents are real and the transport is not.",
                "the VTI side's decision path: `vtc-service`'s `vetting-pcs` feature runs the same \
                 verifier crate against the same wire fixture, but it is not started in this example.",
            ],
        }),
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&Value::Object(report)).unwrap()
    );
}
