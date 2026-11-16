use super::*;
use crate::config::account::{CommunityRecord, CommunityStatus, PersonaId, PersonaRecord};
use crate::test_support::{test_config, test_tdk};
use affinidi_tdk::secrets_resolver::secrets::Secret;

const PERSONA: &str = "did:webvh:QmP:example.com:alice";

fn community_key() -> (String, Secret) {
    let mut s = Secret::generate_ed25519(None, Some(&[0x71; 32]));
    let mb = s.get_public_keymultibase().unwrap();
    let did = format!("did:key:{mb}");
    s.id = format!("{did}#{mb}");
    (did, s)
}

/// A config holding one persona with a Pending join to `vtc`.
fn pending_config(vtc: &str) -> Config {
    let mut config = test_config();
    let pid = PersonaId::new();
    config.account.personas.insert(
        pid,
        PersonaRecord {
            extra: serde_json::Map::new(),
            persona_id: pid,
            did: PERSONA.into(),
            did_document: None,
            did_locator: None,
            key_refs: vec![],
            mediator_did: None,
            origin_context_id: "openvtc".into(),
            created_at: chrono::Utc::now(),
            label: None,
        },
    );
    config.account.add_membership(CommunityRecord::new_pending(
        vtc.into(),
        None,
        "openvtc/x".into(),
        pid,
        uuid::Uuid::new_v4(),
        chrono::Utc::now(),
    ));
    config
}

/// An `issue` as a VTC pushes it: a Trust Task document signed by the
/// community's key, opened out of the binding envelope.
async fn issue(vtc: &str, key: &Secret, credential: serde_json::Value) -> Message {
    let mut document = serde_json::from_value(serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": CREDENTIAL_ISSUE_TYPE,
        "issuer": vtc,
        "recipient": PERSONA,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": { "credential_response": { "credential": credential } },
    }))
    .expect("an issue document");
    crate::capabilities::sign_document(&mut document, key)
        .await
        .expect("sign the delivery");
    Message::build(
        uuid::Uuid::new_v4().to_string(),
        CREDENTIAL_ISSUE_TYPE.to_string(),
        serde_json::to_value(&document).expect("document json"),
    )
    .from(vtc.to_string())
    .to(PERSONA.to_string())
    .created_time(chrono::Utc::now().timestamp() as u64)
    .finalize()
}

async fn membership_vmc(vtc: &str, key: &Secret) -> serde_json::Value {
    let mut vc = serde_json::json!({
        "@context": [
            dtg_credentials::W3C_VC_V2_CONTEXT,
            dtg_credentials::DTG_CONTEXT_V1
        ],
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
        "issuer": vtc,
        "issuerScope": "public",
        "validFrom": "2026-01-01T00:00:00Z",
        "validUntil": "2099-01-01T00:00:00Z",
        "credentialSubject": { "id": PERSONA },
    });
    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &vc,
        key,
        affinidi_data_integrity::SignOptions::new(),
    )
    .await
    .unwrap();
    vc["proof"] = serde_json::to_value(proof).unwrap();
    vc
}

fn status(config: &Config, vtc: &str) -> CommunityStatus {
    config.account.memberships_for(vtc)[0].status.clone()
}

/// A credential delivery is not handled on arrival: it is set aside for
/// its check, and nothing — no credential, no activation — is applied
/// until the check's result comes back. Then a verified credential
/// activates the join, and a refused one leaves it Pending.
#[tokio::test]
async fn a_credential_is_verified_off_the_loop_before_anything_is_applied() {
    let (vtc, key) = community_key();
    let tdk = test_tdk().await;
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let service =
        crate::didcomm::start_empty_service(tx, tokio_util::sync::CancellationToken::new());
    let mut seen = SeenMessages::new();
    let mut pending = PendingReplies::default();

    // A forged (unsigned) credential: deferred, then refused.
    let mut config = pending_config(&vtc);
    let mut forged = membership_vmc(&vtc, &key).await;
    forged.as_object_mut().unwrap().remove("proof");
    let m = issue(&vtc, &key, forged).await;
    let mut effects = InboundEffects::default();
    let changed = process_inbound_message(
        &mut config,
        &tdk,
        &service,
        &mut seen,
        &mut pending,
        &m,
        m.from.as_deref(),
        &mut effects,
        Arrival::FRESH,
    )
    .await
    .unwrap();
    assert!(!changed, "nothing applied on arrival");
    let deferred = effects.deferred.take().expect("set aside for its check");
    assert_eq!(deferred.job.verifying_community(), Some(vtc.as_str()));
    assert!(matches!(
        status(&config, &vtc),
        CommunityStatus::Pending { .. }
    ));
    let pre = deferred.job.run(tdk.clone()).await;
    let mut effects = InboundEffects::default();
    process_inbound_message(
        &mut config,
        &tdk,
        &service,
        &mut seen,
        &mut pending,
        &deferred.message,
        deferred.message.from.as_deref(),
        &mut effects,
        Arrival::Returning(pre),
    )
    .await
    .unwrap();
    assert!(
        effects.deferred.is_none(),
        "handled on its return, not set aside again"
    );
    assert!(
        matches!(status(&config, &vtc), CommunityStatus::Pending { .. }),
        "refused: still Pending"
    );
    assert!(
        config.account.memberships_for(&vtc)[0]
            .credentials
            .is_empty()
    );

    // A genuine credential: deferred, then it activates.
    let mut config = pending_config(&vtc);
    let genuine = membership_vmc(&vtc, &key).await;
    let m = issue(&vtc, &key, genuine).await;
    let mut effects = InboundEffects::default();
    process_inbound_message(
        &mut config,
        &tdk,
        &service,
        &mut seen,
        &mut pending,
        &m,
        m.from.as_deref(),
        &mut effects,
        Arrival::FRESH,
    )
    .await
    .unwrap();
    let deferred = effects.deferred.take().expect("set aside");
    assert!(
        matches!(status(&config, &vtc), CommunityStatus::Pending { .. }),
        "not before its check"
    );
    let pre = deferred.job.run(tdk.clone()).await;
    assert!(matches!(&pre, PreVerified::Credential(Ok(_))));
    let mut effects = InboundEffects::default();
    process_inbound_message(
        &mut config,
        &tdk,
        &service,
        &mut seen,
        &mut pending,
        &deferred.message,
        deferred.message.from.as_deref(),
        &mut effects,
        Arrival::Returning(pre),
    )
    .await
    .unwrap();
    assert!(status(&config, &vtc).is_active(), "activated once verified");
}

/// A community's answer to a hidden-vetting question — here a vetter's enrolment, in the
/// binding envelope the VTC replies in — reaches the vetting router and takes the question
/// it threads on. Dropped before the router saw it, the question would wait out its 30
/// seconds as "no answer" and the vetter would never hold a token to attest with.
#[tokio::test]
async fn a_hidden_vetting_answer_reaches_the_question_it_answers() {
    use crate::vetting::queries::{CommunityQuery, QueryKind};
    use crate::vetting::wire::pcs;

    let (vtc, _key) = community_key();
    let tdk = test_tdk().await;
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let service =
        crate::didcomm::start_empty_service(tx, tokio_util::sync::CancellationToken::new());
    let mut seen = SeenMessages::new();
    let mut pending = PendingReplies::default();
    let mut config = pending_config(&vtc);
    let persona = *config.account.personas.keys().next().unwrap();

    for (kind, task, payload) in [
        (
            QueryKind::PcsRoot,
            pcs::ROOT_TYPE,
            serde_json::json!({ "label": "vetter/2026-10", "preCredential": "z1" }),
        ),
        (
            QueryKind::PcsTokens,
            pcs::TOKENS_TYPE,
            serde_json::json!({ "label": "token/2026-10", "tick": 0, "preCredentials": [] }),
        ),
    ] {
        let asked = format!("urn:uuid:{}", uuid::Uuid::new_v4());
        config.private.vetting.ask(CommunityQuery {
            document_id: asked.clone(),
            community: vtc.clone(),
            persona,
            kind,
            sent_at: chrono::Utc::now(),
        });
        let answer = Message::build(
            uuid::Uuid::new_v4().to_string(),
            crate::capabilities::TRUST_TASK_ENVELOPE_TYPE.to_string(),
            serde_json::json!({
                "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "type": pcs::response_of(task),
                "threadId": asked,
                "issuer": vtc,
                "recipient": PERSONA,
                "payload": payload,
            }),
        )
        .from(vtc.clone())
        .to(PERSONA.to_string())
        .created_time(chrono::Utc::now().timestamp() as u64)
        .finalize();
        let mut effects = InboundEffects::default();
        process_inbound_message(
            &mut config,
            &tdk,
            &service,
            &mut seen,
            &mut pending,
            &answer,
            answer.from.as_deref(),
            &mut effects,
            Arrival::FRESH,
        )
        .await
        .unwrap();
        assert!(
            !config
                .private
                .vetting
                .queries
                .iter()
                .any(|q| q.document_id == asked),
            "the {kind:?} answer was heard, so its question no longer waits to time out"
        );
    }
}

/// A result is taken only for the credential it was produced for.
#[tokio::test]
async fn a_check_result_for_another_credential_is_not_taken() {
    let (vtc, key) = community_key();
    let tdk = test_tdk().await;
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let service =
        crate::didcomm::start_empty_service(tx, tokio_util::sync::CancellationToken::new());
    let mut seen = SeenMessages::new();
    let mut pending = PendingReplies::default();
    let mut config = pending_config(&vtc);

    let other = issue(&vtc, &key, membership_vmc(&vtc, &key).await).await;
    let mut effects = InboundEffects::default();
    process_inbound_message(
        &mut config,
        &tdk,
        &service,
        &mut seen,
        &mut pending,
        &other,
        other.from.as_deref(),
        &mut effects,
        Arrival::FRESH,
    )
    .await
    .unwrap();
    let pre = effects.deferred.take().unwrap().job.run(tdk.clone()).await;

    // A different credential, handed back with the first one's result.
    let mut different = membership_vmc(&vtc, &key).await;
    different["id"] = serde_json::json!("urn:uuid:different");
    let m = issue(&vtc, &key, different).await;
    let mut effects = InboundEffects::default();
    process_inbound_message(
        &mut config,
        &tdk,
        &service,
        &mut seen,
        &mut pending,
        &m,
        m.from.as_deref(),
        &mut effects,
        Arrival::Returning(pre),
    )
    .await
    .unwrap();
    assert!(matches!(
        status(&config, &vtc),
        CommunityStatus::Pending { .. }
    ));
}

/// Operational documents (here a removal notice) are set aside too, and
/// applied only with their check's result.
#[tokio::test]
async fn a_removal_notice_waits_for_its_check() {
    let (vtc, _) = community_key();
    let tdk = test_tdk().await;
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let service =
        crate::didcomm::start_empty_service(tx, tokio_util::sync::CancellationToken::new());
    let mut seen = SeenMessages::new();
    let mut pending = PendingReplies::default();
    let mut config = pending_config(&vtc);
    let m = Message::build(
        uuid::Uuid::new_v4().to_string(),
        MEMBER_REMOVAL_NOTICE_TYPE.to_string(),
        serde_json::json!({ "payload": { "did": PERSONA } }),
    )
    .from(vtc.clone())
    .created_time(chrono::Utc::now().timestamp() as u64)
    .finalize();
    let mut effects = InboundEffects::default();
    process_inbound_message(
        &mut config,
        &tdk,
        &service,
        &mut seen,
        &mut pending,
        &m,
        m.from.as_deref(),
        &mut effects,
        Arrival::FRESH,
    )
    .await
    .unwrap();
    let deferred = effects.deferred.expect("set aside for its check");
    assert!(matches!(deferred.job, VerifyJob::Operational { .. }));
    assert_eq!(deferred.job.verifying_community(), None);
}

/// A config holding one persona with an Active membership of `vtc` whose
/// pre-v1 credentials were set aside on load — what the v1 migration leaves.
///
/// The persona also has a runtime identity, so a reply addressed to it is
/// recognised as ours (`Config::is_persona_did`), as it is at run time.
fn retired_config(vtc: &str) -> Config {
    let mut config = with_identity(pending_config(vtc));
    let record = &mut config.account.communities.get_mut(vtc).unwrap()[0];
    record.activate(chrono::Utc::now());
    for kind in ["Membership", "Role"] {
        record
            .retired_credentials
            .push(crate::config::account::RetiredCredential {
                kind: kind.into(),
                credential_id: None,
                reason: "pre-v1".into(),
                retired_at: chrono::Utc::now(),
            });
    }
    config
}

/// `config` with a runtime identity for `PERSONA`, so a reply addressed
/// to it is recognised as ours (`Config::is_persona_did`), as it is at run
/// time.
fn with_identity(mut config: Config) -> Config {
    use affinidi_tdk::messaging::profiles::{ATMProfile, ATMProfileInner};
    let pid = config.account.persona_id_for_did(PERSONA).unwrap();
    config.identities.insert(
        pid,
        crate::identity::IdentityContext {
            persona_id: pid,
            did: PERSONA.to_string(),
            document: serde_json::from_value(serde_json::json!({ "id": PERSONA }))
                .expect("minimal DID document"),
            profile: Arc::new(ATMProfile {
                inner: Arc::new(ATMProfileInner {
                    did: PERSONA.to_string(),
                    alias: PERSONA.to_string(),
                    mediator: Arc::new(None),
                }),
            }),
            mediator_did: None,
        },
    );
    config
}

/// A Trust Task document from the community to `PERSONA`, threaded on
/// `thid`, signed under `authentication` and carried in the binding
/// envelope — the shape a VTC answers a member verb with.
async fn community_reply(
    vtc: &str,
    key: &Secret,
    typ: &str,
    thid: &str,
    payload: serde_json::Value,
) -> Message {
    let mut document = serde_json::from_value(serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": typ,
        "issuer": vtc,
        "recipient": PERSONA,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "threadId": thid,
        "payload": payload,
    }))
    .expect("a reply document");
    crate::capabilities::sign_document(&mut document, key)
        .await
        .expect("sign the reply");
    Message::build(
        uuid::Uuid::new_v4().to_string(),
        crate::capabilities::TRUST_TASK_ENVELOPE_TYPE.to_string(),
        serde_json::to_value(&document).expect("document json"),
    )
    .from(vtc.to_string())
    .to(PERSONA.to_string())
    .thid(thid.to_string())
    .created_time(chrono::Utc::now().timestamp() as u64)
    .finalize()
}

/// A community role VAC conferring `role:member`, signed by `key`.
async fn role_vac(vtc: &str, key: &Secret) -> serde_json::Value {
    let vac = DTGCredential::new_community_role_vac(
        vtc.to_string(),
        PERSONA.to_string(),
        "member",
        chrono::Utc::now() - chrono::Duration::minutes(1),
        chrono::Utc::now() + chrono::Duration::days(365),
    )
    .unwrap()
    .with_max_attenuation(0)
    .unwrap();
    let mut vc = serde_json::to_value(vac).unwrap();
    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &vc,
        key,
        affinidi_data_integrity::SignOptions::new(),
    )
    .await
    .unwrap();
    vc["proof"] = serde_json::to_value(proof).unwrap();
    vc
}

/// **Renewal, end to end through the dispatcher.** The community's answer
/// to a renewal we asked for is set aside for its check, and only then
/// stored: the re-issued VMC and role VAC replace the set-aside pre-v1
/// credentials, and the notices go with them.
#[tokio::test]
async fn a_renewal_reply_is_checked_then_stored_clearing_the_retired_notices() {
    let (vtc, key) = community_key();
    let tdk = test_tdk().await;
    let mut config = retired_config(&vtc);
    let request = uuid::Uuid::new_v4();
    let mut pending = PendingReplies::default();
    assert!(crate::renewal::record_request(
        &mut pending,
        request,
        &vtc,
        PERSONA
    ));

    let vmc = membership_vmc(&vtc, &key).await;
    let vac = role_vac(&vtc, &key).await;
    let m = community_reply(
        &vtc,
        &key,
        crate::renewal::MEMBERS_RENEW_RESPONSE_TYPE,
        &format!("urn:uuid:{request}"),
        serde_json::json!({
            "did": PERSONA,
            "vmc": vmc,
            "roleVac": vac,
            "personhood": false,
            "personhoodChanged": false,
        }),
    )
    .await;

    let effects = dispatch_waiting(&mut config, &mut pending, &tdk, &m, Arrival::FRESH).await;
    let deferred = effects.deferred.expect("set aside for its check");
    assert!(matches!(deferred.job, VerifyJob::Renewal { .. }));
    assert!(
        config.account.memberships_for(&vtc)[0]
            .credentials
            .is_empty(),
        "nothing stored before the check"
    );

    let pre = deferred.job.run(tdk.clone()).await;
    assert!(matches!(&pre, PreVerified::Renewal(Ok(_))));
    let effects = dispatch_waiting(
        &mut config,
        &mut pending,
        &tdk,
        &deferred.message,
        Arrival::Returning(pre),
    )
    .await;

    let record = &config.account.memberships_for(&vtc)[0];
    assert_eq!(
        record.credentials.get(&crate::CredentialKind::Membership),
        Some(&vmc)
    );
    assert_eq!(
        record.credentials.get(&crate::CredentialKind::Role),
        Some(&vac)
    );
    assert!(record.retired_credentials.is_empty(), "the notices clear");
    let [(from, outcome)] = effects.renewals.as_slice() else {
        panic!("one renewal outcome");
    };
    assert_eq!(from, &vtc);
    let crate::renewal::RenewalOutcome::Renewed {
        summary,
        acknowledged,
    } = outcome
    else {
        panic!("renewed, got {outcome:?}");
    };
    assert_eq!(summary.roles, vec!["member".to_string()]);
    // The test config has no messaging identity, so the acknowledgement
    // cannot go out — and the member is told how to send it.
    assert!(acknowledged.is_err());
    assert!(outcome.describe().contains("press m"));

    // Answered once: the same reply again is not taken.
    let effects = dispatch_waiting(&mut config, &mut pending, &tdk, &m, Arrival::FRESH).await;
    assert!(pending.is_empty(), "the reply took its request");
    assert!(effects.deferred.is_none());
    assert!(effects.renewals.is_empty());
}

/// A reply threading on no renewal of ours is never checked or stored.
#[tokio::test]
async fn a_renewal_reply_we_did_not_ask_for_is_ignored() {
    let (vtc, key) = community_key();
    let tdk = test_tdk().await;
    let mut config = retired_config(&vtc);
    let m = community_reply(
        &vtc,
        &key,
        crate::renewal::MEMBERS_RENEW_RESPONSE_TYPE,
        &format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        serde_json::json!({
            "did": PERSONA,
            "vmc": membership_vmc(&vtc, &key).await,
            "roleVac": role_vac(&vtc, &key).await,
            "personhood": false,
            "personhoodChanged": false,
        }),
    )
    .await;
    let effects = dispatch(&mut config, &tdk, &m, Arrival::FRESH).await;
    assert!(effects.deferred.is_none());
    assert!(effects.renewals.is_empty());
    assert!(
        config.account.memberships_for(&vtc)[0]
            .credentials
            .is_empty()
    );
}

/// **notMember.** The community's signed refusal of our renewal reaches
/// the member as such — not as a join refusal, and with nothing changed.
#[tokio::test]
async fn a_renewal_refused_as_not_a_member_is_reported() {
    let (vtc, key) = community_key();
    let tdk = test_tdk().await;
    let mut config = retired_config(&vtc);
    let request = uuid::Uuid::new_v4();
    let mut pending = PendingReplies::default();
    assert!(crate::renewal::record_request(
        &mut pending,
        request,
        &vtc,
        PERSONA
    ));
    let m = community_reply(
        &vtc,
        &key,
        "https://trusttasks.org/spec/trust-task-error/0.1",
        &format!("urn:uuid:{request}"),
        serde_json::json!({
            "code": crate::renewal::RENEW_NOT_MEMBER,
            "message": "no ACL row — not a member",
            "retryable": false,
        }),
    )
    .await;

    let effects = dispatch_checked_waiting(&mut config, &mut pending, &tdk, &m).await;

    let [(_, outcome)] = effects.renewals.as_slice() else {
        panic!("one renewal outcome");
    };
    assert_eq!(
        outcome,
        &crate::renewal::RenewalOutcome::Refused(crate::renewal::RenewalRefusal::NotMember)
    );
    let record = &config.account.memberships_for(&vtc)[0];
    assert!(record.status.is_active(), "a refused renewal ends nothing");
    assert_eq!(record.retired_credentials.len(), 2);
    assert!(
        !pending.is_awaited(ReplyKind::Renewal, &vtc, &request.to_string()),
        "the refusal took the request"
    );
}

/// Collects what is logged at `WARN` and above while it is the default
/// subscriber on this thread.
#[derive(Clone, Default)]
struct Warnings(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Warnings {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Warnings {
    fn capture(&self) -> tracing::subscriber::DefaultGuard {
        let sink = self.clone();
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::WARN)
                .with_ansi(false)
                .with_writer(move || sink.clone())
                .finish(),
        )
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// Dispatch `m` once it has been through its off-loop check, as the loop
/// does: on arrival it is set aside, then handled with the check's result.
async fn dispatch_checked(config: &mut Config, tdk: &TDK, m: &Message) -> InboundEffects {
    dispatch_checked_waiting(config, &mut PendingReplies::default(), tdk, m).await
}

/// [`dispatch_checked`], with the requests in `pending` waited on.
async fn dispatch_checked_waiting(
    config: &mut Config,
    pending: &mut PendingReplies,
    tdk: &TDK,
    m: &Message,
) -> InboundEffects {
    let effects = dispatch_waiting(config, pending, tdk, m, Arrival::FRESH).await;
    let deferred = effects.deferred.expect("set aside for its check");
    let pre = deferred.job.run(tdk.clone()).await;
    dispatch_waiting(
        config,
        pending,
        tdk,
        &deferred.message,
        Arrival::Returning(pre),
    )
    .await
}

/// A witness's answer reaches the witnessing waiting on it whoever sent it — a witness is
/// no contact and no community — in either carriage, and is not read here: the witnessing
/// verifies it as the witness's. A refusal (`trust-task-error`) is offered too.
#[tokio::test(flavor = "current_thread")]
async fn a_witness_answer_is_handed_to_the_witnessing() {
    let tdk = test_tdk().await;
    let mut config = test_config();
    let witness = "did:key:z6MkWitness";
    let session = "urn:uuid:9e8d7c6b-0000-4000-8000-0000000000aa";
    for (typ, enveloped) in [
        (
            "https://trusttasks.org/spec/witness/session/0.2#response",
            true,
        ),
        (
            "https://trusttasks.org/spec/witness/session/submit/0.2#response",
            false,
        ),
        ("https://trusttasks.org/spec/trust-task-error/0.5", true),
    ] {
        let document = serde_json::json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": typ,
            "threadId": session,
            "issuer": witness,
            "recipient": "did:peer:2.Vz6MkOurs",
            "payload": {},
        });
        let message = Message::build(
            format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            if enveloped {
                crate::capabilities::TRUST_TASK_ENVELOPE_TYPE.to_string()
            } else {
                typ.to_string()
            },
            document.clone(),
        )
        .from(witness.to_string())
        .to("did:peer:2.Vz6MkOurs".to_string())
        .finalize();
        let effects = dispatch(&mut config, &tdk, &message, Arrival::FRESH).await;
        assert!(
            effects.deferred.is_none(),
            "{typ}: nothing to check off the loop"
        );
        let [reply] = effects.witness_replies.as_slice() else {
            panic!(
                "{typ}: one answer for the witnessing, got {:?}",
                effects.witness_replies
            );
        };
        assert_eq!(reply.sender, witness);
        assert_eq!(reply.document, document);
    }
}

/// A community that offers no capability management refuses the query
/// with a signed `trust-task-error`. It is proven and recorded once, for
/// the capability view, and then falls through the other refusal handlers
/// — which must not re-check it, find it already recorded, and warn that a
/// community refusal was ignored as a replay.
#[tokio::test(flavor = "current_thread")]
async fn a_capability_refusal_is_not_reported_as_its_own_replay() {
    let (vtc, key) = community_key();
    let tdk = test_tdk().await;
    let mut config = retired_config(&vtc);
    let thid = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let m = community_reply(
        &vtc,
        &key,
        "https://trusttasks.org/spec/trust-task-error/0.1",
        &thid,
        serde_json::json!({
            "code": "unsupportedType",
            "message": "governance/capability/list is not served here",
            "retryable": false,
        }),
    )
    .await;

    let warnings = Warnings::default();
    let effects = {
        let _guard = warnings.capture();
        dispatch_checked(&mut config, &tdk, &m).await
    };

    let [(from, reply_thid, reply)] = effects.capability_replies.as_slice() else {
        panic!("one capability reply, got {:?}", effects.capability_replies);
    };
    assert_eq!(from, &vtc);
    assert_eq!(reply_thid, &thid);
    assert!(matches!(
        reply,
        crate::capabilities::CapabilityReply::Rejected { code, .. }
            if code == "unsupportedType"
    ));
    let logged = warnings.text();
    assert!(!logged.contains("replay"), "{logged}");
    assert!(!logged.contains("refusal ignored"), "{logged}");
    assert!(
        !logged.contains("did not match a pending request"),
        "{logged}"
    );
    assert!(
        config.account.memberships_for(&vtc)[0].status.is_active(),
        "a capability refusal ends nothing"
    );

    // Replay protection across messages is untouched: the same refusal
    // again is not handed to the view a second time.
    let effects = dispatch_checked(&mut config, &tdk, &m).await;
    assert!(effects.capability_replies.is_empty());
}

/// A genuine join refusal still reaches the join handler, though it too is
/// proven first by the capability arm: a `permissionDenied` threaded on
/// our submit rejects the pending join.
#[tokio::test(flavor = "current_thread")]
async fn a_join_refusal_still_rejects_the_pending_join() {
    let (vtc, key) = community_key();
    let tdk = test_tdk().await;
    let mut config = with_identity(pending_config(&vtc));
    let CommunityStatus::Pending { request_id } = status(&config, &vtc) else {
        panic!("pending");
    };
    let m = community_reply(
        &vtc,
        &key,
        "https://trusttasks.org/spec/trust-task-error/0.1",
        &request_id.to_string(),
        serde_json::json!({
            "code": "permissionDenied",
            "message": "not admitted",
            "retryable": false,
        }),
    )
    .await;

    let warnings = Warnings::default();
    let effects = {
        let _guard = warnings.capture();
        dispatch_checked(&mut config, &tdk, &m).await
    };

    assert!(
        status(&config, &vtc) == CommunityStatus::Rejected,
        "{:?}",
        status(&config, &vtc)
    );
    assert_eq!(effects.inactivated.len(), 1);
    let logged = warnings.text();
    assert!(!logged.contains("replay"), "{logged}");
}

/// VTI-NTF-054: a notification addressed to one of our personas is handed over exactly as
/// received, whoever sent it — this client applies no acceptance policy — and one addressed
/// to a DID this account holds no persona for is not.
#[tokio::test]
async fn vti_ntf_054_a_notification_for_a_persona_is_handed_over_as_received() {
    let tdk = test_tdk().await;
    let mut config = with_identity(pending_config("did:key:z6MkSomeCommunity"));
    let stranger = "did:key:z6MkNotACommunityWeKnow";
    let document = serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": crate::notifications::NOTIFY_TYPE,
        "issuer": stranger,
        "recipient": PERSONA,
        "issuedAt": "2026-11-03T00:00:00.000000Z",
        "payload": { "notification": { "notificationId": "n-1" } },
        "proof": { "type": "DataIntegrityProof", "proofValue": "z5opaque" }
    });
    let wrapped = vta_sdk::tsp_binding::wrap_envelope(&serde_json::to_vec(&document).unwrap());
    let m = crate::didcomm::deliver_tsp_document(&wrapped, stranger, PERSONA)
        .expect("a notification passes the inbound gate");
    let effects = dispatch(&mut config, &tdk, &m, Arrival::FRESH).await;
    assert!(
        effects.deferred.is_none(),
        "nothing is checked before the hand-over"
    );
    assert_eq!(effects.notifications.len(), 1);
    let received = &effects.notifications[0];
    assert_eq!(received.document, document, "exactly as received");
    assert_eq!(received.sender, stranger);
    assert_eq!(received.addressee, PERSONA);

    let mut elsewhere = document.clone();
    elsewhere["recipient"] = serde_json::json!("did:key:z6MkNotOurs");
    elsewhere["id"] = serde_json::json!(format!("urn:uuid:{}", uuid::Uuid::new_v4()));
    let wrapped = vta_sdk::tsp_binding::wrap_envelope(&serde_json::to_vec(&elsewhere).unwrap());
    let m = crate::didcomm::deliver_tsp_document(&wrapped, stranger, PERSONA).unwrap();
    let effects = dispatch(&mut config, &tdk, &m, Arrival::FRESH).await;
    assert!(effects.notifications.is_empty());
}

/// An election answer from a community we hold no membership with — one holding an
/// election a notification told us of — is checked and handed over only on a thread we sent
/// it (VTI-NTF-063); on any other it has no standing and is never set aside for a check.
#[tokio::test]
async fn an_election_answer_from_a_non_member_community_needs_a_thread_we_sent() {
    let (holder, key) = community_key();
    let tdk = test_tdk().await;
    let mut config = with_identity(pending_config("did:key:z6MkTheCommunityWeBelongTo"));
    let answer = |thid: String| {
        let holder = holder.clone();
        let key = key.clone();
        async move {
            let mut document = serde_json::from_value(serde_json::json!({
                "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "type": "https://trusttasks.org/spec/trust-task-error/0.1",
                "issuer": holder,
                "recipient": PERSONA,
                "issuedAt": chrono::Utc::now()
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "threadId": thid,
                "payload": { "code": "vtc/elections/show:electionUnknown" },
            }))
            .unwrap();
            crate::capabilities::sign_document(&mut document, &key)
                .await
                .unwrap();
            let wrapped =
                vta_sdk::tsp_binding::wrap_envelope(&serde_json::to_vec(&document).unwrap());
            crate::didcomm::deliver_tsp_document(&wrapped, &holder, PERSONA).unwrap()
        }
    };

    // Not on a thread we sent it: not even set aside for a check.
    let m = answer(format!("urn:uuid:{}", uuid::Uuid::new_v4())).await;
    let effects = dispatch(&mut config, &tdk, &m, Arrival::FRESH).await;
    assert!(effects.deferred.is_none() && effects.elections_replies.is_empty());

    // On a thread we sent it: checked, then handed to the Elections panel.
    let thid = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let mut pending = PendingReplies::default();
    pending.record(
        &thid,
        &holder,
        crate::pending_replies::Purpose::ElectionAnswer,
    );
    let m = answer(thid.clone()).await;
    let effects = dispatch_checked_waiting(&mut config, &mut pending, &tdk, &m).await;
    assert_eq!(effects.elections_replies.len(), 1);
    assert_eq!(effects.elections_replies[0].thid, thid);
}

/// Dispatch `m` as `arrival`, returning the effects. Nothing is waited on.
async fn dispatch(
    config: &mut Config,
    tdk: &TDK,
    m: &Message,
    arrival: Arrival<'_>,
) -> InboundEffects {
    dispatch_waiting(config, &mut PendingReplies::default(), tdk, m, arrival).await
}

/// [`dispatch`], with the requests in `pending` waited on.
async fn dispatch_waiting(
    config: &mut Config,
    pending: &mut PendingReplies,
    tdk: &TDK,
    m: &Message,
    arrival: Arrival<'_>,
) -> InboundEffects {
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let service =
        crate::didcomm::start_empty_service(tx, tokio_util::sync::CancellationToken::new());
    let mut seen = SeenMessages::new();
    let mut effects = InboundEffects::default();
    process_inbound_message(
        config,
        tdk,
        &service,
        &mut seen,
        pending,
        m,
        m.from.as_deref(),
        &mut effects,
        arrival,
    )
    .await
    .unwrap();
    effects
}

/// The local checks run before anything is queued for a network-bound
/// check: a credential or operational document from a party we hold no
/// membership with, an accept that answers nothing of ours, or a
/// community answer to no question of ours is never set aside (so never
/// resolved or fetched for) — it is handled at once, and refused.
#[tokio::test]
async fn only_what_passes_the_local_checks_is_queued_for_a_check() {
    let (vtc, key) = community_key();
    let tdk = test_tdk().await;
    let mut config = pending_config(&vtc);
    let stranger = "did:key:z6MkStranger";

    // A credential "issued" by a stranger, about itself.
    let mut vc = membership_vmc(&vtc, &key).await;
    vc["issuer"] = serde_json::json!(stranger);
    let effects = dispatch(
        &mut config,
        &tdk,
        &issue(stranger, &key, vc).await,
        Arrival::FRESH,
    )
    .await;
    assert!(effects.deferred.is_none());
    // A credential for someone else, from the community.
    let mut vc = membership_vmc(&vtc, &key).await;
    vc["credentialSubject"]["id"] = serde_json::json!("did:key:z6MkSomeoneElse");
    let effects = dispatch(
        &mut config,
        &tdk,
        &issue(&vtc, &key, vc).await,
        Arrival::FRESH,
    )
    .await;
    assert!(effects.deferred.is_none());
    assert!(matches!(
        status(&config, &vtc),
        CommunityStatus::Pending { .. }
    ));

    // Operational documents from a stranger.
    for typ in [
        MEMBER_REMOVAL_NOTICE_TYPE,
        JOIN_REQUEST_STATUS_RESPONSE_TYPE,
        vta_sdk::protocols::vetting::VETTING_VETTER_LIST_RESPONSE_TYPE,
    ] {
        let m = Message::build(
            uuid::Uuid::new_v4().to_string(),
            typ.to_string(),
            serde_json::json!({ "payload": { "did": PERSONA } }),
        )
        .from(stranger.to_string())
        .created_time(chrono::Utc::now().timestamp() as u64)
        .finalize();
        let effects = dispatch(&mut config, &tdk, &m, Arrival::FRESH).await;
        assert!(effects.deferred.is_none(), "{typ}");
    }

    // A relationship accept answering no request of ours.
    let m = Message::build(
        uuid::Uuid::new_v4().to_string(),
        crate::protocol_urls::RELATIONSHIP_REQUEST_ACCEPT.to_string(),
        serde_json::json!({ "did": stranger }),
    )
    .from(stranger.to_string())
    .thid(uuid::Uuid::new_v4().to_string())
    .created_time(chrono::Utc::now().timestamp() as u64)
    .finalize();
    let effects = dispatch(&mut config, &tdk, &m, Arrival::FRESH).await;
    assert!(effects.deferred.is_none());
}

/// A message whose sender has messages queued for a check waits behind
/// them rather than overtaking them, and is handled when its turn comes.
///
/// The message here has no check of its own, which is what makes it wait
/// as a barrier. (This used `members/request-vmc`, until that became the
/// community's signed document with a check of its own; its ordering is
/// the same, and `a_request_for_our_vmc_waits_for_the_communitys_signature`
/// covers it.)
#[tokio::test]
async fn a_message_behind_a_check_from_its_sender_waits_its_turn() {
    let (vtc, _) = community_key();
    let tdk = test_tdk().await;
    let mut config = pending_config(&vtc);
    let m = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://didcomm.org/trust-ping/2.0/ping".to_string(),
        serde_json::json!({ "response_requested": false }),
    )
    .from(vtc.clone())
    .to(PERSONA.to_string())
    .created_time(chrono::Utc::now().timestamp() as u64)
    .finalize();

    let busy = |sender: &str| sender == vtc;
    let effects = dispatch(&mut config, &tdk, &m, Arrival::New { waiting: &busy }).await;
    let deferred = effects.deferred.expect("waits behind its sender's check");
    assert!(deferred.job.is_barrier());

    // Nobody else is held up.
    let effects = dispatch(&mut config, &tdk, &m, Arrival::FRESH).await;
    assert!(effects.deferred.is_none());

    // Back in its turn, it is handled, not set aside again.
    let effects = dispatch(
        &mut config,
        &tdk,
        &deferred.message,
        Arrival::Returning(PreVerified::Barrier),
    )
    .await;
    assert!(effects.deferred.is_none());
}

/// `members/request-vmc` makes this client sign and send a credential, so
/// it is the community's signed operational document or nothing: it is set
/// aside for that check, never acted on for the transport sender alone, and
/// a check that did not pass issues no VMC.
#[tokio::test]
async fn a_request_for_our_vmc_waits_for_the_communitys_signature() {
    let (vtc, _) = community_key();
    let tdk = test_tdk().await;
    let mut config = pending_config(&vtc);
    let m = Message::build(
        uuid::Uuid::new_v4().to_string(),
        MEMBER_REQUEST_VMC_TYPE.to_string(),
        serde_json::json!({}),
    )
    .from(vtc.clone())
    .to(PERSONA.to_string())
    .created_time(chrono::Utc::now().timestamp() as u64)
    .finalize();

    let effects = dispatch(&mut config, &tdk, &m, Arrival::FRESH).await;
    let deferred = effects
        .deferred
        .expect("a request for our VMC is checked before it is answered");
    assert!(
        matches!(deferred.job, VerifyJob::Operational { .. }),
        "checked as the community's operational document"
    );

    let effects = dispatch(
        &mut config,
        &tdk,
        &deferred.message,
        Arrival::Returning(deferred.job.unfinished()),
    )
    .await;
    assert!(effects.deferred.is_none());
    assert!(
        config
            .account
            .memberships_for(&vtc)
            .iter()
            .all(|m| m.member_vmc.is_none()),
        "an unverified request issues nothing"
    );
}

/// A message kept across a restart is queued for its check again — past
/// the age gate it already passed. One that no longer passes the local
/// checks is not dropped on restore: it waits its turn, and its handler
/// refuses it then.
#[tokio::test]
async fn a_restored_message_is_queued_again() {
    let (vtc, key) = community_key();
    let tdk = test_tdk().await;
    let mut config = pending_config(&vtc);
    let mut m = issue(&vtc, &key, membership_vmc(&vtc, &key).await).await;
    // Older than the replay window allows a fresh message.
    m.created_time = Some(1);
    assert!(
        dispatch(&mut config, &tdk, &m, Arrival::FRESH)
            .await
            .deferred
            .is_none(),
        "a fresh arrival that old is dropped"
    );
    let effects = dispatch(&mut config, &tdk, &m, Arrival::Restored).await;
    assert!(matches!(
        effects.deferred.map(|d| d.job),
        Some(VerifyJob::Credential { .. })
    ));

    // The membership went meanwhile: it waits as a barrier, and on its
    // turn it is refused — nothing is applied.
    config.account = Default::default();
    let deferred = dispatch(&mut config, &tdk, &m, Arrival::Restored)
        .await
        .deferred
        .expect("set aside to wait its turn");
    assert!(deferred.job.is_barrier());
    let effects = dispatch(
        &mut config,
        &tdk,
        &deferred.message,
        Arrival::Returning(PreVerified::Barrier),
    )
    .await;
    assert!(effects.deferred.is_none());
    assert!(config.account.memberships_for(&vtc).is_empty());
}

/// A message that waited as a barrier is triaged again on its turn: if it
/// now needs a check (its sender became a community we hold a record
/// with meanwhile), it is set aside for that check rather than refused as
/// unchecked.
#[tokio::test]
async fn a_barrier_is_triaged_again_on_its_turn() {
    let (vtc, key) = community_key();
    let tdk = test_tdk().await;
    let m = issue(&vtc, &key, membership_vmc(&vtc, &key).await).await;
    // No record with the community yet: no check, and it waits behind
    // its sender's queued work.
    let mut config = pending_config(&vtc);
    let persona_only = {
        let mut c = pending_config(&vtc);
        c.account.communities.clear();
        c
    };
    let mut early = persona_only;
    let busy = |sender: &str| sender == vtc;
    let deferred = dispatch(&mut early, &tdk, &m, Arrival::New { waiting: &busy })
        .await
        .deferred
        .expect("waits its turn");
    assert!(deferred.job.is_barrier());
    // By its turn the join is Pending: it now needs its check.
    let again = dispatch(
        &mut config,
        &tdk,
        &deferred.message,
        Arrival::Returning(PreVerified::Barrier),
    )
    .await
    .deferred
    .expect("set aside for the check it now needs");
    assert!(matches!(again.job, VerifyJob::Credential { .. }));
}

/// A check that did not finish is a refusal: the credential is not stored.
#[tokio::test]
async fn an_unfinished_check_refuses() {
    let (vtc, key) = community_key();
    let tdk = test_tdk().await;
    let mut config = pending_config(&vtc);
    let m = issue(&vtc, &key, membership_vmc(&vtc, &key).await).await;
    let deferred = dispatch(&mut config, &tdk, &m, Arrival::FRESH)
        .await
        .deferred
        .unwrap();
    let pre = deferred.job.unfinished();
    dispatch(
        &mut config,
        &tdk,
        &deferred.message,
        Arrival::Returning(pre),
    )
    .await;
    assert!(matches!(
        status(&config, &vtc),
        CommunityStatus::Pending { .. }
    ));
}

/// Every peer-message handler acts only as the sender the transport
/// authenticated. A message whose `from` is not backed by its sealing key
/// — none bound, or another DID — creates no task, removes none, changes no
/// relationship and hands nothing over.
mod sender_binding {
    use super::*;
    use crate::protocol_urls;
    use crate::relationships::Relationship;

    const ALICE: &str = "did:key:z6MkAlicePeerInAnEstablishedRelationship";
    const CAROL: &str = "did:key:z6MkCarolSomeoneElse";

    fn config_with(state: RelationshipState, task_id: &str) -> Config {
        let mut config = with_identity(pending_config("did:key:z6MkSomeCommunity"));
        let alice = Arc::new(ALICE.to_string());
        config.private.relationships.relationships.insert(
            Arc::clone(&alice),
            Relationship {
                task_id: Arc::new(task_id.to_string()),
                our_did: Arc::new(PERSONA.to_string()),
                remote_did: Arc::clone(&alice),
                remote_p_did: alice,
                created: chrono::Utc::now(),
                state,
                our_persona: None,
                needs_reestablishment: false,
            },
        );
        config
    }

    fn message(
        typ: &str,
        from: Option<&str>,
        thid: Option<&str>,
        body: serde_json::Value,
    ) -> Message {
        let mut b = Message::build(uuid::Uuid::new_v4().to_string(), typ.to_string(), body)
            .to(PERSONA.to_string())
            .created_time(chrono::Utc::now().timestamp() as u64);
        if let Some(from) = from {
            b = b.from(from.to_string());
        }
        if let Some(thid) = thid {
            b = b.thid(thid.to_string());
        }
        b.finalize()
    }

    async fn dispatch_as(
        config: &mut Config,
        m: &Message,
        authenticated: Option<&str>,
    ) -> InboundEffects {
        let tdk = test_tdk().await;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let service =
            crate::didcomm::start_empty_service(tx, tokio_util::sync::CancellationToken::new());
        let mut seen = SeenMessages::new();
        let mut pending = PendingReplies::default();
        let mut effects = InboundEffects::default();
        process_inbound_message(
            config,
            &tdk,
            &service,
            &mut seen,
            &mut pending,
            m,
            authenticated,
            &mut effects,
            Arrival::FRESH,
        )
        .await
        .unwrap();
        effects
    }

    /// The two ways a claimed `from` is not the sender: nothing bound, or
    /// someone else bound.
    const UNBOUND: [Option<&str>; 2] = [None, Some(CAROL)];

    #[tokio::test]
    async fn a_vrc_request_needs_its_sender_authenticated() {
        for authenticated in UNBOUND {
            let mut config = config_with(RelationshipState::Established, "rel");
            let m = message(
                protocol_urls::VRC_REQUEST,
                Some(ALICE),
                None,
                serde_json::json!({ "reason": "please" }),
            );
            dispatch_as(&mut config, &m, authenticated).await;
            assert!(
                config.private.tasks.tasks.is_empty(),
                "no inbox task for {authenticated:?}"
            );
        }
        let mut config = config_with(RelationshipState::Established, "rel");
        let m = message(
            protocol_urls::VRC_REQUEST,
            Some(ALICE),
            None,
            serde_json::json!({ "reason": "please" }),
        );
        dispatch_as(&mut config, &m, Some(ALICE)).await;
        assert_eq!(config.private.tasks.tasks.len(), 1, "authenticated: queued");
    }

    #[tokio::test]
    async fn a_vrc_request_rejection_needs_its_sender_authenticated() {
        let task = Arc::new(uuid::Uuid::new_v4().to_string());
        let setup = || {
            let mut config = config_with(RelationshipState::Established, "rel");
            config.private.tasks.new_task(
                &task,
                TaskType::VRCRequestOutbound {
                    remote_p_did: Arc::new(ALICE.to_string()),
                },
            );
            config
        };
        let reject = || {
            message(
                protocol_urls::VRC_REJECTED,
                Some(ALICE),
                Some(&task),
                serde_json::json!({ "reason": "no" }),
            )
        };
        for authenticated in UNBOUND {
            let mut config = setup();
            dispatch_as(&mut config, &reject(), authenticated).await;
            assert!(config.private.tasks.get_by_id(&task).is_some());
        }
        let mut config = setup();
        dispatch_as(&mut config, &reject(), Some(ALICE)).await;
        assert!(config.private.tasks.get_by_id(&task).is_none());
    }

    /// A pong closes only our ping, answered by the party pinged — never a
    /// task named by thread id alone, and never for a pong with no
    /// authenticated sender.
    #[tokio::test]
    async fn a_pong_closes_only_our_ping_to_its_authenticated_sender() {
        let ping = Arc::new(uuid::Uuid::new_v4().to_string());
        let other = Arc::new(uuid::Uuid::new_v4().to_string());
        let setup = || {
            let mut config = config_with(RelationshipState::Established, "rel");
            config.private.tasks.new_task(
                &ping,
                TaskType::TrustPing {
                    from: Arc::new(PERSONA.to_string()),
                    to: Arc::new(ALICE.to_string()),
                    remote_p_did: Arc::new(ALICE.to_string()),
                },
            );
            config.private.tasks.new_task(
                &other,
                TaskType::VRCRequestOutbound {
                    remote_p_did: Arc::new(ALICE.to_string()),
                },
            );
            config
        };
        let pong = |from: Option<&str>, thid: &str| {
            message(
                protocol_urls::TRUST_PONG,
                from,
                Some(thid),
                serde_json::json!({}),
            )
        };

        // No `from`, nothing authenticated: the old shortcut is gone.
        let mut config = setup();
        dispatch_as(&mut config, &pong(None, &ping), None).await;
        assert!(config.private.tasks.get_by_id(&ping).is_some());

        for authenticated in UNBOUND {
            let mut config = setup();
            dispatch_as(&mut config, &pong(Some(ALICE), &ping), authenticated).await;
            assert!(config.private.tasks.get_by_id(&ping).is_some());
        }

        // Authenticated, but the thread names a task that is not a ping.
        let mut config = setup();
        dispatch_as(&mut config, &pong(Some(ALICE), &other), Some(ALICE)).await;
        assert!(config.private.tasks.get_by_id(&other).is_some());

        // Authenticated as someone we did not ping.
        let mut config = setup();
        dispatch_as(&mut config, &pong(Some(CAROL), &ping), Some(CAROL)).await;
        assert!(config.private.tasks.get_by_id(&ping).is_some());

        let mut config = setup();
        dispatch_as(&mut config, &pong(Some(ALICE), &ping), Some(ALICE)).await;
        assert!(config.private.tasks.get_by_id(&ping).is_none());
        assert!(config.private.tasks.get_by_id(&other).is_some());
    }

    #[tokio::test]
    async fn a_relationship_rejection_needs_its_sender_authenticated() {
        let thid = uuid::Uuid::new_v4().to_string();
        let reject = || {
            message(
                protocol_urls::RELATIONSHIP_REQUEST_REJECT,
                Some(ALICE),
                Some(&thid),
                serde_json::json!({ "reason": "no" }),
            )
        };
        for authenticated in UNBOUND {
            let mut config = config_with(RelationshipState::RequestSent, &thid);
            dispatch_as(&mut config, &reject(), authenticated).await;
            assert_eq!(config.private.relationships.relationships.len(), 1);
        }
        let mut config = config_with(RelationshipState::RequestSent, &thid);
        dispatch_as(&mut config, &reject(), Some(ALICE)).await;
        assert!(config.private.relationships.relationships.is_empty());
    }

    #[tokio::test]
    async fn a_relationship_finalize_needs_its_sender_authenticated() {
        let thid = uuid::Uuid::new_v4().to_string();
        let finalize = || {
            message(
                protocol_urls::RELATIONSHIP_REQUEST_FINALIZE,
                Some(ALICE),
                Some(&thid),
                serde_json::json!({}),
            )
        };
        let state = |config: &Config| {
            config
                .private
                .relationships
                .relationships
                .values()
                .next()
                .map(|r| r.state.clone())
        };
        for authenticated in UNBOUND {
            let mut config = config_with(RelationshipState::RequestAccepted, &thid);
            dispatch_as(&mut config, &finalize(), authenticated).await;
            assert_eq!(state(&config), Some(RelationshipState::RequestAccepted));
        }
        let mut config = config_with(RelationshipState::RequestAccepted, &thid);
        dispatch_as(&mut config, &finalize(), Some(ALICE)).await;
        assert_eq!(state(&config), Some(RelationshipState::Established));
    }

    /// A message dropped for its sender does not enter the replay cache,
    /// so the authenticated message with the same id is still handled.
    #[tokio::test]
    async fn an_unbound_message_does_not_use_up_its_id() {
        let tdk = test_tdk().await;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let service =
            crate::didcomm::start_empty_service(tx, tokio_util::sync::CancellationToken::new());
        let mut seen = SeenMessages::new();
        let mut pending = PendingReplies::default();
        let mut config = config_with(RelationshipState::Established, "rel");
        let m = message(
            protocol_urls::VRC_REQUEST,
            Some(ALICE),
            None,
            serde_json::json!({ "reason": "please" }),
        );
        for authenticated in [None, Some(ALICE)] {
            let mut effects = InboundEffects::default();
            process_inbound_message(
                &mut config,
                &tdk,
                &service,
                &mut seen,
                &mut pending,
                &m,
                authenticated,
                &mut effects,
                Arrival::FRESH,
            )
            .await
            .unwrap();
        }
        assert_eq!(config.private.tasks.tasks.len(), 1);
    }

    #[tokio::test]
    async fn a_trust_ping_task_needs_its_sender_authenticated() {
        for authenticated in UNBOUND {
            let mut config = config_with(RelationshipState::Established, "rel");
            let m = message(
                protocol_urls::TRUST_PING,
                Some(ALICE),
                None,
                serde_json::json!({}),
            );
            dispatch_as(&mut config, &m, authenticated).await;
            assert!(config.private.tasks.tasks.is_empty());
        }
    }

    /// A notification is handed over and answered with a receipt to its
    /// sender; with no authenticated sender there is nobody to answer.
    #[tokio::test]
    async fn a_notification_needs_its_sender_authenticated() {
        let document = || {
            serde_json::json!({
                "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "type": crate::notifications::NOTIFY_TYPE,
                "issuer": ALICE,
                "recipient": PERSONA,
                "issuedAt": "2026-11-03T00:00:00.000000Z",
                "payload": { "notification": { "notificationId": "n-1" } },
            })
        };
        for authenticated in UNBOUND {
            let mut config = config_with(RelationshipState::Established, "rel");
            let m = message(
                crate::notifications::NOTIFY_TYPE,
                Some(ALICE),
                None,
                document(),
            );
            let effects = dispatch_as(&mut config, &m, authenticated).await;
            assert!(effects.notifications.is_empty(), "{authenticated:?}");
        }
        let mut config = config_with(RelationshipState::Established, "rel");
        let m = message(
            crate::notifications::NOTIFY_TYPE,
            Some(ALICE),
            None,
            document(),
        );
        let effects = dispatch_as(&mut config, &m, Some(ALICE)).await;
        assert_eq!(effects.notifications.len(), 1);
        assert_eq!(effects.notifications[0].sender, ALICE);
    }
}

/// One type for every family, as a peer would send it: the registry's own
/// type where a route names one exactly, a version under a prefix, and a known
/// member of each predicate.
fn one_type_per_family() -> Vec<(String, registry::Family)> {
    use registry::{Family, ROUTES, TypeMatcher};
    let mut types: Vec<(String, Family)> = ROUTES
        .iter()
        .filter_map(|route| match route.matcher {
            TypeMatcher::Exact(t) => Some((t.to_string(), route.family)),
            TypeMatcher::Prefix(p) => Some((format!("{p}show/0.1#response"), route.family)),
            TypeMatcher::Predicate(_) => None,
        })
        .collect();
    types.push((
        "https://trusttasks.org/spec/witness/session/0.2#response".into(),
        Family::WitnessReply,
    ));
    types.push((
        "https://trusttasks.org/spec/vetting/request/0.1".into(),
        Family::Vetting,
    ));
    types.push((
        crate::vetting::protocol::JoinProtocol::V0_4
            .submit_response_type()
            .to_string(),
        Family::JoinVerdict,
    ));
    types
}

/// Inbound dispatch, family by family: a message nobody can be shown to have
/// sent — no authenticated sender, no thread we asked on, an empty body —
/// reaches its family's handler and changes nothing. Every family is driven,
/// so a handler that persists, or panics, on an unattributable message fails
/// here by name.
#[tokio::test]
async fn an_unattributable_message_of_every_family_changes_nothing() {
    let tdk = test_tdk().await;
    let types = one_type_per_family();
    for family in registry::Family::ALL {
        assert!(
            types.iter().any(|(_, f)| f == family),
            "{family:?} has no sample type here"
        );
    }
    for (typ, family) in types {
        assert_eq!(
            registry::classify(&typ),
            Some(family),
            "{typ} is not routed to {family:?}"
        );
        let mut config = with_identity(pending_config("did:key:z6MkTheCommunity"));
        let account = serde_json::to_value(&config.account).unwrap();
        let private = serde_json::to_value(&config.private).unwrap();
        let message = Message::build(
            format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            typ.clone(),
            serde_json::json!({}),
        )
        .from("did:key:z6MkStranger".into())
        .to(PERSONA.into())
        .finalize();

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let service =
            crate::didcomm::start_empty_service(tx, tokio_util::sync::CancellationToken::new());
        let mut effects = InboundEffects::default();
        let result = process_inbound_message(
            &mut config,
            &tdk,
            &service,
            &mut SeenMessages::new(),
            &mut PendingReplies::default(),
            &message,
            None,
            &mut effects,
            Arrival::FRESH,
        )
        .await;

        assert!(
            !matches!(result, Ok(true)),
            "{family:?} ({typ}) reported a config change"
        );
        assert_eq!(
            serde_json::to_value(&config.account).unwrap(),
            account,
            "{family:?} ({typ}) changed the account"
        );
        assert_eq!(
            serde_json::to_value(&config.private).unwrap(),
            private,
            "{family:?} ({typ}) changed the protected config"
        );
        assert!(
            effects.inactivated.is_empty() && effects.deferred.is_none(),
            "{family:?} ({typ}) acted on, or queued a check for, a message nobody sent"
        );
    }
}
