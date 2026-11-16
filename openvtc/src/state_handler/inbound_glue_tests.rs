//! Inbound dispatch (core) feeding the TUI's views: a reply taken by
//! [`openvtc_core::inbound::process_inbound_message`] and applied to a view by
//! the CLI's glue. The dispatcher's own tests live with it in
//! `openvtc_core::inbound`.

use std::sync::Arc;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_tdk::{TDK, didcomm::Message};
use openvtc_core::config::Config;
use openvtc_core::config::account::{CommunityRecord, PersonaId, PersonaRecord};
use openvtc_core::inbound::{Arrival, InboundEffects, process_inbound_message};
use openvtc_core::messaging::SeenMessages;

use crate::state_handler::dispatch_util::{test_config, test_tdk};

const PERSONA: &str = "did:webvh:QmP:example.com:alice";

fn community_key() -> (String, Secret) {
    let mut s = Secret::generate_ed25519(None, Some(&[0x71; 32]));
    let mb = s.get_public_keymultibase().unwrap();
    let did = format!("did:key:{mb}");
    s.id = format!("{did}#{mb}");
    (did, s)
}

/// One persona, with a runtime identity, holding an Active membership of `vtc`.
fn member_config(vtc: &str) -> Config {
    use affinidi_tdk::messaging::profiles::{ATMProfile, ATMProfileInner};
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
    let mut record = CommunityRecord::new_pending(
        vtc.into(),
        None,
        "openvtc/x".into(),
        pid,
        uuid::Uuid::new_v4(),
        chrono::Utc::now(),
    );
    record.activate(chrono::Utc::now());
    config.account.add_membership(record);
    config.identities.insert(
        pid,
        openvtc_core::identity::IdentityContext {
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

async fn dispatch(
    config: &mut Config,
    tdk: &TDK,
    m: &Message,
    arrival: Arrival<'_>,
) -> InboundEffects {
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let service =
        openvtc_core::didcomm::start_empty_service(tx, tokio_util::sync::CancellationToken::new());
    let mut seen = SeenMessages::new();
    let mut effects = InboundEffects::default();
    process_inbound_message(
        config,
        tdk,
        &service,
        &mut seen,
        &mut openvtc_core::pending_replies::PendingReplies::default(),
        m,
        m.from.as_deref(),
        &mut effects,
        arrival,
    )
    .await
    .unwrap();
    effects
}

/// Dispatch `m` once it has been through its off-loop check, as the loop does.
async fn dispatch_checked(config: &mut Config, tdk: &TDK, m: &Message) -> InboundEffects {
    let effects = dispatch(config, tdk, m, Arrival::FRESH).await;
    let deferred = effects.deferred.expect("set aside for its check");
    let pre = deferred.job.run(tdk.clone()).await;
    dispatch(config, tdk, &deferred.message, Arrival::Returning(pre)).await
}

/// A TSP-joined member's Repos view loads from the community's
/// `git-ns/view/0.6` answer, taken the whole way a live one is: sealed in
/// the TSP binding envelope, mapped and passed through the inbound gate
/// (`deliver_tsp_document`), checked off the loop and dispatched
/// (`process_inbound_message`), then correlated by the Repos view
/// (`repos_actions::apply_replies`). A gate that drops this type at debug
/// leaves the view timing out on an answer the VTC has sent.
#[tokio::test(flavor = "current_thread")]
async fn a_tsp_git_ns_view_answer_loads_the_repos_view() {
    use crate::state_handler::main_page::repos::{Pending, Purpose, ReposPhase, ReposView};
    let (vtc, key) = community_key();
    let tdk = test_tdk().await;
    let mut config = member_config(&vtc);
    let thid = format!("urn:uuid:{}", uuid::Uuid::new_v4());

    // The signed document, as the VTC sends it over TSP.
    let mut document = serde_json::from_value(serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/git-ns/view/0.6#response",
        "issuer": vtc,
        "recipient": PERSONA,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "threadId": thid,
        "payload": {
            "accounts": [],
            "namespaces": [{"id": "ns_1", "forge": "github.com", "owner": "acme",
                            "kind": "organization", "mode": "bridge", "state": "bound"}],
            "repos": [{"resource": "github.com/acme/gadgets", "forgeId": "1",
                       "visibility": "public", "state": "active", "owners": [PERSONA],
                       "bootstrap": {"workflow": true, "keyring": true,
                                     "variables": true, "requiredCheck": true},
                       "sync": {"state": "inSync", "drift": []}}],
            "rights": [{"subject": PERSONA, "right": "git.repo.own",
                        "resource": "github.com/acme/gadgets", "grantedBy": PERSONA,
                        "grantedAt": "2026-09-02T00:00:00Z"}]
        },
    }))
    .expect("a reply document");
    openvtc_core::capabilities::sign_document(&mut document, &key)
        .await
        .expect("sign the reply");
    let wrapped = vta_sdk::tsp_binding::wrap_envelope(
        &serde_json::to_vec(&document).expect("document bytes"),
    );
    let m = openvtc_core::didcomm::deliver_tsp_document(&wrapped, &vtc, PERSONA)
        .expect("the answer passes the inbound gate");

    let effects = dispatch_checked(&mut config, &tdk, &m).await;
    assert_eq!(effects.git_ns_replies.len(), 1, "handed to the Repos view");

    // The Repos view, waiting on the request this answers.
    let pid = config.account.persona_id_for_did(PERSONA).unwrap();
    let mut state = crate::state_handler::state::State::default();
    let mut view = ReposView::new(vtc.clone(), pid, PERSONA.into(), "Acme".into());
    view.pending = Some(Pending {
        thid: thid.clone(),
        sent_at: std::time::Instant::now(),
        purpose: Purpose::View,
    });
    state.main_page.content_panel.repos.view = Some(view);

    crate::state_handler::repos_actions::apply_replies(&mut state, &config, effects.git_ns_replies);
    let view = state.main_page.content_panel.repos.view.as_ref().unwrap();
    assert_eq!(view.phase, ReposPhase::Loaded);
    assert!(view.pending.is_none(), "the wait is over");
    assert_eq!(view.my_repos().len(), 1);
}
