//! Having a relationship witnessed, off the loop thread.
//!
//! The witnessing itself is `openvtc_core::witness`: the VTA builds and signs every document as
//! the relationship DID, and this client carries them on that DID's own connection. What lives
//! here is the TUI's part — choosing what to present from the account (on the loop thread, from
//! `Config`), running the round as a background job (its own domain: it waits on a witness for up
//! to two minutes, and must not hold up a ping or a VRC request), reporting each step, and
//! recording the result.
//!
//! The witness's answers arrive on the inbound channel like any other document. The dispatcher
//! hands each one to the [`ReplyRouter`], which passes it to the job waiting on that session's
//! thread; the job verifies it as the witness's before reading it.

use std::sync::Arc;

use affinidi_tdk::TDK;
use affinidi_tdk::did_resolver::DIDCacheClient;
use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use chrono::Utc;
use openvtc_core::CredentialKind;
use openvtc_core::config::account::PersonaId;
use openvtc_core::config::{Config, KeyBackend};
use openvtc_core::didcomm::Messaging;
use openvtc_core::relationships::{Relationship, RelationshipState};
use openvtc_core::witness::{
    self, Carrier, DidcommCarrier, MembershipEvidence, ReplyRouter, Round, TspCarrier,
    WitnessError, WitnessRecord, WitnessRequest, WitnessRoute, Witnessed,
};
use serde_json::Value;
use tokio::sync::mpsc::UnboundedSender;
use vta_sdk::client::VtaClient;
use vta_sdk::trust_task_proof::TrustTaskVmResolver;

use crate::state_handler::actions::PersonhoodEvidenceAction;
use crate::state_handler::background_dispatch::{DispatchOutcome, ProgressUpdate};
use crate::state_handler::main_page::content::{
    PersonhoodEvidenceView, RelationshipsMode, WitnessChoice,
};
use crate::state_handler::save_coalesce::SaveScheduler;
use crate::state_handler::state::State;

/// The persona a relationship belongs to: its attribution tag, or — for a relationship from
/// before the tag existed — the account's only persona.
pub(crate) fn relationship_persona(config: &Config, rel: &Relationship) -> Option<PersonaId> {
    rel.our_persona.or_else(|| {
        if config.identities.len() == 1 {
            config.identities.keys().next().copied()
        } else {
            None
        }
    })
}

/// The relationship credential this account issued for `rel` that a witness can be shown: issued
/// by our DID in the relationship to theirs, carrying its own `id` (the VTA names it by vault
/// handle), within its validity period. The newest, if several.
fn issued_vrc(config: &Config, remote_p_did: &str, rel: &Relationship) -> Option<Value> {
    let now = Utc::now();
    config
        .private
        .vrcs_issued
        .get(&Arc::new(remote_p_did.to_string()))?
        .values()
        .filter(|vrc| {
            vrc.issuer() == rel.our_did.as_str()
                && vrc.subject() == rel.remote_did.as_str()
                && vrc.id().is_some()
                && vrc.valid_from() <= now
                && vrc.valid_until().is_none_or(|until| now < until)
        })
        .max_by_key(|vrc| vrc.valid_from())
        .and_then(|vrc| serde_json::to_value(vrc.as_ref()).ok())
}

/// The membership to present beside the relationship credential: a live membership of the
/// relationship's persona whose credential carries its own `id`. When the credential names a
/// DID other than the relationship's (a pairwise relationship DID — the usual case), the VTA
/// links the two for the witness (`memberDid`).
fn membership_evidence(config: &Config, rel: &Relationship) -> Option<MembershipEvidence> {
    let persona = relationship_persona(config, rel)?;
    let credential = config
        .account
        .memberships()
        .filter(|m| m.persona_ref == persona && m.is_live())
        .find_map(|m| {
            m.credentials
                .get(&CredentialKind::Membership)
                .filter(|vc| vc.get("id").and_then(Value::as_str).is_some())
                .cloned()
        })?;
    let named = credential
        .pointer("/credentialSubject/id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let member_did = named.filter(|did| did != rel.our_did.as_str());
    Some(MembershipEvidence {
        credential,
        member_did,
    })
}

/// Everything the round needs, resolved on the loop thread.
pub(crate) struct WitnessJob {
    vta: VtaClient,
    resolver: DIDCacheClient,
    router: ReplyRouter,
    didcomm: DidcommCarrier,
    /// The persona's ATM profile, when the relationship uses the persona DID: the only identity
    /// this client can send TSP as.
    tsp_sender: Option<(ATM, Arc<ATMProfile>)>,
    /// What the member typed: a DID or an agent name, resolved in the job.
    witness_input: String,
    remote_p_did: String,
    request: WitnessRequest,
    progress: UnboundedSender<DispatchOutcome>,
}

/// Choose what to present and how to send it, or say why this relationship cannot be witnessed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare(
    config: &Config,
    tdk: &TDK,
    service: &Messaging,
    admin_vta: Option<&VtaClient>,
    router: &ReplyRouter,
    progress: &UnboundedSender<DispatchOutcome>,
    remote_p_did: &str,
    witness_input: &str,
) -> Result<WitnessJob, String> {
    if matches!(config.key_backend, KeyBackend::Bip32 { .. }) {
        return Err(
            "Witnessing runs through your VTA, which signs every document as this \
             relationship's DID. This account keeps its keys on this device (BIP32), not at a \
             VTA, so its relationships cannot be witnessed."
                .into(),
        );
    }
    let vta = admin_vta
        .cloned()
        .ok_or("No VTA session — witnessing needs your VTA. Reconnect to it and try again.")?;
    let witness_input = witness_input.trim();
    if witness_input.is_empty() {
        return Err("Enter the witness's DID or agent name.".into());
    }
    let rel = config
        .private
        .relationships
        .get(&Arc::new(remote_p_did.to_string()))
        .ok_or_else(|| format!("No relationship with {remote_p_did}."))?;
    if rel.state != RelationshipState::Established {
        return Err("Only an established relationship can be witnessed.".into());
    }
    if rel.needs_reestablishment {
        return Err(
            "This relationship's keys were lost; re-establish it before having it witnessed."
                .into(),
        );
    }
    let relationship_credential = issued_vrc(config, remote_p_did, rel).ok_or(
        "You have not issued this contact a relationship credential that a witness can be \
         shown — a witness observes you presenting the one you issued, and it is issued when \
         you accept their VRC request.",
    )?;

    let our_did = rel.our_did.to_string();
    let tsp_sender = if config.is_persona_did(&our_did) {
        let atm = tdk.atm.as_ref().cloned();
        config
            .identities
            .values()
            .find(|i| i.did == our_did)
            .and_then(|i| atm.map(|atm| (atm, i.profile().clone())))
    } else {
        None
    };

    Ok(WitnessJob {
        vta,
        resolver: tdk.did_resolver().clone(),
        router: router.clone(),
        didcomm: DidcommCarrier {
            service: service.clone(),
            listener_id: openvtc_core::didcomm::listener_id_for_did(&our_did, config),
            relationship_did: our_did.clone(),
            // Set once the witness's DID is resolved, in the job.
            witness_did: String::new(),
        },
        tsp_sender,
        witness_input: witness_input.to_string(),
        remote_p_did: remote_p_did.to_string(),
        request: WitnessRequest {
            witness_did: String::new(),
            relationship_did: our_did,
            counterparty_did: rel.remote_did.to_string(),
            relationship_thread_id: rel.task_id.to_string(),
            relationship_credential,
            membership: membership_evidence(config, rel),
        },
        progress: progress.clone(),
    })
}

impl WitnessJob {
    /// The round. I/O only.
    pub(crate) async fn run(self) -> WitnessOutcome {
        let remote_p_did = self.remote_p_did.clone();
        let relationship_did = self.request.relationship_did.clone();
        let result = self.witness().await.map_err(|e| e.to_string());
        WitnessOutcome {
            remote_p_did,
            relationship_did,
            result,
        }
    }

    async fn witness(mut self) -> Result<Witnessed, WitnessError> {
        let report = |text: &str| {
            let _ = self
                .progress
                .send(DispatchOutcome::Progress(ProgressUpdate::Witness(
                    text.to_string(),
                )));
        };
        report("Resolving the witness…");
        // A name is resolved to a DID and the DID is what is used (and kept).
        let witness_did =
            openvtc_core::agent_name::resolve_identifier(&self.resolver, &self.witness_input)
                .await
                .map_err(|e| WitnessError::Unsupported(format!("The witness: {e}")))?;
        if witness_did == self.request.relationship_did
            || witness_did == self.request.counterparty_did
        {
            return Err(WitnessError::Unsupported(
                "A witness has to be a third party, not one of the relationship's own DIDs.".into(),
            ));
        }
        self.request.witness_did = witness_did.clone();
        self.didcomm.witness_did = witness_did.clone();

        let ours =
            witness::resolve_document(&self.resolver, &self.request.relationship_did).await?;
        let theirs = witness::resolve_document(&self.resolver, &witness_did).await?;
        let tsp;
        let carrier: &dyn Carrier = match witness::select_route(&ours, &theirs, &witness_did)? {
            WitnessRoute::Didcomm => &self.didcomm,
            WitnessRoute::Tsp { witness_mediator } => {
                let (atm, profile) = self.tsp_sender.clone().ok_or_else(|| {
                    WitnessError::NoRoute(
                        "this relationship's DID and the witness both advertise TSP, but this \
                         client can send TSP only as a persona DID, and this relationship uses \
                         its own DID"
                            .into(),
                    )
                })?;
                tsp = TspCarrier {
                    atm,
                    profile,
                    witness_did: witness_did.clone(),
                    witness_mediator,
                };
                &tsp
            }
        };

        let resolver = TrustTaskVmResolver::new(self.resolver.clone());
        let round = Round {
            vta: &self.vta,
            carrier,
            router: &self.router,
            resolver: &resolver,
            answer_timeout: witness::DEFAULT_ANSWER_TIMEOUT,
        };
        let progress = |step: witness::Step| report(step.describe());
        witness::run(&round, &self.request, &progress).await
    }
}

/// What the round did. Data only; applied on the loop thread.
pub(crate) struct WitnessOutcome {
    remote_p_did: String,
    relationship_did: String,
    result: Result<Witnessed, String>,
}

impl WitnessOutcome {
    pub(crate) fn apply(self, state: &mut State, config: &mut Config, save: &mut SaveScheduler) {
        match self.result {
            Ok(witnessed) => {
                let line = format!(
                    "Witnessed by {} — the witness credential is stored at your VTA as {}",
                    witnessed.witness, witnessed.credential_id
                );
                config.private.witnessings.push(WitnessRecord {
                    remote_p_did: self.remote_p_did,
                    relationship_did: self.relationship_did,
                    witnessed_at: Utc::now(),
                    witnessed,
                });
                save.mark_dirty();
                state.main_page.sync_from_config(config);
                // Back to the relationship, which now lists the witnessing. A failure stays on
                // the prompt instead, so another witness can be tried.
                let rels = &mut state.main_page.content_panel.relationships;
                if let RelationshipsMode::Witness { index, .. } = rels.mode {
                    rels.mode = RelationshipsMode::Detail {
                        index,
                        selected_vrc: None,
                    };
                }
                rels.status_message = Some(line.clone());
                state.main_page.log(line);
            }
            Err(e) => {
                let line = format!("Witnessing failed: {e}");
                state.main_page.content_panel.relationships.status_message = Some(line.clone());
                state.main_page.log(line);
            }
        }
    }
}

// ─── Personhood: which witness credentials to present ───────────────────────

/// The witnessings of `persona`'s relationships.
pub(crate) fn persona_witnessings(
    config: &Config,
    persona: PersonaId,
) -> impl Iterator<Item = &WitnessRecord> {
    config.private.witnessings.0.iter().filter(move |r| {
        config
            .private
            .relationships
            .get(&Arc::new(r.remote_p_did.clone()))
            .is_some_and(|rel| relationship_persona(config, rel) == Some(persona))
    })
}

/// What the picker shows for each of `persona`'s witnessed relationships that has a VWC to
/// present: the witness, the other party and the date, by name where one is verified.
pub(crate) fn witness_choices(config: &Config, persona: PersonaId) -> Vec<WitnessChoice> {
    persona_witnessings(config, persona)
        .filter(|r| r.witnessed.vwc().is_some())
        .map(|r| {
            let counterparty = config
                .private
                .contacts
                .find_contact(&r.remote_p_did)
                .and_then(|c| c.alias.clone())
                .or_else(|| config.agent_name_for(&r.remote_p_did).map(str::to_string))
                .unwrap_or_else(|| r.remote_p_did.clone());
            WitnessChoice {
                session_id: r.witnessed.session_id.clone(),
                witness: config
                    .agent_name_for(&r.witnessed.witness)
                    .map_or_else(|| r.witnessed.witness.clone(), str::to_string),
                counterparty,
                witnessed_at: r.witnessed_at.format("%Y-%m-%d %H:%M").to_string(),
                digest: r.witnessed.vwc_digest_multibase.clone(),
            }
        })
        .collect()
}

/// A fresh picker over `choices`, with nothing chosen.
pub(crate) fn evidence_view(choices: Vec<WitnessChoice>) -> PersonhoodEvidenceView {
    PersonhoodEvidenceView {
        chosen: vec![false; choices.len()],
        choices,
        ..PersonhoodEvidenceView::default()
    }
}

pub(crate) fn too_many_witness_credentials() -> String {
    format!(
        "A community accepts at most {} witness credentials in one assertion — choose fewer.",
        witness::MAX_OUTCOME_EVIDENCE
    )
}

/// What a picker key leads to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EvidenceStep {
    Stay,
    Close,
    /// Assert with exactly these witnessings, by session id.
    Assert(Vec<String>),
}

/// The picker's reducer. "Include all" asserts only from an armed confirmation; arming it
/// includes nothing, and it is never remembered past this picker.
pub(crate) fn evidence_step(
    view: &mut PersonhoodEvidenceView,
    action: PersonhoodEvidenceAction,
) -> EvidenceStep {
    use PersonhoodEvidenceAction as A;
    view.notice = None;
    match action {
        A::Up => view.cursor = view.cursor.saturating_sub(1),
        A::Down => {
            if view.cursor + 1 < view.choices.len() {
                view.cursor += 1;
            }
        }
        A::Toggle => {
            let chosen = view.chosen.iter().filter(|c| **c).count();
            if let Some(c) = view.chosen.get_mut(view.cursor) {
                if !*c && chosen >= witness::MAX_OUTCOME_EVIDENCE {
                    view.notice = Some(too_many_witness_credentials());
                } else {
                    *c = !*c;
                }
            }
        }
        A::ArmIncludeAll => {
            if view.choices.len() > witness::MAX_OUTCOME_EVIDENCE {
                view.notice = Some(too_many_witness_credentials());
            } else {
                view.confirm_all = true;
            }
        }
        A::ConfirmIncludeAll => {
            if view.confirm_all {
                return EvidenceStep::Assert(
                    view.choices.iter().map(|c| c.session_id.clone()).collect(),
                );
            }
        }
        A::CancelIncludeAll => view.confirm_all = false,
        A::Close => return EvidenceStep::Close,
    }
    EvidenceStep::Stay
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::{test_config, test_tdk};
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use openvtc_core::config::account::CommunityRecord;
    use openvtc_core::relationships::Relationship as RelRecord;
    use serde_json::json;

    const PERSONA: &str = "did:webvh:QmScidPersona:example.com:alice";
    const OURS: &str = "did:peer:2.Vz6MkOurRelationshipKey";
    const THEIRS: &str = "did:peer:2.Vz6MkTheirRelationshipKey";
    const THEIR_PERSONA: &str = "did:webvh:QmScidBob:example.com:bob";
    const WITNESS: &str = "did:key:z6MkWitness";

    fn vta_config() -> Config {
        let mut config = test_config();
        config.key_backend = KeyBackend::Vta {
            credential_bundle: secrecy::SecretString::new("bundle".into()),
            credential_did: "did:key:z6MkAccount".into(),
            credential_private_key: secrecy::SecretString::new("z".into()),
            vta_did: "did:key:z6MkVta".into(),
            vta_url: "http://127.0.0.1:1".into(),
            mediator_did: None,
            encryption_seed: secrecy::SecretBox::new(Box::new(vec![0u8; 32])),
        };
        config
    }

    /// An established relationship from our relationship DID to theirs, owned by `persona`.
    fn relate(config: &mut Config, persona: PersonaId) {
        config.private.relationships.relationships.insert(
            Arc::new(THEIR_PERSONA.to_string()),
            RelRecord {
                task_id: Arc::new("urn:uuid:relationship-thread".to_string()),
                our_did: Arc::new(OURS.to_string()),
                remote_p_did: Arc::new(THEIR_PERSONA.to_string()),
                remote_did: Arc::new(THEIRS.to_string()),
                created: Utc::now(),
                state: RelationshipState::Established,
                our_persona: Some(persona),
                needs_reestablishment: false,
            },
        );
    }

    /// Our VRC to `subject`, signed, as `prepare_accept_vrc_request` issues one.
    async fn issue_vrc(config: &mut Config, subject: &str) {
        let mut vrc = openvtc_core::vrc::new_identified_vrc(
            OURS,
            openvtc_core::dtg::relationship_issuer_scope(false),
            subject,
            Utc::now() - chrono::TimeDelta::minutes(1),
            None,
        );
        let mut secret = Secret::generate_ed25519(None, Some(&[3u8; 32]));
        secret.id = format!("{OURS}#key-1");
        vrc.sign(&secret, None).await.expect("sign");
        config
            .private
            .vrcs_issued
            .insert(&Arc::new(THEIR_PERSONA.to_string()), Arc::new(vrc))
            .expect("store");
    }

    /// A live membership of `persona` holding a VMC that names `member`.
    fn join(config: &mut Config, persona: PersonaId, member: &str) {
        let mut record = CommunityRecord::new_pending(
            "did:webvh:QmScidVtc:community.example".into(),
            None,
            "community".into(),
            persona,
            uuid::Uuid::new_v4(),
            Utc::now(),
        );
        record.activate(Utc::now());
        record.credentials.insert(
            CredentialKind::Membership,
            json!({ "id": "urn:uuid:vmc-1", "credentialSubject": { "id": member } }),
        );
        config.account.add_membership(record);
    }

    async fn prepared(config: &Config) -> Result<WitnessJob, String> {
        let tdk = test_tdk().await;
        let (event_tx, _event_rx) = tokio::sync::mpsc::unbounded_channel();
        let service = openvtc_core::didcomm::start_empty_service(
            event_tx,
            tokio_util::sync::CancellationToken::new(),
        );
        let (progress, _rx) = tokio::sync::mpsc::unbounded_channel();
        prepare(
            config,
            &tdk,
            &service,
            Some(&VtaClient::new("http://127.0.0.1:1")),
            &ReplyRouter::default(),
            &progress,
            THEIR_PERSONA,
            WITNESS,
        )
    }

    /// Witnessing needs the VTA to hold the relationship's keys: a BIP32 account is told so
    /// before anything else is read.
    #[tokio::test]
    async fn a_bip32_account_is_told_witnessing_needs_a_vta() {
        let err = prepared(&test_config()).await.err().expect("refused");
        assert!(err.contains("BIP32"), "{err}");
    }

    /// The witness observes us presenting the VRC *we* issued; without one there is nothing to
    /// show it, and the member is told how one comes about.
    #[tokio::test]
    async fn without_an_issued_vrc_there_is_nothing_to_present() {
        let mut config = vta_config();
        relate(&mut config, PersonaId::new());
        let err = prepared(&config).await.err().expect("refused");
        assert!(err.contains("relationship credential"), "{err}");

        // One issued to someone else is not this relationship's.
        issue_vrc(&mut config, "did:peer:2.Vz6MkSomebodyElse").await;
        assert!(prepared(&config).await.is_err());
    }

    /// The request names our relationship DID, theirs, the relationship's thread, our VRC, and —
    /// because the VMC names the persona, not the pairwise DID — the member link.
    #[tokio::test]
    async fn the_request_presents_our_vrc_and_links_the_persona() {
        let mut config = vta_config();
        let persona = PersonaId::new();
        relate(&mut config, persona);
        issue_vrc(&mut config, THEIRS).await;
        join(&mut config, persona, PERSONA);

        let job = prepared(&config).await.expect("prepared");
        let request = &job.request;
        assert_eq!(request.relationship_did, OURS);
        assert_eq!(request.counterparty_did, THEIRS);
        assert_eq!(
            request.relationship_thread_id,
            "urn:uuid:relationship-thread"
        );
        assert_eq!(request.relationship_credential["issuer"], OURS);
        let membership = request
            .membership
            .as_ref()
            .expect("the membership is presented");
        assert_eq!(membership.credential["id"], "urn:uuid:vmc-1");
        assert_eq!(membership.member_did.as_deref(), Some(PERSONA));
        assert_eq!(
            job.didcomm.listener_id,
            openvtc_core::didcomm::listener_id_for_did(OURS, &config)
        );
        assert!(
            job.tsp_sender.is_none(),
            "a relationship DID sends DIDComm only"
        );

        // A VMC naming the relationship DID itself needs no link.
        let mut direct = vta_config();
        let persona = PersonaId::new();
        relate(&mut direct, persona);
        issue_vrc(&mut direct, THEIRS).await;
        join(&mut direct, persona, OURS);
        let job = prepared(&direct).await.expect("prepared");
        assert_eq!(job.request.membership.unwrap().member_did, None);
    }

    /// A completed witnessing is kept against its relationship and shown; a failure is said and
    /// keeps nothing.
    #[test]
    fn the_outcome_is_kept_or_explained() {
        let mut config = vta_config();
        let mut state = State::default();
        let mut save = SaveScheduler::new("test");
        state.main_page.content_panel.relationships.mode = RelationshipsMode::Witness {
            index: 0,
            witness_input: WITNESS.into(),
        };

        WitnessOutcome {
            remote_p_did: THEIR_PERSONA.into(),
            relationship_did: OURS.into(),
            result: Err("the witness refused".into()),
        }
        .apply(&mut state, &mut config, &mut save);
        assert!(config.private.witnessings.is_empty());
        let status = state
            .main_page
            .content_panel
            .relationships
            .status_message
            .clone();
        assert_eq!(
            status.as_deref(),
            Some("Witnessing failed: the witness refused")
        );
        assert!(matches!(
            state.main_page.content_panel.relationships.mode,
            RelationshipsMode::Witness { .. }
        ));

        WitnessOutcome {
            remote_p_did: THEIR_PERSONA.into(),
            relationship_did: OURS.into(),
            result: Ok(Witnessed {
                session_id: "urn:uuid:s".into(),
                credential_id: "vwc-1".into(),
                witness: WITNESS.into(),
                vwc_digest_multibase: "z".into(),
                evidence: json!({ "session": {}, "outcome": {} }),
            }),
        }
        .apply(&mut state, &mut config, &mut save);
        let kept: Vec<_> = config
            .private
            .witnessings
            .for_relationship(THEIR_PERSONA)
            .collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].witnessed.credential_id, "vwc-1");
        assert!(matches!(
            state.main_page.content_panel.relationships.mode,
            RelationshipsMode::Detail { index: 0, .. }
        ));
    }

    fn choices(n: usize) -> Vec<WitnessChoice> {
        (0..n)
            .map(|i| WitnessChoice {
                session_id: format!("urn:uuid:{i}"),
                witness: WITNESS.into(),
                counterparty: format!("contact {i}"),
                witnessed_at: "2026-10-15 10:00".into(),
                digest: format!("z{i}"),
            })
            .collect()
    }

    /// The picker opens with nothing chosen, and submits exactly what was chosen.
    #[test]
    fn the_picker_starts_empty_and_chooses_one_at_a_time() {
        let mut view = evidence_view(choices(3));
        assert!(view.selected().is_empty(), "nothing is chosen by default");
        evidence_step(&mut view, PersonhoodEvidenceAction::Down);
        evidence_step(&mut view, PersonhoodEvidenceAction::Toggle);
        assert_eq!(view.selected(), vec!["urn:uuid:1".to_string()]);
        evidence_step(&mut view, PersonhoodEvidenceAction::Toggle);
        assert!(view.selected().is_empty());
        assert_eq!(
            evidence_step(&mut view, PersonhoodEvidenceAction::Close),
            EvidenceStep::Close
        );
    }

    /// "Include all" includes nothing until confirmed; a confirmation nobody asked for does
    /// nothing; backing out leaves the choices as they were.
    #[test]
    fn include_all_needs_its_own_confirmation() {
        let mut view = evidence_view(choices(3));
        assert_eq!(
            evidence_step(&mut view, PersonhoodEvidenceAction::ConfirmIncludeAll),
            EvidenceStep::Stay,
            "an unarmed confirmation is inert"
        );
        assert_eq!(
            evidence_step(&mut view, PersonhoodEvidenceAction::ArmIncludeAll),
            EvidenceStep::Stay,
            "asking includes nothing yet"
        );
        assert!(view.confirm_all && view.selected().is_empty());
        evidence_step(&mut view, PersonhoodEvidenceAction::CancelIncludeAll);
        assert!(!view.confirm_all && view.selected().is_empty());

        evidence_step(&mut view, PersonhoodEvidenceAction::ArmIncludeAll);
        assert_eq!(
            evidence_step(&mut view, PersonhoodEvidenceAction::ConfirmIncludeAll),
            EvidenceStep::Assert(vec![
                "urn:uuid:0".into(),
                "urn:uuid:1".into(),
                "urn:uuid:2".into()
            ])
        );
    }

    /// A selection is held to what a community accepts, and said — never trimmed.
    #[test]
    fn a_selection_over_the_communitys_limit_is_refused_not_trimmed() {
        let mut view = evidence_view(choices(witness::MAX_OUTCOME_EVIDENCE + 1));
        for _ in 0..witness::MAX_OUTCOME_EVIDENCE {
            evidence_step(&mut view, PersonhoodEvidenceAction::Toggle);
            evidence_step(&mut view, PersonhoodEvidenceAction::Down);
        }
        evidence_step(&mut view, PersonhoodEvidenceAction::Toggle);
        assert_eq!(view.selected().len(), witness::MAX_OUTCOME_EVIDENCE);
        assert!(view.notice.is_some());
        evidence_step(&mut view, PersonhoodEvidenceAction::ArmIncludeAll);
        assert!(
            !view.confirm_all,
            "include-all is not offered past the limit"
        );
    }
}
